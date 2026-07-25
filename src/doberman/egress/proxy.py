"""Feature RB, slice RB.2b — the forcing forward proxy: enforcement, not opinion.

RB.2a built the allowlist and the enforcement-proof machinery but had no
listener, so ``LocalEgressBroker`` could never truthfully promise to enforce
anything. This module is the listener: a minimal, stdlib-only (``asyncio``)
HTTP ``CONNECT`` forward proxy that a coding agent's egress can be pointed at.
It applies :class:`~doberman.egress.allowlist.EgressAllowlist` **at the
socket**, before any upstream connection exists — a denied destination's
upstream socket is never opened, full stop.

Known limitations (deliberate scope for this slice, not TODOs):

- **HTTP ``CONNECT`` only.** No SOCKS4/5 support. A client that cannot speak
  an HTTP proxy (``CONNECT host:port HTTP/1.1``) cannot be mediated by this
  proxy.
- **No transparent / SNI-sniffing mode.** This proxy only sees traffic a
  client explicitly routes to it via ``CONNECT``; it cannot intercept traffic
  that bypasses it (e.g. a process configured to ignore the proxy, or one
  that opens raw sockets directly). Enforcement is only as strong as the
  guarantee that *all* of the protected agent's egress is actually routed
  through this proxy — that guarantee is out of scope here.

Granting no ``PASS``: nothing in this module changes any Doberman decision.
It is a standalone TCP listener; only code that explicitly constructs and
runs it is affected, and only :mod:`doberman.egress.local` (RB.2b's wiring)
reads its recorded events — and even that is not yet registered on the
decision path (RB.4).
"""

import asyncio
import contextlib
import logging
from collections import deque
from collections.abc import Sequence
from datetime import datetime, timezone

from doberman.egress.allowlist import EgressAllowlist
from doberman.egress.broker import ConnectionEvent

logger = logging.getLogger("doberman.egress.proxy")

#: The proxy MUST bind loopback only. An externally reachable open forward
#: proxy is a severe vulnerability — anyone who can reach this port could
#: tunnel arbitrary TCP through it, bypassing every allowlist check that
#: matters to *this* machine's egress. Never widen this to "0.0.0.0" (or any
#: non-loopback address) and never make the bind host caller-configurable
#: without a lot more thought than this slice gives it — `ForwardProxy`
#: refuses construction with anything else (see `__init__`).
BIND_HOST = "127.0.0.1"

#: Bound read for the CONNECT request/header block: caps memory a hostile or
#: broken client can force us to buffer before we give up and close.
_MAX_REQUEST_BYTES = 8192

#: Default cap on retained `ConnectionEvent`s (a `collections.deque` is
#: self-trimming — oldest attempts are dropped first, never SQLite/disk).
_MAX_EVENTS = 1000

_READ_CHUNK = 4096
_RELAY_CHUNK = 65536


class ForwardProxy:
    """An asyncio HTTP ``CONNECT`` forward proxy that enforces an allowlist.

    Construct with an :class:`~doberman.egress.allowlist.EgressAllowlist`,
    ``await start()``, then point a client's proxy settings at
    ``127.0.0.1:<port>``. ``stop()`` closes the listener; connections already
    tunneling are unaffected (the relay tears down on its own when either
    side closes).
    """

    def __init__(
        self,
        allowlist: EgressAllowlist,
        *,
        host: str = BIND_HOST,
        port: int = 0,
        entity_id: str = "local",
        max_events: int = _MAX_EVENTS,
    ) -> None:
        if host != BIND_HOST:
            # ponytail: loopback-only, no exceptions — see BIND_HOST above.
            raise ValueError(f"ForwardProxy must bind {BIND_HOST!r}; refusing host={host!r}")
        self._allowlist = allowlist
        self._host = host
        self._requested_port = port
        #: Keyed HMAC fingerprint of the entity this proxy serves (see
        #: `ConnectionEvent.entity_id`) — never a raw role/path string. RB.2b
        #: is single-tenant (one proxy per local machine/agent), so this is a
        #: constructor-level constant rather than per-connection.
        self._entity_id = entity_id
        self._server: asyncio.AbstractServer | None = None
        self._events: deque[ConnectionEvent] = deque(maxlen=max_events)

    @property
    def port(self) -> int:
        """The bound port. Valid only once `start()` has completed."""
        if self._server is None or not self._server.sockets:
            raise RuntimeError("ForwardProxy is not started")
        return self._server.sockets[0].getsockname()[1]

    def is_running(self) -> bool:
        return self._server is not None

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, self._host, self._requested_port)

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def __aenter__(self) -> "ForwardProxy":
        await self.start()
        return self

    async def __aexit__(self, *_exc_info: object) -> None:
        await self.stop()

    def events(self) -> Sequence[ConnectionEvent]:
        """A snapshot of recorded connection attempts, oldest first."""
        return tuple(self._events)

    async def probe(self, host: str, port: int) -> None:
        """Connect through this proxy to ``host:port``; raise on any failure.

        The positive half of :class:`~doberman.egress.enforcement.
        EnforcementProbe`'s two-sided check — a real, end-to-end confirmation
        that a listener is up and genuinely lets an allowlisted destination
        through. Raises ``ConnectionError``/``OSError``/``TimeoutError`` on
        anything but a ``200`` reply; never returns a "maybe."
        """
        reader, writer = await asyncio.open_connection(self._host, self.port)
        try:
            writer.write(f"CONNECT {host}:{port} HTTP/1.1\r\n\r\n".encode("ascii"))
            await writer.drain()
            status_line = await asyncio.wait_for(reader.readline(), timeout=5)
            if b" 200 " not in status_line:
                raise ConnectionError(f"forward proxy probe refused: {status_line!r}")
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    # --- connection handling -----------------------------------------------

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await self._handle_inner(reader, writer)
        except Exception:  # noqa: BLE001 — one bad connection must never kill the server
            logger.debug("forward proxy connection handler failed", exc_info=True)
        finally:
            with contextlib.suppress(Exception):
                writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    async def _handle_inner(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        request_line = await self._read_request_line(reader)
        if request_line is None:
            await self._reply(writer, 400, "Bad Request")
            return
        host, port = self._parse_connect(request_line)
        if host is None or port is None:
            await self._reply(writer, 400, "Bad Request")
            return

        if not self._allowlist.is_allowed(host):
            self._record_event(host, bytes_sent=0)
            await self._reply(writer, 403, "Forbidden")
            return

        try:
            upstream_reader, upstream_writer = await asyncio.open_connection(host, port)
        except OSError:
            self._record_event(host, bytes_sent=0)
            await self._reply(writer, 502, "Bad Gateway")
            return

        await self._reply(writer, 200, "Connection Established")
        sent = await self._relay(reader, writer, upstream_reader, upstream_writer)
        self._record_event(host, bytes_sent=sent)

    async def _read_request_line(self, reader: asyncio.StreamReader) -> str | None:
        """Read up to the blank line ending the request, bounded to 8 KiB.

        Returns the first line only (the ``CONNECT`` request line); any
        further headers are read (to reach the terminator) and discarded —
        this proxy never inspects or forwards header content.
        """
        buf = b""
        while b"\r\n\r\n" not in buf:
            if len(buf) >= _MAX_REQUEST_BYTES:
                return None
            chunk = await reader.read(_READ_CHUNK)
            if not chunk:
                return None
            buf += chunk
        head = buf.split(b"\r\n\r\n", 1)[0]
        first_line = head.split(b"\r\n", 1)[0]
        try:
            return first_line.decode("ascii")
        except UnicodeDecodeError:
            return None

    @staticmethod
    def _parse_connect(request_line: str) -> tuple[str | None, int | None]:
        parts = request_line.split(" ")
        if len(parts) < 3 or parts[0] != "CONNECT":
            return None, None
        authority = parts[1]
        host, sep, port_str = authority.rpartition(":")
        if not sep or not host or not port_str.isdigit():
            return None, None
        return host, int(port_str)

    def _record_event(self, host: str, *, bytes_sent: int) -> None:
        # will_enforce=True: this event only ever exists because *this*
        # enforcing proxy actually decided the connection's fate (allowed and
        # tunneled, or denied and blocked) — never a passive observation.
        self._events.append(
            ConnectionEvent(
                entity_id=self._entity_id,
                ts=datetime.now(timezone.utc),
                host=host,
                bytes_sent=bytes_sent,
                will_enforce=True,
            )
        )

    @staticmethod
    async def _reply(writer: asyncio.StreamWriter, code: int, reason: str) -> None:
        with contextlib.suppress(Exception):
            writer.write(f"HTTP/1.1 {code} {reason}\r\n\r\n".encode("ascii"))
            await writer.drain()

    @staticmethod
    async def _relay(
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        upstream_reader: asyncio.StreamReader,
        upstream_writer: asyncio.StreamWriter,
    ) -> int:
        """Relay both directions until either side closes. Returns bytes sent
        client -> upstream (the entity's own outbound volume)."""

        async def pump(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> int:
            total = 0
            try:
                while True:
                    chunk = await src.read(_RELAY_CHUNK)
                    if not chunk:
                        break
                    dst.write(chunk)
                    await dst.drain()
                    total += len(chunk)
            except (ConnectionError, OSError):
                pass
            finally:
                with contextlib.suppress(Exception):
                    dst.write_eof()
            return total

        sent, _received = await asyncio.gather(
            pump(client_reader, upstream_writer),
            pump(upstream_reader, client_writer),
        )
        with contextlib.suppress(Exception):
            upstream_writer.close()
        return sent
