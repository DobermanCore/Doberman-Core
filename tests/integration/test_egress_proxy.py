"""Feature RB, slice RB.2b — the forcing forward proxy: enforcement, not opinion.

`test_denied_destination_never_opens_the_upstream_socket` is the load-bearing
test in this file: it proves a denied `CONNECT` never touches the upstream
socket, not just that the client sees a `403`. Everything runs over real
loopback sockets on ephemeral ports — no fixed ports, no fixed sleeps
standing in for synchronization, servers always closed via fixture teardown.
"""

import asyncio
import contextlib
import socket

import pytest

from doberman.egress.allowlist import EgressAllowlist
from doberman.egress.broker import EnforcementStatus
from doberman.egress.enforcement import EnforcementProbe
from doberman.egress.proxy import BIND_HOST, ForwardProxy

# --- fixtures & helpers ------------------------------------------------------


class _FakeOrigin:
    """A tiny echo server standing in for a real upstream origin."""

    def __init__(self) -> None:
        self.connections = 0
        self._server: asyncio.AbstractServer | None = None

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, "localhost", 0)

    async def stop(self) -> None:
        assert self._server is not None
        self._server.close()
        await self._server.wait_closed()

    @property
    def port(self) -> int:
        assert self._server is not None
        return self._server.sockets[0].getsockname()[1]

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.connections += 1
        try:
            while True:
                data = await reader.read(4096)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        finally:
            with contextlib.suppress(Exception):
                writer.close()


@pytest.fixture
async def origin():
    o = _FakeOrigin()
    await o.start()
    yield o
    await o.stop()


@pytest.fixture
def allowlist():
    # "localhost" is a real hostname (not an IP literal), so it's eligible
    # for the allowlist's registered-domain match — unlike a raw IP, which
    # `EgressAllowlist` never trusts by name.
    return EgressAllowlist(extra_hosts=("localhost",))


@pytest.fixture
async def proxy(allowlist):
    p = ForwardProxy(allowlist, port=0)
    await p.start()
    yield p
    await p.stop()


async def _read_all(reader: asyncio.StreamReader, cap: int = 65536) -> bytes:
    """Read until EOF (bounded), for the short fixed replies this proxy sends."""
    data = b""
    while len(data) < cap:
        chunk = await reader.read(cap)
        if not chunk:
            break
        data += chunk
    return data


async def _close(writer: asyncio.StreamWriter) -> None:
    writer.close()
    with contextlib.suppress(Exception):
        await writer.wait_closed()


# --- CONNECT handling ---------------------------------------------------------


async def test_allowed_destination_tunnels_bytes_both_ways(proxy, origin):
    reader, writer = await asyncio.open_connection("127.0.0.1", proxy.port)
    writer.write(f"CONNECT localhost:{origin.port} HTTP/1.1\r\n\r\n".encode())
    await writer.drain()

    status_line = await reader.readline()
    assert status_line == b"HTTP/1.1 200 Connection Established\r\n"
    assert (await reader.readline()) == b"\r\n"

    writer.write(b"hello")
    await writer.drain()
    assert (await reader.read(5)) == b"hello"

    # Half-close and read to EOF: this deterministically waits for the full
    # tunnel teardown (and therefore the event record) to complete — see the
    # events test below for why that ordering is safe to rely on.
    writer.write_eof()
    await _read_all(reader)
    await _close(writer)

    assert origin.connections == 1


async def test_denied_destination_never_opens_the_upstream_socket(proxy, origin):
    # The load-bearing test: a destination the allowlist refuses must never
    # cause any upstream connection — the fake origin must record ZERO
    # connections, not merely "the client saw a 403".
    reader, writer = await asyncio.open_connection("127.0.0.1", proxy.port)
    writer.write(f"CONNECT not-allowed.example:{origin.port} HTTP/1.1\r\n\r\n".encode())
    await writer.drain()
    response = await _read_all(reader)
    await _close(writer)

    assert response.startswith(b"HTTP/1.1 403")
    assert origin.connections == 0


async def test_malformed_request_line_is_rejected(proxy, origin):
    reader, writer = await asyncio.open_connection("127.0.0.1", proxy.port)
    writer.write(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    await writer.drain()
    response = await _read_all(reader)
    await _close(writer)

    assert response.startswith(b"HTTP/1.1 400")
    assert origin.connections == 0


async def test_oversized_header_is_rejected_without_blowup(proxy):
    reader, writer = await asyncio.open_connection("127.0.0.1", proxy.port)
    # Never send the terminating blank line — forces the bounded reader to
    # give up rather than buffer indefinitely.
    writer.write(b"CONNECT localhost:1 HTTP/1.1\r\n" + b"X-Pad: " + b"a" * 9000 + b"\r\n")
    await writer.drain()
    response = await _read_all(reader)
    await _close(writer)

    assert response.startswith(b"HTTP/1.1 400")


async def test_upstream_refused_returns_502_and_server_keeps_serving(proxy):
    # Bind-then-release a loopback port so nothing listens there -> ECONNREFUSED.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        dead_port = s.getsockname()[1]

    reader, writer = await asyncio.open_connection("127.0.0.1", proxy.port)
    writer.write(f"CONNECT localhost:{dead_port} HTTP/1.1\r\n\r\n".encode())
    await writer.drain()
    response = await _read_all(reader)
    await _close(writer)
    assert response.startswith(b"HTTP/1.1 502")

    # The handler exception path must never crash the server loop.
    reader2, writer2 = await asyncio.open_connection("127.0.0.1", proxy.port)
    writer2.write(b"malformed\r\n\r\n")
    await writer2.drain()
    response2 = await _read_all(reader2)
    await _close(writer2)
    assert response2.startswith(b"HTTP/1.1 400")


# --- recorded events -----------------------------------------------------------


async def test_events_recorded_for_allowed_and_denied_carry_no_payload(proxy, origin):
    # Denied: recorded synchronously before the 403 is even written, so by
    # the time we've read the reply the event already exists.
    reader, writer = await asyncio.open_connection("127.0.0.1", proxy.port)
    writer.write(b"CONNECT not-allowed.example:443 HTTP/1.1\r\n\r\n")
    await writer.drain()
    await _read_all(reader)
    await _close(writer)

    # Allowed: the event is appended synchronously the instant both relay
    # pumps finish, strictly before that completion can propagate back to
    # this test as an observable EOF on `reader` — so waiting for EOF here
    # (via the half-close dance) is a safe, deterministic way to know the
    # event has already been recorded, with no fixed sleep involved.
    reader2, writer2 = await asyncio.open_connection("127.0.0.1", proxy.port)
    writer2.write(f"CONNECT localhost:{origin.port} HTTP/1.1\r\n\r\n".encode())
    await writer2.drain()
    await reader2.readline()
    await reader2.readline()
    writer2.write(b"payload-bytes")
    await writer2.drain()
    assert (await reader2.read(len(b"payload-bytes"))) == b"payload-bytes"
    writer2.write_eof()
    await _read_all(reader2)
    await _close(writer2)

    events = proxy.events()
    assert len(events) == 2
    assert {e.host for e in events} == {"not-allowed.example", "localhost"}
    for event in events:
        # Redaction-shaped: only the fields ConnectionEvent declares — no
        # payload/body/raw-request field exists to leak through.
        assert set(type(event).model_fields) == {
            "entity_id",
            "ts",
            "host",
            "bytes_sent",
            "will_enforce",
        }
        assert isinstance(event.bytes_sent, int)
        assert event.bytes_sent >= 0

    allowed_event = next(e for e in events if e.host == "localhost")
    assert allowed_event.bytes_sent == len(b"payload-bytes")
    denied_event = next(e for e in events if e.host == "not-allowed.example")
    assert denied_event.bytes_sent == 0


async def test_events_deque_is_bounded(allowlist):
    small = ForwardProxy(allowlist, port=0, max_events=3)
    await small.start()
    try:
        for _ in range(5):
            reader, writer = await asyncio.open_connection("127.0.0.1", small.port)
            writer.write(b"CONNECT not-allowed.example:443 HTTP/1.1\r\n\r\n")
            await writer.drain()
            await _read_all(reader)
            await _close(writer)
        assert len(small.events()) == 3
    finally:
        await small.stop()


# --- bind policy -----------------------------------------------------------------


def test_default_bind_host_is_loopback():
    assert BIND_HOST == "127.0.0.1"


def test_forward_proxy_refuses_a_non_loopback_bind_host(allowlist):
    with pytest.raises(ValueError):
        ForwardProxy(allowlist, host="0.0.0.0")  # noqa: S104 — asserting this is REFUSED


# --- enforcement PROVEN via a real proxy ------------------------------------------


async def test_enforcement_status_proven_via_a_running_proxy(proxy, origin):
    def failing_direct_connector(host, port, timeout):
        raise OSError("simulated: no direct route out of this machine")

    def broker_probe():
        asyncio.run(proxy.probe("localhost", origin.port))

    probe = EnforcementProbe(connector=failing_direct_connector, broker_probe=broker_probe)
    # Run the sync, blocking probe in a worker thread so the proxy's own
    # server (bound to this test's event loop) stays free to service the
    # probe's own connection attempt back into itself.
    status = await asyncio.to_thread(probe.status)
    assert status is EnforcementStatus.PROVEN


def test_enforcement_status_unproven_with_no_proxy_running():
    def failing_direct_connector(host, port, timeout):
        raise OSError("simulated: no direct route out of this machine")

    # No broker_probe -> per EnforcementProbe's contract, can never be PROVEN.
    probe = EnforcementProbe(connector=failing_direct_connector)
    assert probe.status() is EnforcementStatus.UNPROVEN
