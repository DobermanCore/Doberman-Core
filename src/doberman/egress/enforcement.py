"""The two-sided enforcement probe (Feature RB, slice RB.2a).

Answers one question: is this machine's egress actually constrained to the
broker right now? A deployment attestation token can be forged or stale; an
ACTIVE PROBE cannot lie the same way.

Proof requires BOTH halves, not a negative result alone:

* NEGATIVE — a DIRECT connection to a non-allowlisted destination FAILS with
  a network-level error (refused, timed out, unreachable).
* POSITIVE — a connection made THROUGH THE BROKER to an allowlisted
  destination SUCCEEDS.

A one-sided (negative-only) probe is unsound: a corporate firewall that
*drops* packets (the most common enterprise block) produces a ``TimeoutError``,
and a resolver policy that blocks the specific probe target (many
enterprises block ``1.1.1.1`` outright) produces a ``ConnectionRefusedError``
-- both indistinguishable from real broker enforcement, even on a machine
whose egress is otherwise wide open. The positive half is what rules that
out: it proves the network (and the probe target) are working, so a direct
failure can then only mean egress really is constrained.

Truth table::

    direct fails  + broker succeeds       -> PROVEN
    direct succeeds + broker (any)        -> UNPROVEN (demonstrably unconstrained)
    direct fails  + broker fails/absent   -> UNPROVEN (proves nothing; may be offline)
    unexpected exception in either half   -> UNPROVEN

Never raises. RB.2a wires no listener yet, so no ``broker_probe`` can be
supplied — :meth:`EnforcementProbe.status` can therefore only ever return
``UNPROVEN`` here; RB.2b enables ``PROVEN`` simply by supplying a real one.

:meth:`EnforcementProbe.status` never runs the probe on a call within the TTL
window — it returns the cached verdict. Only the call that crosses the TTL
boundary pays the (short, bounded) probe cost; see the ponytail note there.
"""

import socket
import time
from collections.abc import Callable

from doberman.egress.broker import EnforcementStatus

# The default target is a stable, well-known, publicly reachable host:port
# (Cloudflare's 1.1.1.1:443) that is not on the static TRUSTED_HOSTS
# allowlist. With two-sided proof the exact target is less load-bearing than
# it was for a negative-only probe (a blocked/dropped target alone can no
# longer produce a false PROVEN), but it should still be a host that
# normally ACCEPTS connections rather than a closed port. Override for
# air-gapped or egress-restrictive environments where this default is
# itself unreachable for reasons unrelated to broker enforcement.
DEFAULT_PROBE_HOST = "1.1.1.1"
DEFAULT_PROBE_PORT = 443
DEFAULT_PROBE_TIMEOUT_SECONDS = 1.5
#: How long a PROVEN/UNPROVEN verdict is trusted before the next call re-probes.
DEFAULT_ENFORCEMENT_TTL_SECONDS = 300.0

#: A connector attempts one direct TCP connect to (host, port) within
#: timeout seconds, raising on failure and returning (and closing) on
#: success. Constructor-injectable so tests never touch a real socket.
Connector = Callable[[str, int, float], None]

#: A broker probe attempts one connection THROUGH the broker to an
#: allowlisted destination, raising on failure and returning on success.
#: ``None`` (the RB.2a default -- no listener exists yet) means the
#: positive half can never be satisfied, so ``status()`` can only ever
#: return ``UNPROVEN``.
BrokerProbe = Callable[[], None]


def _socket_connector(host: str, port: int, timeout: float) -> None:
    """A direct TCP connect, bypassing any broker/proxy -- real network I/O.

    This is the production connector, but it is deliberately NOT the
    constructor default (see ``_no_network_connector``): a caller that wants
    the real probe must pass ``connector=_socket_connector`` explicitly.
    """
    with socket.create_connection((host, port), timeout=timeout):
        pass


def _no_network_connector(host: str, port: int, timeout: float) -> None:
    """Fail-closed default connector: performs no network I/O whatsoever.

    ``EnforcementProbe`` must never reach the network unless a caller
    deliberately opts in via ``connector=_socket_connector`` (or an
    equivalent). Raising ``OSError`` makes the direct-connection half read
    as "failed" without ever dialing out -- combined with the default
    ``broker_probe=None``, a default-constructed probe can therefore only
    ever report ``UNPROVEN`` (truth table: direct fails + broker absent ->
    UNPROVEN), which is also the correct fail-closed answer.
    """
    raise OSError("EnforcementProbe has no connector configured (network I/O is opt-in)")


class EnforcementProbe:
    """Caches a two-sided proof verdict, TTL'd, and never raises.

    :meth:`status` is the only entry point; a broker's ``enforcement_status()``
    should simply delegate to it.
    """

    def __init__(
        self,
        *,
        host: str = DEFAULT_PROBE_HOST,
        port: int = DEFAULT_PROBE_PORT,
        timeout: float = DEFAULT_PROBE_TIMEOUT_SECONDS,
        ttl: float = DEFAULT_ENFORCEMENT_TTL_SECONDS,
        connector: Connector | None = None,
        broker_probe: BrokerProbe | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._host = host
        self._port = port
        self._timeout = timeout
        self._ttl = ttl
        self._connector = connector or _no_network_connector
        self._broker_probe = broker_probe
        self._clock = clock
        self._cached: EnforcementStatus | None = None
        self._cached_at: float | None = None

    def status(self) -> EnforcementStatus:
        """The cached enforcement verdict, refreshing once the TTL elapses.

        # ponytail: the single call that crosses the TTL boundary pays the
        # probe's bounded timeout (~1.5s by default); every other call is a
        # cache read. A background refresh thread would remove even that, but
        # RB.2a never wires this broker into a live decision path (it isn't
        # registered yet) so that's unwarranted complexity here -- revisit if
        # probe latency becomes visible once RB.2b registers a real broker.
        """
        now = self._clock()
        if self._cached is None or self._cached_at is None or (now - self._cached_at) >= self._ttl:
            self._cached = self._probe_once()
            self._cached_at = now
        return self._cached

    def _probe_once(self) -> EnforcementStatus:
        try:
            direct_succeeded = self._direct_connection_succeeds()
        except Exception:  # noqa: BLE001 — a non-network exception is a probe bug, not
            # a network signal either way; it can't count toward PROVEN.
            return EnforcementStatus.UNPROVEN
        if direct_succeeded:
            # Egress is demonstrably NOT constrained -- the positive half
            # can't change that verdict.
            return EnforcementStatus.UNPROVEN
        if self._broker_connection_succeeds():
            # The direct attempt failed AND a broker-routed connection
            # works: the network is fine, so the direct failure can only be
            # egress enforcement.
            return EnforcementStatus.PROVEN
        # Direct failed but there's no working broker probe to corroborate
        # it -- proves nothing; the direct failure may just mean this
        # machine (or the probe target) is offline.
        return EnforcementStatus.UNPROVEN

    def _direct_connection_succeeds(self) -> bool:
        try:
            self._connector(self._host, self._port, self._timeout)
        except OSError:  # a real network-level failure: refused, timed out, unreachable
            return False
        return True

    def _broker_connection_succeeds(self) -> bool:
        if self._broker_probe is None:
            return False
        try:
            self._broker_probe()
        except Exception:  # noqa: BLE001 — any failure means the positive half is unmet
            return False
        return True
