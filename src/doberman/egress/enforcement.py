"""The enforcement negative probe (Feature RB, slice RB.2a).

Answers one question: is this machine's egress actually constrained to the
broker right now? A deployment attestation token can be forged or stale; an
ACTIVE NEGATIVE PROBE cannot lie the same way — it attempts the thing an
unconstrained agent would do (open a direct socket to a destination outside
the broker) and watches whether that attempt is actually stopped.

Fail-closed rule (the whole point of this module):

* Direct connection SUCCEEDS -> egress is NOT constrained -> ``UNPROVEN``.
* ``ConnectionRefusedError`` / ``TimeoutError`` -> a definitive rejection of
  the direct attempt -> egress appears constrained -> ``PROVEN``.
* Any other error (a plain ``OSError`` such as a DNS failure or "network
  unreachable", or a non-``OSError`` bug in the connector) is ambiguous -- it
  may mean the probe itself is misconfigured rather than that egress is
  enforced -> ``UNPROVEN``. Never raises.

:meth:`EnforcementProbe.status` never runs the probe on a call within the TTL
window — it returns the cached verdict. Only the call that crosses the TTL
boundary pays the (short, bounded) probe cost; see the ponytail note there.
"""

import logging
import socket
import time
from collections.abc import Callable

from doberman.egress.broker import EnforcementStatus

logger = logging.getLogger("doberman.egress.enforcement")

# The default target is a stable, well-known, publicly reachable host:port
# (Cloudflare's 1.1.1.1:443) that is not on the static TRUSTED_HOSTS
# allowlist. It must be something that ACCEPTS a connection when reached
# directly, not merely a closed port -- a closed port produces the same
# ConnectionRefusedError as a local firewall REJECT, which would make an
# *unconstrained* machine falsely read as PROVEN. Override for air-gapped or
# egress-restrictive environments where this default is itself unreachable
# for reasons unrelated to broker enforcement.
DEFAULT_PROBE_HOST = "1.1.1.1"
DEFAULT_PROBE_PORT = 443
DEFAULT_PROBE_TIMEOUT_SECONDS = 1.5
#: How long a PROVEN/UNPROVEN verdict is trusted before the next call re-probes.
DEFAULT_ENFORCEMENT_TTL_SECONDS = 300.0

#: A connector attempts one direct TCP connect to (host, port) within
#: timeout seconds, raising on failure and returning (and closing) on
#: success. Constructor-injectable so tests never touch a real socket.
Connector = Callable[[str, int, float], None]


def _socket_connector(host: str, port: int, timeout: float) -> None:
    """Default connector: a direct TCP connect, bypassing any broker/proxy."""
    with socket.create_connection((host, port), timeout=timeout):
        pass


class EnforcementProbe:
    """Caches an active negative-probe verdict, TTL'd, and never raises.

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
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._host = host
        self._port = port
        self._timeout = timeout
        self._ttl = ttl
        self._connector = connector or _socket_connector
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
            self._connector(self._host, self._port, self._timeout)
        except (ConnectionRefusedError, TimeoutError):
            # A definitive rejection of the direct attempt -- egress appears
            # constrained to the broker.
            return EnforcementStatus.PROVEN
        except Exception:  # noqa: BLE001 — any other failure is ambiguous; fail closed
            logger.debug(
                "egress enforcement probe raised an unexpected error; treating as UNPROVEN"
            )
            return EnforcementStatus.UNPROVEN
        else:
            # The direct connection SUCCEEDED -- egress is demonstrably NOT
            # constrained to the broker.
            return EnforcementStatus.UNPROVEN
