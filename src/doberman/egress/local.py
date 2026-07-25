"""``LocalEgressBroker`` (Feature RB, slice RB.2a) — a concrete `EgressBroker`.

RB.2a builds the allowlist + the enforcement-proof machinery only. There is no
listener/proxy yet (that's RB.2b) — so this broker can genuinely PROVE
enforcement (:mod:`doberman.egress.enforcement`'s probe answers a real
question about *this machine's* egress), but it can never truthfully promise
to enforce any particular destination, because nothing is actually
intercepting traffic. ``classify()`` therefore always returns
``will_enforce=False``; RB.2b is what makes that field meaningful, and RB.4 is
what lets a broker verdict actually change a decision.

Not registered as a ``doberman.egress_brokers`` entry point by this slice —
constructing this class has no effect on any decision until something opts in
and RB.4 lands.
"""

import logging
from collections.abc import Sequence

from pydantic import AwareDatetime

from doberman.egress.allowlist import EgressAllowlist
from doberman.egress.broker import BrokerVerdict, ConnectionEvent, EnforcementStatus
from doberman.egress.enforcement import EnforcementProbe
from doberman.engine.rules.destinations import _extract_destination
from doberman.models import ReasonCode, SecurityObject

logger = logging.getLogger("doberman.egress.local")


class LocalEgressBroker:
    """The core reference `EgressBroker` (Option A topology, plan §3.2).

    RB.2a: allowlist + enforcement-proof only — no listener, no PASS, no
    observed connections.
    """

    def __init__(
        self,
        *,
        allowlist: EgressAllowlist | None = None,
        probe: EnforcementProbe | None = None,
    ) -> None:
        self._allowlist = allowlist if allowlist is not None else EgressAllowlist()
        self._probe = probe if probe is not None else EnforcementProbe()

    def enforcement_status(self) -> EnforcementStatus:
        """The cached two-sided enforcement-probe verdict; never blocks/raises."""
        return self._probe.status()

    def classify(self, action: SecurityObject) -> BrokerVerdict:
        """Prospective only: would ``action``'s destination be allowlisted?

        Never claims to know the actual runtime socket a pending action will
        open — see the module docstring in :mod:`doberman.egress.broker`.
        ``will_enforce`` is unconditionally ``False`` in RB.2a: with no
        listener, this broker cannot truthfully promise to enforce anything.
        """
        destination = _extract_destination(action)
        allowlisted = bool(destination) and self._allowlist.is_allowed(destination)
        reason_codes = [] if allowlisted else [ReasonCode.unknown_external_destination]
        return BrokerVerdict(allowlisted=allowlisted, will_enforce=False, reason_codes=reason_codes)

    def connection_events(
        self, entity: str, window: tuple[AwareDatetime, AwareDatetime]
    ) -> Sequence[ConnectionEvent]:
        # RB.2a has no listener, so nothing has ever been observed. RB.2b
        # populates this from the proxy's real connection log.
        return ()
