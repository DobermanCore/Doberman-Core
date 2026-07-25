"""``LocalEgressBroker`` (Feature RB, slices RB.2a + RB.2b) — a concrete
`EgressBroker`.

RB.2a built the allowlist + the enforcement-proof machinery with no listener,
so it could never truthfully promise to enforce anything (``will_enforce`` was
always ``False``, ``connection_events`` always empty). RB.2b adds an *optional*
:class:`~doberman.egress.proxy.ForwardProxy`: when one is injected, this
broker's answers become real — ``classify()`` can report ``will_enforce=True``
for a proxy that is actually running, ``connection_events`` reflects what the
proxy actually observed, and ``enforcement_status()`` can genuinely reach
``PROVEN`` (the injected probe's positive half connects *through* the proxy).
With no proxy (the default), behavior is byte-for-byte RB.2a.

Not registered as a ``doberman.egress_brokers`` entry point by this slice —
constructing this class has no effect on any decision until something opts in
and RB.4 lands.
"""

import asyncio
import logging
from collections.abc import Sequence

from pydantic import AwareDatetime

from doberman.egress.allowlist import EgressAllowlist
from doberman.egress.broker import BrokerVerdict, ConnectionEvent, EnforcementStatus
from doberman.egress.enforcement import EnforcementProbe
from doberman.egress.proxy import ForwardProxy
from doberman.engine.rules.destinations import _extract_destination
from doberman.models import ReasonCode, SecurityObject

logger = logging.getLogger("doberman.egress.local")


class LocalEgressBroker:
    """The core reference `EgressBroker` (Option A topology, plan §3.2).

    With no ``proxy`` injected: allowlist + enforcement-proof only — no
    listener, no PASS, no observed connections (RB.2a behavior, unchanged).
    """

    def __init__(
        self,
        *,
        allowlist: EgressAllowlist | None = None,
        probe: EnforcementProbe | None = None,
        proxy: ForwardProxy | None = None,
        probe_target: tuple[str, int] = ("github.com", 443),
    ) -> None:
        self._allowlist = allowlist if allowlist is not None else EgressAllowlist()
        self._proxy = proxy
        if probe is not None:
            self._probe = probe
        elif proxy is not None:
            # ponytail: probe one well-known allowlisted host through the
            # proxy — enough to prove "this proxy is actually enforcing
            # egress right now" without a configurable target list. The
            # direct connector stays at EnforcementProbe's safe default
            # (no-network, raises); only a caller building a real deployment
            # opts into the real-network `_socket_connector` explicitly.
            target_host, target_port = probe_target
            self._probe = EnforcementProbe(
                broker_probe=lambda: asyncio.run(proxy.probe(target_host, target_port))
            )
        else:
            self._probe = EnforcementProbe()

    def enforcement_status(self) -> EnforcementStatus:
        """The cached two-sided enforcement-probe verdict; never blocks/raises."""
        return self._probe.status()

    def classify(self, action: SecurityObject) -> BrokerVerdict:
        """Prospective only: would ``action``'s destination be allowlisted?

        Never claims to know the actual runtime socket a pending action will
        open — see the module docstring in :mod:`doberman.egress.broker`.
        ``will_enforce`` is only ever ``True`` when a proxy is actually
        running (and so would genuinely mediate that destination, whether it
        ends up allowed or denied) — with no proxy attached, always ``False``.
        """
        destination = _extract_destination(action)
        allowlisted = bool(destination) and self._allowlist.is_allowed(destination)
        reason_codes = [] if allowlisted else [ReasonCode.unknown_external_destination]
        will_enforce = bool(destination) and self._proxy is not None and self._proxy.is_running()
        return BrokerVerdict(
            allowlisted=allowlisted, will_enforce=will_enforce, reason_codes=reason_codes
        )

    def connection_events(
        self, entity: str, window: tuple[AwareDatetime, AwareDatetime]
    ) -> Sequence[ConnectionEvent]:
        # No proxy attached: nothing has ever been observed (RB.2a behavior).
        if self._proxy is None:
            return ()
        start, end = window
        return tuple(
            event
            for event in self._proxy.events()
            if event.entity_id == entity and start <= event.ts <= end
        )
