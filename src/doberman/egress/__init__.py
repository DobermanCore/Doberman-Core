"""The runtime egress broker seam (Feature RB, slice RB.1).

A pluggable second layer, ALONGSIDE the static :class:`~doberman.engine.rules.
destinations.ExternalDestinationRule`, that can eventually back an egress
``PASS`` with a runtime enforcement promise instead of a parse-time guess. RB.1
ships only the seam: the interface, entry-point discovery, and a fail-closed
consultation helper. It is wired into the decision path but **dormant** — no
broker verdict can raise OR lower a verdict yet (that starts at RB.4). A real
forcing-proxy broker (enterprise or a future core slice) registers via the
``doberman.egress_brokers`` entry-point group — core never imports one by name.
"""

from doberman.egress.broker import (
    BrokerVerdict,
    ConnectionEvent,
    EgressBroker,
    EnforcementStatus,
    consult_broker,
)

__all__ = [
    "BrokerVerdict",
    "ConnectionEvent",
    "EgressBroker",
    "EnforcementStatus",
    "consult_broker",
]
