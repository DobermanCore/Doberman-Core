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

# NOTE: allowlist.py/local.py are deliberately NOT re-exported here. They
# import doberman.engine.rules.destinations, which itself imports
# doberman.egress.broker at its own module top — eagerly importing them from
# this package __init__ would make that resolution order-dependent (whichever
# of the two modules some caller imports first) and can deadlock on a
# partially-initialized module. Import them directly:
# `from doberman.egress.allowlist import EgressAllowlist`,
# `from doberman.egress.local import LocalEgressBroker`.

__all__ = [
    "BrokerVerdict",
    "ConnectionEvent",
    "EgressBroker",
    "EnforcementStatus",
    "consult_broker",
]
