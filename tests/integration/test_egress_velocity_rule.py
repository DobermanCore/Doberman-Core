"""RB.6 — ``ExternalDestinationRule`` wiring for the real per-entity egress
velocity signal: raise-only, wins over an RB.4 broker PASS, never lowers an
already-BLOCK, and is dormant without a broker.
"""

from datetime import datetime, timezone

from doberman.egress.broker import BrokerVerdict, ConnectionEvent, EnforcementStatus
from doberman.egress.velocity import _BURST_THRESHOLD
from doberman.engine.rules.destinations import ExternalDestinationRule
from doberman.models import (
    ActionType,
    EvalContext,
    ReasonCode,
    SecurityObject,
    Verdict,
)

_NOW = datetime(2026, 7, 24, 12, 0, 0, tzinfo=timezone.utc)


def _trusted_host_action(**overrides) -> SecurityObject:
    """A network request to a host on TRUSTED_HOSTS -- statically PASS."""
    base = dict(
        id="rb6-trusted-1",
        ts=_NOW,
        agent_role="unknown",
        action_type=ActionType.network_request,
        tool_name="net_get",
        target="https://pypi.org/simple/requests/",
        external_destination="pypi.org",
    )
    base.update(overrides)
    return SecurityObject(**base)


def _network_action(**overrides) -> SecurityObject:
    """A network request to an unknown/untrusted host -- statically AUTH."""
    base = dict(
        id="rb6-net-1",
        ts=_NOW,
        agent_role="unknown",
        action_type=ActionType.network_request,
        tool_name="net_get",
        target="https://unknown-saas.example/api",
        external_destination="unknown-saas.example",
    )
    base.update(overrides)
    return SecurityObject(**base)


def _ctx(mode: str = "balanced", **metadata) -> EvalContext:
    return EvalContext(mode=mode, metadata=metadata)


def _burst_events(entity: str, host: str) -> list[ConnectionEvent]:
    return [
        ConnectionEvent(entity_id=entity, ts=_NOW, host=host, bytes_sent=1)
        for _ in range(_BURST_THRESHOLD + 1)
    ]


class _Broker:
    """Configurable fake ``EgressBroker`` for RB.6 rule-integration tests."""

    def __init__(
        self,
        events=(),
        *,
        status: EnforcementStatus = EnforcementStatus.PROVEN,
        allowlisted: bool = True,
        will_enforce: bool = True,
        events_raise: bool = False,
    ) -> None:
        self._events = tuple(events)
        self._status = status
        self._allowlisted = allowlisted
        self._will_enforce = will_enforce
        self._events_raise = events_raise

    def enforcement_status(self) -> EnforcementStatus:
        return self._status

    def classify(self, action) -> BrokerVerdict:
        return BrokerVerdict(allowlisted=self._allowlisted, will_enforce=self._will_enforce)

    def connection_events(self, entity, window):
        if self._events_raise:
            raise RuntimeError("broker exploded in connection_events()")
        start, end = window
        return tuple(e for e in self._events if e.entity_id == entity and start <= e.ts <= end)


def test_velocity_trip_raises_pass_to_auth_with_reason_code():
    broker = _Broker(events=_burst_events("ent-1", "github.com"))  # trusted host: no divergence
    rule = ExternalDestinationRule(egress_broker=broker)
    ctx = _ctx(entity_id="ent-1")
    result = rule.evaluate(_trusted_host_action(), ctx)
    assert result.verdict is Verdict.AUTH
    assert ReasonCode.anomalous_egress_velocity in result.reason_codes
    assert ReasonCode.egress_route_divergence not in result.reason_codes


def test_velocity_trip_wins_over_broker_backed_pass():
    """RB.4 would otherwise grant PASS for this unknown destination -- a
    velocity trip must still raise it to AUTH, never leaving it at PASS.
    """
    broker = _Broker(
        status=EnforcementStatus.PROVEN,
        allowlisted=True,
        will_enforce=True,
        events=_burst_events("ent-1", "github.com"),
    )
    rule = ExternalDestinationRule(egress_broker=broker)
    ctx = _ctx(entity_id="ent-1")
    result = rule.evaluate(_network_action(), ctx)
    assert result.verdict is Verdict.AUTH
    assert result.verdict is not Verdict.PASS
    assert ReasonCode.anomalous_egress_velocity in result.reason_codes


def test_already_block_plus_velocity_trip_stays_block():
    """RB.5 paranoid hard-block (PROVEN, not allowlisted, will enforce) is
    already BLOCK; a velocity trip must append its reason code without ever
    lowering the verdict.
    """
    broker = _Broker(
        status=EnforcementStatus.PROVEN,
        allowlisted=False,
        will_enforce=True,
        events=_burst_events("ent-1", "github.com"),
    )
    rule = ExternalDestinationRule(egress_broker=broker)
    ctx = _ctx(mode="paranoid", entity_id="ent-1")
    result = rule.evaluate(_network_action(), ctx)
    assert result.verdict is Verdict.BLOCK
    assert ReasonCode.anomalous_egress_velocity in result.reason_codes


def test_no_broker_velocity_check_is_unchanged():
    rule = ExternalDestinationRule(load_broker=False)
    result = rule.evaluate(_trusted_host_action(), _ctx(entity_id="ent-1"))
    assert result.verdict is Verdict.PASS
    assert ReasonCode.anomalous_egress_velocity not in result.reason_codes


def test_broker_raising_in_connection_events_is_no_signal_and_does_not_crash():
    broker = _Broker(events_raise=True)
    rule = ExternalDestinationRule(egress_broker=broker)
    result = rule.evaluate(_trusted_host_action(), _ctx(entity_id="ent-1"))
    assert result.verdict is Verdict.PASS
    assert ReasonCode.anomalous_egress_velocity not in result.reason_codes
