"""RB.6 policy wiring — egress-velocity thresholds from PolicyDoc to tracker.

Covers the full pipeline:
  VelocityThresholds → PolicyDoc → to_mapping/from_mapping (YAML round-trip)
  → ExternalDestinationRule(velocity_thresholds=...) → EgressVelocityTracker

Also covers the serve.py rebuild path: a policy file on disk with tighter
thresholds must produce a DEFAULT_OBJECTIVE that trips at the tighter level,
not the built-in default.
"""

from datetime import datetime, timezone

from doberman.config import load_policy, save_policy
from doberman.egress.broker import BrokerVerdict, ConnectionEvent, EnforcementStatus
from doberman.egress.velocity import (
    VelocityThresholds,
)
from doberman.engine.objective import ObjectiveGuardrail
from doberman.engine.rules.destinations import ExternalDestinationRule
from doberman.models import ActionType, EvalContext, ReasonCode, SecurityObject, Verdict
from doberman.policy.checklist import PolicyDoc, recommend_policy

_NOW = datetime(2026, 7, 24, 12, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _trusted_action() -> SecurityObject:
    return SecurityObject(
        id="wiring-1",
        ts=_NOW,
        agent_role="unknown",
        action_type=ActionType.network_request,
        tool_name="net_get",
        target="https://pypi.org/simple/requests/",
        external_destination="pypi.org",
    )


def _ctx(entity: str = "ent-1", mode: str = "balanced") -> EvalContext:
    return EvalContext(mode=mode, metadata={"entity_id": entity})


def _events(n: int, entity: str = "ent-1") -> list[ConnectionEvent]:
    return [
        ConnectionEvent(entity_id=entity, ts=_NOW, host="pypi.org", bytes_sent=1) for _ in range(n)
    ]


class _Broker:
    def __init__(self, events=()):
        self._events = list(events)

    def enforcement_status(self):
        return EnforcementStatus.PROVEN

    def classify(self, action):
        return BrokerVerdict(allowlisted=True, will_enforce=True)

    def connection_events(self, entity, window):
        start, end = window
        return [e for e in self._events if e.entity_id == entity and start <= e.ts <= end]


# ---------------------------------------------------------------------------
# A: VelocityThresholds constructor override wires into tracker correctly
# ---------------------------------------------------------------------------


def test_tighter_burst_threshold_trips_earlier():
    """A threshold of 5 (tighter than the 20 default) should trip on 6 events."""
    tighter = VelocityThresholds(burst=5)
    broker = _Broker(events=_events(6))
    rule = ExternalDestinationRule(egress_broker=broker, velocity_thresholds=tighter)
    result = rule.evaluate(_trusted_action(), _ctx())
    assert result.verdict is Verdict.AUTH
    assert ReasonCode.anomalous_egress_velocity in result.reason_codes


def test_tighter_burst_threshold_does_not_trip_below_its_own_level():
    """5 events should not trip when burst=5 (threshold is exclusive: > not >=)."""
    tighter = VelocityThresholds(burst=5)
    broker = _Broker(events=_events(5))
    rule = ExternalDestinationRule(egress_broker=broker, velocity_thresholds=tighter)
    result = rule.evaluate(_trusted_action(), _ctx())
    assert ReasonCode.anomalous_egress_velocity not in result.reason_codes


def test_default_threshold_does_not_trip_on_sub_default_count():
    """With the built-in threshold (20), 6 events should not trip."""
    broker = _Broker(events=_events(6))
    rule = ExternalDestinationRule(egress_broker=broker)  # no velocity_thresholds
    result = rule.evaluate(_trusted_action(), _ctx())
    assert ReasonCode.anomalous_egress_velocity not in result.reason_codes


def test_tighter_fanout_threshold():
    tighter = VelocityThresholds(fanout=2)
    events = [
        ConnectionEvent(entity_id="ent-1", ts=_NOW, host=f"h{i}.example.com", bytes_sent=1)
        for i in range(3)
    ]
    broker = _Broker(events=events)
    rule = ExternalDestinationRule(egress_broker=broker, velocity_thresholds=tighter)
    result = rule.evaluate(_trusted_action(), _ctx())
    assert ReasonCode.anomalous_egress_velocity in result.reason_codes


def test_tighter_volume_threshold():
    tighter = VelocityThresholds(volume_bytes=100)
    events = [ConnectionEvent(entity_id="ent-1", ts=_NOW, host="pypi.org", bytes_sent=101)]
    broker = _Broker(events=events)
    rule = ExternalDestinationRule(egress_broker=broker, velocity_thresholds=tighter)
    result = rule.evaluate(_trusted_action(), _ctx())
    assert ReasonCode.anomalous_egress_velocity in result.reason_codes


# ---------------------------------------------------------------------------
# B: PolicyDoc round-trip preserves thresholds
# ---------------------------------------------------------------------------


def test_policydoc_round_trip_preserves_thresholds():
    thresholds = VelocityThresholds(burst=8, volume_bytes=1024 * 1024, fanout=3)
    doc = recommend_policy().with_egress_velocity_thresholds(thresholds)

    mapping = doc.to_mapping()
    assert mapping["egress_velocity_thresholds"] == {
        "burst": 8,
        "volume_bytes": 1024 * 1024,
        "fanout": 3,
    }

    loaded = PolicyDoc.from_mapping(mapping)
    assert loaded.egress_velocity_thresholds is not None
    assert loaded.egress_velocity_thresholds.burst == 8
    assert loaded.egress_velocity_thresholds.volume_bytes == 1024 * 1024
    assert loaded.egress_velocity_thresholds.fanout == 3


def test_policydoc_round_trip_without_thresholds_is_none():
    doc = recommend_policy()
    assert doc.egress_velocity_thresholds is None
    loaded = PolicyDoc.from_mapping(doc.to_mapping())
    assert loaded.egress_velocity_thresholds is None


def test_policydoc_malformed_thresholds_fall_back_to_none():
    mapping = recommend_policy().to_mapping()
    mapping["egress_velocity_thresholds"] = {"burst": "not-an-int"}
    loaded = PolicyDoc.from_mapping(mapping)
    # Malformed value must not crash; built-in defaults apply.
    assert loaded.egress_velocity_thresholds is None


def test_with_egress_velocity_thresholds_none_clears_field():
    thresholds = VelocityThresholds(burst=5)
    doc = recommend_policy().with_egress_velocity_thresholds(thresholds)
    cleared = doc.with_egress_velocity_thresholds(None)
    assert cleared.egress_velocity_thresholds is None


# ---------------------------------------------------------------------------
# C: Full disk-round-trip: save_policy → load_policy → rule uses thresholds
# ---------------------------------------------------------------------------


def test_policy_file_thresholds_reach_rule_via_load_policy(tmp_path):
    """Write a policy with burst=5 to disk, load it, build the rule from the
    loaded doc, and confirm 6 events trip at the tighter level."""
    thresholds = VelocityThresholds(burst=5)
    doc = recommend_policy().with_egress_velocity_thresholds(thresholds)
    save_policy(doc, repo_root=str(tmp_path))

    loaded_doc = load_policy(str(tmp_path))
    assert loaded_doc is not None
    assert loaded_doc.egress_velocity_thresholds is not None

    broker = _Broker(events=_events(6))
    rule = ExternalDestinationRule(
        egress_broker=broker,
        velocity_thresholds=loaded_doc.egress_velocity_thresholds,
    )
    result = rule.evaluate(_trusted_action(), _ctx())
    assert ReasonCode.anomalous_egress_velocity in result.reason_codes


def test_policy_file_thresholds_reach_default_objective_via_serve_rebuild(tmp_path):
    """Simulate the serve.py startup path: set REPO_ROOT, write policy, rebuild
    DEFAULT_OBJECTIVE, confirm a trip at the tighter threshold."""

    # Write a policy with burst=5.
    thresholds = VelocityThresholds(burst=5)
    doc = recommend_policy().with_egress_velocity_thresholds(thresholds)
    save_policy(doc, repo_root=str(tmp_path))

    # Simulate serve.py's rebuild.
    _policy = load_policy(str(tmp_path))
    _vt = _policy.egress_velocity_thresholds if _policy else None
    broker = _Broker(events=_events(6))
    rebuilt = ObjectiveGuardrail(
        rules=[
            ExternalDestinationRule(
                load_broker=False,
                egress_broker=broker,
                velocity_thresholds=_vt,
            )
        ]
    )

    result = rebuilt.evaluate(_trusted_action(), _ctx())
    assert ReasonCode.anomalous_egress_velocity in result.reason_codes
