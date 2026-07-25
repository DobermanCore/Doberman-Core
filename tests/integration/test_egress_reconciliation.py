"""Feature RB, slice RB.3 — retrospective ground-truth egress reconciliation.

RB.3 is strictly RAISE-ONLY and RETROSPECTIVE: a forward proxy only learns an
action's real destination at CONNECT time, after the tool-call decision was
already made — so this can never be a pre-flight check of the PENDING
action's own destination. Instead ``ExternalDestinationRule.evaluate`` looks
at what the broker already observed for this entity (``connection_events``)
within a bounded recent window and, if any observed host diverges from this
rule's static host-trust classification, raises the verdict it was already
going to return. Every test here defends one property of that raise-only
seam; the dormant-without-a-broker regression is the most important one —
today's shipped egress behavior must be byte-for-byte unchanged with no
broker registered.
"""

from datetime import datetime, timedelta, timezone

from doberman.egress.broker import ConnectionEvent, EnforcementStatus
from doberman.engine.decision_engine import combine
from doberman.engine.rules.destinations import ExternalDestinationRule
from doberman.models import (
    ActionType,
    EvalContext,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    Verdict,
)

_NOW = datetime(2026, 7, 24, 12, 0, 0, tzinfo=timezone.utc)


def _egress_action(action_type=ActionType.network_request, **overrides):
    base = dict(
        id="rb3-1",
        ts=_NOW,
        agent_role="unknown",
        action_type=action_type,
        tool_name="net_get",
        target="https://github.com",
        external_destination="github.com",
    )
    base.update(overrides)
    return SecurityObject(**base)


def _ctx(entity="ent-1", **metadata_overrides):
    metadata = {"entity_id": entity}
    metadata.update(metadata_overrides)
    return EvalContext(metadata=metadata)


class _EventsBroker:
    """Minimal fake ``EgressBroker``: ``connection_events`` window-filters a
    fixed set, mirroring ``LocalEgressBroker``'s own filtering. Status is
    always ABSENT so the RB.1 ``consult_broker`` discard path (unrelated to
    RB.3) never even reaches ``classify()``.
    """

    def __init__(self, events):
        self._events = tuple(events)

    def enforcement_status(self):
        return EnforcementStatus.ABSENT

    def classify(self, action):  # pragma: no cover — ABSENT means never called
        raise AssertionError("classify() must not be called when ABSENT")

    def connection_events(self, entity, window):
        start, end = window
        return tuple(e for e in self._events if e.entity_id == entity and start <= e.ts <= end)


class _RaisingEventsBroker:
    def enforcement_status(self):
        return EnforcementStatus.ABSENT

    def classify(self, action):  # pragma: no cover — ABSENT means never called
        raise AssertionError("classify() must not be called when ABSENT")

    def connection_events(self, entity, window):
        raise RuntimeError("broker exploded reading connection events")


# --- 1. dormant without a broker — the regression that matters most -------------


def test_no_broker_network_request_decision_unchanged():
    rule = ExternalDestinationRule(load_broker=False)
    result = rule.evaluate(_egress_action(), _ctx())
    assert result.verdict is Verdict.PASS
    assert result.reason_codes == []


def test_no_broker_shell_egress_decision_unchanged():
    rule = ExternalDestinationRule(load_broker=False)
    action = _egress_action(
        action_type=ActionType.shell_exec,
        tool_name="shell_exec",
        target="curl https://github.com/x",
    )
    result = rule.evaluate(action, _ctx())
    assert result.verdict is Verdict.AUTH
    assert result.reason_codes == [ReasonCode.egress_requires_auth]


# --- 2. a registered broker with no divergence changes nothing ------------------


def test_broker_with_no_divergent_events_unchanged():
    broker = _EventsBroker([ConnectionEvent(entity_id="ent-1", ts=_NOW, host="github.com")])
    rule = ExternalDestinationRule(egress_broker=broker)
    result = rule.evaluate(_egress_action(), _ctx())
    assert result.verdict is Verdict.PASS
    assert result.reason_codes == []


def test_broker_with_empty_events_unchanged():
    rule = ExternalDestinationRule(egress_broker=_EventsBroker([]))
    result = rule.evaluate(_egress_action(), _ctx())
    assert result.verdict is Verdict.PASS
    assert result.reason_codes == []


# --- 3. a divergent observed host raises PASS -> AUTH ---------------------------


def test_divergent_observed_host_raises_pass_to_auth_with_reason_code():
    broker = _EventsBroker(
        [
            ConnectionEvent(
                entity_id="ent-1", ts=_NOW - timedelta(minutes=5), host="evil.example.com"
            )
        ]
    )
    rule = ExternalDestinationRule(egress_broker=broker)
    result = rule.evaluate(_egress_action(), _ctx())
    assert result.verdict is Verdict.AUTH
    assert ReasonCode.egress_route_divergence in result.reason_codes
    assert result.explanation.strip()


def test_divergence_appends_reason_code_to_an_already_auth_command_egress():
    broker = _EventsBroker(
        [
            ConnectionEvent(
                entity_id="ent-1", ts=_NOW - timedelta(minutes=1), host="evil.example.com"
            )
        ]
    )
    rule = ExternalDestinationRule(egress_broker=broker)
    action = _egress_action(
        action_type=ActionType.shell_exec,
        tool_name="shell_exec",
        target="curl https://github.com/x",
    )
    result = rule.evaluate(action, _ctx())
    assert result.verdict is Verdict.AUTH
    assert ReasonCode.egress_requires_auth in result.reason_codes
    assert ReasonCode.egress_route_divergence in result.reason_codes


def test_divergence_explanation_never_leaks_the_observed_host():
    broker = _EventsBroker(
        [
            ConnectionEvent(
                entity_id="ent-1", ts=_NOW - timedelta(minutes=1), host="evil.example.com"
            )
        ]
    )
    rule = ExternalDestinationRule(egress_broker=broker)
    result = rule.evaluate(_egress_action(), _ctx())
    assert "evil.example.com" not in result.explanation
    assert "evil.example.com" not in " ".join(c.value for c in result.reason_codes)


# --- 4. raise-only: never lowers an already-BLOCK combined decision -------------


def test_divergence_never_lowers_an_already_block_combined_decision():
    broker = _EventsBroker(
        [
            ConnectionEvent(
                entity_id="ent-1", ts=_NOW - timedelta(minutes=1), host="evil.example.com"
            )
        ]
    )
    rule = ExternalDestinationRule(egress_broker=broker)
    destinations_result = rule.evaluate(_egress_action(), _ctx())
    assert destinations_result.verdict is Verdict.AUTH  # divergence alone only reaches AUTH

    secrets_block = GuardrailResult(
        verdict=Verdict.BLOCK,
        risk=Risk.critical,
        reason_codes=[ReasonCode.secret_exfiltration],
        explanation="a synthetic secret left in the payload",
    )
    combined = combine(secrets_block, destinations_result)
    assert combined.verdict is Verdict.BLOCK


# --- 5. bounded window: divergence outside it never raises ----------------------


def test_divergence_outside_the_bounded_window_does_not_raise():
    broker = _EventsBroker(
        [
            ConnectionEvent(
                entity_id="ent-1", ts=_NOW - timedelta(minutes=30), host="evil.example.com"
            )
        ]
    )
    rule = ExternalDestinationRule(egress_broker=broker)
    result = rule.evaluate(_egress_action(), _ctx())
    assert result.verdict is Verdict.PASS
    assert ReasonCode.egress_route_divergence not in result.reason_codes


# --- 6. a raising broker is no signal, never a crash -----------------------------


def test_broker_connection_events_raising_is_no_signal_and_does_not_crash():
    rule = ExternalDestinationRule(egress_broker=_RaisingEventsBroker())
    result = rule.evaluate(_egress_action(), _ctx())
    assert result.verdict is Verdict.PASS
    assert ReasonCode.egress_route_divergence not in result.reason_codes


# --- 7. no entity id available => no signal --------------------------------------


def test_no_entity_id_in_context_is_no_signal():
    broker = _EventsBroker(
        [
            ConnectionEvent(
                entity_id="ent-1", ts=_NOW - timedelta(minutes=1), host="evil.example.com"
            )
        ]
    )
    rule = ExternalDestinationRule(egress_broker=broker)
    result = rule.evaluate(_egress_action(), EvalContext())  # no entity_id in metadata
    assert result.verdict is Verdict.PASS
    assert ReasonCode.egress_route_divergence not in result.reason_codes


# --- 8. reconciliation only ever applies to egress-classified actions -----------


def test_non_egress_action_type_never_reconciled():
    broker = _EventsBroker(
        [
            ConnectionEvent(
                entity_id="ent-1", ts=_NOW - timedelta(minutes=1), host="evil.example.com"
            )
        ]
    )
    rule = ExternalDestinationRule(egress_broker=broker)
    action = _egress_action(
        action_type=ActionType.file_read,
        tool_name="read_file",
        target="README.md",
        external_destination=None,
    )
    result = rule.evaluate(action, _ctx())
    assert result.verdict is Verdict.PASS
    assert ReasonCode.egress_route_divergence not in result.reason_codes
