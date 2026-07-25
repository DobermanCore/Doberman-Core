"""Feature RB, slice RB.4 — broker-backed egress PASS behind proven enforcement.

``combine()`` (``doberman.engine.decision_engine``) is raise-only by
construction: max() over verdict and risk, union over reason codes. RB.4
never touches it. It only lets ``ExternalDestinationRule`` contribute
``PASS`` — instead of its usual AUTH for command egress / an unknown
destination — when a broker has *proven* it enforces egress AND both
allowlists AND will itself enforce this exact destination at the socket
(``_broker_grants_pass``). Every other rule's AUTH/BLOCK still dominates via
``max()``, so a broker PASS can never punch through the secrets floor, the
lethal-trifecta floor, or RB.3's route-divergence raise. The
fail-closed-heart test (UNPROVEN despite allowlisted+will_enforce) is the
single most important assertion in this file.
"""

from datetime import datetime, timezone

from doberman.egress.broker import BrokerVerdict, ConnectionEvent, EnforcementStatus
from doberman.engine.decision_engine import StaticGuardrail, decide
from doberman.engine.objective import ObjectiveGuardrail
from doberman.engine.rules.destinations import ExternalDestinationRule
from doberman.engine.rules.secrets import SecretLeakageRule
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

# A synthetic, clearly-fake credential (the same fixture already used by
# test_egress_coverage.py) — an AWS-key-shaped STRONG secret. The EXAMPLE
# marker does not suppress it: marker suppression is WEAK-path only.
_FAKE_AWS = "AKIAIOSFODNN7EXAMPLE"  # noqa: S105 — reason-code adjacent, not a secret


def _command_egress_action(**overrides) -> SecurityObject:
    """Shell egress to a host on no trust list — always AUTH pre-RB.4."""
    base = dict(
        id="rb4-cmd-1",
        ts=_NOW,
        agent_role="unknown",
        action_type=ActionType.shell_exec,
        tool_name="shell_exec",
        target="curl https://internal-tool.example/upload",
        external_destination="internal-tool.example",
    )
    base.update(overrides)
    return SecurityObject(**base)


def _network_action(**overrides) -> SecurityObject:
    """A network request to an unknown/untrusted host."""
    base = dict(
        id="rb4-net-1",
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


class _Broker:
    """Configurable fake ``EgressBroker``. ``status_raises``/``classify_raises``
    let a test assert consult_broker's fail-closed isolation without a crash.
    """

    def __init__(
        self,
        status: EnforcementStatus = EnforcementStatus.PROVEN,
        *,
        allowlisted: bool = True,
        will_enforce: bool = True,
        status_raises: bool = False,
        classify_raises: bool = False,
        events=(),
    ) -> None:
        self._status = status
        self._allowlisted = allowlisted
        self._will_enforce = will_enforce
        self._status_raises = status_raises
        self._classify_raises = classify_raises
        self._events = tuple(events)

    def enforcement_status(self) -> EnforcementStatus:
        if self._status_raises:
            raise RuntimeError("broker exploded checking enforcement_status")
        return self._status

    def classify(self, action) -> BrokerVerdict:
        if self._status is not EnforcementStatus.PROVEN:  # pragma: no cover — guard
            raise AssertionError("classify() must not be called when not PROVEN")
        if self._classify_raises:
            raise RuntimeError("broker exploded in classify()")
        return BrokerVerdict(allowlisted=self._allowlisted, will_enforce=self._will_enforce)

    def connection_events(self, entity, window):
        start, end = window
        return tuple(e for e in self._events if e.entity_id == entity and start <= e.ts <= end)


# --- 1. the core gate: all three conditions must hold ---------------------------


def test_proven_allowlisted_enforced_grants_pass_for_command_egress():
    rule = ExternalDestinationRule(egress_broker=_Broker())
    result = rule.evaluate(_command_egress_action(), _ctx())
    assert result.verdict is Verdict.PASS
    assert result.reason_codes == [ReasonCode.egress_broker_enforced]


def test_proven_allowlisted_enforced_grants_pass_for_unknown_network_destination():
    rule = ExternalDestinationRule(egress_broker=_Broker())
    result = rule.evaluate(_network_action(), _ctx(mode="strict"))
    assert result.verdict is Verdict.PASS
    assert result.reason_codes == [ReasonCode.egress_broker_enforced]


def test_unproven_allowlisted_enforced_stays_auth_fail_closed_heart():
    """The fail-closed heart of RB.4: an UNPROVEN broker's claims (even
    allowlisted=True, will_enforce=True) are never trusted. consult_broker
    must short-circuit to None BEFORE classify() is even called (the fake
    broker raises AssertionError if classify() is reached while UNPROVEN).
    """
    broker = _Broker(status=EnforcementStatus.UNPROVEN)
    rule = ExternalDestinationRule(egress_broker=broker)
    result = rule.evaluate(_command_egress_action(), _ctx())
    assert result.verdict is Verdict.AUTH
    assert result.reason_codes == [ReasonCode.egress_requires_auth]


def test_absent_status_stays_auth_no_crash():
    broker = _Broker(status=EnforcementStatus.ABSENT)
    rule = ExternalDestinationRule(egress_broker=broker)
    result = rule.evaluate(_command_egress_action(), _ctx())
    assert result.verdict is Verdict.AUTH


def test_no_broker_registered_stays_auth_no_crash():
    rule = ExternalDestinationRule(load_broker=False)
    result = rule.evaluate(_command_egress_action(), _ctx())
    assert result.verdict is Verdict.AUTH


def test_broker_raising_on_enforcement_status_stays_auth_no_crash():
    broker = _Broker(status_raises=True)
    rule = ExternalDestinationRule(egress_broker=broker)
    result = rule.evaluate(_command_egress_action(), _ctx())
    assert result.verdict is Verdict.AUTH


def test_broker_raising_on_classify_stays_auth_no_crash():
    broker = _Broker(classify_raises=True)
    rule = ExternalDestinationRule(egress_broker=broker)
    result = rule.evaluate(_command_egress_action(), _ctx())
    assert result.verdict is Verdict.AUTH


def test_allowlisted_but_not_enforced_stays_auth():
    """No proxy actually running: a bare allowlist claim is not proof."""
    broker = _Broker(allowlisted=True, will_enforce=False)
    rule = ExternalDestinationRule(egress_broker=broker)
    result = rule.evaluate(_command_egress_action(), _ctx())
    assert result.verdict is Verdict.AUTH


def test_not_allowlisted_stays_auth_never_pass():
    broker = _Broker(allowlisted=False, will_enforce=True)
    rule = ExternalDestinationRule(egress_broker=broker)
    result = rule.evaluate(_network_action(), _ctx(mode="strict"))
    assert result.verdict is Verdict.AUTH
    assert result.verdict is not Verdict.PASS


# --- 2. floors: a broker PASS can never outrank another rule's AUTH/BLOCK -------


def test_secret_content_and_broker_enforced_destination_still_blocks():
    """The single most important test: real decide()-adjacent guardrail path
    (ObjectiveGuardrail -> combine()), secrets rule BLOCK + destination
    rule's broker-granted PASS -> still BLOCK, and both reason codes survive
    the union (proving combine() actually ran, not just one rule).
    """
    action = _network_action()
    ctx = _ctx(mode="strict", raw_arguments={"body": f"leaking creds: {_FAKE_AWS}"})
    guardrail = ObjectiveGuardrail(
        rules=[SecretLeakageRule(), ExternalDestinationRule(egress_broker=_Broker())],
        load_plugins=False,
    )
    result = guardrail.evaluate(action, ctx)
    assert result.verdict is Verdict.BLOCK
    assert ReasonCode.secret_exfiltration in result.reason_codes
    assert ReasonCode.egress_broker_enforced in result.reason_codes  # broker PASS did fire


def test_lethal_trifecta_and_broker_enforced_destination_still_at_least_auths():
    """Objective PASS (via a fully proven/enforcing broker) still reaches the
    subjective lethal-trifecta floor, which is honored as a hard BLOCK (the
    real, non-monkeypatched allowlist) — never clamped, never overridden.
    """
    action = _network_action()
    ctx = _ctx(mode="strict")
    objective = ObjectiveGuardrail(
        rules=[ExternalDestinationRule(egress_broker=_Broker())], load_plugins=False
    )
    # Sanity: the objective layer alone really does PASS via the broker.
    assert objective.evaluate(action, ctx).verdict is Verdict.PASS

    subjective = StaticGuardrail(
        GuardrailResult(
            verdict=Verdict.BLOCK,
            risk=Risk.critical,
            reason_codes=[ReasonCode.lethal_trifecta],
            explanation="lethal trifecta; blocked regardless of score.",
        )
    )
    decision = decide(action, objective, subjective, ctx)
    assert decision.final_verdict is Verdict.BLOCK  # BLOCK >= the required "at least AUTH"
    assert ReasonCode.subjective_block_clamped not in decision.reason_codes
    assert ReasonCode.lethal_trifecta in decision.reason_codes


def test_route_divergence_wins_over_broker_pass():
    """RB.3 divergence must still raise even when the broker would otherwise
    grant PASS — divergence wins, never overridden by a broker PASS.
    """

    broker = _Broker(events=[ConnectionEvent(entity_id="ent-1", ts=_NOW, host="evil.example.com")])
    rule = ExternalDestinationRule(egress_broker=broker)
    ctx = _ctx(mode="strict", entity_id="ent-1")
    result = rule.evaluate(_network_action(), ctx)
    assert result.verdict is Verdict.AUTH
    assert result.verdict is not Verdict.PASS
    assert ReasonCode.egress_route_divergence in result.reason_codes


# --- 3. dormant by default: byte-for-byte unchanged with no broker --------------


def test_dormant_no_broker_command_egress_byte_for_byte_unchanged():
    rule = ExternalDestinationRule(load_broker=False)
    result = rule.evaluate(_command_egress_action(), _ctx())
    assert result.verdict is Verdict.AUTH
    assert result.risk is Risk.high
    assert result.reason_codes == [ReasonCode.egress_requires_auth]


def test_dormant_no_broker_unknown_network_destination_byte_for_byte_unchanged():
    rule = ExternalDestinationRule(load_broker=False)
    result = rule.evaluate(_network_action(), _ctx(mode="strict"))
    assert result.verdict is Verdict.AUTH
    assert result.risk is Risk.medium
    assert result.reason_codes == [ReasonCode.unknown_external_destination]
