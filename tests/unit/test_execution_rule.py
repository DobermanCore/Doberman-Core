"""Slice 2.3 — the execution-rule state machine, line by line vs the thesis."""

from datetime import datetime, timezone

import pytest

from doberman.engine import decision_engine
from doberman.engine.decision_engine import decide
from doberman.models import (
    ActionType,
    EvalContext,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    Verdict,
)

CTX = EvalContext()

ACTION = SecurityObject(
    id="act-er-1",
    ts=datetime(2026, 6, 7, 12, 0, 0, tzinfo=timezone.utc),
    agent_role="unknown",
    action_type=ActionType.file_delete,
    tool_name="fs_delete",
    target="backend/auth/session.ts",
)


def result(verdict: Verdict, risk: Risk = Risk.low) -> GuardrailResult:
    if verdict is Verdict.PASS:
        return GuardrailResult(verdict=verdict, risk=risk)
    return GuardrailResult(
        verdict=verdict,
        risk=risk,
        reason_codes=[ReasonCode.unknown_tool],
        explanation=f"{verdict} from stub.",
    )


class CountingGuardrail:
    def __init__(self, outcome: GuardrailResult | Exception | object) -> None:
        self.outcome = outcome
        self.calls = 0

    def evaluate(self, action: SecurityObject, ctx: EvalContext) -> GuardrailResult:
        self.calls += 1
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self.outcome  # type: ignore[return-value]


# --- The thesis table -------------------------------------------------------
# (objective verdict, subjective verdict or None=skipped, expected final)
THESIS_TABLE = [
    (Verdict.BLOCK, None, Verdict.BLOCK),  # obj BLOCK → BLOCK, subjective skipped
    (Verdict.AUTH, None, Verdict.AUTH),  # obj AUTH → AUTH, subjective skipped
    (Verdict.PASS, Verdict.PASS, Verdict.PASS),  # both pass → PASS
    (Verdict.PASS, Verdict.AUTH, Verdict.AUTH),  # subjective escalates → AUTH
    (Verdict.PASS, Verdict.BLOCK, Verdict.AUTH),  # subjective block CLAMPED → AUTH
]


@pytest.mark.parametrize(("obj_verdict", "subj_verdict", "expected"), THESIS_TABLE)
def test_thesis_execution_rule_table(obj_verdict, subj_verdict, expected):
    objective = CountingGuardrail(result(obj_verdict, Risk.medium))
    subjective = CountingGuardrail(
        result(subj_verdict, Risk.medium) if subj_verdict else result(Verdict.PASS)
    )
    decision = decide(ACTION, objective, subjective, CTX)

    assert decision.final_verdict is expected
    assert objective.calls == 1
    if subj_verdict is None:
        # Short-circuit: subjective never ran and is absent from the record.
        assert subjective.calls == 0
        assert decision.subjective is None
    else:
        assert subjective.calls == 1
        assert decision.subjective is not None


def test_subjective_block_clamped_with_reason_and_audit_truth():
    objective = CountingGuardrail(result(Verdict.PASS))
    subjective = CountingGuardrail(result(Verdict.BLOCK, Risk.high))
    decision = decide(ACTION, objective, subjective, CTX)

    assert decision.final_verdict is Verdict.AUTH  # clamped
    assert decision.final_risk is Risk.high  # risk NOT lowered by the clamp
    assert ReasonCode.subjective_block_clamped in decision.reason_codes
    # Audit truth: the original (unclamped) subjective result is preserved.
    assert decision.subjective is not None
    assert decision.subjective.verdict is Verdict.BLOCK


def test_allowlisted_subjective_block_is_honored(monkeypatch):
    monkeypatch.setattr(
        decision_engine,
        "SUBJECTIVE_HARD_BLOCK_ALLOWLIST",
        frozenset({ReasonCode.unknown_tool}),
    )
    objective = CountingGuardrail(result(Verdict.PASS))
    subjective = CountingGuardrail(result(Verdict.BLOCK, Risk.critical))
    decision = decide(ACTION, objective, subjective, CTX)

    assert decision.final_verdict is Verdict.BLOCK
    assert ReasonCode.subjective_block_clamped not in decision.reason_codes


def test_objective_error_fails_closed_and_skips_subjective():
    objective = CountingGuardrail(RuntimeError("objective exploded"))
    subjective = CountingGuardrail(result(Verdict.PASS))
    decision = decide(ACTION, objective, subjective, CTX)

    assert decision.final_verdict is Verdict.BLOCK
    assert decision.final_risk is Risk.high
    assert ReasonCode.objective_guardrail_error in decision.reason_codes
    assert subjective.calls == 0
    assert decision.subjective is None


def test_subjective_error_fails_upward_to_auth():
    objective = CountingGuardrail(result(Verdict.PASS))
    subjective = CountingGuardrail(RuntimeError("subjective exploded"))
    decision = decide(ACTION, objective, subjective, CTX)

    assert decision.final_verdict is Verdict.AUTH  # fail upward, not open
    assert ReasonCode.subjective_guardrail_error in decision.reason_codes
    assert decision.explanation


@pytest.mark.parametrize("garbage", ["not-a-result", None, 42, {"verdict": "PASS"}])
def test_objective_garbage_return_fails_closed(garbage):
    decision = decide(
        ACTION, CountingGuardrail(garbage), CountingGuardrail(result(Verdict.PASS)), CTX
    )
    assert decision.final_verdict is Verdict.BLOCK
    assert ReasonCode.objective_guardrail_error in decision.reason_codes


@pytest.mark.parametrize("garbage", ["not-a-result", None, 42])
def test_subjective_garbage_return_fails_upward(garbage):
    decision = decide(
        ACTION, CountingGuardrail(result(Verdict.PASS)), CountingGuardrail(garbage), CTX
    )
    assert decision.final_verdict is Verdict.AUTH
    assert ReasonCode.subjective_guardrail_error in decision.reason_codes


def test_risk_combines_raise_only_across_guardrails():
    objective = CountingGuardrail(result(Verdict.PASS, Risk.low))
    subjective = CountingGuardrail(result(Verdict.AUTH, Risk.high))
    decision = decide(ACTION, objective, subjective, CTX)
    assert decision.final_risk is Risk.high
    assert decision.final_verdict is Verdict.AUTH


def test_decision_carries_action_id_and_aware_timestamp():
    decision = decide(
        ACTION,
        CountingGuardrail(result(Verdict.PASS)),
        CountingGuardrail(result(Verdict.PASS)),
        CTX,
    )
    assert decision.action_id == ACTION.id
    assert decision.decided_at.tzinfo is not None


def test_base_exception_unwinds_and_forwards_nothing():
    # Documented behavior: BaseException is NOT converted to a verdict — it
    # unwinds. Unwinding is fail-closed by construction (no Decision, no
    # forward). The engine never converts an interrupt into an allow.
    objective = CountingGuardrail(result(Verdict.PASS))

    class Aborting:
        def evaluate(self, action, ctx):
            raise SystemExit(1)

    with pytest.raises(SystemExit):
        decide(ACTION, Aborting(), CountingGuardrail(result(Verdict.PASS)), CTX)
    with pytest.raises(SystemExit):
        decide(ACTION, objective, Aborting(), CTX)


def test_decide_never_raises_for_any_valid_guardrail_outputs():
    # Adversarial sweep: for EVERY pair of valid GuardrailResult outputs,
    # decide() must return a valid Decision — never raise via the Decision
    # validators (regression guard for validator/combine drift).
    all_results = [result(v, r) for v in Verdict for r in Risk]
    for obj in all_results:
        for subj in all_results:
            decision = decide(ACTION, CountingGuardrail(obj), CountingGuardrail(subj), CTX)
            assert decision.action_id == ACTION.id


def test_non_pass_decisions_always_explained():
    for outcome in (Verdict.AUTH, Verdict.BLOCK):
        decision = decide(
            ACTION,
            CountingGuardrail(result(outcome, Risk.medium)),
            CountingGuardrail(result(Verdict.PASS)),
            CTX,
        )
        assert decision.reason_codes
        assert decision.explanation.strip()
