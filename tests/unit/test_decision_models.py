"""Slice 2.1 — tests for the Guardrail contract, EvalContext, and Decision."""

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from doberman.engine.decision_engine import Guardrail
from doberman.models import (
    Decision,
    EvalContext,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    Verdict,
)

NOW = datetime(2026, 6, 7, 12, 0, 0, tzinfo=timezone.utc)

PASS_LOW = GuardrailResult(verdict=Verdict.PASS, risk=Risk.low)
BLOCK_HIGH = GuardrailResult(
    verdict=Verdict.BLOCK,
    risk=Risk.high,
    reason_codes=[ReasonCode.unknown_tool],
    explanation="Unknown tool.",
)


class StubGuardrail:
    """Minimal structural implementation of the Guardrail Protocol."""

    def __init__(self, result: GuardrailResult) -> None:
        self._result = result

    def evaluate(self, action: SecurityObject, ctx: EvalContext) -> GuardrailResult:
        return self._result


def test_stub_satisfies_protocol():
    assert isinstance(StubGuardrail(PASS_LOW), Guardrail)


def test_non_guardrail_does_not_satisfy_protocol():
    class NotAGuardrail:
        def judge(self):  # wrong method name
            pass

    assert not isinstance(NotAGuardrail(), Guardrail)


def test_eval_context_is_frozen_with_defaults():
    ctx = EvalContext()
    assert ctx.metadata == {}
    with pytest.raises(ValidationError, match="frozen"):
        ctx.metadata = {"x": 1}


def test_decision_valid_construction_pass():
    decision = Decision(
        action_id="act-1",
        final_verdict=Verdict.PASS,
        final_risk=Risk.low,
        objective=PASS_LOW,
        decided_at=NOW,
    )
    assert decision.subjective is None  # subjective skipped is representable
    assert decision.reason_codes == []


def test_decision_block_requires_reasons_and_explanation():
    with pytest.raises(ValidationError):
        Decision(
            action_id="act-1",
            final_verdict=Verdict.BLOCK,
            final_risk=Risk.high,
            objective=BLOCK_HIGH,
            decided_at=NOW,
        )
    with pytest.raises(ValidationError):  # reasons present, explanation blank
        Decision(
            action_id="act-1",
            final_verdict=Verdict.BLOCK,
            final_risk=Risk.high,
            objective=BLOCK_HIGH,
            reason_codes=[ReasonCode.unknown_tool],
            explanation="   ",
            decided_at=NOW,
        )
    ok = Decision(
        action_id="act-1",
        final_verdict=Verdict.BLOCK,
        final_risk=Risk.high,
        objective=BLOCK_HIGH,
        reason_codes=[ReasonCode.unknown_tool],
        explanation="Unknown tool is blocked.",
        decided_at=NOW,
    )
    assert ok.final_verdict is Verdict.BLOCK


@pytest.mark.parametrize(
    "overrides",
    [
        {"action_id": ""},
        {"decided_at": datetime(2026, 6, 7, 12, 0, 0)},  # naive timestamp
        {"final_verdict": "MAYBE"},
        {"reason_codes": ["made_up_code"]},
    ],
)
def test_decision_rejects_invalid_fields(overrides):
    kwargs = dict(
        action_id="act-1",
        final_verdict=Verdict.PASS,
        final_risk=Risk.low,
        objective=PASS_LOW,
        decided_at=NOW,
    )
    kwargs.update(overrides)
    with pytest.raises(ValidationError):
        Decision(**kwargs)


def test_decision_is_frozen():
    decision = Decision(
        action_id="act-1",
        final_verdict=Verdict.PASS,
        final_risk=Risk.low,
        objective=PASS_LOW,
        decided_at=NOW,
    )
    with pytest.raises(ValidationError, match="frozen"):
        decision.final_verdict = Verdict.BLOCK
