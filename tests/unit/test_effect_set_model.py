"""C2 — EffectSet value type and its structural isolation on Decision."""

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from doberman.models import Decision, EffectSet, GuardrailResult, ReasonCode, Risk, Verdict


def _pass_decision(**overrides):
    objective = GuardrailResult(verdict=Verdict.PASS, risk=Risk.low)
    base = dict(
        action_id="a1",
        final_verdict=Verdict.PASS,
        final_risk=Risk.low,
        objective=objective,
        reason_codes=[],
        explanation="",
        decided_at=datetime.now(timezone.utc),
    )
    base.update(overrides)
    return Decision(**base)


def test_effect_set_diverged_is_a_reason_code():
    assert ReasonCode.effect_set_diverged.value == "effect_set_diverged"


def test_effect_set_is_frozen():
    effects = EffectSet(
        file_count=3,
        dir_count=1,
        capped=False,
        hits_git=False,
        hits_outside_repo=False,
        digest="d",
    )
    with pytest.raises(ValidationError, match="frozen"):
        effects.file_count = 4  # type: ignore[misc]


def test_decision_defaults_effects_to_none():
    decision = _pass_decision()
    assert decision.effects is None


def test_decision_accepts_an_effect_set_without_touching_verdict_or_risk():
    effects = EffectSet(
        file_count=812,
        dir_count=37,
        capped=False,
        hits_git=False,
        hits_outside_repo=False,
        digest="abc123",
    )
    decision = _pass_decision(effects=effects)
    assert decision.effects is effects
    assert decision.final_verdict is Verdict.PASS  # untouched — structurally isolated
    assert decision.final_risk is Risk.low


def test_decision_accepts_a_capped_unknown_effect_set_on_an_auth_decision():
    objective = GuardrailResult(
        verdict=Verdict.AUTH,
        risk=Risk.high,
        reason_codes=[ReasonCode.destructive_command],
        explanation="bulk delete",
    )
    effects = EffectSet(
        file_count=None,
        dir_count=None,
        capped=True,
        hits_git=False,
        hits_outside_repo=False,
        digest="unknown-sentinel",
    )
    decision = Decision(
        action_id="a2",
        final_verdict=Verdict.AUTH,
        final_risk=Risk.high,
        objective=objective,
        reason_codes=[ReasonCode.destructive_command],
        explanation="bulk delete",
        decided_at=datetime.now(timezone.utc),
        effects=effects,
    )
    assert decision.effects.capped is True
    assert decision.effects.file_count is None
