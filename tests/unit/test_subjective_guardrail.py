"""Slice 9.3 — the SubjectiveGuardrail: abnormality + detectors, raise-only."""

from datetime import datetime, timezone

from doberman.engine.decision_engine import StaticGuardrail
from doberman.engine.subjective import SubjectiveGuardrail
from doberman.models import (
    ActionType,
    EvalContext,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    Verdict,
)

_NOW = datetime(2026, 6, 8, tzinfo=timezone.utc)


def _action():
    return SecurityObject(
        id="sg-1",
        ts=_NOW,
        agent_role="frontend",
        action_type=ActionType.file_write,
        tool_name="fs_write",
        target="backend/api.ts",
    )


def _ctx(score, mode="balanced"):
    return EvalContext(mode=mode, metadata={"abnormality": score})


class ExplodingDetector:
    def evaluate(self, action, ctx):
        raise RuntimeError("detector boom")


_PASS_DETECTOR = StaticGuardrail(GuardrailResult(verdict=Verdict.PASS, risk=Risk.low))
_AUTH_DETECTOR = StaticGuardrail(
    GuardrailResult(
        verdict=Verdict.AUTH,
        risk=Risk.high,
        reason_codes=[ReasonCode.unusual_for_workflow],
        explanation="detector says unusual",
    )
)


def test_below_threshold_passes():
    g = SubjectiveGuardrail(load_plugins=False)
    assert g.evaluate(_action(), _ctx(0.5)).verdict is Verdict.PASS  # balanced threshold 0.7


def test_at_or_above_threshold_auths_with_signal():
    g = SubjectiveGuardrail(load_plugins=False)
    result = g.evaluate(_action(), _ctx(0.8))
    assert result.verdict is Verdict.AUTH
    assert ReasonCode.unusual_for_workflow in result.reason_codes
    assert "unusual" in result.explanation.lower()


def test_light_mode_disables_abnormality_step_up():
    g = SubjectiveGuardrail(load_plugins=False)
    # Even a maximally-novel action passes under Light (escalate_unusual=False).
    assert g.evaluate(_action(), _ctx(1.0, mode="light")).verdict is Verdict.PASS


def test_paranoid_mode_steps_up_sooner():
    g = SubjectiveGuardrail(load_plugins=False)
    # Paranoid threshold is 0.3, so a mid score that PASSes under Balanced AUTHs.
    assert g.evaluate(_action(), _ctx(0.4, mode="balanced")).verdict is Verdict.PASS
    assert g.evaluate(_action(), _ctx(0.4, mode="paranoid")).verdict is Verdict.AUTH


def test_no_detectors_is_just_the_baseline_signal():
    g = SubjectiveGuardrail(load_plugins=False)
    assert g.evaluate(_action(), _ctx(0.0)).verdict is Verdict.PASS


def test_detector_can_only_raise_never_lower():
    # A PASS detector cannot undo a high baseline score.
    g = SubjectiveGuardrail(load_plugins=False, extra_detectors=[_PASS_DETECTOR])
    assert g.evaluate(_action(), _ctx(0.9)).verdict is Verdict.AUTH
    # An AUTH detector escalates even when the baseline is calm.
    g2 = SubjectiveGuardrail(load_plugins=False, extra_detectors=[_AUTH_DETECTOR])
    assert g2.evaluate(_action(), _ctx(0.0)).verdict is Verdict.AUTH


def test_failing_detector_is_isolated_as_auth():
    g = SubjectiveGuardrail(load_plugins=False, extra_detectors=[ExplodingDetector()])
    result = g.evaluate(_action(), _ctx(0.0))
    assert result.verdict is Verdict.AUTH
    assert ReasonCode.rule_error in result.reason_codes


def test_evaluate_never_raises_on_missing_score():
    g = SubjectiveGuardrail(load_plugins=False)
    # No abnormality key in metadata → treated as 0.0, not a crash.
    assert g.evaluate(_action(), EvalContext()).verdict is Verdict.PASS
