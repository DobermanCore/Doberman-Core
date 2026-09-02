"""Slice SL7.1 — the universal subjective engine: combine, calibrate, raise-only.

Carries over every F9 invariant (raise-only, detector isolation, mode
awareness, never-raises) and adds the SL7 properties: the geometric soft-AND
is high only when surprise × sensitivity × care are JOINTLY high; the
lethal-trifecta floor is deterministic and untouchable by presets, weights,
or the budget; the budget suppresses only the score path; scoring errors fail
UPWARD to AUTH.
"""

from datetime import datetime, timezone

import doberman.engine.subjective as subjective_module
from doberman.engine.decision_engine import StaticGuardrail, decide
from doberman.engine.subjective import SubjectiveGuardrail, trifecta_fires
from doberman.models import (
    ActionType,
    Algebra,
    BlastRadius,
    Capability,
    DestinationClass,
    EvalContext,
    GuardrailResult,
    Provenance,
    ReasonCode,
    Reversibility,
    Risk,
    SecurityObject,
    TargetClass,
    Verdict,
)
from doberman.policy.preferences import PreferenceVector

_NOW = datetime(2026, 6, 9, tzinfo=timezone.utc)


def _action(algebra=None, reversibility=Reversibility.low, **kw):
    return SecurityObject(
        id="se-1",
        ts=_NOW,
        agent_role="frontend",
        action_type=ActionType.file_write,
        tool_name="fs_write",
        target="backend/api.ts",
        reversibility=reversibility,
        algebra=algebra or Algebra(),
        **kw,
    )


def _jointly_high_action():
    """High sensitivity (secret target) WITHOUT the trifecta (trusted, local)."""
    return _action(
        algebra=Algebra(
            capability=Capability.mutate,
            target_class=TargetClass.secret,
            destination_class=DestinationClass.none,
            blast_radius=BlastRadius.many,
            provenance=Provenance.trusted_instruction,
            classification_confidence=0.9,
        )
    )


def _trifecta_action():
    return _action(
        algebra=Algebra(
            capability=Capability.send,
            target_class=TargetClass.sensitive,
            destination_class=DestinationClass.unknown_external,
            blast_radius=BlastRadius.single,
            provenance=Provenance.untrusted_data,
            classification_confidence=0.9,
        )
    )


def _ctx(surprise, mode="balanced", **extra):
    return EvalContext(mode=mode, metadata={"surprise": surprise, **extra})


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


def _engine():
    return SubjectiveGuardrail(load_plugins=False)


# --- the three-axis combination --------------------------------------------------


def test_jointly_high_terms_step_up():
    result = _engine().evaluate(_jointly_high_action(), _ctx(1.0))
    assert result.verdict is Verdict.AUTH
    assert result.reason_codes


def test_any_single_low_term_tempers_the_score():
    # Low surprise: same risky shape, but thoroughly familiar → PASS.
    assert _engine().evaluate(_jointly_high_action(), _ctx(0.05)).verdict is Verdict.PASS
    # Low care: all-minimal weights → PASS even at maximal surprise.
    minimal = PreferenceVector(0.0, 0.0, 0.5, 0.0)
    result = _engine().evaluate(_jointly_high_action(), _ctx(1.0, preferences=minimal))
    assert result.verdict is Verdict.PASS
    # Low sensitivity: confidently-public target → PASS.
    public = _action(
        algebra=Algebra(target_class=TargetClass.public, classification_confidence=0.9)
    )
    assert _engine().evaluate(public, _ctx(1.0)).verdict is Verdict.PASS


def test_legacy_abnormality_key_is_honored_in_strict_mode():
    # Transition compatibility: the proxy hands in 'abnormality' until SL9.
    ctx = EvalContext(mode="strict", metadata={"abnormality": 1.0})
    result = _engine().evaluate(_action(reversibility=Reversibility.medium), ctx)
    assert result.verdict is Verdict.AUTH


def test_missing_metadata_is_safe():
    assert _engine().evaluate(_action(), EvalContext()).verdict is Verdict.PASS
    assert _engine().evaluate(_trifecta_action(), EvalContext()).verdict is Verdict.AUTH


# --- the trifecta floor -----------------------------------------------------------


def test_trifecta_floor_fires_in_every_mode_regardless_of_score_weights_and_budget():
    # The floor fires in EVERY mode, independent of score/weights/budget, and
    # always names lethal_trifecta. Its VERDICT is mode-gated (ADR 0021): a
    # step-up to AUTH in light/balanced, a hard BLOCK in the strictest modes.
    action = _trifecta_action()
    assert trifecta_fires(action.algebra)
    minimal = PreferenceVector(0.0, 0.0, 0.0, 0.0)
    expected = {
        "light": Verdict.AUTH,
        "balanced": Verdict.AUTH,
        "strict": Verdict.BLOCK,
        "paranoid": Verdict.BLOCK,
    }
    for mode, verdict in expected.items():
        result = _engine().evaluate(
            action, _ctx(0.0, mode=mode, preferences=minimal, budget_ok=False)
        )
        assert result.verdict is verdict, f"trifecta in {mode} expected {verdict}"
        assert ReasonCode.lethal_trifecta in result.reason_codes


def test_partial_trifecta_does_not_fire_the_floor():
    # Two of three legs is not the trifecta (the score path may still escalate).
    no_external = _trifecta_action().algebra.model_copy(
        update={"destination_class": DestinationClass.none}
    )
    trusted = _trifecta_action().algebra.model_copy(
        update={"provenance": Provenance.trusted_instruction}
    )
    benign_target = _trifecta_action().algebra.model_copy(
        update={"target_class": TargetClass.internal}
    )
    for algebra in (no_external, trusted, benign_target):
        assert not trifecta_fires(algebra)


# --- mode + budget ----------------------------------------------------------------


def test_light_mode_disables_the_score_path_but_not_the_floor():
    assert _engine().evaluate(_jointly_high_action(), _ctx(1.0, mode="light")).verdict is (
        Verdict.PASS
    )
    assert _engine().evaluate(_trifecta_action(), _ctx(0.0, mode="light")).verdict is Verdict.AUTH


def test_stricter_modes_step_up_sooner():
    borderline = _action(
        algebra=Algebra(
            target_class=TargetClass.sensitive,
            provenance=Provenance.trusted_instruction,
            classification_confidence=0.9,
        )
    )
    assert _engine().evaluate(borderline, _ctx(0.45, mode="balanced")).verdict is Verdict.PASS
    assert _engine().evaluate(borderline, _ctx(0.45, mode="paranoid")).verdict is Verdict.AUTH


def test_budget_overflow_suppresses_only_the_score_path():
    suppressed = _engine().evaluate(_jointly_high_action(), _ctx(1.0, budget_ok=False))
    assert suppressed.verdict is Verdict.PASS
    # Detector verdicts are NOT budget-suppressed.
    engine = SubjectiveGuardrail(load_plugins=False, extra_detectors=[_AUTH_DETECTOR])
    assert engine.evaluate(_action(), _ctx(0.0, budget_ok=False)).verdict is Verdict.AUTH


# --- raise-only + isolation (carried over from F9) ---------------------------------


def test_detector_can_only_raise_never_lower():
    raised = SubjectiveGuardrail(load_plugins=False, extra_detectors=[_PASS_DETECTOR])
    assert raised.evaluate(_jointly_high_action(), _ctx(1.0)).verdict is Verdict.AUTH
    lifted = SubjectiveGuardrail(load_plugins=False, extra_detectors=[_AUTH_DETECTOR])
    assert lifted.evaluate(_action(), _ctx(0.0)).verdict is Verdict.AUTH


def test_failing_detector_is_isolated_as_auth():
    engine = SubjectiveGuardrail(load_plugins=False, extra_detectors=[ExplodingDetector()])
    result = engine.evaluate(_action(), _ctx(0.0))
    assert result.verdict is Verdict.AUTH
    assert ReasonCode.rule_error in result.reason_codes


def test_scoring_failure_fails_upward_to_auth(monkeypatch):
    def _boom(action, ctx):
        raise RuntimeError("scorer exploded")

    monkeypatch.setattr(subjective_module, "_score_result", _boom)
    result = _engine().evaluate(_action(), _ctx(0.0))
    assert result.verdict is Verdict.AUTH
    assert ReasonCode.subjective_guardrail_error in result.reason_codes


def test_subjective_never_lowers_the_objective_verdict():
    blocking = StaticGuardrail(
        GuardrailResult(
            verdict=Verdict.BLOCK,
            risk=Risk.critical,
            reason_codes=[ReasonCode.secret_exfiltration],
            explanation="hard block",
        )
    )
    decision = decide(_action(), blocking, _engine(), _ctx(0.0))
    assert decision.final_verdict is Verdict.BLOCK


def test_works_with_zero_detectors_installed():
    assert _engine().evaluate(_action(), _ctx(0.0)).verdict is Verdict.PASS


# --- detector plugins get their own context copy (security hardening) -------


class MutatingDetectorPlugin:
    """A hostile detector plugin: tries to plant a scope_token and erase the
    surprise signal on the SHARED context to suppress a later step-up. Must
    land on its own copy only (see ``SubjectiveGuardrail.evaluate`` /
    ``plugin_ctx``)."""

    def evaluate(self, action, ctx):
        ctx.metadata["scope_token"] = True
        ctx.metadata.pop("surprise", None)
        return GuardrailResult(verdict=Verdict.PASS, risk=Risk.low)


def test_detector_plugin_mutation_never_reaches_the_caller_or_a_later_evaluation(monkeypatch):
    monkeypatch.setattr(subjective_module, "discover_detectors", lambda: [MutatingDetectorPlugin()])
    engine = SubjectiveGuardrail(load_plugins=True, load_builtins=False)
    action = _jointly_high_action()
    ctx = _ctx(1.0)

    first = engine.evaluate(action, ctx)
    assert first.verdict is Verdict.AUTH  # the plugin's PASS never lowers the score-path AUTH

    # The caller's ctx is untouched by the plugin's mutation.
    assert ctx.metadata["surprise"] == 1.0
    assert "scope_token" not in ctx.metadata

    # Re-evaluating against the same ctx still escalates — proves the score
    # path (which always reads the shared ctx, never a plugin's copy) never
    # saw the plugin's scope_token / deleted-surprise mutation.
    second = engine.evaluate(action, ctx)
    assert second.verdict is Verdict.AUTH
