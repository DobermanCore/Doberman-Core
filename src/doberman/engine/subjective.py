"""The universal subjective guardrail (SL7 — replaces the basic F9 scorer).

The *second* guardrail: after the objective guardrail PASSes, this one decides
whether the action is unusual or unwanted *for this deployment* by combining
three independent axes, each normalized to [0, 1]:

* **surprise** — learned, per-entity (computed by the proxy from the streaming
  baseline and handed in via ``EvalContext.metadata['surprise']``; the legacy
  ``'abnormality'`` key is honored for transition compatibility);
* **sensitivity** — inferred from the action's algebra (SL2/SL3), elevated for
  unclassified actions;
* **care** — the deployment's declared+revealed preference vector (SL5).

``score = (surprise × sensitivity × care) ** (1/3)`` — a geometric soft-AND:
high only when the terms are JOINTLY high, monotone in each. The active mode's
threshold (scaled by interruption tolerance) maps the score to PASS/step-up.

**Lethal-trifecta floor (deterministic, score-independent).** A
sensitive/secret target + untrusted/mixed provenance + an external destination
is the highest-signal co-occurrence in the literature (Willison 2025) and
steps up REGARDLESS of the combined score, the budget, the preset (including
Light), preference weights, or revealed learning. It is checked before any
score math and sits below every tunable surface.

Safety properties (unchanged from F9):

* **Raise-only.** Every result reduces through ``combine()``; this layer can
  only add risk, and the execution rule clamps a subjective BLOCK to AUTH.
* **Budget-aware, never for the floor.** The sliding step-up budget
  (``metadata['budget_ok']``) suppresses only the SCORE path's step-up (the
  proxy logs the overflow); the trifecta floor and detector verdicts ignore it.
* **Detectors are isolated.** A detector that raises or returns garbage
  becomes a conservative ``AUTH/high (rule_error)`` — never a silent PASS.
* **Detector plugins get their own context copy.** A plugin detector (opt-in
  by name, :mod:`doberman.engine.plugin_config`) runs against its own copy of
  ``ctx.metadata`` (``plugin_ctx``), so it can never mutate the shared dict a
  later built-in/plugin or the caller sees.

This module is part of the policy core: it must never import ``doberman.proxy``.
"""

import logging
from collections.abc import Sequence

from doberman.engine.decision_engine import Guardrail, combine, plugin_ctx
from doberman.engine.detectors import BUILTIN_DETECTOR_TYPES
from doberman.engine.registry import discover_detectors

# Re-exported from the models-only leaf module: the objective-rules package now
# shares the same predicate without importing this ML-heavy module. The names
# stay importable from here so existing callers/tests that do
# ``from doberman.engine.subjective import trifecta_fires`` (or the frozensets)
# keep resolving.
from doberman.engine.trifecta import (  # noqa: F401 — re-export for back-compat
    TRIFECTA_DESTINATIONS,
    TRIFECTA_PROVENANCE,
    TRIFECTA_TARGETS,
    trifecta_fires,
)
from doberman.models import (
    Algebra,
    EvalContext,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    Verdict,
)
from doberman.policy.modes import thresholds_for
from doberman.policy.preferences import (
    PreferenceVector,
    care_contributions,
    effective_threshold,
    vector_for,
)
from doberman.subjective.infer import is_unclassified, sensitivity

logger = logging.getLogger("doberman.engine.subjective")

_PASS = GuardrailResult(verdict=Verdict.PASS, risk=Risk.low)


def _isolate(detector: Guardrail, action: SecurityObject, ctx: EvalContext) -> GuardrailResult:
    """Run one detector; any failure becomes a conservative AUTH/high (rule_error)."""
    try:
        result = detector.evaluate(action, ctx)
    except Exception:  # noqa: BLE001 — the guardrail owns per-detector failure
        logger.warning("subjective detector %s raised; isolating as AUTH", type(detector).__name__)
        result = None
    if not isinstance(result, GuardrailResult):
        return GuardrailResult(
            verdict=Verdict.AUTH,
            risk=Risk.high,
            reason_codes=[ReasonCode.rule_error],
            explanation="A subjective detector failed to evaluate; escalating to authentication.",
        )
    return result


def _read_surprise(ctx: EvalContext) -> float:
    """The proxy-precomputed surprise term (legacy 'abnormality' honored)."""
    if not isinstance(ctx.metadata, dict):
        return 0.0
    for key in ("surprise", "abnormality"):
        raw = ctx.metadata.get(key)
        if isinstance(raw, (int, float)):
            return max(0.0, min(1.0, float(raw)))
    return 0.0


def _read_preferences(ctx: EvalContext) -> PreferenceVector:
    """The active preference vector (falls back to the mode's preset)."""
    if isinstance(ctx.metadata, dict):
        prefs = ctx.metadata.get("preferences")
        if isinstance(prefs, PreferenceVector):
            return prefs
    return vector_for(ctx.mode)


def _budget_ok(ctx: EvalContext) -> bool:
    """Whether the sliding step-up budget allows a SCORE-path step-up."""
    if isinstance(ctx.metadata, dict) and ctx.metadata.get("budget_ok") is False:
        return False
    return True


def _scope_token_active(ctx: EvalContext) -> bool:
    """Whether an SL6 "approve for this task" token covers this action.

    Tokens suppress only the SCORE path (a bounded, TTL'd nuisance reduction
    granted by an operator approval) — never the trifecta floor or detectors.
    """
    return bool(isinstance(ctx.metadata, dict) and ctx.metadata.get("scope_token") is True)


def _step_up_result(
    surprise: float,
    sensitivity_term: float,
    care_terms: dict[str, float],
    algebra: Algebra,
) -> GuardrailResult:
    """Build the explained step-up (SL7.2): name the dominant driver, classes only."""
    care_term = max(care_terms.values()) if care_terms else 0.0
    reasons: list[ReasonCode] = []
    if surprise >= care_term:
        reasons.extend([ReasonCode.unusual_for_deployment, ReasonCode.unusual_for_workflow])
        explanation = (
            f"Unusual for this deployment (capability {algebra.capability.value}, "
            f"target class {algebra.target_class.value}); authentication required."
        )
    else:
        dominant = max(care_terms, key=care_terms.get)  # type: ignore[arg-type]
        if dominant == "confidentiality":
            reasons.append(ReasonCode.confidentiality_sensitive_destination)
            explanation = (
                f"Confidentiality-sensitive action (target class "
                f"{algebra.target_class.value}, destination "
                f"{algebra.destination_class.value}); authentication required."
            )
        else:
            reasons.append(ReasonCode.irreversible_high_blast)
            explanation = (
                f"Hard-to-undo or high-blast action (blast radius "
                f"{algebra.blast_radius.value}); authentication required."
            )
    if is_unclassified(algebra):
        reasons.append(ReasonCode.unclassified_action)
    return GuardrailResult(
        verdict=Verdict.AUTH,
        risk=Risk.medium if sensitivity_term < 0.7 else Risk.high,
        reason_codes=reasons,
        explanation=explanation,
    )


def _score_result(action: SecurityObject, ctx: EvalContext) -> GuardrailResult:
    """Trifecta floor → mode gate → three-axis score → threshold → budget."""
    algebra = action.algebra
    thresholds = thresholds_for(ctx.mode)

    # 1. The deterministic floor — before any score math, in EVERY preset. In the
    #    strictest modes it hard-BLOCKs the exfil (ADR 0021); otherwise it steps up
    #    to AUTH. Either way it fires regardless of score/weights/budget/tokens.
    if trifecta_fires(algebra):
        hard = thresholds.trifecta_hard_block
        return GuardrailResult(
            verdict=Verdict.BLOCK if hard else Verdict.AUTH,
            risk=Risk.critical if hard else Risk.high,
            reason_codes=[ReasonCode.lethal_trifecta],
            explanation=(
                "Sensitive data + untrusted provenance + external destination "
                "(lethal trifecta); "
                + (
                    "blocked regardless of score."
                    if hard
                    else "authentication required regardless of score."
                )
            ),
        )

    # 2. The mode gate (Light disables the SCORE path only — never the floor).
    if not thresholds.escalate_unusual:
        return _PASS

    # 3. The three axes, combined as a geometric soft-AND.
    prefs = _read_preferences(ctx)
    surprise = _read_surprise(ctx)
    sensitivity_term = sensitivity(algebra)
    care_terms = care_contributions(prefs, algebra, action.reversibility)
    care_term = max(care_terms.values())
    score = (surprise * sensitivity_term * care_term) ** (1.0 / 3.0)

    # 4. Threshold (mode base scaled by interruption tolerance).
    if score < effective_threshold(thresholds.abnormality_threshold, prefs):
        return _PASS

    # 5. The fatigue budget and any live SL6 scope token suppress only this
    #    score-path step-up; the overflow/consumption is logged by the proxy.
    if not _budget_ok(ctx) or _scope_token_active(ctx):
        return _PASS

    return _step_up_result(surprise, sensitivity_term, care_terms, algebra)


class SubjectiveGuardrail:
    """Three-axis calibrated scoring + built-in + registered detectors, combined raise-only.

    The scoring signal is the universal subjective layer (SL7): a calibrated
    three-axis (surprise × sensitivity × care) score with the lethal-trifecta
    floor. Built-in detectors
    (:data:`~doberman.engine.detectors.BUILTIN_DETECTOR_TYPES`) are constructed
    once at init with their defaults and always run; they abstain (PASS) on
    benign input, so with nothing unusual present this is equivalent to the
    scoring signal alone. Detector *plugins* are discovered once at init via the
    entry-point registry (group ``doberman.detectors``) and are gated by
    ``load_plugins`` (mirrors :class:`~doberman.engine.objective.ObjectiveGuardrail`).
    Pass ``extra_detectors`` to inject detectors directly (tests); pass
    ``load_builtins=False`` to run scoring-only (tests).
    """

    def __init__(
        self,
        *,
        load_plugins: bool = True,
        load_builtins: bool = True,
        extra_detectors: Sequence[Guardrail] = (),
    ) -> None:
        builtin: list[Guardrail] = (
            [detector_type() for detector_type in BUILTIN_DETECTOR_TYPES] if load_builtins else []
        )
        plugins: list[Guardrail] = list(discover_detectors()) if load_plugins else []
        self._detectors: tuple[Guardrail, ...] = (*builtin, *extra_detectors, *plugins)
        # Built-ins (+ extra_detectors) share the caller's ctx; only this
        # trailing slice (plugins) gets its own metadata copy — see plugin_ctx().
        self._plugin_start = len(builtin) + len(extra_detectors)

    def evaluate(self, action: SecurityObject, ctx: EvalContext) -> GuardrailResult:
        """Reduce the scoring signal + every detector raise-only.

        Never raises from detector failures (each is isolated) and the
        reduction only ever moves the verdict/risk up. A failure in the scoring
        step itself escalates (fail upward, never PASS-through on error).
        Built-in detectors run against the shared ``ctx``; plugin detectors run
        against their own copy (``plugin_ctx``) so a plugin can never mutate
        metadata a later built-in/plugin or the caller sees.
        """
        try:
            combined = _score_result(action, ctx)
        except Exception:  # noqa: BLE001 — scoring failure fails UPWARD, never PASS
            logger.warning("subjective scoring failed (action %s); escalating", action.id)
            combined = GuardrailResult(
                verdict=Verdict.AUTH,
                risk=Risk.high,
                reason_codes=[ReasonCode.subjective_guardrail_error],
                explanation="Subjective scoring failed; escalating to authentication.",
            )
        for i, detector in enumerate(self._detectors):
            detector_ctx = plugin_ctx(ctx) if i >= self._plugin_start else ctx
            combined = combine(combined, _isolate(detector, action, detector_ctx))
        return combined
