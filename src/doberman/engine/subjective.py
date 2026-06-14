"""The subjective guardrail (Feature 9, slice 9.3).

The *second* guardrail: after the objective guardrail PASSes, this one catches
actions that are technically allowed but **unusual for this workflow**, raising
them to ``AUTH``. It combines a baseline-driven abnormality score (computed by
the proxy and handed in via ``EvalContext.metadata['abnormality']``) with any
registered behavioral :class:`Detector` plugins (group ``doberman.detectors``).

Safety properties (mirrors the objective guardrail):

* **Raise-only.** Every result is reduced with ``combine()``; the subjective
  layer can only ever *add* risk. It also **cannot hard-block** in the MVP — the
  execution rule clamps a subjective BLOCK to AUTH — so this guardrail tops out
  at AUTH by design (escalation, not paternalism).
* **Mode-aware.** The abnormality step-up uses the active mode's threshold;
  **Light disables it** (``escalate_unusual=False``). Stricter modes step up
  sooner.
* **Detectors are isolated.** A detector that raises or returns garbage becomes a
  conservative ``AUTH/high (rule_error)`` — never a silent PASS, never a crash —
  and is bound by the same raise-only ``combine``. With nothing installed, only
  the baseline signal runs.

This module is part of the policy core: it must never import ``doberman.proxy``.
"""

import logging
from collections.abc import Sequence

from doberman.engine.decision_engine import Guardrail, combine
from doberman.engine.detectors import BUILTIN_DETECTOR_TYPES
from doberman.engine.registry import discover_detectors
from doberman.models import (
    EvalContext,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    Verdict,
)
from doberman.policy.modes import thresholds_for

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


def _abnormality_result(score: float, mode: str) -> GuardrailResult:
    """Map the precomputed abnormality score to PASS or AUTH for the active mode."""
    thresholds = thresholds_for(mode)
    if not thresholds.escalate_unusual or score < thresholds.abnormality_threshold:
        return _PASS
    return GuardrailResult(
        verdict=Verdict.AUTH,
        risk=Risk.medium,
        reason_codes=[ReasonCode.unusual_for_workflow],
        explanation=(
            "This action is unusual for your established workflow; "
            "authentication required (subjective escalation)."
        ),
    )


class SubjectiveGuardrail:
    """Baseline abnormality + built-in + registered detectors, combined raise-only.

    Built-in detectors (:data:`~doberman.engine.detectors.BUILTIN_DETECTOR_TYPES`)
    are constructed once at init with their defaults and always run; they abstain
    (PASS) on benign input, so with nothing unusual present this is equivalent to
    the baseline signal alone. Detector *plugins* are discovered once at init via
    the entry-point registry (group ``doberman.detectors``) and are gated by
    ``load_plugins`` (mirrors :class:`~doberman.engine.objective.ObjectiveGuardrail`).
    Pass ``extra_detectors`` to inject detectors directly (tests); pass
    ``load_builtins=False`` to run baseline-only (tests).
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

    def evaluate(self, action: SecurityObject, ctx: EvalContext) -> GuardrailResult:
        """Reduce the abnormality signal + every detector raise-only.

        Never raises: each detector is isolated and the reduction only ever moves
        the verdict/risk up. Reads the abnormality score from
        ``ctx.metadata['abnormality']`` (0.0 when the proxy did not supply one).
        """
        score = 0.0
        if isinstance(ctx.metadata, dict):
            raw = ctx.metadata.get("abnormality", 0.0)
            if isinstance(raw, (int, float)):
                score = float(raw)

        combined = _abnormality_result(score, ctx.mode)
        for detector in self._detectors:
            combined = combine(combined, _isolate(detector, action, ctx))
        return combined
