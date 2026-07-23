"""Fail-upward floor for actions that could not be normalized safely."""

from doberman.models import (
    EvalContext,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    Verdict,
)


class NormalizationFailureRule:
    """Require authentication when normalization returned its safe fallback."""

    def evaluate(self, action: SecurityObject, ctx: EvalContext) -> GuardrailResult:
        metadata = action.metadata if isinstance(action.metadata, dict) else {}
        raw_reasons = metadata.get("reason_codes", ())
        reasons = raw_reasons if isinstance(raw_reasons, (list, tuple, set)) else ()
        if ReasonCode.normalization_failed not in reasons:
            return GuardrailResult(verdict=Verdict.PASS, risk=Risk.low)
        return GuardrailResult(
            verdict=Verdict.AUTH,
            risk=Risk.high,
            reason_codes=[ReasonCode.normalization_failed],
            explanation=(
                "The action could not be normalized safely; authentication required (fail closed)."
            ),
        )
