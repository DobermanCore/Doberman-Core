"""Shadow-only adjudication seam (Phase 0 of the "adaptive precision" method).

A pluggable **second-opinion** layer that may *observe* a decision and record what
it WOULD recommend — but **never** changes the live verdict. Phase 0 is
shadow-only by construction:

* An adjudicator is handed a **redacted feature Mapping** (:func:`redacted_features`),
  not a :class:`SecurityObject`/:class:`EvalContext`, so it *structurally* cannot see
  raw arguments, file contents, secrets, or the raw destination — only classes,
  the algebra, reason-code strings, and fingerprint counts.
* Its recommendation is attached to :attr:`~doberman.models.Decision.shadow` and is
  passed to **no** part of the ``final_verdict``/``final_risk`` computation. There is
  no code path by which an adjudicator can raise (or lower) the live decision.
* It is **fail-closed**: any error consulting an adjudicator (raise, garbage return)
  is logged at debug and ignored — the decision proceeds unchanged.
* It is subordinate to the raise-only floor: the engine only ever consults it in the
  ambiguous AUTH step-up band; a floor/BLOCK or PASS decision is never shown to it.

A real anomaly-model / cheap-LLM adjudicator (enterprise) plugs in here by
implementing :class:`Adjudicator` and registering via the ``doberman.adjudicators``
entry-point group — core never imports it by name.
"""

import logging
from collections.abc import Mapping, Sequence
from typing import Any, Protocol, runtime_checkable

from doberman.models import GuardrailResult, Risk, SecurityObject, TargetClass, Verdict

logger = logging.getLogger("doberman.engine.adjudicator")

#: The low-sensitivity target classes the built-in reference treats as benign.
_BENIGN_TARGET_CLASSES = frozenset({TargetClass.public.value, TargetClass.internal.value})


@runtime_checkable
class Adjudicator(Protocol):
    """The contract a shadow adjudicator implements.

    ``adjudicate`` receives a plain **redacted** feature Mapping (never a
    ``SecurityObject``/``EvalContext``) plus the current :class:`GuardrailResult`,
    and returns either a :class:`GuardrailResult` recommendation or ``None`` to
    abstain. It is SHADOW-ONLY: the engine never uses the return value to build
    the live verdict.

    CAVEAT: ``isinstance(obj, Adjudicator)`` is structural-only (checks for an
    ``adjudicate`` attribute, not its signature) — the real gate is that the
    return value is validated as a ``GuardrailResult``/``None`` and any error is
    isolated (:func:`run_shadow_adjudication`).
    """

    def adjudicate(
        self, features: Mapping[str, Any], current: GuardrailResult
    ) -> GuardrailResult | None:
        """Recommend a verdict for a decision, or ``None`` to abstain."""
        ...


def redacted_features(action: SecurityObject, current: GuardrailResult) -> dict[str, Any]:
    """Build the EXPLICIT allowlist of redacted features shown to an adjudicator.

    Only redaction-safe classes/counts leave here. It MUST NOT include
    ``raw_args_redacted``, ``ctx.metadata``, the raw ``external_destination``
    string, ``explanation``, or any raw value — an adjudicator can only ever see
    the algebra, sensitivity classes, reason-code strings, and fingerprint
    counts. ``tool_name`` is a low-risk identifier and is kept.
    """
    algebra = action.algebra
    return {
        "action_type": action.action_type.value,
        "tool_name": action.tool_name,
        "target_path_class": action.target_path_class,
        "risk": action.risk.value,
        "verdict": current.verdict.value,
        "reason_codes": [rc.value for rc in current.reason_codes],
        "algebra": {
            "capability": algebra.capability.value,
            "target_class": algebra.target_class.value,
            "destination_class": algebra.destination_class.value,
            "blast_radius": algebra.blast_radius.value,
            "provenance": algebra.provenance.value,
            "classification_confidence": algebra.classification_confidence,
        },
        "has_external_destination": action.external_destination is not None,
        "fingerprint_count": len(action.payload_fingerprints),
    }


class LocalReferenceAdjudicator:
    """A minimal, illustrative built-in adjudicator (no network, core-safe).

    This is a REFERENCE demonstrating the seam contract; it is SHADOW-ONLY and
    never affects the live verdict. On a benign-looking AUTH decision it records
    a "would-PASS" second opinion; otherwise it abstains. A real anomaly-model /
    LLM adjudicator plugs in at this same interface.
    """

    def adjudicate(
        self, features: Mapping[str, Any], current: GuardrailResult
    ) -> GuardrailResult | None:
        algebra = features.get("algebra", {})
        looks_benign = (
            current.verdict is Verdict.AUTH
            and algebra.get("target_class") in _BENIGN_TARGET_CLASSES
            and not features.get("has_external_destination", True)
            and algebra.get("classification_confidence", 0.0) >= 0.8
        )
        if looks_benign:
            return GuardrailResult(
                verdict=Verdict.PASS,
                risk=Risk.low,
                explanation="shadow: looks benign for this deployment",
            )
        return None


def run_shadow_adjudication(
    adjudicators: Sequence[Adjudicator],
    action: SecurityObject,
    current: GuardrailResult,
) -> GuardrailResult | None:
    """Consult adjudicators on redacted features; return the first recommendation.

    Fail-closed and NEVER raises: building the features or any adjudicator raising
    / returning a non-``GuardrailResult`` is logged at debug and skipped. Returns
    the first non-``None`` :class:`GuardrailResult` recommendation, or ``None``.
    The return value is a SHADOW annotation only — the caller never uses it to
    build the live verdict.
    """
    if not adjudicators:
        return None
    try:
        features = redacted_features(action, current)
    except Exception:  # noqa: BLE001 — shadow must never affect the live decision
        logger.debug("shadow: building redacted features failed; skipping", exc_info=True)
        return None
    for adjudicator in adjudicators:
        try:
            recommendation = adjudicator.adjudicate(features, current)
        except Exception:  # noqa: BLE001 — a raising adjudicator is isolated
            logger.debug("shadow: adjudicator raised; skipping", exc_info=True)
            continue
        if recommendation is None:
            continue
        if not isinstance(recommendation, GuardrailResult):
            logger.debug("shadow: adjudicator returned a non-GuardrailResult; skipping")
            continue
        return recommendation
    return None
