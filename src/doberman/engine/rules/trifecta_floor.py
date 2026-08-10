"""Lethal-trifecta floor at the OBJECTIVE layer (defense-in-depth).

The mandated lethal-trifecta floor (sensitive/secret data + untrusted/mixed
provenance + external destination) also lives in the subjective layer
(:func:`doberman.engine.subjective._score_result`). But the execution rule runs
the objective guardrail first and short-circuits on any non-PASS: an objective
``AUTH`` (e.g. from :class:`~doberman.engine.rules.destinations.ExternalDestinationRule`)
means the subjective guardrail — and therefore its floor — never runs. That let
an objective ``AUTH`` MASK the mandated hard ``BLOCK`` in strict/paranoid.

This rule re-asserts the floor objective-side so the hard block can no longer be
masked. It is a **minimal, raise-only** addition: it emits ``BLOCK`` *only* in the
hard-block modes (strict/paranoid, ``ModeThresholds.trifecta_hard_block``); in the
soft modes it abstains (``PASS``), leaving the existing subjective soft-mode
``AUTH`` path byte-identical. It imports only the models-only leaf predicate and
the lightweight (dataclass) mode thresholds — never subjective's ML import chain —
so it stays safe to run on every tool call.
"""

from doberman.engine.trifecta import trifecta_fires
from doberman.models import (
    EvalContext,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    Verdict,
)
from doberman.policy.modes import thresholds_for

_PASS = GuardrailResult(verdict=Verdict.PASS, risk=Risk.low)


class TrifectaFloorRule:
    """Hard-block a lethal-trifecta action in strict/paranoid; abstain otherwise.

    Deliberately narrow: only the hard-block branch of the floor lives here. The
    soft-mode step-up (Light/Balanced → AUTH) stays solely in the subjective
    layer, so this rule changes nothing except closing the AUTH-masks-BLOCK gap.
    A default (all-unknown) algebra never fires the predicate → ``PASS``.
    """

    def evaluate(self, action: SecurityObject, ctx: EvalContext) -> GuardrailResult:
        if thresholds_for(ctx.mode).trifecta_hard_block and trifecta_fires(action.algebra):
            return GuardrailResult(
                verdict=Verdict.BLOCK,
                risk=Risk.critical,
                reason_codes=[ReasonCode.lethal_trifecta],
                explanation=(
                    "Sensitive data + untrusted provenance + external destination "
                    "(lethal trifecta); blocked regardless of score."
                ),
            )
        return _PASS
