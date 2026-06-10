"""The decision engine: the `Guardrail` contract, the raise-only
combination, and the objective-first execution rule.

This module is part of the policy core — it must never import
``doberman.proxy`` (enforced by import-linter).
"""

import logging
from collections.abc import Sequence
from datetime import datetime, timezone
from typing import Protocol, runtime_checkable

from doberman.engine.adjudicator import Adjudicator, run_shadow_adjudication
from doberman.models import (
    RISK_ORDER,
    VERDICT_ORDER,
    Decision,
    EvalContext,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    TurnObject,
    Verdict,
)

logger = logging.getLogger("doberman.engine.decision_engine")

# Reason codes for which a SUBJECTIVE BLOCK is honored as a hard block (rather
# than clamped to AUTH). The subjective guardrail is otherwise AUTH-only
# ("escalation, not paternalism") — a learned/score signal must not hard-lock the
# user out on a false positive. The ONE exception is the deterministic
# lethal-trifecta floor (sensitive data + untrusted provenance + external dest): a
# high-confidence, score-independent check that only emits a BLOCK in the strictest
# modes (strict/paranoid, ``ModeThresholds.trifecta_hard_block``). Honoring it is
# therefore raise-only and user-directed (ADR 0021), not a weakening. Adding ANY
# OTHER code here weakens the clamp and must go through the Feature 10 human-approved
# path. NOTE: this is a module-global frozenset; rebinding the NAME at runtime is
# possible for code inside the process trust boundary and would bypass F10 — treat
# any runtime rebinding as an attack.
SUBJECTIVE_HARD_BLOCK_ALLOWLIST: frozenset[ReasonCode] = frozenset({ReasonCode.lethal_trifecta})


@runtime_checkable
class Guardrail(Protocol):
    """The contract every guardrail implements.

    Guardrails are pure functions of ``(action, ctx)``: no side effects, no
    mutation of the action (it is frozen anyway), one :class:`GuardrailResult`
    out. The engine — not the guardrail — owns combination and short-circuit
    semantics, so a guardrail can never lower another's verdict.

    CAVEAT: ``isinstance(obj, Guardrail)`` is structural-only (method name,
    not signature or return type) — ``runtime_checkable`` cannot verify more.
    The engine must therefore never treat an isinstance check as a type-safety
    gate: the real gate is that ``evaluate``'s return value is validated as a
    ``GuardrailResult`` (anything else fails closed).
    """

    def evaluate(self, action: SecurityObject, ctx: EvalContext) -> GuardrailResult:
        """Judge one action and return a verdict with reasons."""
        ...


class StaticGuardrail:
    """A guardrail that always returns a fixed result.

    The MVP stub used until Feature 3 (objective) and Feature 9 (subjective)
    provide real implementations; also handy in tests.
    """

    def __init__(self, result: GuardrailResult) -> None:
        self._result = result

    def evaluate(self, action: SecurityObject, ctx: EvalContext) -> GuardrailResult:
        return self._result


#: Default stubs: observe-everything (PASS/low) until F3/F9 land.
PASS_STUB = StaticGuardrail(GuardrailResult(verdict=Verdict.PASS, risk=Risk.low))


def max_verdict(a: Verdict, b: Verdict) -> Verdict:
    """The more severe of two verdicts (PASS < AUTH < BLOCK)."""
    return a if VERDICT_ORDER[a] >= VERDICT_ORDER[b] else b


def max_risk(a: Risk, b: Risk) -> Risk:
    """The higher of two risk levels (low < medium < high < critical)."""
    return a if RISK_ORDER[a] >= RISK_ORDER[b] else b


def combine(a: GuardrailResult, b: GuardrailResult | None) -> GuardrailResult:
    """Combine two guardrail results — RAISE-ONLY, by construction.

    Returns the **max** verdict, the **max** risk, and the **union** of
    reason codes (order-preserving, ``a`` first). There is deliberately no
    code path that returns a verdict or risk lower than either input: the
    only operations used are max() over the severity orderings and set
    union over reasons. ``b is None`` (subjective skipped) returns a copy of
    ``a`` (never the same instance — reason_codes is a mutable list and the
    caller must not be able to alias it).
    """
    if b is None:
        return a.model_copy(deep=True)
    merged_reasons = list(dict.fromkeys([*a.reason_codes, *b.reason_codes]))
    explanation = " ".join(part for part in (a.explanation.strip(), b.explanation.strip()) if part)
    return GuardrailResult(
        verdict=max_verdict(a.verdict, b.verdict),
        risk=max_risk(a.risk, b.risk),
        reason_codes=merged_reasons,
        explanation=explanation,
    )


def _safe_evaluate(
    guardrail: Guardrail,
    action: SecurityObject,
    ctx: EvalContext,
    *,
    on_error_verdict: Verdict,
    error_code: ReasonCode,
    error_explanation: str,
) -> GuardrailResult:
    """Run one guardrail; any ``Exception`` (raise or junk return) yields the
    configured conservative result instead of escaping the engine.

    ``BaseException`` (KeyboardInterrupt/SystemExit/CancelledError) is
    deliberately NOT caught: those must unwind the stack — and an unwind is
    fail-closed by construction, because the downstream forward only happens
    on a *returned* PASS decision. A guardrail aborting the process can deny
    service, never grant access.
    """
    try:
        result = guardrail.evaluate(action, ctx)
    except Exception:  # noqa: BLE001 — the engine owns failure semantics
        result = None
    if not isinstance(result, GuardrailResult):
        # Covers both the exception path and a signature-blind impostor
        # returning garbage (the runtime_checkable Protocol cannot catch it).
        return GuardrailResult(
            verdict=on_error_verdict,
            risk=Risk.high,
            reason_codes=[error_code],
            explanation=error_explanation,
        )
    return result


def _shadow_for(
    adjudicators: Sequence[Adjudicator] | None,
    action: SecurityObject,
    final: GuardrailResult,
) -> GuardrailResult | None:
    """The shadow annotation for a FINAL result — shadow-only and fail-closed.

    Consulted ONLY in the ambiguous AUTH step-up band: a floor/BLOCK or a PASS
    decision is never shown to an adjudicator (floor-untouchable). The return
    value is attached to ``Decision.shadow`` and is NEVER used to build
    ``final_verdict``/``final_risk``. Any failure leaves ``shadow=None`` and the
    decision proceeds unchanged.
    """
    if not adjudicators or final.verdict is not Verdict.AUTH:
        return None
    try:
        return run_shadow_adjudication(adjudicators, action, final)
    except Exception:  # noqa: BLE001 — shadow must never affect the live decision
        logger.debug("shadow adjudication failed; ignoring", exc_info=True)
        return None


def decide(
    action: SecurityObject,
    objective: Guardrail,
    subjective: Guardrail,
    ctx: EvalContext,
    *,
    adjudicators: Sequence[Adjudicator] | None = None,
) -> Decision:
    """The execution rule (thesis §4/§8) — objective first, raise-only.

    1. Run the objective guardrail. If it errors → **BLOCK** (fail closed).
    2. Objective ``BLOCK`` → final BLOCK; subjective is NOT run.
    3. Objective ``AUTH`` → final AUTH; subjective is NOT run (straight to
       authentication — subjective can never weaken it).
    4. Objective ``PASS`` → run the subjective guardrail (errors → treated
       as AUTH, fail upward) and ``combine`` raise-only.
    5. A subjective ``BLOCK`` is honored only if one of its reason codes is
       on ``SUBJECTIVE_HARD_BLOCK_ALLOWLIST``; otherwise it is clamped to
       ``AUTH`` (the original subjective result is preserved on the
       Decision for audit).

    ``adjudicators`` (default ``None`` → zero behavior change) enables the
    shadow-only seam: when the FINAL verdict is ``AUTH``, a second-opinion
    recommendation is computed on REDACTED features and attached to
    ``Decision.shadow`` for observation. It never touches ``final_verdict``/
    ``final_risk`` and is never consulted for a floor/BLOCK or PASS decision.
    """
    objective_result = _safe_evaluate(
        objective,
        action,
        ctx,
        on_error_verdict=Verdict.BLOCK,
        error_code=ReasonCode.objective_guardrail_error,
        error_explanation="Objective guardrail failed; failing closed.",
    )

    # Steps 2–3: objective short-circuit — subjective never runs, so it can
    # never weaken (or even observe) an objective AUTH/BLOCK.
    if objective_result.verdict is not Verdict.PASS:
        return Decision(
            action_id=action.id,
            final_verdict=objective_result.verdict,
            final_risk=objective_result.risk,
            objective=objective_result,
            subjective=None,
            reason_codes=list(objective_result.reason_codes),
            explanation=objective_result.explanation,
            decided_at=datetime.now(timezone.utc),
            # Shadow-only annotation; never part of final_verdict/final_risk above.
            shadow=_shadow_for(adjudicators, action, objective_result),
        )

    # Step 4: objective PASS → consult the subjective guardrail.
    subjective_result = _safe_evaluate(
        subjective,
        action,
        ctx,
        on_error_verdict=Verdict.AUTH,
        error_code=ReasonCode.subjective_guardrail_error,
        error_explanation="Subjective guardrail failed; escalating to authentication.",
    )

    # Step 5: clamp a non-allowlisted subjective hard block to AUTH.
    effective_subjective = subjective_result
    if subjective_result.verdict is Verdict.BLOCK and not (
        SUBJECTIVE_HARD_BLOCK_ALLOWLIST & set(subjective_result.reason_codes)
    ):
        effective_subjective = GuardrailResult(
            verdict=Verdict.AUTH,
            risk=subjective_result.risk,
            reason_codes=[*subjective_result.reason_codes, ReasonCode.subjective_block_clamped],
            explanation=(
                f"{subjective_result.explanation} "
                "(subjective block clamped to authentication; not on the hard-block allowlist)"
            ).strip(),
        )

    combined = combine(objective_result, effective_subjective)
    return Decision(
        action_id=action.id,
        final_verdict=combined.verdict,
        final_risk=combined.risk,
        objective=objective_result,
        subjective=subjective_result,  # the ORIGINAL result, for audit truth
        reason_codes=list(combined.reason_codes),
        explanation=combined.explanation,
        decided_at=datetime.now(timezone.utc),
        # Shadow-only annotation; never part of final_verdict/final_risk above.
        shadow=_shadow_for(adjudicators, action, combined),
    )


# --- Feature 11 — turn gate: the engine's second invocation point ----------


@runtime_checkable
class TurnGuardrail(Protocol):
    """A guardrail evaluated at the pre-inference hook, on a :class:`TurnObject`.

    Same purity contract as :class:`Guardrail` (one result out, no side
    effects). Tier 0 guardrails may return BLOCK; Tier 1 guardrails are
    AUTH-only and any BLOCK they emit is clamped by :func:`decide_turn`.
    """

    def evaluate(self, turn: TurnObject, ctx: EvalContext) -> GuardrailResult:
        """Judge one turn and return a verdict with reasons."""
        ...


def _safe_evaluate_turn(
    guardrail: TurnGuardrail, turn: TurnObject, ctx: EvalContext
) -> GuardrailResult:
    """Run one turn guardrail; any failure becomes AUTH/high (turn_gate_error).

    AUTH-first by design: an internal failure defers the turn to the human, never
    a silent PASS (which would let an unscreened turn reach the model) and never a
    hard BLOCK (a BLOCK on a *bug* would be an escape-hatch-less lockout). Mirrors
    :func:`_safe_evaluate` but fails *upward* rather than closed-to-BLOCK.
    """
    try:
        result = guardrail.evaluate(turn, ctx)
    except Exception:  # noqa: BLE001 — the engine owns turn-guardrail failure
        result = None
    if not isinstance(result, GuardrailResult):
        return GuardrailResult(
            verdict=Verdict.AUTH,
            risk=Risk.high,
            reason_codes=[ReasonCode.turn_gate_error],
            explanation="Turn guardrail failed to evaluate; deferring to the human (fail upward).",
        )
    return result


def decide_turn(
    turn: TurnObject,
    tier0: TurnGuardrail,
    tier1: TurnGuardrail,
    ctx: EvalContext,
) -> Decision:
    """The turn-gate execution rule — Tier 0 first, raise-only, AUTH-first.

    1. Run **Tier 0** (deterministic signatures). Any non-PASS verdict is final
       and **Tier 1 never runs** (the same short-circuit as the action path's
       objective layer). A Tier 0 error fails to AUTH (defer to the human).
    2. Tier 0 ``PASS`` → run **Tier 1** (heuristic). Tier 1 is structurally
       AUTH-only: a Tier 1 ``BLOCK`` is **clamped to AUTH** (mirror of the
       subjective clamp) so the only hard-stop in the gate is Tier 0.

    Returns a :class:`Decision` whose ``objective`` slot is the Tier 0 result and
    ``subjective`` slot is the Tier 1 result (``None`` on Tier 0 short-circuit),
    so the unified audit model and the never-weaker-than-objective invariant both
    apply unchanged.
    """
    tier0_result = _safe_evaluate_turn(tier0, turn, ctx)

    if tier0_result.verdict is not Verdict.PASS:
        return Decision(
            action_id=turn.id,
            final_verdict=tier0_result.verdict,
            final_risk=tier0_result.risk,
            objective=tier0_result,
            subjective=None,
            reason_codes=list(tier0_result.reason_codes),
            explanation=tier0_result.explanation,
            decided_at=datetime.now(timezone.utc),
        )

    tier1_result = _safe_evaluate_turn(tier1, turn, ctx)

    effective_tier1 = tier1_result
    if tier1_result.verdict is Verdict.BLOCK:
        effective_tier1 = GuardrailResult(
            verdict=Verdict.AUTH,
            risk=tier1_result.risk,
            reason_codes=[*tier1_result.reason_codes, ReasonCode.subjective_block_clamped],
            explanation=(
                f"{tier1_result.explanation} "
                "(Tier 1 block clamped to authentication; only Tier 0 may hard-block a turn)"
            ).strip(),
        )

    combined = combine(tier0_result, effective_tier1)
    return Decision(
        action_id=turn.id,
        final_verdict=combined.verdict,
        final_risk=combined.risk,
        objective=tier0_result,
        subjective=tier1_result,  # the ORIGINAL result, for audit truth
        reason_codes=list(combined.reason_codes),
        explanation=combined.explanation,
        decided_at=datetime.now(timezone.utc),
    )
