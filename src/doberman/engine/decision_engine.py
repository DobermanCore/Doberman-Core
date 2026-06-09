"""The decision engine: the `Guardrail` contract, the raise-only
combination, and the objective-first execution rule.

This module is part of the policy core — it must never import
``doberman.proxy`` (enforced by import-linter).
"""

from datetime import datetime, timezone
from typing import Protocol, runtime_checkable

from doberman.models import (
    RISK_ORDER,
    VERDICT_ORDER,
    Decision,
    EvalContext,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    Verdict,
)

# Reason codes for which a SUBJECTIVE BLOCK is honored as a hard block.
# Deliberately EMPTY in the MVP: the subjective guardrail escalates to AUTH,
# it does not hard-block ("subjective is for escalation, not paternalism").
# Growing this list is a policy weakening of the clamp and must go through
# the Feature 10 human-approved path. NOTE: this is a module-global frozenset;
# rebinding the NAME at runtime is possible for code inside the process trust
# boundary and would bypass F10 — treat any runtime rebinding as an attack.
SUBJECTIVE_HARD_BLOCK_ALLOWLIST: frozenset[ReasonCode] = frozenset()


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


def decide(
    action: SecurityObject,
    objective: Guardrail,
    subjective: Guardrail,
    ctx: EvalContext,
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
    )
