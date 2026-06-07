"""The decision engine: the `Guardrail` contract (and, next slices, the
raise-only combination and the objective-first execution rule).

This module is part of the policy core — it must never import
``doberman.proxy`` (enforced by import-linter).
"""

from typing import Protocol, runtime_checkable

from doberman.models import (
    RISK_ORDER,
    VERDICT_ORDER,
    EvalContext,
    GuardrailResult,
    Risk,
    SecurityObject,
    Verdict,
)


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
