"""The decision engine: the `Guardrail` contract (and, next slices, the
raise-only combination and the objective-first execution rule).

This module is part of the policy core — it must never import
``doberman.proxy`` (enforced by import-linter).
"""

from typing import Protocol, runtime_checkable

from doberman.models import EvalContext, GuardrailResult, SecurityObject


@runtime_checkable
class Guardrail(Protocol):
    """The contract every guardrail implements.

    Guardrails are pure functions of ``(action, ctx)``: no side effects, no
    mutation of the action (it is frozen anyway), one :class:`GuardrailResult`
    out. The engine — not the guardrail — owns combination and short-circuit
    semantics, so a guardrail can never lower another's verdict.
    """

    def evaluate(self, action: SecurityObject, ctx: EvalContext) -> GuardrailResult:
        """Judge one action and return a verdict with reasons."""
        ...
