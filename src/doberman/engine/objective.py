"""The objective guardrail (Feature 3, slice 3.7).

Assembles the built-in basic rules (secrets, protected paths, destructive
commands, external destinations) plus any registered plugin rules into a single
:class:`~doberman.engine.decision_engine.Guardrail`. It runs every rule,
**isolates each rule's failures**, and reduces all the results raise-only with
``combine()`` (the engine's invariant — strongest verdict wins, risk only goes
up, reasons union).

Two safety properties this class guarantees:

* **A single failing rule never makes the guardrail pass.** Per-rule exceptions
  (or garbage returns) are caught and turned into ``AUTH / high
  (rule_error)`` — failing *upward*: one buggy rule cannot slam everything to
  BLOCK, but it also can never silently PASS. ``evaluate`` itself never raises,
  so the decision engine's own fail-closed path is a backstop, not the norm.
* **Plugins can only raise risk.** Registered plugins go through the exact same
  isolation + ``combine`` as built-ins, so an external plugin can only ever add
  risk; it has no path to lower a verdict (slice 3.8). This is now true even
  of a plugin's *side effects*, not just its return value: a plugin rule runs
  against its OWN copy of ``ctx.metadata`` (see ``_plugin_ctx``), so a plugin
  that deletes or rewrites shared metadata (``raw_arguments``, a
  ``scope_token`` flag, ...) can never affect what a later built-in or plugin
  sees, and can never affect the caller's own context after ``evaluate``
  returns.
"""

import logging
from collections.abc import Sequence

from doberman.engine.decision_engine import Guardrail, combine, plugin_ctx
from doberman.engine.registry import discover_rules
from doberman.engine.rules import BUILTIN_RULE_TYPES
from doberman.models import (
    EvalContext,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    Verdict,
)

logger = logging.getLogger("doberman.engine.objective")

#: The neutral seed for the raise-only reduction. Combining anything with this
#: returns the other result; if every rule abstains, the guardrail passes.
_PASS_SEED = GuardrailResult(verdict=Verdict.PASS, risk=Risk.low)


def _isolate(rule: Guardrail, action: SecurityObject, ctx: EvalContext) -> GuardrailResult:
    """Run one rule; any failure becomes a conservative AUTH/high (rule_error).

    Catches ``Exception`` only — ``BaseException`` (cancellation, SystemExit)
    must unwind, and an unwind is fail-closed by construction. A non-
    ``GuardrailResult`` return (a signature-blind impostor) is treated the same
    as a raise: we never trust a rule's output without validating its type.
    """
    try:
        result = rule.evaluate(action, ctx)
    except Exception:  # noqa: BLE001 — the guardrail owns per-rule failure
        logger.warning("objective rule %s raised; isolating as AUTH", type(rule).__name__)
        result = None
    if not isinstance(result, GuardrailResult):
        return GuardrailResult(
            verdict=Verdict.AUTH,
            risk=Risk.high,
            reason_codes=[ReasonCode.rule_error],
            explanation=(
                "An objective rule failed to evaluate; escalating to authentication (fail upward)."
            ),
        )
    return result


class ObjectiveGuardrail:
    """Run all built-in rules + registered plugins, combine raise-only.

    Built-in rules are constructed once at init with their defaults (F6 will
    later override the policy lists). Plugin rules are discovered once at init
    via the entry-point registry; with nothing installed, only built-ins run.
    Pass ``extra_rules`` to inject rules directly (used by tests).
    """

    def __init__(
        self,
        rules: Sequence[Guardrail] | None = None,
        *,
        load_plugins: bool = True,
        extra_rules: Sequence[Guardrail] = (),
    ) -> None:
        if rules is not None:
            builtin: list[Guardrail] = list(rules)
        else:
            builtin = [rule_type() for rule_type in BUILTIN_RULE_TYPES]
        plugins: list[Guardrail] = list(discover_rules()) if load_plugins else []
        self._rules: tuple[Guardrail, ...] = (*builtin, *extra_rules, *plugins)
        # Built-ins (+ extra_rules) share the caller's ctx; only this trailing
        # slice (plugins) gets its own metadata copy — see plugin_ctx().
        self._plugin_start = len(builtin) + len(extra_rules)

    def evaluate(self, action: SecurityObject, ctx: EvalContext) -> GuardrailResult:
        """Evaluate every rule and reduce the results raise-only.

        Never raises: each rule is isolated, and the reduction only ever moves
        the verdict/risk up. With every rule abstaining, returns PASS/low.
        Built-ins run against the shared ``ctx``; plugins run against their
        own copy (``plugin_ctx``) so a plugin can never mutate metadata a
        later built-in/plugin or the caller sees.
        """
        combined = _PASS_SEED
        for i, rule in enumerate(self._rules):
            rule_ctx = plugin_ctx(ctx) if i >= self._plugin_start else ctx
            combined = combine(combined, _isolate(rule, action, rule_ctx))
        return combined
