"""Decision pipelines for the two benchmark profiles.

A :class:`Pipeline` pairs an objective + subjective guardrail and runs core's
public ``decide()`` over an action. The only difference between the two profiles
is the already-shipped ``load_plugins`` flag:

* ``builtins_only`` (``load_plugins=False``) — only the built-in rules/detectors.
* ``with_plugins``  (``load_plugins=True``)  — built-ins **plus** any entry-point
  plugins installed in the environment.

With nothing installed the two are identical, so on a standalone core install the
profiles report the same numbers (uplift 0). The harness imports only core's
public engine API — it registers nothing and changes nothing.
"""

from __future__ import annotations

from dataclasses import dataclass

from doberman.engine.decision_engine import Guardrail, decide
from doberman.engine.objective import ObjectiveGuardrail
from doberman.engine.subjective import SubjectiveGuardrail
from doberman.models import Decision, EvalContext, GuardrailResult, Risk, SecurityObject, Verdict

from .mapping import BENCHMARK_TS

#: Profile identifiers used as keys throughout reports.
BUILTINS_ONLY = "builtins_only"
WITH_PLUGINS = "with_plugins"

#: The "before Doberman" baseline: no engine on the tool path at all.
NO_GUARDRAIL = "no_guardrail"


@dataclass(frozen=True)
class Pipeline:
    """An objective + subjective guardrail pair that decides one action."""

    name: str
    objective: Guardrail
    subjective: Guardrail

    def decide(self, action: SecurityObject, ctx: EvalContext) -> Decision:
        return decide(action, self.objective, self.subjective, ctx)


def build_pipeline(*, load_plugins: bool) -> Pipeline:
    """Construct a pipeline for one profile.

    ``load_plugins=False`` → ``builtins_only``; ``True`` → ``with_plugins``.
    """
    name = WITH_PLUGINS if load_plugins else BUILTINS_ONLY
    return Pipeline(
        name=name,
        objective=ObjectiveGuardrail(load_plugins=load_plugins),
        subjective=SubjectiveGuardrail(load_plugins=load_plugins),
    )


def _allow_decision(action_id: str) -> Decision:
    """A PASS for any action — models an unmediated tool path (no guardrail)."""
    return Decision(
        action_id=action_id,
        final_verdict=Verdict.PASS,
        final_risk=Risk.low,
        objective=GuardrailResult(verdict=Verdict.PASS, risk=Risk.low),
        decided_at=BENCHMARK_TS,
    )


@dataclass(frozen=True)
class PassthroughPipeline:
    """The "before Doberman" arm: every action is allowed, no engine consulted.

    This is the honest unmediated baseline. With no guardrail on the tool path
    every candidate action would execute, so every labeled attack bypasses
    (ASR 1.0) and benign work runs with zero friction (FPR 0.0). The delta of a
    real Doberman pipeline against this baseline is exactly what the layer adds —
    attacks stopped vs. benign friction introduced. It conforms to the same
    ``decide(action, ctx) -> Decision`` shape as :class:`Pipeline` so the runner
    treats it identically.
    """

    name: str = NO_GUARDRAIL

    def decide(self, action: SecurityObject, ctx: EvalContext) -> Decision:
        return _allow_decision(action.id)
