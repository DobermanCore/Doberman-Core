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
from doberman.models import Decision, EvalContext, SecurityObject

#: Profile identifiers used as keys throughout reports.
BUILTINS_ONLY = "builtins_only"
WITH_PLUGINS = "with_plugins"


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
