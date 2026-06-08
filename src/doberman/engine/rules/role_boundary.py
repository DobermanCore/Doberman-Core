"""Role-boundary rule (Feature 4, slice 4.3).

Escalates path actions that cross the active agent role's boundaries. This lives
in the **objective** layer on purpose: role authority outranks casual user
intent and must not be something the subjective/learning layer can soften — a
frontend agent editing ``backend/auth/session.ts`` escalates no matter how
friendly the prompt is.

Verdicts (raise-only; the objective guardrail combines this with the other
rules):

* target classifies as ``blocked`` for the role → ``BLOCK (role_blocked_target)``
* target classifies as ``suspicious`` (incl. out-of-scope-by-default) →
  ``AUTH (role_out_of_scope)``
* ``allowed`` / non-path action / no active role → abstain (``PASS``)

SECURITY: the explanation names the role and the boundary class only — never
the raw path. With ``ctx.role is None`` the rule abstains, so role enforcement
is strictly opt-in and never silently blocks a repo that has not set a role.
"""

from doberman.models import (
    ActionType,
    EvalContext,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    Verdict,
)
from doberman.roles.roles import RoleBoundary, classify

#: Only path-shaped actions are classified against role path globs. A shell or
#: network action's ``target`` is a command/URL, not a path, so this rule
#: abstains on them (the command/destination rules cover those).
_PATH_ACTION_TYPES = frozenset(
    {ActionType.file_read, ActionType.file_write, ActionType.file_delete}
)

_DEFAULT_ROOT = "."

# Worst-wins ordering for batch actions.
_SEVERITY = {
    RoleBoundary.allowed: 0,
    RoleBoundary.unknown: 0,
    RoleBoundary.suspicious: 1,
    RoleBoundary.blocked: 2,
}


def _candidate_paths(action: SecurityObject) -> list[str]:
    raw_paths = action.metadata.get("raw_paths") if isinstance(action.metadata, dict) else None
    if isinstance(raw_paths, (list, tuple)) and raw_paths:
        return [str(p) for p in raw_paths if isinstance(p, str) and p]
    if action.target:
        return [action.target]
    return []


class RoleBoundaryRule:
    """Escalate actions that cross the active role's path boundaries."""

    def evaluate(self, action: SecurityObject, ctx: EvalContext) -> GuardrailResult:
        role = ctx.role
        if role is None:
            return GuardrailResult(verdict=Verdict.PASS, risk=Risk.low)
        if action.action_type not in _PATH_ACTION_TYPES:
            return GuardrailResult(verdict=Verdict.PASS, risk=Risk.low)

        paths = _candidate_paths(action)
        if not paths:
            return GuardrailResult(verdict=Verdict.PASS, risk=Risk.low)

        root = _DEFAULT_ROOT
        if isinstance(ctx.metadata, dict):
            root = str(ctx.metadata.get("repo_root") or _DEFAULT_ROOT)

        worst = RoleBoundary.allowed
        for raw_path in paths:
            boundary = classify(role, raw_path, root=root)
            if _SEVERITY[boundary] > _SEVERITY[worst]:
                worst = boundary
            if worst is RoleBoundary.blocked:
                break

        return self._verdict_for(worst, role.name)

    @staticmethod
    def _verdict_for(boundary: RoleBoundary, role_name: str) -> GuardrailResult:
        if boundary is RoleBoundary.blocked:
            return GuardrailResult(
                verdict=Verdict.BLOCK,
                risk=Risk.high,
                reason_codes=[ReasonCode.role_blocked_target],
                explanation=(
                    f"Target is forbidden for the active '{role_name}' role; blocked by role policy."
                ),
            )
        if boundary is RoleBoundary.suspicious:
            return GuardrailResult(
                verdict=Verdict.AUTH,
                risk=Risk.medium,
                reason_codes=[ReasonCode.role_out_of_scope],
                explanation=(
                    f"Target is outside the active '{role_name}' role's scope; "
                    "authentication required (role outranks user intent)."
                ),
            )
        return GuardrailResult(verdict=Verdict.PASS, risk=Risk.low)
