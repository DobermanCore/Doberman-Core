"""Role-boundary rule (Feature 4, slice 4.3).

Escalates path actions that cross the active agent role's boundaries. This lives
in the **objective** layer on purpose: role authority outranks casual user
intent and must not be something the subjective/learning layer can soften — a
frontend agent editing ``backend/auth/session.ts`` escalates no matter how
friendly the prompt is.

Verdicts (raise-only; the objective guardrail combines this with the other
rules):

* target classifies as ``blocked`` for the role → ``BLOCK (role_blocked_target)``
  (a hard floor — never mode-gated)
* target classifies as ``suspicious`` (incl. out-of-scope-by-default) →
  ``AUTH (role_out_of_scope)`` in Balanced/Strict/Paranoid; ``PASS`` in Light
  (mode flag ``escalate_out_of_scope``)
* ``allowed`` / non-path action / no active role → abstain (``PASS``)

SECURITY: the explanation names the role and the boundary class only — never
the raw path. With ``ctx.role is None`` the rule abstains, so role enforcement
is strictly opt-in and never silently blocks a repo that has not set a role.

Role elevation (Feature 7.4): an active, narrow elevation grant (passed in via
``ctx.metadata['elevations']``) satisfies a ``suspicious`` (out-of-scope) target
for exactly that path — turning its AUTH into a PASS *for the role rule only*.
A ``blocked`` target is NEVER softened by an elevation, and every other
objective rule still runs and combines, so elevation can only ever lift the role
boundary's own escalation, nothing else.
"""

from doberman.auth.elevation import ElevationGrant, find_cover
from doberman.engine.rules.paths import RAW_PATH_KEYS_STRICT, raw_path_candidates
from doberman.models import (
    ActionType,
    EvalContext,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    Verdict,
)
from doberman.policy.modes import thresholds_for
from doberman.roles.roles import RoleBoundary, classify

#: Path-shaped action types are always classified against role path globs. A
#: non-path-typed tool whose raw arguments still carry a path-shaped value
#: (an unrecognized tool name, {"path": ...}) is also classified — see
#: ``evaluate`` — since the tool's declared type is caller-supplied and not a
#: trust boundary. A shell or network action's ``target`` is a command/URL,
#: not a path, so those still abstain (the command/destination rules cover
#: them) unless their raw arguments happen to carry a path-shaped key too.
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


def _active_elevations(ctx: EvalContext) -> tuple[ElevationGrant, ...]:
    """Read the already-active elevation grants the proxy loaded into context.

    The proxy queries the storage layer (which filters expired/revoked/spent
    grants) and hands the survivors in via ``ctx.metadata['elevations']`` — so
    the rule never touches the database and time/expiry are decided upstream.
    """
    if not isinstance(ctx.metadata, dict):
        return ()
    raw = ctx.metadata.get("elevations")
    if not isinstance(raw, (list, tuple)):
        return ()
    return tuple(g for g in raw if isinstance(g, ElevationGrant))


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

        if action.action_type in _PATH_ACTION_TYPES:
            paths = _candidate_paths(action)
        else:
            # A tool whose declared type isn't path-shaped can still carry a
            # path-shaped raw argument (an unrecognized tool name, {"path":
            # ...}) — the tool NAME is caller-supplied and not a trust
            # boundary, so classify those candidates too rather than
            # abstaining. Only the unambiguous keys ("path"/"file"/
            # "filename") count here: a shell or network tool's "target"
            # is a command line / host, not a path, so it still abstains.
            raw_arguments = (
                ctx.metadata.get("raw_arguments") if isinstance(ctx.metadata, dict) else None
            )
            paths = (
                raw_path_candidates(raw_arguments, RAW_PATH_KEYS_STRICT)
                if isinstance(raw_arguments, dict)
                else []
            )
        if not paths:
            return GuardrailResult(verdict=Verdict.PASS, risk=Risk.low)

        root = _DEFAULT_ROOT
        if isinstance(ctx.metadata, dict):
            root = str(ctx.metadata.get("repo_root") or _DEFAULT_ROOT)
        grants = _active_elevations(ctx)

        worst = RoleBoundary.allowed
        for raw_path in paths:
            boundary = classify(role, raw_path, root=root)
            # A narrow, temporary elevation can satisfy a suspicious (out-of-
            # scope) target for exactly that path — but never a blocked one.
            if (
                boundary is RoleBoundary.suspicious
                and grants
                and find_cover(raw_path, grants, root=root) is not None
            ):
                boundary = RoleBoundary.allowed
            if _SEVERITY[boundary] > _SEVERITY[worst]:
                worst = boundary
            if worst is RoleBoundary.blocked:
                break

        escalate_oos = thresholds_for(getattr(ctx, "mode", "balanced")).escalate_out_of_scope
        return self._verdict_for(worst, role.name, escalate_out_of_scope=escalate_oos)

    @staticmethod
    def _verdict_for(
        boundary: RoleBoundary, role_name: str, *, escalate_out_of_scope: bool = True
    ) -> GuardrailResult:
        if boundary is RoleBoundary.blocked:
            # A blocked target is a hard floor — never mode-gated.
            return GuardrailResult(
                verdict=Verdict.BLOCK,
                risk=Risk.high,
                reason_codes=[ReasonCode.role_blocked_target],
                explanation=(
                    f"Target is forbidden for the active '{role_name}' role; blocked by role policy."
                ),
            )
        if boundary is RoleBoundary.suspicious and escalate_out_of_scope:
            # An out-of-scope (but not blocked) target only steps up when the
            # mode escalates it — Light relaxes this to abstain; Balanced and
            # stricter still AUTH. A blocked target is unaffected (above).
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
