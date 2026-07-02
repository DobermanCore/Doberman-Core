"""Slice 4.3 — role escalation in the objective layer.

Covers: out-of-scope path → AUTH; role-blocked path → BLOCK; user intent never
lowers a role escalation; no active role → abstain; non-path action → abstain;
the most-restrictive fallback escalates everything; and the role rule combines
into the objective guardrail (so role authority sits in the objective layer and
cannot be learned away).
"""

from datetime import datetime, timezone

from doberman.engine.objective import ObjectiveGuardrail
from doberman.engine.rules.role_boundary import RoleBoundaryRule
from doberman.models import (
    ActionType,
    EvalContext,
    ReasonCode,
    SecurityObject,
    SourceContext,
    Verdict,
)
from doberman.roles.roles import MOST_RESTRICTIVE_ROLE, RoleDefinition, load_builtin_roles

FRONTEND = load_builtin_roles()["frontend"]
RULE = RoleBoundaryRule()


def _action(target, action_type=ActionType.file_write, source=SourceContext.unknown):
    return SecurityObject(
        id="ra-1",
        ts=datetime(2026, 6, 8, tzinfo=timezone.utc),
        agent_role="frontend",
        action_type=action_type,
        tool_name="fs_write",
        target=target,
        source_context=source,
    )


def _ctx(role, tmp_path, mode="balanced"):
    return EvalContext(role=role, mode=mode, metadata={"repo_root": str(tmp_path)})


def test_out_of_scope_path_requires_auth(tmp_path):
    result = RULE.evaluate(_action("src/utils/helper.ts"), _ctx(FRONTEND, tmp_path))
    assert result.verdict is Verdict.AUTH
    assert ReasonCode.role_out_of_scope in result.reason_codes


def test_out_of_scope_path_passes_in_light_mode(tmp_path):
    # Light relaxes the out-of-scope *step-up* (escalate_out_of_scope=False)...
    result = RULE.evaluate(_action("src/utils/helper.ts"), _ctx(FRONTEND, tmp_path, mode="light"))
    assert result.verdict is Verdict.PASS


def test_role_blocked_path_still_blocks_in_light_mode(tmp_path):
    # ...but a *blocked* role target is a hard floor — Light must not relax it.
    role = RoleDefinition(name="scoped", allowed=["app/**"], blocked=["app/secret/**"])
    result = RULE.evaluate(
        _action("app/secret/key.txt", action_type=ActionType.file_delete),
        _ctx(role, tmp_path, mode="light"),
    )
    assert result.verdict is Verdict.BLOCK
    assert ReasonCode.role_blocked_target in result.reason_codes


def test_in_scope_path_passes(tmp_path):
    result = RULE.evaluate(_action("frontend/Button.tsx"), _ctx(FRONTEND, tmp_path))
    assert result.verdict is Verdict.PASS


def test_role_blocked_path_is_blocked(tmp_path):
    role = RoleDefinition(name="scoped", allowed=["app/**"], blocked=["app/secret/**"])
    result = RULE.evaluate(
        _action("app/secret/key.txt", action_type=ActionType.file_delete), _ctx(role, tmp_path)
    )
    assert result.verdict is Verdict.BLOCK
    assert ReasonCode.role_blocked_target in result.reason_codes


def test_user_intent_does_not_lower_a_role_escalation(tmp_path):
    # A friendly "the user asked for it" source must not soften the escalation —
    # the role rule never consults source_context.
    result = RULE.evaluate(
        _action("backend/auth/session.ts", source=SourceContext.user), _ctx(FRONTEND, tmp_path)
    )
    assert result.verdict is Verdict.AUTH


def test_no_active_role_abstains(tmp_path):
    result = RULE.evaluate(_action("anything/at/all.py"), _ctx(None, tmp_path))
    assert result.verdict is Verdict.PASS


def test_non_path_action_abstains(tmp_path):
    action = _action("rm -rf /", action_type=ActionType.shell_exec)
    assert RULE.evaluate(action, _ctx(FRONTEND, tmp_path)).verdict is Verdict.PASS


def test_missing_role_resolves_restrictive_and_escalates_everything(tmp_path):
    # The most-restrictive fallback (used for an unknown configured role) treats
    # every path as out of scope → AUTH.
    result = RULE.evaluate(_action("frontend/Button.tsx"), _ctx(MOST_RESTRICTIVE_ROLE, tmp_path))
    assert result.verdict is Verdict.AUTH


def test_role_escalation_combines_into_the_objective_guardrail(tmp_path):
    guardrail = ObjectiveGuardrail(load_plugins=False)
    result = guardrail.evaluate(_action("src/utils/helper.ts"), _ctx(FRONTEND, tmp_path))
    assert result.verdict is Verdict.AUTH
    assert ReasonCode.role_out_of_scope in result.reason_codes
