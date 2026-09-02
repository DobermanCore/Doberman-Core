"""Slice 4.3 — role escalation in the objective layer.

Covers: out-of-scope path → AUTH; role-blocked path → BLOCK; user intent never
lowers a role escalation; no active role → abstain; non-path action → abstain;
the most-restrictive fallback escalates everything; and the role rule combines
into the objective guardrail (so role authority sits in the objective layer and
cannot be learned away).
"""

from datetime import datetime, timezone

import pytest

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


def _action(
    target,
    action_type=ActionType.file_write,
    source=SourceContext.unknown,
    metadata=None,
):
    return SecurityObject(
        id="ra-1",
        ts=datetime(2026, 6, 8, tzinfo=timezone.utc),
        agent_role="frontend",
        action_type=action_type,
        tool_name="fs_write",
        target=target,
        source_context=source,
        metadata=metadata or {},
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


@pytest.mark.parametrize(
    "raw_paths",
    [
        ["app/public.txt", "app/secret/key.txt"],
        ["app/secret/key.txt", "app/public.txt"],
    ],
    ids=["blocked-last", "blocked-first"],
)
def test_batch_paths_use_worst_role_boundary_regardless_of_order(tmp_path, raw_paths):
    role = RoleDefinition(name="scoped", allowed=["app/**"], blocked=["app/secret/**"])
    action = _action(
        "app/public.txt",
        action_type=ActionType.file_delete,
        metadata={"raw_paths": raw_paths},
    )

    result = RULE.evaluate(action, _ctx(role, tmp_path))

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


# --- Payload-shape classification: the tool NAME is not a trust boundary ----
# A tool that doesn't normalize to a path action type (e.g. an unrecognized
# name) but whose raw arguments still carry a path-shaped value must be
# classified exactly like write_file — the tool NAME is caller-supplied, not
# a trust boundary (#519/#527, the same regression class as
# DestructiveCommandRule's payload-shape fix).


def test_unrecognized_tool_with_path_argument_matches_write_file_verdict(tmp_path):
    write_result = RULE.evaluate(_action("backend/db.py"), _ctx(FRONTEND, tmp_path))

    other_action = _action("backend/db.py", action_type=ActionType.other)
    other_ctx = EvalContext(
        role=FRONTEND,
        mode="balanced",
        metadata={"repo_root": str(tmp_path), "raw_arguments": {"path": "backend/db.py"}},
    )
    other_result = RULE.evaluate(other_action, other_ctx)

    assert write_result.verdict is other_result.verdict is Verdict.AUTH
    assert ReasonCode.role_out_of_scope in write_result.reason_codes
    assert ReasonCode.role_out_of_scope in other_result.reason_codes


def test_shell_command_argument_still_abstains_on_role_boundary(tmp_path):
    # A shell command's raw argument is a command line, not a path-shaped key
    # ("path"/"file"/"filename"/"target") — no path candidate exists, so the
    # rule still abstains (the command/destination rules cover this target).
    action = _action("ls", action_type=ActionType.shell_exec)
    ctx = EvalContext(
        role=FRONTEND,
        mode="balanced",
        metadata={"repo_root": str(tmp_path), "raw_arguments": {"command": "ls"}},
    )
    assert RULE.evaluate(action, ctx).verdict is Verdict.PASS
