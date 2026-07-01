"""HK.5.0b: shell commands that target Doberman's control plane are blocked.

A path-*target* rule misses a control-plane path hidden inside a Bash command
string (`echo > .claude/settings.json`, `rm -rf .doberman`,
`doberman uninstall-hooks`). The command rule scans each segment's argv tokens
(operands + redirect targets) via `names_control_plane`, and the Doberman
hook-install CLI, and BLOCKs them with `protected_path_blocked`.
"""

from datetime import datetime, timezone

from doberman.engine.objective import ObjectiveGuardrail
from doberman.engine.rules.commands import DestructiveCommandRule
from doberman.models import ActionType, EvalContext, ReasonCode, SecurityObject, Verdict

RULE = DestructiveCommandRule()


def _cmd(command, *, root="."):
    action = SecurityObject(
        id="cp-cmd-1",
        ts=datetime(2026, 6, 26, tzinfo=timezone.utc),
        agent_role="unknown",
        action_type=ActionType.shell_exec,
        tool_name="Bash",
        target=command,
        metadata={},
    )
    ctx = EvalContext(metadata={"raw_arguments": {"command": command}, "repo_root": root})
    return RULE.evaluate(action, ctx)


# --- writes/deletes of the control plane via shell → BLOCK ---


def test_redirect_into_claude_settings_is_blocked():
    result = _cmd("echo '{}' > .claude/settings.json")
    assert result.verdict is Verdict.BLOCK
    assert ReasonCode.protected_path_blocked in result.reason_codes


def test_append_into_claude_settings_is_blocked():
    assert _cmd("echo x >> .claude/settings.json").verdict is Verdict.BLOCK


def test_sed_in_place_on_claude_settings_is_blocked():
    assert _cmd("sed -i s/a/b/ .claude/settings.json").verdict is Verdict.BLOCK


def test_rm_rf_doberman_is_blocked():
    result = _cmd("rm -rf .doberman")
    assert result.verdict is Verdict.BLOCK
    assert ReasonCode.protected_path_blocked in result.reason_codes


def test_cat_doberman_policy_is_blocked():
    # Reading the control plane via shell is blocked too — mirrors the path rule,
    # which blocks .doberman reads (planning evasion off the policy/baseline).
    assert _cmd("cat .doberman/policies.yaml").verdict is Verdict.BLOCK


def test_mv_over_claude_settings_is_blocked():
    assert _cmd("mv evil.json .claude/settings.json").verdict is Verdict.BLOCK


def test_flag_attached_control_plane_path_is_blocked():
    # --flag=path form: the path is the value after '='.
    result = _cmd("git config --file=.claude/settings.json user.name x")
    assert result.verdict is Verdict.BLOCK


def test_chained_command_is_blocked():
    assert _cmd("cd src && echo x > .claude/settings.json").verdict is Verdict.BLOCK


def test_substitution_body_is_scanned():
    assert _cmd("echo $(rm -rf .doberman)").verdict is Verdict.BLOCK


def test_nested_bash_c_payload_is_blocked():
    assert _cmd('bash -c "rm -rf .doberman"').verdict is Verdict.BLOCK


def test_traversal_into_control_plane_is_blocked():
    assert _cmd("rm a/../.doberman/policies.yaml").verdict is Verdict.BLOCK


# --- the Doberman hook-install CLI invoked via shell → BLOCK ---


def test_doberman_uninstall_hooks_is_blocked():
    result = _cmd("doberman uninstall-hooks")
    assert result.verdict is Verdict.BLOCK
    assert ReasonCode.protected_path_blocked in result.reason_codes


def test_doberman_install_hooks_is_blocked():
    assert _cmd("doberman install-hooks --global").verdict is Verdict.BLOCK


def test_doberman_setup_is_blocked():
    assert _cmd("doberman setup --yes").verdict is Verdict.BLOCK


# --- redaction + no over-block ---


def test_explanation_does_not_echo_the_command_or_path():
    result = _cmd("echo supersecret > .claude/settings.json")
    explanation = result.explanation or ""
    assert ".claude/settings.json" not in explanation
    assert "supersecret" not in explanation


def test_control_plane_block_explains_the_recovery_path():
    # A legitimate user who wants to change/uninstall the hooks needs to know the
    # recovery path is out-of-band (a plain terminal) — the agent itself is blocked
    # from doing it (anti-tamper). The block message must point there so the user
    # isn't dead-ended.
    explanation = (_cmd("doberman uninstall-hooks").explanation or "").lower()
    assert "uninstall-hooks" in explanation
    assert "terminal" in explanation


def test_recovery_hint_does_not_echo_a_user_control_plane_path():
    # The appended hint must not leak the user's targeted path (redaction holds).
    explanation = _cmd("echo x > .claude/settings.json").explanation or ""
    assert ".claude/settings.json" not in explanation


def test_benign_command_passes():
    assert _cmd("echo hello world").verdict is Verdict.PASS


def test_similar_but_different_paths_pass():
    # `mydoberman` / `claude.md` must not trip the `.doberman` / `.claude` globs.
    assert _cmd("cat src/mydoberman_notes.md").verdict is Verdict.PASS
    assert _cmd("cat docs/claude.md").verdict is Verdict.PASS


def test_ordinary_git_commit_passes():
    assert _cmd('git commit -m "update project config"').verdict is Verdict.PASS


def test_objective_guardrail_blocks_a_control_plane_command():
    action = SecurityObject(
        id="cp-cmd-2",
        ts=datetime(2026, 6, 26, tzinfo=timezone.utc),
        agent_role="unknown",
        action_type=ActionType.shell_exec,
        tool_name="Bash",
        target="rm -rf .doberman",
        metadata={},
    )
    ctx = EvalContext(metadata={"raw_arguments": {"command": "rm -rf .doberman"}, "repo_root": "."})
    result = ObjectiveGuardrail(load_plugins=False).evaluate(action, ctx)
    assert result.verdict is Verdict.BLOCK
    assert ReasonCode.protected_path_blocked in result.reason_codes
