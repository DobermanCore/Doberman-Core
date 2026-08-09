"""HK.5.0: the host-hook PreToolUse path blocks an agent editing its own hooks.

A ``Write``/``Edit`` to ``.claude/settings.json`` is exactly how an agent would
remove the Doberman hooks and disable enforcement at the harness level ("fire the
cop"). The control-plane path rule (extended in HK.5.0, ADR 0024) makes that a
BLOCK, and the hook turns a BLOCK into a Claude Code ``permissionDecision: "deny"``.
"""

import pytest

from doberman.hosthooks.claude_code import evaluate_pre


def _pre(tool_name, tool_input, cwd):
    return evaluate_pre({"tool_name": tool_name, "tool_input": tool_input, "cwd": str(cwd)})


@pytest.mark.guarantee("control-plane-self-protection", host="claude-code")
def test_pre_hook_denies_writing_claude_settings(tmp_path):
    out = _pre("Write", {"file_path": ".claude/settings.json", "content": "{}"}, tmp_path)
    assert out is not None
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_pre_hook_denies_editing_claude_settings(tmp_path):
    out = _pre("Edit", {"file_path": ".claude/settings.json"}, tmp_path)
    assert out is not None
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_pre_hook_deny_reason_does_not_leak_the_raw_path(tmp_path):
    out = _pre("Write", {"file_path": ".claude/settings.json", "content": "{}"}, tmp_path)
    reason = out["hookSpecificOutput"]["permissionDecisionReason"]
    assert ".claude/settings.json" not in reason


def test_pre_hook_allows_an_ordinary_write(tmp_path):
    # No over-block: an ordinary source write abstains (PASS -> None, raise-only).
    out = _pre("Write", {"file_path": "src/app/main.py", "content": "print(1)\n"}, tmp_path)
    assert out is None


# --- HK.5.0b: Bash commands that tamper with the control plane are denied too ---


def test_pre_hook_denies_bash_rm_of_doberman(tmp_path):
    out = _pre("Bash", {"command": "rm -rf .doberman"}, tmp_path)
    assert out is not None
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_pre_hook_denies_bash_write_to_claude_settings(tmp_path):
    out = _pre("Bash", {"command": "echo '{}' > .claude/settings.json"}, tmp_path)
    assert out is not None
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_pre_hook_denies_doberman_uninstall_hooks(tmp_path):
    out = _pre("Bash", {"command": "doberman uninstall-hooks"}, tmp_path)
    assert out is not None
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_pre_hook_allows_an_ordinary_bash_command(tmp_path):
    # No over-block: a benign shell command abstains (PASS -> None).
    out = _pre("Bash", {"command": "echo hello && ls src"}, tmp_path)
    assert out is None
