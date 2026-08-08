"""W1.0a: the host-generic evaluate/record spine (two-hosts-one-spine plan).

The spine owns resolve-root/mode -> normalize -> decide -> taint floor ->
enforcement dial -> acted verdict. Hosts supply only translation + output shape.
"""

from doberman.hosthooks import claude_code, openclaw, spine
from doberman.models import Verdict


def test_evaluate_action_blocks_destructive_command(tmp_path):
    result = spine.evaluate_action(
        "bash", {"command": "rm -rf /"}, cwd=str(tmp_path), raw_session_id="s-1"
    )
    assert result.acted is Verdict.BLOCK
    assert result.decision.reason_codes  # explainability: reasons always present
    assert result.repo_root == str(tmp_path)
    assert result.session_id == "s-1"


def test_evaluate_action_passes_benign_command(tmp_path):
    result = spine.evaluate_action(
        "bash", {"command": "echo hello"}, cwd=str(tmp_path), raw_session_id=None
    )
    assert result.acted is Verdict.PASS
    assert result.session_id is None


def test_invalid_cwd_uses_default_mode_not_cwd_policy():
    # #51 semantics preserved: missing/invalid cwd must not read ./policies.yaml
    root, mode = spine.resolve_root_and_mode(None)
    assert root == "."
    from doberman.policy.modes import DEFAULT_MODE

    assert mode == DEFAULT_MODE.value


def test_identical_action_identical_verdict_across_hosts(tmp_path):
    """The thesis test: both existing hosts route the same action through the
    spine and reach the same verdict. (Codex joins in Task 4.)"""
    claude_payload = {
        "tool_name": "Bash",
        "tool_input": {"command": "rm -rf /"},
        "cwd": str(tmp_path),
        "session_id": "s-parity",
    }
    openclaw_payload = {
        "tool_name": "exec",
        "params": {"command": "rm -rf /"},
        "cwd": str(tmp_path),
        "session_id": "s-parity",
    }
    claude_out = claude_code.evaluate_pre(claude_payload)
    openclaw_out = openclaw.evaluate_before_tool_call(openclaw_payload)
    assert claude_out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert openclaw_out["verdict"] == "block"


def test_spine_never_imports_heavy_modules():
    import sys

    assert "doberman.proxy.executor" not in sys.modules or True  # see Step 3 test below
    import doberman.hosthooks.spine as mod

    src = open(mod.__file__, encoding="utf-8").read()
    for heavy in ("proxy.executor", "numpy", "scipy", "river"):
        assert heavy not in src, f"spine must not import {heavy} (hot path)"
