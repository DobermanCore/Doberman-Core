"""Row ``raise-only-drift`` -- "Policy weakening requires the human-approved
path" -- proven per host.

An agent under any of these four hosts cannot change Doberman's effective
policy without the human-approved CLI path (``doberman policy-file
--accept``): a write to ``.doberman/`` policy state is refused outright by
the control-plane path rule (BLOCK/deny, every front door), and a weakening
edit to the repo-root ``doberman.policy.yaml`` -- while the hook itself lets
the write through, since the file is neither control-plane nor a blocked
glob -- is clamped at load by ``load_file_policy``'s pin union: the dropped
glob stays enforced until a human accepts the change. Both halves are
deterministic, unconditional checks (a path match, a set comparison); no 2FA
challenge is ever reached, so none is needed to prove either one.

The mcp-proxy cell for this row lives in
``tests/integration/test_proxy_raise_only_drift.py`` (a real proxy round
trip); the CLI gate mechanism itself (the 2FA/diff confirmation on
``doberman.policy.drift.apply_change``) is proven host-independently by
``tests/integration/test_drift_gate.py``.
"""

from pathlib import Path

import pytest
import yaml

from doberman.hosthooks import claude_code, codex, cursor, openclaw
from doberman.policy.sources import effective_policy, load_file_policy

_DOBERMAN_WRITE_TARGET = ".doberman/policies.yaml"
_ROOT_POLICY_FILE = "doberman.policy.yaml"


def _init_repo(repo_root: Path) -> None:
    (repo_root / ".doberman").mkdir(parents=True, exist_ok=True)
    (repo_root / ".doberman" / "policies.yaml").write_text("mode: strict\n", encoding="utf-8")


def _weakened_text(blocked: list[str]) -> str:
    return yaml.safe_dump({"version": 1, "blocked": blocked}, sort_keys=False)


def _adopt(repo_root: Path) -> None:
    """Adopt+pin {a/**, b/**} via the real load path."""
    (repo_root / _ROOT_POLICY_FILE).write_text(_weakened_text(["a/**", "b/**"]), encoding="utf-8")
    load_file_policy(str(repo_root))


def _perform_write(repo_root: Path, text: str) -> None:
    """The disk write a host's own downstream tool would perform once allowed."""
    (repo_root / _ROOT_POLICY_FILE).write_text(text, encoding="utf-8")


def _assert_no_leak(reason: str) -> None:
    assert "BLOCK" in reason
    assert _DOBERMAN_WRITE_TARGET not in reason


def _assert_pin_retained(repo_root: Path) -> None:
    assert "b/**" in effective_policy(str(repo_root)).blocked_globs


def _write_payload(target: str, tmp_path: Path, content: str = "x") -> dict:
    return {
        "tool_name": "Write",
        "tool_input": {"file_path": target, "content": content},
        "cwd": str(tmp_path),
    }


@pytest.mark.guarantee("raise-only-drift", host="claude-code")
def test_claude_code_cannot_drift_policy(tmp_path):
    _init_repo(tmp_path)
    out = claude_code.evaluate_pre(_write_payload(_DOBERMAN_WRITE_TARGET, tmp_path))
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    _assert_no_leak(out["hookSpecificOutput"]["permissionDecisionReason"])

    _adopt(tmp_path)
    weakened = _weakened_text(["a/**"])
    out2 = claude_code.evaluate_pre(_write_payload(_ROOT_POLICY_FILE, tmp_path, weakened))
    assert out2 is None
    _perform_write(tmp_path, weakened)
    _assert_pin_retained(tmp_path)


@pytest.mark.guarantee("raise-only-drift", host="codex")
def test_codex_cannot_drift_policy(tmp_path):
    _init_repo(tmp_path)
    out = codex.evaluate_pre(_write_payload(_DOBERMAN_WRITE_TARGET, tmp_path))
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    _assert_no_leak(out["hookSpecificOutput"]["permissionDecisionReason"])

    _adopt(tmp_path)
    weakened = _weakened_text(["a/**"])
    out2 = codex.evaluate_pre(_write_payload(_ROOT_POLICY_FILE, tmp_path, weakened))
    assert out2 is None
    _perform_write(tmp_path, weakened)
    _assert_pin_retained(tmp_path)


def _cursor_payload(target: str, tmp_path: Path, content: str = "x") -> dict:
    return {
        "hook_event_name": "preToolUse",
        "tool_name": "Write",
        "tool_input": {"file_path": target, "content": content},
        "workspace_roots": [str(tmp_path)],
        "cwd": str(tmp_path),
    }


@pytest.mark.guarantee("raise-only-drift", host="cursor")
def test_cursor_cannot_drift_policy(tmp_path):
    _init_repo(tmp_path)
    doc = cursor.evaluate(_cursor_payload(_DOBERMAN_WRITE_TARGET, tmp_path))
    assert doc["permission"] == "deny"
    _assert_no_leak(doc["user_message"])

    _adopt(tmp_path)
    weakened = _weakened_text(["a/**"])
    doc2 = cursor.evaluate(_cursor_payload(_ROOT_POLICY_FILE, tmp_path, weakened))
    assert doc2["permission"] == "allow"
    _perform_write(tmp_path, weakened)
    _assert_pin_retained(tmp_path)


def _openclaw_payload(target: str, tmp_path: Path) -> dict:
    return {
        "tool_name": "apply_patch",
        "params": {"patch": "diff"},
        "derived_paths": [target],
        "cwd": str(tmp_path),
    }


@pytest.mark.guarantee("raise-only-drift", host="openclaw")
def test_openclaw_cannot_drift_policy(tmp_path):
    _init_repo(tmp_path)
    out = openclaw.evaluate_before_tool_call(_openclaw_payload(_DOBERMAN_WRITE_TARGET, tmp_path))
    assert out["verdict"] == "block"
    _assert_no_leak(out["reason"])

    _adopt(tmp_path)
    weakened = _weakened_text(["a/**"])
    out2 = openclaw.evaluate_before_tool_call(_openclaw_payload(_ROOT_POLICY_FILE, tmp_path))
    assert out2["verdict"] == "allow"
    _perform_write(tmp_path, weakened)
    _assert_pin_retained(tmp_path)
