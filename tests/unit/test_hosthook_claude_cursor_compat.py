"""Claude-compat routing for Cursor-shaped payloads (Cursor slice 3).

Cursor's "Third Party Hooks" setting loads Claude Code hooks from the Claude
settings files and invokes them with Cursor's OWN payload shape (empty/absent
``cwd``, ``tool_name: "Shell"``), not Claude Code's. Without this routing,
``doberman hook pre`` fails closed on every Cursor call even when the native
``doberman hook cursor`` hook would allow it. Covers ``is_cursor_payload``,
``claude_code.run_pre_hook``'s delegation to ``cursor.respond``, the shared
single-flight between the native and Claude-compat channels (either order),
the unpaired-tool (``tool_use_id``-only) dedupe fallback, the hot-path import
guarantee, and ``run_post_hook`` on a Cursor-origin ``postToolUse`` payload.

Fixture-driven against REAL captured Cursor payloads
(``tests/fixtures/cursor_payloads/`` — ``cursor-agent`` 2026.09.02 on Windows;
``user_email`` scrubbed, everything else verbatim, BOM preserved).
"""

import json
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

from doberman.hosthooks import claude_code, cursor

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "cursor_payloads"


class _NoChannel:
    """A prompter that cannot present a challenge -> every AUTH must deny."""

    def confirm(self, *a, **k):
        raise RuntimeError("no channel")

    def read_code(self, *a, **k):
        raise RuntimeError("no channel")


@pytest.fixture(autouse=True)
def _no_gui(monkeypatch):
    # Never let a test fall through to the default GUI->TTY prompter.
    monkeypatch.setattr(cursor, "AUTH_PROMPTER", _NoChannel())


def _load(name: str, tmp_path) -> dict:
    """A real captured payload, reshaped for one test: a tmp workspace root/cwd
    and fresh conversation/generation ids (a leftover single-flight marker from
    a previous run must never pre-satisfy a replay)."""
    raw = (FIXTURES / name).read_bytes()
    payload = json.loads(raw.decode("utf-8-sig"))
    payload["workspace_roots"] = [str(tmp_path)]
    if "cwd" in payload:
        payload["cwd"] = str(tmp_path)
    payload["conversation_id"] = "conv-" + uuid.uuid4().hex
    payload["generation_id"] = "gen-" + uuid.uuid4().hex
    return payload


# --- is_cursor_payload -----------------------------------------------------


@pytest.mark.parametrize(
    "name", ["pre_tool_use_shell.json", "pre_tool_use_read.json", "session_start.json"]
)
def test_real_captures_are_recognised(name, tmp_path):
    assert claude_code.is_cursor_payload(_load(name, tmp_path)) is True


def test_normal_claude_payload_is_not_a_cursor_payload():
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "ls"},
        "cwd": "/repo",
    }
    assert claude_code.is_cursor_payload(payload) is False


def test_cwd_set_and_no_workspace_roots_is_not_a_cursor_payload():
    payload = {"tool_name": "Bash", "tool_input": {"command": "ls"}, "cwd": "/repo"}
    assert claude_code.is_cursor_payload(payload) is False


# --- run_pre_hook delegation -------------------------------------------------


def test_real_shell_fixture_git_status_abstains(tmp_path):
    payload = _load("pre_tool_use_shell.json", tmp_path)
    payload["tool_input"]["command"] = "git status"
    assert claude_code.run_pre_hook(json.dumps(payload)) is None


def test_real_shell_fixture_destructive_command_is_denied(tmp_path):
    payload = _load("pre_tool_use_shell.json", tmp_path)
    payload["tool_input"]["command"] = "rm -rf /"
    out = json.loads(claude_code.run_pre_hook(json.dumps(payload)))
    hso = out["hookSpecificOutput"]
    assert hso["permissionDecision"] == "deny"
    assert "destructive_command" in hso["permissionDecisionReason"]


# --- single-flight shared with the native channel, either order ------------


def _count_evaluations(monkeypatch) -> dict:
    calls = {"n": 0}
    real = cursor.evaluate

    def counting(payload):
        calls["n"] += 1
        return real(payload)

    monkeypatch.setattr(cursor, "evaluate", counting)
    return calls


def test_native_then_compat_shares_one_flight(tmp_path, monkeypatch):
    calls = _count_evaluations(monkeypatch)
    payload = _load("pre_tool_use_shell.json", tmp_path)
    payload["tool_input"]["command"] = "rm -rf /"

    native_text, native_code = cursor.run_cursor(json.dumps(payload))
    compat_out = claude_code.run_pre_hook(json.dumps(payload))

    assert calls["n"] == 1
    assert json.loads(native_text)["permission"] == "deny" and native_code == 2
    hso = json.loads(compat_out)["hookSpecificOutput"]
    assert hso["permissionDecision"] == "deny"


def test_compat_then_native_shares_one_flight(tmp_path, monkeypatch):
    calls = _count_evaluations(monkeypatch)
    payload = _load("pre_tool_use_shell.json", tmp_path)
    payload["tool_input"]["command"] = "rm -rf /"

    compat_out = claude_code.run_pre_hook(json.dumps(payload))
    native_text, native_code = cursor.run_cursor(json.dumps(payload))

    assert calls["n"] == 1
    hso = json.loads(compat_out)["hookSpecificOutput"]
    assert hso["permissionDecision"] == "deny"
    assert json.loads(native_text)["permission"] == "deny" and native_code == 2


# --- unpaired-tool dedupe (tool_use_id fallback) ----------------------------


def _write_payload(tmp_path) -> dict:
    return {
        "hook_event_name": "preToolUse",
        "tool_name": "Write",
        "tool_input": {"file_path": str(tmp_path / "notes.txt"), "content": "x"},
        "cwd": str(tmp_path),
        "workspace_roots": [str(tmp_path)],
        "cursor_version": "2026.09.02-c22c1a3",
        "tool_use_id": "tu-" + uuid.uuid4().hex,
    }


def test_unpaired_write_dedupes_on_tool_use_id(tmp_path, monkeypatch):
    calls = _count_evaluations(monkeypatch)
    payload = _write_payload(tmp_path)

    native_text, native_code = cursor.run_cursor(json.dumps(payload))
    compat_out = claude_code.run_pre_hook(json.dumps(payload))

    assert calls["n"] == 1
    assert json.loads(native_text) == {"permission": "allow"} and native_code == 0
    assert compat_out is None  # raise-only: an allow abstains, never suppresses Cursor's prompt


def test_no_tool_use_id_means_no_unpaired_dedupe(tmp_path, monkeypatch):
    calls = _count_evaluations(monkeypatch)
    payload = _write_payload(tmp_path)
    del payload["tool_use_id"]

    cursor.run_cursor(json.dumps(payload))
    claude_code.run_pre_hook(json.dumps(payload))

    assert calls["n"] == 2  # no id to key a marker on -> each channel evaluates independently


# --- hot path: the Claude path must never import the Cursor adapter --------


def test_claude_payload_does_not_import_cursor_module():
    code = (
        "import sys, json;"
        "from doberman.hosthooks.claude_code import run_pre_hook;"
        "run_pre_hook(json.dumps({'tool_name':'Bash','tool_input':{'command':'ls'},'cwd':'.'}));"
        "print('doberman.hosthooks.cursor' in sys.modules)"
    )
    result = subprocess.run(  # noqa: S603 — controlled call: our own interpreter + a fixed string
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "False"


# --- run_post_hook on a Cursor-origin postToolUse payload -------------------


def test_post_hook_cursor_shell_abstains(tmp_path):
    payload = _load("pre_tool_use_shell.json", tmp_path)
    payload["hook_event_name"] = "postToolUse"
    assert claude_code.run_post_hook(json.dumps(payload)) is None


def test_post_hook_cursor_read_abstains(tmp_path):
    payload = _load("pre_tool_use_read.json", tmp_path)
    payload["hook_event_name"] = "postToolUse"
    assert claude_code.run_post_hook(json.dumps(payload)) is None
