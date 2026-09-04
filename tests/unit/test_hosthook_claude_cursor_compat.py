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
from typer.testing import CliRunner

from doberman.hosthooks import claude_code, cursor, singleflight

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


def _before_shell(pre_payload: dict, command: str) -> dict:
    """A native ``beforeShellExecution`` payload pairing with *pre_payload*'s
    ``preToolUse``/``Shell`` call: same conversation/generation id and command,
    so it shares the same dedupe key. Mirrors the doc-derived
    ``tests/fixtures/cursor/before_shell.json`` shape."""
    return {
        "hook_event_name": cursor.EVENT_SHELL,
        "conversation_id": pre_payload["conversation_id"],
        "generation_id": pre_payload["generation_id"],
        "command": command,
        "cwd": pre_payload.get("cwd") or pre_payload["workspace_roots"][0],
        "workspace_roots": pre_payload["workspace_roots"],
        "cursor_version": pre_payload.get("cursor_version", "2026.09.02-c22c1a3"),
    }


def test_compat_pre_before_shares_one_flight(tmp_path, monkeypatch):
    # Both hook sources installed: a Shell call reaches respond() THREE times —
    # compat preToolUse, native preToolUse, native beforeShellExecution (the
    # closing event of the pair). Still exactly one evaluation.
    calls = _count_evaluations(monkeypatch)
    pre = _load("pre_tool_use_shell.json", tmp_path)
    pre["tool_input"]["command"] = "rm -rf /"
    before = _before_shell(pre, "rm -rf /")

    compat_out = claude_code.run_pre_hook(json.dumps(pre))
    native_pre_text, native_pre_code = cursor.run_cursor(json.dumps(pre))
    native_before_text, native_before_code = cursor.run_cursor(json.dumps(before))

    assert calls["n"] == 1
    assert json.loads(compat_out)["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert json.loads(native_pre_text)["permission"] == "deny" and native_pre_code == 2
    assert json.loads(native_before_text)["permission"] == "deny" and native_before_code == 2
    key = cursor.dedupe_key(cursor.EVENT_SHELL, before)
    assert singleflight.replay(key) is None  # consumed by the closing event


def test_pre_compat_before_shares_one_flight(tmp_path, monkeypatch):
    calls = _count_evaluations(monkeypatch)
    pre = _load("pre_tool_use_shell.json", tmp_path)
    pre["tool_input"]["command"] = "rm -rf /"
    before = _before_shell(pre, "rm -rf /")

    native_pre_text, native_pre_code = cursor.run_cursor(json.dumps(pre))
    compat_out = claude_code.run_pre_hook(json.dumps(pre))
    native_before_text, native_before_code = cursor.run_cursor(json.dumps(before))

    assert calls["n"] == 1
    assert json.loads(native_pre_text)["permission"] == "deny" and native_pre_code == 2
    assert json.loads(compat_out)["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert json.loads(native_before_text)["permission"] == "deny" and native_before_code == 2
    key = cursor.dedupe_key(cursor.EVENT_SHELL, before)
    assert singleflight.replay(key) is None  # consumed by the closing event


def test_marker_survives_compat_then_native_pre_until_the_closing_event(tmp_path):
    # A replay by preToolUse (either channel) must NOT consume the marker —
    # only the closing native beforeShellExecution/beforeMCPExecution/
    # beforeReadFile does, so the marker is still there for whichever of those
    # arrives last.
    pre = _load("pre_tool_use_shell.json", tmp_path)
    pre["tool_input"]["command"] = "git status"
    before = _before_shell(pre, "git status")
    key = cursor.dedupe_key(cursor.EVENT_PRE_TOOL, pre)

    claude_code.run_pre_hook(json.dumps(pre))  # records (compat channel)
    cursor.run_cursor(json.dumps(pre))  # replays (native preToolUse) — must not consume
    assert singleflight.replay(key) is not None  # still there

    cursor.run_cursor(json.dumps(before))  # the closing event — replays AND consumes
    assert singleflight.replay(key) is None


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


# --- BOM-prefixed stdin: `hook pre`/`hook post` read bytes, not text -------
#
# `cursor-agent` prefixes every hook payload with a UTF-8 BOM. `sys.stdin.read()`
# (console text mode) plus a plain `json.loads` breaks on that BOM before
# `is_cursor_payload` ever runs, so the CLI failed closed on every real Cursor
# call even though the delegation above (fed already-decoded text) worked.
# These exercise the real fixture BYTES (BOM included) through the actual
# `hook pre` command, not the adapter function directly.


def test_real_shell_fixture_bytes_through_cli_are_not_denied_closed():
    from doberman.cli.main import app

    raw = (FIXTURES / "pre_tool_use_shell.json").read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf")  # the BOM cursor-agent actually sends
    result = CliRunner().invoke(app, ["hook", "pre"], input=raw)
    assert result.exit_code == 0
    # "echo hello-doberman" is benign -> abstain (nothing printed), not a deny.
    assert result.stdout.strip() == ""


def test_real_read_fixture_bytes_through_cli_denies_the_protected_path():
    from doberman.cli.main import app

    raw = (FIXTURES / "pre_tool_use_read.json").read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf")
    result = CliRunner().invoke(app, ["hook", "pre"], input=raw)
    assert result.exit_code == 0
    out = json.loads(result.stdout.strip())
    reason = out["hookSpecificOutput"]["permissionDecisionReason"]
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "protected_path_blocked" in reason
    # Not the unparseable-input failsafe -> the payload really was evaluated.
    assert "failing closed" not in reason


def test_bom_prefixed_claude_payload_behaves_like_the_same_payload_without_it(tmp_path):
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "rm -rf /"},
        "cwd": str(tmp_path),
    }
    plain = claude_code.run_pre_hook(json.dumps(payload))
    with_str_bom = claude_code.run_pre_hook("﻿" + json.dumps(payload))
    with_bytes_bom = claude_code.run_pre_hook(b"\xef\xbb\xbf" + json.dumps(payload).encode("utf-8"))
    assert plain is not None
    # Each call mints a fresh action id inside the reason text, so compare the
    # decision + reason code rather than the literal string.
    plain_hso = json.loads(plain)["hookSpecificOutput"]
    for other in (with_str_bom, with_bytes_bom):
        hso = json.loads(other)["hookSpecificOutput"]
        assert hso["permissionDecision"] == plain_hso["permissionDecision"] == "deny"
        assert "destructive_command" in hso["permissionDecisionReason"]
        assert "destructive_command" in plain_hso["permissionDecisionReason"]


# --- integrity-warning cwd: the Cursor workspace root, not the empty payload
# --- cwd (Correction 4, MEDIUM) --------------------------------------------


def test_integrity_warning_uses_the_cursor_workspace_root(tmp_path, monkeypatch):
    # A genuine Cursor payload has no top-level `cwd` -- `_attach_integrity_warning`
    # must not silently fall back to the process cwd; it must see the real
    # `workspace_roots[0]`. Warning-only: must never change the verdict itself.
    payload = _load("pre_tool_use_shell.json", tmp_path)
    payload["tool_input"]["command"] = "rm -rf /"
    payload["cwd"] = ""  # genuine Cursor shape: empty, not the process/tmp cwd

    seen_cwd = {}
    real_attach = claude_code._attach_integrity_warning

    def spy(out, warn_payload):
        seen_cwd["cwd"] = warn_payload.get("cwd")
        return real_attach(out, warn_payload)

    monkeypatch.setattr(claude_code, "_attach_integrity_warning", spy)
    out = json.loads(claude_code.run_pre_hook(json.dumps(payload)))

    assert seen_cwd["cwd"] == str(tmp_path)  # cursor.repo_root_of(payload), not ""
    # The warning is systemMessage-only -- the deny verdict is untouched.
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "systemMessage" not in out  # tmp_path isn't a registered Doberman project
