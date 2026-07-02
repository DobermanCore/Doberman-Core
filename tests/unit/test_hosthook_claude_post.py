"""Unit tests for the Claude Code PostToolUse host-hook adapter (Feature HK.2).

Covers output-scanning for secret material (string and dict responses), the
fail-closed behaviour on bad input, the internal-tool abstain rule, the
history-recording guarantee, redaction safety (secret never in block reason),
and the hot-path weight guarantee (river/numpy/scipy must not load).
"""

import asyncio
import json
import subprocess
import sys

import pytest

from doberman.hosthooks.claude_code import evaluate_post, run_post_hook
from doberman.storage.log import read_decisions

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_SYNTHETIC_SECRET = "AKIAIOSFODNN7EXAMPLE"  # noqa: S105 — synthetic test value


@pytest.fixture
def cwd(tmp_path):
    """An isolated repo root so the test never inherits a real ``.doberman`` policy."""
    return str(tmp_path)


def _post(tool, tool_input, tool_response, cwd_path):
    payload = {
        "hook_event_name": "PostToolUse",
        "tool_name": tool,
        "tool_input": tool_input,
        "tool_response": tool_response,
        "cwd": cwd_path,
    }
    return run_post_hook(json.dumps(payload))


# ---------------------------------------------------------------------------
# Benign output — abstain (return None)
# ---------------------------------------------------------------------------


def test_benign_bash_output_abstains(cwd):
    out = _post("Bash", {"command": "echo hi"}, "build succeeded", cwd)
    assert out is None


def test_benign_read_output_abstains(cwd):
    out = _post("Read", {"file_path": "README.md"}, "# Project\nsome docs", cwd)
    assert out is None


def test_benign_grep_output_abstains(cwd):
    out = _post("Grep", {"pattern": "def main"}, "src/main.py:1:def main():", cwd)
    assert out is None


def test_weak_high_entropy_output_passes_through(cwd):
    # Slice B (benign reads): a shapeless high-entropy token is only WEAK evidence
    # (possible_high_entropy_secret) — the heuristic false-positives on hashes /
    # UUIDs / base64 fragments, so the output scan lets the read through instead of
    # nuking it. (A real credential shape still blocks — see below.)
    token = "Xk9mQ2pL7vN4wR8tY3zA6bC1dE5fG0hJwZ7vB3nM"  # noqa: S105 — shapeless, high-entropy
    out = _post("Read", {"file_path": "cache.bin"}, f"cache id: {token}", cwd)
    assert out is None


def test_strong_credential_output_still_blocked(cwd):
    # Recall guard: a known credential shape (sensitive_secret_access) in output is
    # still hard-blocked — the severity split only relaxes the weak tier.
    out = _post("Read", {"file_path": "cfg"}, f"key = {_SYNTHETIC_SECRET}", cwd)
    assert out is not None
    assert json.loads(out)["decision"] == "block"


# ---------------------------------------------------------------------------
# Secret in tool_response (string) → block; secret never in reason
# ---------------------------------------------------------------------------


def test_secret_string_response_is_blocked(cwd):
    secret = _SYNTHETIC_SECRET
    out = _post(
        "Bash", {"command": "cat ~/.aws/credentials"}, f"[default]\naws_access_key_id={secret}", cwd
    )
    assert out is not None
    data = json.loads(out)
    assert data["decision"] == "block"


def test_secret_string_block_is_recorded_in_decision_log(cwd):
    secret = _SYNTHETIC_SECRET
    out = _post(
        "Bash", {"command": "cat ~/.aws/credentials"}, f"[default]\naws_access_key_id={secret}", cwd
    )
    assert out is not None

    rows = asyncio.run(read_decisions(cwd))
    assert rows
    latest = rows[0]
    assert latest["final_verdict"] == "BLOCK"
    assert latest["auth_result"] == "blocked"
    reasons = json.loads(latest["reason_codes_json"] or "[]")
    assert set(reasons) & {"secret_exfiltration", "sensitive_secret_access"}
    assert secret not in repr(latest)


def test_secret_string_not_in_block_reason(cwd):
    secret = _SYNTHETIC_SECRET
    out = _post("Bash", {"command": "cat ~/.aws/credentials"}, f"found key: {secret}", cwd)
    assert out is not None
    # The raw secret must never appear in the agent-visible block reason
    assert secret not in out


# ---------------------------------------------------------------------------
# Secret in tool_response (dict) → block
# ---------------------------------------------------------------------------


def test_secret_dict_response_is_blocked(cwd):
    secret = _SYNTHETIC_SECRET
    response_dict = {"content": f"found: {secret}"}
    out = _post("Read", {"file_path": ".env"}, response_dict, cwd)
    assert out is not None
    data = json.loads(out)
    assert data["decision"] == "block"


def test_secret_dict_response_secret_not_in_reason(cwd):
    secret = _SYNTHETIC_SECRET
    response_dict = {"result": secret}
    out = _post("Read", {"file_path": "secrets.txt"}, response_dict, cwd)
    assert out is not None
    assert secret not in out


# ---------------------------------------------------------------------------
# Fail-closed behaviour
# ---------------------------------------------------------------------------


def test_unparseable_stdin_fails_closed():
    out = run_post_hook("not json at all")
    assert out is not None
    data = json.loads(out)
    assert data["decision"] == "block"


def test_non_object_payload_fails_closed():
    out = run_post_hook(json.dumps([1, 2, 3]))
    assert out is not None
    data = json.loads(out)
    assert data["decision"] == "block"


def test_empty_tool_name_fails_closed(cwd):
    payload = {
        "hook_event_name": "PostToolUse",
        "tool_name": "",
        "tool_input": {},
        "tool_response": "ok",
        "cwd": cwd,
    }
    out = run_post_hook(json.dumps(payload))
    assert out is not None
    data = json.loads(out)
    assert data["decision"] == "block"


# ---------------------------------------------------------------------------
# Internal tools → abstain (no scan, no history)
# ---------------------------------------------------------------------------


def test_internal_tool_todowrite_abstains(cwd):
    out = _post("TodoWrite", {"todos": []}, "ok", cwd)
    assert out is None


def test_internal_tool_task_abstains(cwd):
    out = _post("Task", {"prompt": "do x"}, "done", cwd)
    assert out is None


# ---------------------------------------------------------------------------
# History: after a post-hook call for a Bash, a decision row is recorded
# ---------------------------------------------------------------------------


def test_history_is_recorded_after_benign_bash(cwd):
    # A benign Bash call should still record a history row.
    out = _post("Bash", {"command": "ls -la"}, "total 0", cwd)
    assert out is None  # benign → no block
    rows = asyncio.run(read_decisions(cwd))
    assert len(rows) >= 1


def test_history_is_recorded_after_benign_read(cwd):
    out = _post("Read", {"file_path": "app.py"}, "import sys", cwd)
    assert out is None
    rows = asyncio.run(read_decisions(cwd))
    assert len(rows) >= 1


# ---------------------------------------------------------------------------
# Redaction: secret never appears in the block reason (comprehensive)
# ---------------------------------------------------------------------------


def test_redaction_comprehensive(cwd):
    """All possible output paths must not echo the secret back to the agent."""
    secret = _SYNTHETIC_SECRET
    for tool, tool_input, tool_response in [
        ("Bash", {"command": "cat file"}, f"key={secret}"),
        ("Read", {"file_path": ".env"}, {"key": secret}),
        ("Grep", {"pattern": "secret"}, f"line 1: AWS_KEY={secret}"),
    ]:
        out = _post(tool, tool_input, tool_response, cwd)
        if out is not None:
            assert secret not in out, f"secret leaked in output for {tool}: {out!r}"


# ---------------------------------------------------------------------------
# evaluate_post API contract
# ---------------------------------------------------------------------------


def test_evaluate_post_returns_dict_or_none_for_clean(cwd):
    payload = {
        "tool_name": "Bash",
        "tool_input": {"command": "echo hi"},
        "tool_response": "hi",
        "cwd": cwd,
    }
    result = evaluate_post(payload)
    assert result is None


def test_evaluate_post_returns_dict_for_secret(cwd):
    secret = _SYNTHETIC_SECRET
    payload = {
        "tool_name": "Bash",
        "tool_input": {"command": "cat secrets"},
        "tool_response": f"aws_key={secret}",
        "cwd": cwd,
    }
    result = evaluate_post(payload)
    assert isinstance(result, dict)
    assert result.get("decision") == "block"


# ---------------------------------------------------------------------------
# MCP tools are gated (output scanned)
# ---------------------------------------------------------------------------


def test_mcp_tool_with_secret_output_is_blocked(cwd):
    secret = _SYNTHETIC_SECRET
    out = _post("mcp__fs__read_file", {"path": "/home/.aws/credentials"}, f"KEY={secret}", cwd)
    assert out is not None
    data = json.loads(out)
    assert data["decision"] == "block"


def test_mcp_tool_clean_output_abstains(cwd):
    out = _post("mcp__fs__list_dir", {"path": "/home"}, ["a", "b", "c"], cwd)
    assert out is None


# ---------------------------------------------------------------------------
# Hot-path weight (UX guarantee): heavy numeric stack must not load
# ---------------------------------------------------------------------------


def test_post_hook_does_not_load_the_numeric_stack():
    """A PostToolUse hook runs after EVERY tool call — it must stay light.

    Asserts (in a clean subprocess) that running the post-hook does NOT import
    river/numpy/scipy (the subjective baseline stack), mirroring the guard in
    test_hosthook_claude_pre.
    """
    code = (
        "import sys, json;"
        "from doberman.hosthooks.claude_code import run_post_hook;"
        "run_post_hook(json.dumps({"
        "'tool_name':'Bash',"
        "'tool_input':{'command':'ls'},"
        "'tool_response':'total 0',"
        "'cwd':'.',"
        "}));"
        "print(','.join(m for m in ('river','numpy','scipy') if m in sys.modules))"
    )
    result = subprocess.run(  # noqa: S603 — controlled call: our own interpreter + a fixed string
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "", f"hot path pulled heavy modules: {result.stdout!r}"
