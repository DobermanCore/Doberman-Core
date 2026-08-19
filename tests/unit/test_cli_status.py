"""Unit tests for `doberman status`'s observability additions (#68):

the installed Doberman version, per-scope Claude Code hook-install state, and
the last 5 recorded decisions. `status` must never crash — on a project with
no settings.json and no decision database it still exits 0 with friendly
placeholder lines.
"""

import asyncio
import json
from datetime import datetime, timezone

from typer.testing import CliRunner

from doberman import __version__
from doberman.auth import totp
from doberman.cli.main import app
from doberman.hosthooks.install import (
    merge_doberman_hooks,
    resolve_settings_path,
    write_settings,
)
from doberman.models import (
    ActionType,
    Decision,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    Verdict,
)
from doberman.storage.log import record_decision
from doberman.storage.taint import (
    TAINT_SECRET_ACCESS,
    TAINT_UNTRUSTED_READ,
    entity_scope,
    record_taints,
)

runner = CliRunner()
_NOW = datetime(2026, 7, 6, tzinfo=timezone.utc)


def _seed_block(root: str) -> None:
    objective = GuardrailResult(
        verdict=Verdict.BLOCK,
        risk=Risk.critical,
        reason_codes=[ReasonCode.destructive_command],
        explanation="destructive command blocked",
    )
    decision = Decision(
        action_id="act-status-1",
        final_verdict=Verdict.BLOCK,
        final_risk=Risk.critical,
        objective=objective,
        reason_codes=[ReasonCode.destructive_command],
        explanation="destructive command blocked",
        decided_at=_NOW,
    )
    action = SecurityObject(
        id="act-status-1",
        ts=_NOW,
        agent_role="cli",
        action_type=ActionType.shell_exec,
        tool_name="bash",
        target="rm -rf /",
    )
    asyncio.run(record_decision(decision, action, repo_root=root, auth_result="blocked"))


def test_status_shows_installed_version(tmp_path):
    result = runner.invoke(app, ["status", "--path", str(tmp_path)])
    assert result.exit_code == 0
    assert f"Version: {__version__}" in result.stdout


def test_status_reports_hook_install_state_per_scope(tmp_path):
    root = str(tmp_path)
    local_path = resolve_settings_path("local", root)
    write_settings(local_path, merge_doberman_hooks({}))

    result = runner.invoke(app, ["status", "--path", root])
    assert result.exit_code == 0
    assert "Hooks:" in result.stdout
    assert "project" in result.stdout
    assert "global" in result.stdout
    assert "local" in result.stdout
    # The local settings.json has Doberman's hooks merged in -> installed.
    assert "[installed]" in result.stdout
    # Project scope was never written -> not installed.
    assert "[not installed]" in result.stdout


def test_status_shows_recent_decisions(tmp_path):
    root = str(tmp_path)
    _seed_block(root)
    result = runner.invoke(app, ["status", "--path", root])
    assert result.exit_code == 0
    assert "Recent decisions:" in result.stdout
    assert "BLOCK" in result.stdout
    assert "destructive_command" in result.stdout


def test_status_reports_missed_challenges(tmp_path):
    root = str(tmp_path)
    _seed_block(root)
    rows_now = datetime.now(timezone.utc)
    objective = GuardrailResult(
        verdict=Verdict.AUTH,
        risk=Risk.medium,
        reason_codes=[ReasonCode.unknown_external_destination],
        explanation="authentication required",
    )
    decision = Decision(
        action_id="act-status-timeout",
        final_verdict=Verdict.AUTH,
        final_risk=Risk.medium,
        objective=objective,
        reason_codes=[ReasonCode.unknown_external_destination],
        explanation="authentication required",
        decided_at=rows_now,
    )
    action = SecurityObject(
        id="act-status-timeout",
        ts=rows_now,
        agent_role="cli",
        action_type=ActionType.network_request,
        tool_name="fetch",
        target="https://example.invalid",
    )
    asyncio.run(
        record_decision(decision, action, repo_root=root, auth_result="timeout", now=rows_now)
    )

    result = runner.invoke(app, ["status", "--path", root])

    assert result.exit_code == 0
    assert "warning: 1 challenge(s) auto-denied in the last 24h - see doberman log" in result.output


def test_status_never_crashes_with_no_db_and_no_settings(tmp_path):
    result = runner.invoke(app, ["status", "--path", str(tmp_path)])
    assert result.exit_code == 0
    assert "(no decisions recorded yet)" in result.stdout
    assert "[not installed]" in result.stdout


def test_status_shows_taint_state(tmp_path):
    root = str(tmp_path)
    scope = entity_scope(root)
    asyncio.run(record_taints(root, [scope], [TAINT_SECRET_ACCESS, TAINT_UNTRUSTED_READ]))

    result = runner.invoke(app, ["status", "--path", root])
    assert result.exit_code == 0
    assert "Taint:" in result.stdout
    assert "secret_access=1" in result.stdout
    assert "untrusted_read=1" in result.stdout


def test_status_shows_no_taint_by_default(tmp_path):
    result = runner.invoke(app, ["status", "--path", str(tmp_path)])
    assert result.exit_code == 0
    assert "Taint: (none)" in result.stdout


# ---------------------------------------------------------------------------
# #258 — status --json + sectioned text; secret never leaks
# ---------------------------------------------------------------------------

_EXPECTED_STATUS_KEYS = {
    "version",
    "path",
    "doberman_version",
    "role",
    "mode",
    "message_tone",
    "prefs",
    "prefs_preset",
    "policy",
    "twofa",
    "password",
    "elevations",
    "taint",
    "hooks",
    "excluded_from_global",
    "recent_decisions",
    "missed_challenges_24h",
}


def test_status_json_parses_with_expected_keys(tmp_path):
    result = runner.invoke(app, ["status", "--path", str(tmp_path), "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["version"] == 1
    assert payload["path"] == str(tmp_path)
    assert set(payload) == _EXPECTED_STATUS_KEYS
    assert isinstance(payload["prefs"], dict)
    assert isinstance(payload["elevations"], list)
    assert isinstance(payload["hooks"], list)
    assert isinstance(payload["recent_decisions"], list)
    assert isinstance(payload["taint"], dict)
    assert isinstance(payload["twofa"], bool)
    assert isinstance(payload["password"], bool)
    assert isinstance(payload["missed_challenges_24h"], int)
    assert isinstance(payload["excluded_from_global"], bool)
    # deterministic separators / keys (mirror scan --json)
    again = runner.invoke(app, ["status", "--path", str(tmp_path), "--json"])
    assert again.stdout == result.stdout


def test_status_reports_excluded_from_global(tmp_path):
    from doberman.storage.exclusions import add_exclusion

    add_exclusion(str(tmp_path))

    text_result = runner.invoke(app, ["status", "--path", str(tmp_path)])
    assert text_result.exit_code == 0, text_result.output
    assert "excluded from global" in text_result.output.lower()

    json_result = runner.invoke(app, ["status", "--path", str(tmp_path), "--json"])
    payload = json.loads(json_result.stdout)
    assert payload["excluded_from_global"] is True


def test_status_text_has_blank_line_section_breaks(tmp_path):
    result = runner.invoke(app, ["status", "--path", str(tmp_path)])
    assert result.exit_code == 0
    # Each major block is separated by a blank line so the dump scans as sections.
    assert "\n\nRole:" in result.stdout
    assert "\n\nMode:" in result.stdout
    assert "\n\nPrefs:" in result.stdout
    assert "\n\nPolicy:" in result.stdout
    assert "\n\n2FA:" in result.stdout
    assert "\n\nPassword:" in result.stdout
    assert "\n\nElevations:" in result.stdout
    assert "\n\nTaint:" in result.stdout
    assert "\n\nHooks:" in result.stdout
    assert "\n\nRecent decisions:" in result.stdout


def test_status_never_leaks_enrolled_secret_in_either_view(tmp_path):
    """A synthetic TOTP secret seeded into state must never appear in text or JSON."""
    totp.enroll()
    secret = totp._read_secret()
    assert secret is not None and len(secret) >= 8

    text = runner.invoke(app, ["status", "--path", str(tmp_path)])
    assert text.exit_code == 0, text.output
    assert secret not in text.stdout
    assert secret not in text.output

    js = runner.invoke(app, ["status", "--path", str(tmp_path), "--json"])
    assert js.exit_code == 0, js.output
    assert secret not in js.stdout
    payload = json.loads(js.stdout)
    # Enrollment is reported as a boolean, never the secret material.
    assert payload["twofa"] is True
    dumped = json.dumps(payload)
    assert secret not in dumped
