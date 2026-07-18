"""Unit tests for `doberman status`'s observability additions (#68):

the installed Doberman version, per-scope Claude Code hook-install state, and
the last 5 recorded decisions. `status` must never crash — on a project with
no settings.json and no decision database it still exits 0 with friendly
placeholder lines.
"""

import asyncio
from datetime import datetime, timezone

from typer.testing import CliRunner

from doberman import __version__
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
