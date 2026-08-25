"""Slice 8.3 — `doberman log` and `doberman memory` views (redaction-safe)."""

import asyncio
from datetime import datetime, timezone

from typer.testing import CliRunner

from doberman.cli.main import app
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

runner = CliRunner()
_NOW = datetime(2026, 6, 8, tzinfo=timezone.utc)
_SECRET = "AKIA-FAKE-CLIVIEW-SECRET-321"  # noqa: S105 — synthetic test value


def _seed_auth_secret_read(root: str) -> None:
    objective = GuardrailResult(
        verdict=Verdict.AUTH,
        risk=Risk.high,
        reason_codes=[ReasonCode.sensitive_secret_access],
        explanation="local secret access",
    )
    decision = Decision(
        action_id="act-1",
        final_verdict=Verdict.AUTH,
        final_risk=Risk.high,
        objective=objective,
        reason_codes=[ReasonCode.sensitive_secret_access],
        explanation="local secret access",
        decided_at=_NOW,
    )
    action = SecurityObject(
        id="act-1",
        ts=_NOW,
        agent_role="backend",
        action_type=ActionType.file_read,
        tool_name="fs_read",
        target="backend/secrets/local.env",
        payload_fingerprints=["hmac:abc123"],
    )
    asyncio.run(record_decision(decision, action, repo_root=root, auth_result="denied"))


def test_log_empty_when_nothing_recorded(tmp_path):
    result = runner.invoke(app, ["log", "--path", str(tmp_path)])
    assert result.exit_code == 0
    assert "no decisions recorded yet" in result.stdout


def test_log_shows_rows_and_reasons(tmp_path):
    root = str(tmp_path)
    _seed_auth_secret_read(root)
    result = runner.invoke(app, ["log", "--path", root])
    assert result.exit_code == 0
    assert "AUTH" in result.stdout
    assert "sensitive_secret_access" in result.stdout  # reason codes are shown
    assert "backend/secrets/*.env" in result.stdout  # the path CLASS, not a raw file
    assert _SECRET not in result.stdout


def test_decision_log_prune_requires_a_policy(tmp_path):
    result = runner.invoke(app, ["decision-log-prune", "--path", str(tmp_path)])
    assert result.exit_code == 2
    assert "specify --older-than-days and/or --max-rows" in result.output


def test_decision_log_prune_reports_count_only(tmp_path):
    root = str(tmp_path)
    _seed_auth_secret_read(root)

    result = runner.invoke(
        app,
        ["decision-log-prune", "--older-than-days", "90", "--max-rows", "1", "--path", root],
    )

    assert result.exit_code == 0, result.output
    assert "Decision log pruned: 0 row(s)." in result.output
    assert "hmac:abc123" not in result.output  # no fingerprint value
    assert _SECRET not in result.stdout


def test_memory_shows_classes_and_counts_only(tmp_path):
    root = str(tmp_path)
    _seed_auth_secret_read(root)
    result = runner.invoke(app, ["memory", "--path", root])
    assert result.exit_code == 0
    assert "Decisions recorded: 1" in result.stdout
    # Habits/classes are shown; a count of distinct secrets is shown, never a value.
    assert "backend/secrets/*.env" in result.stdout
    assert "Distinct secrets seen" in result.stdout
    assert "hmac:abc123" not in result.stdout  # no fingerprint value
    assert _SECRET not in result.stdout
