"""`doberman policy-history --json` emits a JSON array of ledger rows (#190)."""

from __future__ import annotations

import asyncio
import json

from typer.testing import CliRunner

from doberman.cli.main import app
from doberman.storage.db import open_db

runner = CliRunner()


def test_policy_history_json_empty_is_array(tmp_path):
    result = runner.invoke(app, ["policy-history", "--path", str(tmp_path), "--json"])
    assert result.exit_code == 0
    assert json.loads(result.stdout) == []


def test_policy_history_default_empty_message_unchanged(tmp_path):
    result = runner.invoke(app, ["policy-history", "--path", str(tmp_path)])
    assert result.exit_code == 0
    assert "(no policy changes recorded yet)" in result.stdout


async def _seed_policy_rows(repo_root: str) -> None:
    async with open_db(repo_root) as conn:
        await conn.execute(
            "INSERT INTO policy_changes "
            "(ts, rule_id, from_state, to_state, classification, reason, "
            "approval_method, approved, approved_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "2026-01-01T00:00:00+00:00",
                "shell",
                "ask",
                "deny",
                "strengthen",
                "tighten",
                "two_factor",
                1,
                "local",
            ),
        )
        await conn.execute(
            "INSERT INTO policy_changes "
            "(ts, rule_id, from_state, to_state, classification, reason, "
            "approval_method, approved, approved_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "2026-01-02T00:00:00+00:00",
                "network",
                "deny",
                "ask",
                "weaken",
                "relax",
                "denied",
                0,
                None,
            ),
        )
        await conn.commit()


def test_policy_history_json_populated_and_deterministic(tmp_path):
    asyncio.run(_seed_policy_rows(str(tmp_path)))
    first = runner.invoke(app, ["policy-history", "--path", str(tmp_path), "--json"])
    second = runner.invoke(app, ["policy-history", "--path", str(tmp_path), "--json"])
    assert first.exit_code == second.exit_code == 0
    assert first.stdout == second.stdout
    rows = json.loads(first.stdout)
    assert isinstance(rows, list)
    assert len(rows) == 2
    # newest first
    assert rows[0]["rule_id"] == "network"
    assert rows[1]["rule_id"] == "shell"
    assert set(rows[0]) >= {
        "ts",
        "rule_id",
        "from_state",
        "to_state",
        "classification",
        "reason",
        "approval_method",
        "approved",
        "approved_by",
    }
    expected = json.dumps(rows, sort_keys=True, separators=(",", ":"), default=str)
    assert first.stdout.strip() == expected
