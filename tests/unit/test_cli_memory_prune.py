"""Subj1 — ``doberman memory prune``: retention-limit maintenance, ungated.

Storage-level correctness (boundary, per-table coverage, decisions untouched)
is pinned in ``test_memory_governance.py``; these tests cover the CLI surface:
no possession-factor gate (unlike ``memory reset``), the required
``--older-than-days`` flag, and redaction-safe output.
"""

import asyncio
from datetime import datetime, timedelta, timezone

from typer.testing import CliRunner

from doberman.cli.main import app
from doberman.storage.db import open_db

runner = CliRunner()

_NOW = datetime(2026, 8, 13, tzinfo=timezone.utc)


async def _seed(root: str, eid: str, touched: datetime) -> None:
    stamp = touched.isoformat()
    async with open_db(root) as conn:
        await conn.execute(
            "INSERT INTO baseline_counts "
            "(entity_id, feature_key, role, count, last_touched) "
            "VALUES (?, '__total__', 'r', 1, ?)",
            (eid, stamp),
        )
        await conn.commit()


def test_prune_requires_older_than_days(tmp_path):
    result = runner.invoke(app, ["memory", "prune", "--path", str(tmp_path)])
    assert result.exit_code != 0  # missing required option


def test_prune_is_not_gated_behind_a_possession_factor(tmp_path, monkeypatch):
    # No `2fa`/`password` enrollment at all, and any prompter call would fail
    # the test outright — prune must never invoke one.
    root = str(tmp_path)

    class _Explodes:
        def confirm(self, message):
            raise AssertionError("memory prune must never confirm/prompt")

        def read_code(self, message):
            raise AssertionError("memory prune must never confirm/prompt")

    from doberman.cli import main as cli_main

    monkeypatch.setattr(cli_main, "CliPrompter", lambda: _Explodes())
    asyncio.run(_seed(root, "hmac:stale", _NOW - timedelta(days=365)))

    result = runner.invoke(app, ["memory", "prune", "--older-than-days", "30", "--path", root])

    assert result.exit_code == 0, result.output


def test_prune_drops_stale_keeps_fresh_and_reports_counts(tmp_path):
    root = str(tmp_path)
    asyncio.run(_seed(root, "hmac:stale", _NOW - timedelta(days=200)))
    asyncio.run(_seed(root, "hmac:fresh", _NOW - timedelta(days=1)))

    result = runner.invoke(app, ["memory", "prune", "--older-than-days", "90", "--path", root])

    assert result.exit_code == 0, result.output
    assert "1 stale entity class(es)" in result.output


def test_prune_output_never_contains_an_entity_id(tmp_path):
    root = str(tmp_path)
    asyncio.run(_seed(root, "hmac:stale", _NOW - timedelta(days=365)))

    result = runner.invoke(app, ["memory", "prune", "--older-than-days", "30", "--path", root])

    assert result.exit_code == 0, result.output
    assert "hmac:stale" not in result.output
    assert root not in result.output
