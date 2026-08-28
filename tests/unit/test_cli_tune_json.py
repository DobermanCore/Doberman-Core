"""`doberman tune --json` compact output contract (#431)."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone

from typer.testing import CliRunner

from doberman.cli.main import app
from doberman.storage.db import active_elevations

runner = CliRunner()


def _seed_approved_decisions(root) -> None:
    from tests.unit.test_friction_tune import _seed_five_approved_migrations

    _seed_five_approved_migrations(root)


def test_tune_json_is_compact(tmp_path):
    root = str(tmp_path)
    _seed_approved_decisions(root)

    result = runner.invoke(app, ["tune", "--path", root, "--json"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert "proposals" in payload
    assert '", "' not in result.stdout
    assert '": "' not in result.stdout
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert asyncio.run(active_elevations(root, now)) == []
