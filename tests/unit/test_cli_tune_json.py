"""`doberman tune --json` uses the CLI's compact machine-readable contract."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from doberman.cli.main import app
from tests.unit.test_friction_tune import _seed_five_approved_migrations

runner = CliRunner()


def test_tune_json_is_parseable_and_compact(tmp_path):
    root = str(tmp_path)
    _seed_five_approved_migrations(root)

    result = runner.invoke(app, ["tune", "--path", root, "--json"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert "proposals" in payload
    assert '", "' not in result.stdout
    assert '": "' not in result.stdout
