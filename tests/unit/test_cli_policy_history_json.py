"""`doberman policy-history --json` emits a JSON array of ledger rows (#190)."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from doberman.cli.main import app

runner = CliRunner()


def test_policy_history_json_empty_is_array(tmp_path):
    result = runner.invoke(app, ["policy-history", "--path", str(tmp_path), "--json"])
    assert result.exit_code == 0
    assert json.loads(result.stdout) == []


def test_policy_history_default_empty_message_unchanged(tmp_path):
    result = runner.invoke(app, ["policy-history", "--path", str(tmp_path)])
    assert result.exit_code == 0
    assert "(no policy changes recorded yet)" in result.stdout
