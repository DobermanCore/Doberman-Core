"""`doberman doctor --json` emits JSON and keeps exit semantics (#179)."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from doberman.cli.main import app

runner = CliRunner()


def test_doctor_json_is_parseable(tmp_path):
    result = runner.invoke(app, ["doctor", "--path", str(tmp_path), "--json"])
    # empty/tmp root may fail critical checks — still must be JSON
    payload = json.loads(result.stdout)
    assert payload["version"] == 1
    assert "checks" in payload
    assert "ok" in payload
    assert isinstance(payload["critical_failures"], list)
    # exit 0 iff ok
    if payload["ok"]:
        assert result.exit_code == 0
    else:
        assert result.exit_code == 1
