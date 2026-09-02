"""`doberman doctor --json` emits JSON and keeps exit semantics (#179)."""

from __future__ import annotations

import json
from typing import Any

from typer.testing import CliRunner

from doberman.cli.main import app

runner = CliRunner()


def _check_by_name(payload: dict[str, Any], name: str) -> dict[str, Any]:
    return next(check for check in payload["checks"] if check["name"] == name)


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


def test_doctor_json_reports_enrolled_password(tmp_path, monkeypatch):
    monkeypatch.setattr("doberman.auth.password.is_enrolled", lambda: True)

    result = runner.invoke(app, ["doctor", "--path", str(tmp_path), "--json"])

    payload = json.loads(result.stdout)
    check = _check_by_name(payload, "Password")
    assert check["status"] == "ok"
    assert check["detail"] == "set"


def test_doctor_json_reports_missing_password(tmp_path, monkeypatch):
    monkeypatch.setattr("doberman.auth.password.is_enrolled", lambda: False)

    result = runner.invoke(app, ["doctor", "--path", str(tmp_path), "--json"])

    payload = json.loads(result.stdout)
    check = _check_by_name(payload, "Password")
    assert check["status"] == "warn"
    # ASCII, not an em dash (round 4 item 16: doctor's detail strings are cp1252-safe).
    assert check["detail"] == "not set (optional) - run `doberman password set`"
