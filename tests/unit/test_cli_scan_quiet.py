"""`doberman scan --quiet` suppresses stdout while keeping exit semantics (#187).

Carried over from @NanoRisk6's PR #206, which #208 supersedes. These invoke the
real `scan` command against a real repo root — no mocked capability enumeration —
so they cover the discovery path that the mocked tests in `test_cli_scan_json.py`
deliberately stub out.
"""

from __future__ import annotations

from typer.testing import CliRunner

from doberman.cli.main import app

runner = CliRunner()


def test_scan_quiet_prints_nothing_to_stdout(tmp_path):
    result = runner.invoke(app, ["scan", "--path", str(tmp_path), "--quiet"])
    assert result.exit_code == 0
    assert result.stdout == ""


def test_scan_default_still_prints_risk_map(tmp_path):
    quiet = runner.invoke(app, ["scan", "--path", str(tmp_path), "--quiet"])
    loud = runner.invoke(app, ["scan", "--path", str(tmp_path)])
    assert quiet.exit_code == loud.exit_code == 0
    assert loud.stdout
    assert quiet.stdout == ""
