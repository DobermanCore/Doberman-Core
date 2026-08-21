"""`doberman demo --quiet` suppresses narration while keeping exit semantics (#441).

Mirrors `test_cli_scan_quiet.py`'s approach: invoke the real `demo` command against
a real repo root, not a mocked one, so this covers the actual CLI wiring. `--fast`
skips the pacing delay between scenarios, same as `test_demo.py` does.
"""

from __future__ import annotations

from typer.testing import CliRunner

from doberman.cli.main import app

runner = CliRunner()


def test_demo_quiet_prints_far_fewer_lines_than_default(tmp_path):
    quiet = runner.invoke(app, ["demo", "--path", str(tmp_path), "--fast", "--quiet"])
    loud = runner.invoke(app, ["demo", "--path", str(tmp_path), "--fast"])

    assert quiet.exit_code == loud.exit_code == 0
    quiet_lines = quiet.stdout.splitlines()
    loud_lines = loud.stdout.splitlines()
    assert len(quiet_lines) < len(loud_lines)
    # The banner and the closing "doberman dash" hint are narration, not the summary.
    assert "Doberman demo" not in quiet.stdout
    assert "doberman dash" not in quiet.stdout


def test_demo_quiet_still_reports_the_summary(tmp_path):
    result = runner.invoke(app, ["demo", "--path", str(tmp_path), "--fast", "--quiet"])
    assert result.exit_code == 0
    assert "scenarios matched" in result.stdout
