"""Slice 5.2 — risk rating, risk-map rendering, and the `doberman scan` CLI.

Covers: the rating mapping; the renderer includes every capability and marks
critical items distinctly; the CLI runs read-only and never prints secrets.
"""

from typer.testing import CliRunner

from doberman import __version__
from doberman.cli.main import app
from doberman.discovery.scan import (
    enumerate_capabilities,
    rate_capabilities,
    render_risk_map,
)
from doberman.models import Risk

FAKE_SECRET = "AKIAIOSFODNN7EXAMPLE"  # noqa: S105 — synthetic AWS example key
runner = CliRunner()


def _rated(tmp_path):
    return rate_capabilities(enumerate_capabilities(["shell_exec"], str(tmp_path)))


def test_rating_mapping(tmp_path):
    rated = {c.name: c for c in _rated(tmp_path)}
    assert rated["dotenv_visible"].risk is Risk.critical
    assert rated["shell"].risk is Risk.high
    assert rated["filesystem_read"].risk is Risk.low


def test_renderer_includes_every_capability(tmp_path):
    rated = _rated(tmp_path)
    out = render_risk_map(rated)
    for cap in rated:
        assert cap.name in out


def test_renderer_marks_critical_present_items(tmp_path):
    (tmp_path / ".env").write_text("X=1", encoding="utf-8")
    rated = rate_capabilities(enumerate_capabilities([], str(tmp_path)))
    out = render_risk_map(rated)
    # The present .env capability is rendered with a CRITICAL marker.
    assert "CRITICAL" in out
    assert "dotenv_visible" in out


def test_cli_scan_runs_and_reports(tmp_path):
    (tmp_path / ".env").write_text(f"KEY={FAKE_SECRET}\n", encoding="utf-8")
    result = runner.invoke(app, ["scan", "--path", str(tmp_path)])
    assert result.exit_code == 0
    assert "risk map" in result.output.lower()
    assert "dotenv_visible" in result.output
    # The CLI must never echo a secret value.
    assert FAKE_SECRET not in result.output


def test_cli_version(tmp_path):
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_cli_no_args_shows_help():
    result = runner.invoke(app, [])
    # no_args_is_help → exits non-zero with usage, listing the scan command.
    assert "scan" in result.output.lower()
