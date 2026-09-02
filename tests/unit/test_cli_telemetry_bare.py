"""Round 8 item P1 - bare `doberman telemetry` (no subcommand) prints the same
status line `doberman telemetry status` does, symmetric with bare `doberman
mode` printing the current mode instead of Typer's generic group help.
"""

from typer.testing import CliRunner

import doberman.cli.main as cli_module

runner = CliRunner()


def test_bare_telemetry_prints_status_line(tmp_path, monkeypatch):
    monkeypatch.setenv("DOBERMAN_HOME", str(tmp_path))

    result = runner.invoke(cli_module.app, ["telemetry"])

    assert result.exit_code == 0, result.output
    assert "Telemetry:" in result.output
    assert "Distinct id:" in result.output
    assert "Usage:" not in result.output  # never Typer's generic group help


def test_bare_telemetry_matches_explicit_status_output(tmp_path, monkeypatch):
    monkeypatch.setenv("DOBERMAN_HOME", str(tmp_path))

    bare = runner.invoke(cli_module.app, ["telemetry"])
    explicit = runner.invoke(cli_module.app, ["telemetry", "status"])

    assert bare.exit_code == 0, bare.output
    assert explicit.exit_code == 0, explicit.output
    assert bare.output == explicit.output


def test_telemetry_subcommands_still_run_with_the_new_bare_callback(tmp_path, monkeypatch):
    """The new bare-invocation callback must never swallow a real subcommand."""
    monkeypatch.setenv("DOBERMAN_HOME", str(tmp_path))

    on = runner.invoke(cli_module.app, ["telemetry", "on"])
    assert on.exit_code == 0, on.output
    assert "Telemetry enabled" in on.output

    off = runner.invoke(cli_module.app, ["telemetry", "off"])
    assert off.exit_code == 0, off.output
    assert "Telemetry disabled" in off.output


def test_telemetry_help_still_renders(tmp_path, monkeypatch):
    """`--help` must still work now that the group takes a real callback."""
    monkeypatch.setenv("DOBERMAN_HOME", str(tmp_path))

    result = runner.invoke(cli_module.app, ["telemetry", "--help"])

    assert result.exit_code == 0, result.output
    assert "Usage:" in result.output
