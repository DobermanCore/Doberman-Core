"""Unit tests for `doberman --version` / `-V`.

Today `doberman version` (a subcommand) works, but `doberman --version` errored with
"No such option: --version" (exit 2). The top-level app now also accepts an eager
`--version` / `-V` flag that prints the same single-sourced version string
(`doberman.__version__`, see ADR 0041) and exits 0 without requiring a subcommand.
"""

from typer.testing import CliRunner

from doberman import __version__
from doberman.cli.main import app

runner = CliRunner()


def test_version_flag_prints_same_string_as_version_command() -> None:
    flag_result = runner.invoke(app, ["--version"])
    command_result = runner.invoke(app, ["version"])

    assert flag_result.exit_code == 0
    assert command_result.exit_code == 0
    assert flag_result.stdout.strip() == command_result.stdout.strip() == __version__


def test_short_version_flag_also_works() -> None:
    result = runner.invoke(app, ["-V"])
    assert result.exit_code == 0
    assert result.stdout.strip() == __version__


def test_no_args_still_shows_help_not_a_version_error() -> None:
    # --version is eager but not required; invoking with no args must keep the
    # existing no_args_is_help behavior, not silently print a version or crash.
    result = runner.invoke(app, [])
    assert "Usage:" in result.stdout
