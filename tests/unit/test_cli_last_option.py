"""`--last` agrees across `log`, `tune` and `policy-history` (#716).

`tui` already refused a bad value; the other three took a negative `--last`
and quietly showed nothing, and `tune` had no `-n` short form.
"""

import pytest
from typer.testing import CliRunner

from doberman.cli.main import app

runner = CliRunner()

_COMMANDS = ["log", "tune", "policy-history"]


@pytest.mark.parametrize("command", _COMMANDS)
@pytest.mark.parametrize("flag", ["--last", "-n"])
def test_a_negative_last_is_a_usage_error(tmp_path, command, flag):
    result = runner.invoke(app, [command, "--path", str(tmp_path), flag, "-1"])

    assert result.exit_code == 2, result.output
    assert "-1" in result.output


@pytest.mark.parametrize("command", _COMMANDS)
def test_zero_is_still_allowed(tmp_path, command):
    # 0 means zero rows (#430), not a usage error.
    result = runner.invoke(app, [command, "--path", str(tmp_path), "--last", "0"])

    assert result.exit_code == 0, result.output


def test_tune_accepts_the_short_form(tmp_path):
    short = runner.invoke(app, ["tune", "--path", str(tmp_path), "-n", "5"])
    long = runner.invoke(app, ["tune", "--path", str(tmp_path), "--last", "5"])

    assert short.exit_code == 0, short.output
    assert short.output == long.output
