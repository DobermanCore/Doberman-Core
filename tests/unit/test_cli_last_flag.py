"""`--last` is consistent across `log`, `tune` and `policy-history` (#716).

`tui` already rejected a negative `--last` (`min=1`); `log`, `tune` and
`policy-history` silently showed nothing instead. `tune` also lacked the `-n`
short form the other three commands have.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from doberman.cli.main import app

runner = CliRunner()


@pytest.mark.parametrize("command", ["log", "tune", "policy-history"])
def test_last_negative_is_a_usage_error(tmp_path, command):
    root = str(tmp_path)

    result = runner.invoke(app, [command, "--path", root, "--last", "-1"])

    assert result.exit_code == 2, result.output


def test_tune_accepts_short_flag(tmp_path):
    root = str(tmp_path)

    result = runner.invoke(app, ["tune", "--path", root, "-n", "5"])

    assert result.exit_code == 0, result.output
