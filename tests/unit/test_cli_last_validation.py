"""Tests for CLI --last option consistency across commands (#716)."""

from __future__ import annotations

import re

import pytest
from typer.main import get_command
from typer.testing import CliRunner

from doberman.cli.main import app

runner = CliRunner()
ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


@pytest.mark.parametrize("command", ["log", "tune", "policy-history"])
@pytest.mark.parametrize("flag", ["--last", "-n"])
def test_negative_last_exits_2(command: str, flag: str, tmp_path):
    root = str(tmp_path)
    result = runner.invoke(app, [command, "--path", root, flag, "-1"])
    assert result.exit_code == 2
    assert "Invalid value" in result.output
    assert "x>=0" in result.output


@pytest.mark.parametrize("command", ["log", "tune", "policy-history"])
@pytest.mark.parametrize("flag", ["--last", "-n"])
def test_zero_last_succeeds(command: str, flag: str, tmp_path):
    root = str(tmp_path)
    result = runner.invoke(app, [command, "--path", root, flag, "0"])
    assert result.exit_code == 0


def test_tune_supports_n_short_flag(tmp_path):
    root = str(tmp_path)
    result = runner.invoke(app, ["tune", "--path", root, "-n", "5"])
    assert result.exit_code == 0


def test_tune_has_short_n_param():
    cmd = get_command(app).get_command(None, "tune")
    param = next(p for p in cmd.params if "--last" in p.opts)
    assert "-n" in param.opts


def test_tune_help_documents_short_n():
    result = runner.invoke(app, ["tune", "--help"])
    assert result.exit_code == 0
    clean = ANSI_ESCAPE.sub("", result.output)
    assert "-n" in clean
    assert "--last" in clean
