"""`python -m doberman` runs the CLI when the `doberman` script is not on PATH."""

import runpy
import sys

import click
import pytest


def test_python_m_doberman_runs_the_cli(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["doberman", "--help"])
    # CI forces colour; Rich would wrap the usage line in ANSI codes.
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setenv("COLUMNS", "200")
    with pytest.raises(SystemExit) as exit_info:
        runpy.run_module("doberman", run_name="__main__")
    assert exit_info.value.code == 0
    assert "Usage: doberman" in click.unstyle(capsys.readouterr().out)
