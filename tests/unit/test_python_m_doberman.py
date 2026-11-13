"""`python -m doberman` runs the CLI when the `doberman` script is not on PATH."""

import runpy
import sys

import pytest


def test_python_m_doberman_runs_the_cli(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["doberman", "--help"])
    with pytest.raises(SystemExit) as exit_info:
        runpy.run_module("doberman", run_name="__main__")
    assert exit_info.value.code == 0
    assert "Usage: doberman" in capsys.readouterr().out
