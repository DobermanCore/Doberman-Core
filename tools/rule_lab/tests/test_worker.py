"""Unit tests for rule-lab worker input safeguards."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import worker  # noqa: E402


def test_evaluate_rejects_overlapping_tune_and_holdout(monkeypatch: pytest.MonkeyPatch):
    def fail_if_called(suite: str) -> dict:
        raise AssertionError(f"unexpected benchmark run for {suite}")

    monkeypatch.setattr(worker, "run_suite_both", fail_if_called)

    with pytest.raises(ValueError, match="must be disjoint"):
        worker.evaluate(["agentdojo", "synthetic"], ["synthetic"], eps_fpr=0.0)


def test_main_rejects_eps_fpr_above_safe_bound(capsys: pytest.CaptureFixture[str]):
    with pytest.raises(SystemExit) as exc:
        worker.main(["--tune", "agentdojo", "--holdout", "synthetic", "--eps-fpr", "0.5"])

    assert exc.value.code == 2
    assert "outside safe range" in capsys.readouterr().err
