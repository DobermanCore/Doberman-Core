"""CLI-level regression test for --replay-session: runs the built-in,
dependency-free synthetic suite end to end (no operator data needed) and
proves the flag parses, the run completes, and the report is labeled."""

from __future__ import annotations

import json

import pytest

from tests.benchmarks.run import main


def test_replay_session_flag_runs_and_labels_the_report(capsys):
    exit_code = main(["--suite", "synthetic", "--profile", "before_after", "--replay-session"])
    assert exit_code == 0
    report = json.loads(capsys.readouterr().out)
    assert report["session_replay"] is True


def test_default_run_is_not_labeled_as_replayed(capsys):
    exit_code = main(["--suite", "synthetic", "--profile", "before_after"])
    assert exit_code == 0
    report = json.loads(capsys.readouterr().out)
    assert report["session_replay"] is False


@pytest.mark.parametrize("flag", ["--corpus", "--subjective", "--poisoning"])
def test_replay_session_rejected_with_standalone_flags(flag, capsys):
    with pytest.raises(SystemExit) as excinfo:
        main(["--suite", "synthetic", "--replay-session", flag])
    assert excinfo.value.code == 2
    stderr = capsys.readouterr().err
    assert "--replay-session does not apply to --corpus/--subjective/--poisoning" in stderr
