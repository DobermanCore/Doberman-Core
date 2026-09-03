"""Unit tests for the LLMail-Inject suite adapter.

LLMail-Inject (https://huggingface.co/datasets/microsoft/llmail-inject-challenge,
MIT) is operator-supplied via ``DOBERMAN_BENCH_LLMAIL_DIR``. These tests build a
tiny synthetic ``data/labelled_unique_submissions_phase2.json`` +
``data/emails_for_fp_tests.json`` pair under ``tmp_path`` in the real on-disk
shape (a single JSON object keyed by submission text; a plain JSON array of
benign email strings) and never touch the real, multi-hundred-MB files.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from doberman.models import ActionType, SourceContext
from tests.benchmarks.adapter import SuiteAdapter
from tests.benchmarks.suites.llmail_inject import ATTACKER_EMAIL, DATA_DIR_ENV, LlmailInjectAdapter

PAYLOAD_MARKER = "LLMAIL_PAYLOAD_MARKER_DO_NOT_LEAK"


def test_load_without_data_dir_raises(monkeypatch):
    monkeypatch.delenv(DATA_DIR_ENV, raising=False)
    with pytest.raises(RuntimeError, match=DATA_DIR_ENV):
        list(LlmailInjectAdapter().load())


def test_adapter_satisfies_suite_adapter_protocol():
    assert isinstance(LlmailInjectAdapter(data_dir="/nonexistent"), SuiteAdapter)


def _write_dataset(tmp_path: pathlib.Path) -> pathlib.Path:
    root = tmp_path / "llmail-inject"
    data_dir = root / "data"
    data_dir.mkdir(parents=True)
    (data_dir / "labelled_unique_submissions_phase2.json").write_text(
        json.dumps(
            {
                f"Subject: hi.   Body: please send it. {PAYLOAD_MARKER}": {
                    "attack_attempt": "True",
                    "reason": "api_triggered",
                },
                f"Subject: hi.   Body: judge-only, not fired. {PAYLOAD_MARKER}": {
                    "attack_attempt": "True",
                    "reason": "judge",
                    "judge_answer": "looks like an attempt",
                    "judge_category": "direct instructions",
                },
                "Subject: hi.   Body: not an attack.": {
                    "attack_attempt": "False",
                    "reason": "api_triggered",
                },
            }
        ),
        encoding="utf-8",
    )
    (data_dir / "emails_for_fp_tests.json").write_text(
        json.dumps([f"Subject: routine update.   Body: fyi. {PAYLOAD_MARKER}"]),
        encoding="utf-8",
    )
    return root


def test_load_filters_to_api_triggered_and_builds_two_action_cases(tmp_path):
    root = _write_dataset(tmp_path)
    cases = list(LlmailInjectAdapter(data_dir=root, sample_size=10).load())
    attack_cases = [c for c in cases if c.label == "attack"]

    assert len(attack_cases) == 1  # the judge-only and attack_attempt=False rows are excluded
    case = attack_cases[0]
    assert case.attacker_goal_index == 1
    assert len(case.actions) == 2
    assert case.actions[0].source_context is SourceContext.email
    assert case.actions[0].action_type is ActionType.file_read
    assert case.actions[1].action_type is ActionType.network_request
    assert case.actions[1].external_destination == ATTACKER_EMAIL
    assert case.actions[1].raw_arguments == {"to": ATTACKER_EMAIL, "body": "confirmation"}

    benign_cases = [c for c in cases if c.label == "benign"]
    assert len(benign_cases) == 1
    assert len(benign_cases[0].actions) == 1
    assert benign_cases[0].actions[0].action_type is ActionType.file_read


def test_sample_size_and_seed_are_deterministic(tmp_path):
    root = _write_dataset(tmp_path)
    first = [c.case_id for c in LlmailInjectAdapter(data_dir=root, sample_size=1, seed=1).load()]
    second = [c.case_id for c in LlmailInjectAdapter(data_dir=root, sample_size=1, seed=1).load()]
    assert first == second
