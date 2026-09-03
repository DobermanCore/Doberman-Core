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
import random

import pytest

from doberman.models import ActionType, ReasonCode, SourceContext, Verdict
from tests.benchmarks.adapter import SuiteAdapter
from tests.benchmarks.mapping import to_eval_context, to_security_object
from tests.benchmarks.profiles import build_pipeline
from tests.benchmarks.suites.llmail_inject import (
    ATTACKER_EMAIL,
    BENIGN_SEND_DESTINATION,
    DATA_DIR_ENV,
    LlmailInjectAdapter,
)

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
    # A2: one read-only case (unchanged) PLUS one synthetic benign SEND variant
    # per fp email (the dataset carries no sender addresses, so the recipient
    # is a fixed, clearly-synthetic constant).
    assert len(benign_cases) == 2
    read_case = next(c for c in benign_cases if c.case_id == "llmail-benign-00000")
    assert len(read_case.actions) == 1
    assert read_case.actions[0].action_type is ActionType.file_read

    send_case = next(c for c in benign_cases if c.case_id == "llmail-benign-send-00000")
    assert len(send_case.actions) == 1
    send_action = send_case.actions[0]
    assert send_action.action_type is ActionType.network_request
    assert send_action.tool_name == "send_email"
    assert send_action.external_destination == BENIGN_SEND_DESTINATION
    assert send_action.source_context is SourceContext.email
    assert send_case.attacker_goal_index is None


def test_benign_send_variant_shows_honest_auth_friction_never_a_hard_block(tmp_path):
    """A2 (LLMail-Inject review carry-forward): the synthetic benign SEND
    variant must not be tuned away. It is a bare `user@host` destination, so
    the real objective destination rule AUTHs it (embedded-credentials smell,
    `unknown_external_destination`) in every mode -- never a hard BLOCK. Report
    both honestly rather than trimming the benign set to avoid the friction."""
    root = _write_dataset(tmp_path)
    cases = list(LlmailInjectAdapter(data_dir=root, sample_size=10).load())
    send_case = next(c for c in cases if c.case_id == "llmail-benign-send-00000")
    action = send_case.actions[0]

    pipeline = build_pipeline(load_plugins=False)
    decision = pipeline.decide(
        to_security_object("probe:llmail-benign-send", action), to_eval_context(action)
    )

    assert decision.final_verdict is Verdict.AUTH
    assert ReasonCode.unknown_external_destination in decision.reason_codes


def _write_dataset_with_n_qualifying_attacks(tmp_path: pathlib.Path, n: int) -> pathlib.Path:
    """M2: a pool with more than one qualifying (attack_attempt=True,
    reason=api_triggered) row, so sampling a strict subset is actually
    possible -- a 1-row pool (like ``_write_dataset``) can never fail a
    determinism/seed-dependence test, since `min(sample_size, 1)` always
    returns that one row regardless of seed."""
    root = tmp_path / "llmail-inject"
    data_dir = root / "data"
    data_dir.mkdir(parents=True)
    labelled = {
        f"Subject: hi.   Body: qualifying attack row {i}.": {
            "attack_attempt": "True",
            "reason": "api_triggered",
        }
        for i in range(n)
    }
    (data_dir / "labelled_unique_submissions_phase2.json").write_text(
        json.dumps(labelled), encoding="utf-8"
    )
    (data_dir / "emails_for_fp_tests.json").write_text(json.dumps([]), encoding="utf-8")
    return root


def test_sample_size_and_seed_are_deterministic(tmp_path):
    root = _write_dataset_with_n_qualifying_attacks(tmp_path, 6)
    all_prompts = sorted(
        json.loads(
            (root / "data" / "labelled_unique_submissions_phase2.json").read_text(encoding="utf-8")
        ).keys()
    )

    def _bodies(seed: int) -> list[str]:
        cases = LlmailInjectAdapter(data_dir=root, sample_size=3, seed=seed).load()
        return [c.actions[0].raw_arguments["body"] for c in cases if c.label == "attack"]

    first = _bodies(seed=1)
    second = _bodies(seed=1)
    assert first == second  # same seed -> byte-identical selection, same order

    expected = sorted(random.Random(1).sample(all_prompts, 3))  # noqa: S311 — mirrors the adapter
    assert first == expected  # a specific, non-trivial expected subset (not the whole pool)

    different_seed = _bodies(seed=2)
    assert set(different_seed) != set(first)  # a different seed must select a different subset


def test_redaction_payload_never_in_case_id_or_note(tmp_path):
    root = _write_dataset(tmp_path)
    cases = list(LlmailInjectAdapter(data_dir=root, sample_size=10).load())
    for case in cases:
        assert PAYLOAD_MARKER not in case.case_id
        assert PAYLOAD_MARKER not in case.note
    attack = next(c for c in cases if c.label == "attack")
    assert PAYLOAD_MARKER in attack.actions[0].raw_arguments["body"]
    benign = next(c for c in cases if c.label == "benign")
    assert PAYLOAD_MARKER in benign.actions[0].raw_arguments["body"]
