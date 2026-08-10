"""Schema, mapping, and redaction tests for the labelled corpus."""

from __future__ import annotations

import json

import pytest

from doberman.models import Verdict
from tests.benchmarks.corpus import CorpusAdapter, CorpusRow, load_corpus
from tests.benchmarks.metrics import ActionOutcome, build_report


def test_corpus_has_stable_shape_and_four_categories():
    rows = load_corpus()
    assert len(rows) == 100
    assert len({row.case_id for row in rows}) == len(rows)
    assert {row.kind for row in rows} == {"injection", "exfiltration", "secrets", "benign"}
    assert all(row.is_attack == (row.kind != "benign") for row in rows)


def test_corpus_adapter_maps_rows_without_payload_in_case_metadata():
    adapter = CorpusAdapter()
    cases = adapter.load()
    assert len(cases) == len(adapter.rows)
    assert {case.note for case in cases} == {"injection", "exfiltration", "secrets", "benign"}
    assert all(
        row.payload not in case.case_id and row.payload not in case.note
        for row, case in zip(adapter.rows, cases, strict=True)
    )


def test_corpus_validation_rejects_duplicate_ids_and_wrong_attack_flag(tmp_path):
    row = {
        "id": "case-1",
        "kind": "benign",
        "surfaces": ["file"],
        "payload": "safe synthetic text",
        "is_attack": False,
        "expected_verdict_at_least": "PASS",
        "forbidden_verdict_at_least": "AUTH",
        "notes": "fixture",
    }
    path = tmp_path / "duplicate.jsonl"
    path.write_text(json.dumps(row) + "\n" + json.dumps(row) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate id"):
        load_corpus(path)

    bad = dict(row, is_attack=True)
    with pytest.raises(ValueError, match="is_attack does not match"):
        CorpusRow.from_mapping(bad, line_number=1)


def test_category_metrics_report_tpr_fpr_and_precision():
    report = build_report(
        "suite",
        "profile",
        [
            ActionOutcome("attack", Verdict.BLOCK, category="secrets"),
            ActionOutcome("attack", Verdict.PASS, category="secrets"),
            ActionOutcome("benign", Verdict.AUTH, category="secrets"),
        ],
    )
    metrics = report.to_dict()["category_metrics"]["secrets"]
    assert metrics == {
        "n_attack": 2,
        "n_benign": 1,
        "tpr": 0.5,
        "fpr": 1.0,
        "precision": 0.5,
    }
