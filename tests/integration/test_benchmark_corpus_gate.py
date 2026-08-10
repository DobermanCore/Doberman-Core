"""The labelled corpus must satisfy its declared verdict contracts."""

from __future__ import annotations

import json

from doberman.models import Verdict
from tests.benchmarks.corpus import CorpusAdapter
from tests.benchmarks.mapping import to_eval_context, to_security_object
from tests.benchmarks.profiles import build_pipeline
from tests.benchmarks.runner import run_suite


def test_corpus_rows_meet_expected_and_false_positive_thresholds():
    adapter = CorpusAdapter()
    pipeline = build_pipeline(load_plugins=False)
    for row, case in zip(adapter.rows, adapter.load(), strict=True):
        action = case.actions[0]
        decision = pipeline.decide(
            to_security_object(f"corpus:{case.case_id}:0", action),
            to_eval_context(action),
        )
        assert _order(decision.final_verdict) >= _order(row.expected_verdict_at_least), row.case_id
        if row.forbidden_verdict_at_least is not None:
            assert _order(decision.final_verdict) < _order(row.forbidden_verdict_at_least), (
                row.case_id
            )


def test_corpus_report_is_redacted_and_has_category_metrics():
    report = run_suite(CorpusAdapter(), build_pipeline(load_plugins=False)).to_dict()
    serialized = json.dumps(report)
    for row in CorpusAdapter().rows:
        assert row.payload not in serialized
    assert report["n_attack"] == 75
    assert report["n_benign"] == 25
    assert set(report["category_metrics"]) == {"injection", "exfiltration", "secrets", "benign"}


def _order(verdict: Verdict) -> int:
    return {Verdict.PASS: 0, Verdict.AUTH: 1, Verdict.BLOCK: 2}[verdict]
