"""C8 — the shipped detection corpus, driven through the REAL engine (issue #241).

This is the deterministic tier #241 requires to run green in CI: every benign
row stays below its false-positive guard (no legitimate action is over-blocked),
and every attack row meets its measured, raise-only floor (no detection
regression). Payload text never leaks into the report.

It uses the built-in objective rules only (``load_plugins=False``) so it is
hermetic and stable regardless of what plugins happen to be installed.
"""

from __future__ import annotations

import json

from doberman.models import Verdict
from tests.benchmarks.metrics import corpus_metrics
from tests.benchmarks.profiles import build_pipeline
from tests.benchmarks.suites.corpus import evaluate_corpus, load_corpus


def _results():
    return evaluate_corpus(load_corpus(), build_pipeline(load_plugins=False))


def test_no_benign_row_is_over_blocked():
    """FPR gate: a legitimate action must never reach its forbidden verdict."""
    offenders = [(r.row.id, r.verdict.value) for r in _results() if not r.forbidden_ok]
    assert offenders == [], f"benign rows over-blocked (false positives): {offenders}"


def test_no_attack_row_regressed_below_its_floor():
    """Raise-only gate: an attack must stay at or above its calibrated floor."""
    offenders = [
        (
            r.row.id,
            r.row.expected_verdict_at_least.value if r.row.expected_verdict_at_least else None,
            r.verdict.value,
        )
        for r in _results()
        if not r.floor_ok
    ]
    assert offenders == [], f"attack rows regressed below their measured floor: {offenders}"


def test_corpus_report_is_clean_and_consistent():
    m = corpus_metrics(_results())
    # The gate's headline invariants.
    assert m["floor_violations"] == []
    assert m["forbidden_violations"] == []
    # Current honest state: zero benign friction on the objective layer.
    assert m["fpr"] == 0.0
    assert m["hard_fpr"] == 0.0
    # A real corpus with attacks the layer genuinely catches, but not all of them
    # (documented gaps keep the number honest — never assert a perfect score).
    assert 0.0 < m["tpr"] < 1.0
    assert m["n_attack"] >= 80 and m["n_benign"] >= 20


def test_payload_never_leaks_into_the_real_report():
    # Drive a known destructive payload; its command text must not appear anywhere
    # in the serialized per-category report.
    m = corpus_metrics(_results())
    blob = json.dumps(m)
    for needle in ("rm -rf", "Ignore all previous", "id_rsa", Verdict.PASS.name.lower() + "word"):
        assert needle not in blob


def test_secrets_and_destructive_are_caught_in_balanced():
    """The categories built on deterministic patterns should detect well even in
    balanced mode — a sanity floor on the corpus's discriminative power."""
    by_cat = corpus_metrics(_results())["by_category"]
    assert by_cat["secrets"]["tpr"] >= 0.8
    assert by_cat["destructive"]["tpr"] >= 0.6
