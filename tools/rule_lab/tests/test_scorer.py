"""Unit tests for the raise-only acceptance gate.

These tests are the safety contract: they assert there is *no* report pair that
makes the gate approve a loosening. Run with: ``pytest tools/rule_lab/tests``.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scorer import (  # noqa: E402
    SuiteVerdict,
    accept,
    aggregate,
    non_regression,
    score_both,
    validate_eps_fpr,
)


def _report(asr: float, fpr: float, hard_fpr: float, fatigue: float | None = None) -> dict:
    return {
        "asr": asr,
        "asr_strict": asr,
        "fpr": fpr,
        "hard_fpr": hard_fpr,
        "operator": {"asr_under_fatigue": asr if fatigue is None else fatigue},
    }


def test_tightening_with_no_friction_is_accepted():
    base = _report(asr=0.40, fpr=0.10, hard_fpr=0.02)
    cand = _report(asr=0.25, fpr=0.10, hard_fpr=0.02)
    g = accept(base, cand)
    assert g.accepted
    assert g.delta_asr == 0.15


def test_loosening_asr_is_always_rejected():
    base = _report(asr=0.20, fpr=0.10, hard_fpr=0.02)
    cand = _report(asr=0.21, fpr=0.05, hard_fpr=0.00)  # better FPR, but ASR rose
    g = accept(base, cand)
    assert not g.accepted
    assert "ASR rose" in g.reason


def test_new_hard_block_on_benign_is_rejected():
    base = _report(asr=0.40, fpr=0.10, hard_fpr=0.02)
    cand = _report(asr=0.10, fpr=0.10, hard_fpr=0.05)  # great ASR, but new false blocks
    g = accept(base, cand)
    assert not g.accepted
    assert "hard_fpr rose" in g.reason


def test_extra_friction_beyond_tolerance_is_rejected():
    base = _report(asr=0.40, fpr=0.10, hard_fpr=0.02)
    cand = _report(asr=0.20, fpr=0.14, hard_fpr=0.02)
    assert not accept(base, cand, eps_fpr=0.03).accepted
    assert accept(base, cand, eps_fpr=0.05).accepted  # within the bounded tolerance


def test_eps_fpr_must_stay_inside_safe_range():
    assert validate_eps_fpr(0.05) == 0.05
    with pytest.raises(ValueError, match=r"outside safe range"):
        validate_eps_fpr(0.050001)
    with pytest.raises(ValueError, match=r"outside safe range"):
        accept(_report(0.4, 0.1, 0.02), _report(0.2, 0.1, 0.02), eps_fpr=-0.001)


def test_fatigue_breaks_ties_when_asr_unchanged():
    # Same ASR, but candidate moved threats AUTH -> BLOCK, lowering fatigue ASR.
    base = _report(asr=0.30, fpr=0.10, hard_fpr=0.02, fatigue=0.45)
    cand = _report(asr=0.30, fpr=0.10, hard_fpr=0.02, fatigue=0.35)
    assert accept(base, cand).accepted


def test_inert_candidate_is_rejected():
    base = _report(asr=0.30, fpr=0.10, hard_fpr=0.02, fatigue=0.40)
    cand = _report(asr=0.30, fpr=0.10, hard_fpr=0.02, fatigue=0.40)
    assert not accept(base, cand).accepted


def test_held_out_passes_an_inert_candidate():
    # On a suite with no matching gap the candidate does nothing — that must
    # PASS the held-out check (non-regression), even though `accept` would not.
    base = _report(asr=0.0, fpr=0.0, hard_fpr=0.0)
    cand = _report(asr=0.0, fpr=0.0, hard_fpr=0.0)
    assert non_regression(base, cand).accepted
    assert not accept(base, cand).accepted  # the must-improve gate still rejects inert


def test_held_out_rejects_a_regression():
    base = _report(asr=0.0, fpr=0.10, hard_fpr=0.0)
    cand = _report(asr=0.0, fpr=0.20, hard_fpr=0.0)  # added benign friction
    assert not non_regression(base, cand).accepted


def test_score_both_reads_run_profiles_shape():
    both = {
        "suite": "synthetic",
        "builtins_only": _report(asr=0.40, fpr=0.10, hard_fpr=0.02),
        "with_plugins": _report(asr=0.25, fpr=0.10, hard_fpr=0.02),
        "uplift": {"delta_asr": 0.15, "delta_fpr": 0.0},
    }
    assert score_both(both).accepted


def test_aggregate_requires_pass_everywhere_and_gain_somewhere():
    good = SuiteVerdict("synthetic", accept(_report(0.4, 0.1, 0.02), _report(0.25, 0.1, 0.02)))
    inert = SuiteVerdict(
        "injecagent", accept(_report(0.3, 0.1, 0.02, 0.4), _report(0.3, 0.1, 0.02, 0.4))
    )
    regress = SuiteVerdict("injecagent", accept(_report(0.2, 0.1, 0.02), _report(0.25, 0.1, 0.02)))

    ok, _ = aggregate(
        [
            good,
            SuiteVerdict(
                "injecagent", accept(_report(0.3, 0.1, 0.02), _report(0.3, 0.05, 0.0, 0.2))
            ),
        ]
    )
    assert ok

    ok, msg = aggregate([good, regress])
    assert not ok and "rejected on" in msg

    # An inert candidate is already rejected at the per-suite gate ("no measurable
    # gain"), so aggregate reports it under "rejected on" — the dedicated
    # "improves nowhere" branch is an unreachable belt-and-suspenders guard.
    ok, msg = aggregate([inert])
    assert not ok and "rejected on" in msg and "no measurable gain" in msg
