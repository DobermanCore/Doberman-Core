"""Cheap, no-SQLite tests for the devsession suite adapter itself: determinism
and the warm/held-out disjointness the subjective harness relies on. The
expensive full-eval tests (warm sufficiency, redaction, FPR sanity) are in
the ``real_hst``-tier block below (module-scoped fixture, one shared run)."""

from __future__ import annotations

import hashlib
import json
import os
import sys

import pytest

from doberman.subjective.baseline import HST_WARMUP
from doberman.subjective.drift import K_OBSERVATIONS
from tests.benchmarks.subjective_runner import HOLDOUT_EVERY, run_subjective_eval
from tests.benchmarks.suites.devsession import PAYLOAD_MARKER, DevSessionAdapter


def _case_repr(cases: tuple) -> str:
    return json.dumps(
        [
            {
                "case_id": c.case_id,
                "label": c.label,
                "note": c.note,
                "actions": [
                    {
                        "action_type": a.action_type.value,
                        "tool_name": a.tool_name,
                        "target": a.target,
                        "external_destination": a.external_destination,
                        "source_context": a.source_context.value,
                        "raw_arguments": a.raw_arguments,
                    }
                    for a in c.actions
                ],
            }
            for c in cases
        ],
        sort_keys=True,
    )


def test_same_seed_produces_byte_identical_case_list():
    a = tuple(DevSessionAdapter(seed=42).load())
    b = tuple(DevSessionAdapter(seed=42).load())
    assert a == b
    assert (
        hashlib.sha256(_case_repr(a).encode()).hexdigest()
        == hashlib.sha256(_case_repr(b).encode()).hexdigest()
    )


def test_different_seed_produces_a_different_case_list():
    a = tuple(DevSessionAdapter(seed=1).load())
    b = tuple(DevSessionAdapter(seed=2).load())
    assert a != b


def test_held_out_and_warm_case_ids_are_disjoint():
    # Mirrors subjective_runner._warm_and_score's own interleaved split, at
    # the adapter level so this test needs no SQLite / no full eval.
    cases = sorted(DevSessionAdapter().load(), key=lambda c: c.case_id)
    by_archetype: dict[str, list] = {}
    for c in cases:
        if c.label == "benign":
            by_archetype.setdefault(c.case_id.split("/", 1)[0], []).append(c.case_id)
    assert by_archetype  # sanity: archetypes actually produced benign cases
    for archetype, ids in by_archetype.items():
        warm = {cid for i, cid in enumerate(ids) if i % HOLDOUT_EVERY != 0}
        holdout = {cid for i, cid in enumerate(ids) if i % HOLDOUT_EVERY == 0}
        assert warm.isdisjoint(holdout), archetype
        assert holdout, archetype
        assert warm, archetype


# --- one real eval over the full devsession corpus --------------------------
# Not real_hst-tier: the warm-sufficiency proof compares n_warm_observations
# against K_OBSERVATIONS/HST_WARMUP, and hst_engaged/cold_start_active are
# both `observed` vs those same constants (subjective_runner.py) — none of it
# depends on HST tree SIZE (HST_TREES/HST_HEIGHT), which is all the real_hst
# marker controls (conftest.py's _apply_hst_size). So this block runs at the
# default fast HST on every PR leg, and at production size only when the
# nightly deep workflow sets DOBERMAN_TEST_REAL_HST=1 (conftest.py's
# pytest_runtest_setup forces production size for every item then,
# regardless of marker). Marks are applied per-test (not a module-level
# ``pytestmark``) because this module also carries the cheap tests above,
# which must stay unmarked/fast — a module-level pytestmark would apply to
# the whole file.

_real_hst_marks = (
    # Measured 172-396s at the default fast HST on a loaded Windows box (worst
    # case ~1.8x headroom; nightly production-size run 345s, ~2x) (also covers the
    # nightly's DOBERMAN_TEST_REAL_HST=1 production-size run, measured ~327s).
    pytest.mark.timeout(700),
    # ONE shared xdist group so this module's 3 tests (1 module-scoped
    # fixture, 4 archetypes x ~650 warm+held-out actions each opening
    # SQLite) never run in parallel with another heavy suite.
    pytest.mark.xdist_group("real_hst"),
)


def _real_hst_test(fn):
    for mark in _real_hst_marks:
        fn = mark(fn)
    return fn


# issue #560: even with with_provenance skipped above, this test's xdist worker
# has died without a traceback ("[gwN] node down: Not properly terminated")
# building the devsession_report fixture on the windows-latest/3.12 PR leg
# specifically, three times (runs 33707622306, 33713310252, 33716795652) —
# Windows 3.11 and every Ubuntu leg pass the same test every time. Narrow,
# platform+version+leg-specific skip; the nightly deep workflow
# (DOBERMAN_TEST_REAL_HST=1) and every other CI leg still run it.
_WIN312_FAST_GATE_CRASH_560 = (
    sys.platform == "win32"
    and sys.version_info[:2] == (3, 12)
    and bool(os.environ.get("DOBERMAN_TEST_FAST_HST_GATES"))
    and not os.environ.get("DOBERMAN_TEST_REAL_HST")
)


@pytest.fixture(scope="module")
def devsession_report() -> dict:
    # include_with_provenance=False: none of this module's 3 tests read the
    # "with_provenance" arm (only "provenance_free", the honest one) — computing
    # it anyway doubles this fixture's SQLite-backed work (2 arms x 4 suites x
    # ~650 warm+held-out actions each). That made this the single most expensive
    # item in the whole suite (336s setup measured in CI) and crashed the
    # windows-latest/3.12 xdist worker twice in a row (issue #560); the other
    # legs merely ran it slowly. Skipping the unread arm halves the work with no
    # loss of coverage for what this module actually asserts.
    return run_subjective_eval(DevSessionAdapter(), include_with_provenance=False)


@_real_hst_test
@pytest.mark.skipif(
    _WIN312_FAST_GATE_CRASH_560,
    reason=(
        "issue #560: xdist worker dies without a traceback "
        "('[gwN] node down: Not properly terminated') on the windows-latest/3.12 "
        "PR leg; nightly real-HST and every other leg still run it"
    ),
)
def test_warm_phase_clears_full_ensemble_engagement(devsession_report):
    needed = max(K_OBSERVATIONS, HST_WARMUP)
    per_suite = devsession_report["arms"]["provenance_free"]["per_suite"]
    assert set(per_suite) == {"backend-dev", "script-runner", "test-ci-loop", "git-heavy-dev"}
    for suite, stats in per_suite.items():
        assert stats["n_warm_observations"] >= needed, suite
        assert stats["hst_engaged"] is True, suite
        assert stats["cold_start_active"] is False, suite


@_real_hst_test
def test_report_never_leaks_payload_marker(devsession_report):
    assert PAYLOAD_MARKER not in json.dumps(devsession_report)


@_real_hst_test
def test_auc_and_held_out_fpr_are_bounded_and_present(devsession_report):
    arm = devsession_report["arms"]["provenance_free"]
    for suite, stats in arm["per_suite"].items():
        if stats["auc"] is not None:
            assert 0.0 <= stats["auc"] <= 1.0, suite
        assert stats["benign"]["n"] > 0, suite  # held-out benign bucket is non-empty
        assert stats["held_out_fpr"] is not None, suite
        assert 0.0 <= stats["held_out_fpr"] <= 1.0, suite
    pooled = arm["pooled"]
    assert pooled["held_out_fpr"] is not None
    assert 0.0 <= pooled["held_out_fpr"] <= 1.0
