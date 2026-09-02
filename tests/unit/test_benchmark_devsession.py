"""Cheap, no-SQLite tests for the devsession suite adapter itself: determinism
and the warm/held-out disjointness the subjective harness relies on. The
expensive full-eval tests (warm sufficiency, redaction, FPR sanity) are in
the ``real_hst``-tier block below (module-scoped fixture, one shared run)."""

from __future__ import annotations

import hashlib
import json

from tests.benchmarks.subjective_runner import HOLDOUT_EVERY
from tests.benchmarks.suites.devsession import DevSessionAdapter


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
