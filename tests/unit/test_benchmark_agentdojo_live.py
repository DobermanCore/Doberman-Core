"""Guarded live smoke test: the subjective-layer eval against real AgentDojo.

Skips cleanly when the operator-supplied ``agentdojo`` package isn't installed
(the default in CI) — mirrors the ``pytest.importorskip`` guard used elsewhere
in this suite for optional dependencies (e.g. ``tests/unit/test_tui.py``).
Runs no live model: ``run_subjective_eval`` only replays recorded AgentDojo
tool-call traces through the production ``observe()``/``surprise_blended()``
read path (see ``tests/benchmarks/subjective_runner.py``). The unit-level
mapping tests for the adapter itself (fully mocked, no ``agentdojo`` needed)
live in ``tests/unit/test_benchmark_agentdojo.py``.
"""

from __future__ import annotations

import pytest

pytest.importorskip("agentdojo")

from tests.benchmarks.subjective_runner import (  # noqa: E402 — after the importorskip, by design
    run_subjective_eval,
)
from tests.benchmarks.suites.agentdojo import AgentDojoAdapter  # noqa: E402

# These gates measure the model's shape, so they keep production-size trees; the
# module-scoped eval fixture then lands on the first collected item, which needs
# more than CI's default per-test timeout.
pytestmark = [
    pytest.mark.real_hst,
    pytest.mark.timeout(1200),
    # One xdist worker builds the module fixture once (--dist loadgroup); without
    # the group every worker that draws an item from this module rebuilds it. One
    # group PER module, so the production-size modules still run in parallel with
    # each other instead of trailing the suite as one serial chain.
    pytest.mark.xdist_group("real_hst_agentdojo"),
]


def test_subjective_eval_reports_all_suites_and_both_arms():
    report = run_subjective_eval(AgentDojoAdapter())

    arms = report["arms"]
    assert "provenance_free" in arms
    assert "with_provenance" in arms

    per_suite = arms["provenance_free"]["per_suite"]
    assert set(per_suite) == {"banking", "slack", "travel", "workspace"}
    for suite_report in per_suite.values():
        assert suite_report["n_warm_observations"] >= 0
