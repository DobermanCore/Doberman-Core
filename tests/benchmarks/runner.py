"""Run a suite's cases through a decision pipeline and aggregate the result.

The runner is the orchestration layer: for each ``BenchmarkCase`` it builds a
``SecurityObject`` + ``EvalContext`` per candidate action, asks the pipeline to
``decide``, classifies the verdict into an :class:`ActionOutcome`, and hands the
stream to :func:`build_report`. A case that raises is **isolated** (logged and
skipped) so one malformed case can never abort a whole run.

``run_suite`` accepts any object exposing ``name`` + ``decide(action, ctx)`` —
in tests that is a stub returning canned verdicts; in real runs it is a
:class:`~tests.benchmarks.profiles.Pipeline`.
"""

from __future__ import annotations

import logging
from typing import Protocol

from doberman.models import Decision, EvalContext, SecurityObject

from .adapter import BenchmarkCase, CandidateAction, SuiteAdapter
from .mapping import to_eval_context, to_security_object
from .metrics import ActionOutcome, Bucket, SuiteReport, build_report
from .profiles import build_pipeline

logger = logging.getLogger("doberman.benchmarks.runner")


class DecidingPipeline(Protocol):
    """Anything that can decide an action (the real pipeline or a test stub)."""

    name: str

    def decide(self, action: SecurityObject, ctx: EvalContext) -> Decision: ...


def _action_bucket(case: BenchmarkCase, index: int) -> Bucket | None:
    """Which metric bucket the ``index``-th action of ``case`` belongs to.

    Benign cases: every action counts toward FPR. Attack cases: only the
    attacker-goal action(s) count toward ASR; other steps are ignored (``None``).
    """
    if case.label == "benign":
        return "benign"
    if case.attacker_goal_index is None:
        return "attack"
    return "attack" if index == case.attacker_goal_index else None


def _evaluate_case(
    case: BenchmarkCase, suite_name: str, pipeline: DecidingPipeline
) -> list[ActionOutcome]:
    """Decide every counting action in one case; raises propagate to the caller."""
    outcomes: list[ActionOutcome] = []
    for index, action in enumerate(case.actions):
        bucket = _action_bucket(case, index)
        if bucket is None:
            continue
        outcomes.append(_decide_one(suite_name, case.case_id, index, action, bucket, pipeline))
    return outcomes


def _decide_one(
    suite_name: str,
    case_id: str,
    index: int,
    action: CandidateAction,
    bucket: Bucket,
    pipeline: DecidingPipeline,
) -> ActionOutcome:
    action_id = f"{suite_name}:{case_id}:{index}"
    security_object = to_security_object(action_id, action)
    ctx = to_eval_context(action)
    decision = pipeline.decide(security_object, ctx)
    return ActionOutcome(
        bucket=bucket,
        verdict=decision.final_verdict,
        reason_codes=tuple(decision.reason_codes),
    )


def run_suite(adapter: SuiteAdapter, pipeline: DecidingPipeline) -> SuiteReport:
    """Run every case from ``adapter`` through ``pipeline`` and aggregate.

    A case that raises while loading or evaluating is logged (by case id, never
    payload) and skipped — measurement never crashes on one bad case.
    """
    outcomes: list[ActionOutcome] = []
    for case in adapter.load():
        try:
            outcomes.extend(_evaluate_case(case, adapter.suite_name, pipeline))
        except Exception:  # noqa: BLE001 — isolate a bad case, keep measuring
            logger.warning(
                "benchmark case %r in suite %r failed to evaluate; skipping",
                getattr(case, "case_id", "?"),
                adapter.suite_name,
            )
    return build_report(adapter.suite_name, pipeline.name, outcomes)


def run_profiles(adapter: SuiteAdapter) -> dict:
    """Run both profiles and report each plus the plugin **uplift** delta.

    ``delta_asr`` = builtins_only ASR − with_plugins ASR (positive = plugins
    caught more attacks). ``delta_fpr`` = with_plugins FPR − builtins_only FPR
    (positive = plugins added benign friction). With no plugins installed both
    deltas are 0.
    """
    builtins = run_suite(adapter, build_pipeline(load_plugins=False))
    with_plugins = run_suite(adapter, build_pipeline(load_plugins=True))
    return {
        "suite": adapter.suite_name,
        "builtins_only": builtins.to_dict(),
        "with_plugins": with_plugins.to_dict(),
        "uplift": {
            "delta_asr": round(builtins.asr - with_plugins.asr, 6),
            "delta_fpr": round(with_plugins.fpr - builtins.fpr, 6),
        },
    }
