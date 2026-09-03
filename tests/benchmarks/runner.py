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
from .profiles import PassthroughPipeline, build_pipeline

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
    case: BenchmarkCase,
    suite_name: str,
    pipeline: DecidingPipeline,
    mode: str | None = None,
    *,
    session_replay: bool = False,
) -> list[ActionOutcome]:
    """Decide every counting action in one case; raises propagate to the caller.

    ``session_replay=True`` delegates to :mod:`session_replay`, which decides
    each action AND applies the post-decide floors (taint floor, echo
    tripwire, session correlator) the proxy/host-hook spine apply in
    production, inside a fresh isolated per-case session — see that module's
    docstring. Default (``False``) is the existing stateless per-action path
    below, unchanged.
    """
    if session_replay:
        from . import session_replay as _session_replay  # lazy: avoid a module cycle

        return _session_replay.replay_case(case, suite_name, pipeline, mode)

    outcomes: list[ActionOutcome] = []
    for index, action in enumerate(case.actions):
        bucket = _action_bucket(case, index)
        if bucket is None:
            continue
        outcomes.append(
            _decide_one(suite_name, case.case_id, index, action, bucket, pipeline, mode)
        )
    return outcomes


def _decide_one(
    suite_name: str,
    case_id: str,
    index: int,
    action: CandidateAction,
    bucket: Bucket,
    pipeline: DecidingPipeline,
    mode: str | None = None,
) -> ActionOutcome:
    action_id = f"{suite_name}:{case_id}:{index}"
    security_object = to_security_object(action_id, action)
    ctx = to_eval_context(action)
    if mode is not None:
        ctx = ctx.model_copy(update={"mode": mode})
    decision = pipeline.decide(security_object, ctx)
    return ActionOutcome(
        bucket=bucket,
        verdict=decision.final_verdict,
        reason_codes=tuple(decision.reason_codes),
    )


def run_suite(
    adapter: SuiteAdapter,
    pipeline: DecidingPipeline,
    *,
    mode: str | None = None,
    session_replay: bool = False,
) -> SuiteReport:
    """Run every case from ``adapter`` through ``pipeline`` and aggregate.

    A case that raises while loading or evaluating is logged (by case id, never
    payload) and skipped — measurement never crashes on one bad case.

    ``session_replay=True`` replays each case through the real post-decide
    floors inside a fresh isolated per-case session (see ``session_replay.py``)
    instead of deciding each action statelessly; the report is labeled via
    ``SuiteReport.session_replay``.
    """
    outcomes: list[ActionOutcome] = []
    for case in adapter.load():
        try:
            outcomes.extend(
                _evaluate_case(case, adapter.suite_name, pipeline, mode, session_replay=session_replay)
            )
        except Exception:  # noqa: BLE001 — isolate a bad case, keep measuring
            logger.warning(
                "benchmark case %r in suite %r failed to evaluate; skipping",
                getattr(case, "case_id", "?"),
                adapter.suite_name,
            )
    return build_report(adapter.suite_name, pipeline.name, outcomes, session_replay=session_replay)


def run_profiles(
    adapter: SuiteAdapter, *, mode: str | None = None, session_replay: bool = False
) -> dict:
    """Run both profiles and report each plus the plugin **uplift** delta.

    ``delta_asr`` = builtins_only ASR − with_plugins ASR (positive = plugins
    caught more attacks). ``delta_fpr`` = with_plugins FPR − builtins_only FPR
    (positive = plugins added benign friction). With no plugins installed both
    deltas are 0. ``session_replay`` is forwarded to both arms and also
    surfaced at the top level, so it can never be missed.
    """
    builtins = run_suite(
        adapter, build_pipeline(load_plugins=False), mode=mode, session_replay=session_replay
    )
    with_plugins = run_suite(
        adapter, build_pipeline(load_plugins=True), mode=mode, session_replay=session_replay
    )
    return {
        "suite": adapter.suite_name,
        "session_replay": session_replay,
        "builtins_only": builtins.to_dict(),
        "with_plugins": with_plugins.to_dict(),
        "uplift": {
            "delta_asr": round(builtins.asr - with_plugins.asr, 6),
            "delta_fpr": round(with_plugins.fpr - builtins.fpr, 6),
        },
    }


def run_before_after(
    adapter: SuiteAdapter,
    *,
    load_plugins: bool = False,
    mode: str | None = None,
    session_replay: bool = False,
) -> dict:
    """Run the no-guardrail baseline (**before**) and a real Doberman pipeline
    (**after**), reporting each plus what the engine changed.

    ``before`` is the unmediated tool path — every action allowed, so on a
    ground-truth attack corpus ASR is 1.0 and benign FPR is 0.0 by construction.
    ``after`` is Doberman (built-ins; plus entry-point plugins when
    ``load_plugins`` is set). The ``delta`` is the headline: ``attacks_stopped``
    is the fraction of otherwise-executing attacks the engine now mitigates
    (BLOCK or AUTH), ``attacks_stopped_strict`` counts BLOCK only, and the two
    ``*_added`` fields are the benign friction the engine introduces.
    ``session_replay`` is forwarded to both arms (the ``before`` arm never
    applies a floor regardless — see ``session_replay.py``'s own baseline
    carve-out) and surfaced at the top level.
    """
    before = run_suite(adapter, PassthroughPipeline(), mode=mode, session_replay=session_replay)
    after = run_suite(
        adapter, build_pipeline(load_plugins=load_plugins), mode=mode, session_replay=session_replay
    )
    return {
        "suite": adapter.suite_name,
        "session_replay": session_replay,
        "before": before.to_dict(),
        "after": after.to_dict(),
        "delta": {
            "attacks_stopped": round(before.asr - after.asr, 6),
            "attacks_stopped_strict": round(before.asr_strict - after.asr_strict, 6),
            "fpr_added": round(after.fpr - before.fpr, 6),
            "hard_fpr_added": round(after.hard_fpr - before.hard_fpr, 6),
        },
    }
