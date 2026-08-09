"""Map a suite-neutral ``CandidateAction`` onto core's evaluation types.

This is the single seam between the benchmark vocabulary and Doberman's
``SecurityObject`` / ``EvalContext``. It uses a **fixed timestamp** so a run is
byte-for-byte reproducible (the engine does not depend on ``ts`` for a verdict;
it only needs a valid aware datetime).
"""

from __future__ import annotations

from datetime import datetime, timezone

from doberman.models import EvalContext, SecurityObject
from doberman.subjective.adapters import apply_adapters
from doberman.subjective.infer import infer_algebra, infer_reversibility

from .adapter import CandidateAction

#: Fixed, timezone-aware timestamp for every benchmarked action — determinism.
BENCHMARK_TS = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)


def to_security_object(action_id: str, action: CandidateAction) -> SecurityObject:
    """Build the redacted ``SecurityObject`` the engine decides over.

    Only structural fields are carried; payload text rides in the
    ``EvalContext`` (see :func:`to_eval_context`), never in this object's
    ``raw_args_redacted``. The ``algebra`` + ``reversibility`` are populated by
    the same generic inference the proxy runs in production (``proxy.normalize``)
    so the benchmark exercises the real classification path instead of feeding
    the engine a default all-unknown algebra. Inference never raises — a failure
    leaves the conservative default in place.
    """
    base = SecurityObject(
        id=action_id,
        ts=BENCHMARK_TS,
        agent_role=action.agent_role,
        action_type=action.action_type,
        tool_name=action.tool_name,
        target=action.target,
        external_destination=action.external_destination,
        source_context=action.source_context,
    )
    raw_arguments = dict(action.raw_arguments) if action.raw_arguments else {}
    algebra = apply_adapters(
        infer_algebra(base, raw_arguments),
        {"tool_name": action.tool_name, "arguments": raw_arguments},
    )
    return base.model_copy(
        update={
            "algebra": algebra,
            "reversibility": infer_reversibility(base, raw_arguments),
        }
    )


def to_eval_context(action: CandidateAction) -> EvalContext:
    """Build the ``EvalContext`` for one action.

    The suite's ``raw_arguments`` are placed under
    ``metadata['raw_arguments']`` — the exact path core's content rules/detectors
    read (mirrors the proxy's real normalization).
    """
    metadata: dict[str, object] = {}
    if action.raw_arguments:
        metadata["raw_arguments"] = dict(action.raw_arguments)
    return EvalContext(mode=action.mode, metadata=metadata)
