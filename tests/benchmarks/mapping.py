"""Map a suite-neutral ``CandidateAction`` onto core's evaluation types.

This is the single seam between the benchmark vocabulary and Doberman's
``SecurityObject`` / ``EvalContext``. It uses a **fixed timestamp** so a run is
byte-for-byte reproducible (the engine does not depend on ``ts`` for a verdict;
it only needs a valid aware datetime).
"""

from __future__ import annotations

from datetime import datetime, timezone

from doberman.models import ActionType, EvalContext, SecurityObject
from doberman.proxy.normalize import _command_text, _extract_egress_destination, _redact_args
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

    When the adapter left ``external_destination`` unset and the raw arguments
    compose a command line, destination classification is ALSO borrowed from
    the proxy's own command-egress extractor (``proxy.normalize._extract_
    egress_destination``) — the same one ``normalize()`` runs in production —
    so a bare ``nc host port`` shell command is measured the way the live
    proxy classifies it, not silently under-reported as PASS. Raise-only: an
    adapter-supplied destination is never replaced, a non-command action is
    untouched, and extraction never raises — a failure leaves today's object
    in place.
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
    if (
        base.external_destination is None
        and action.action_type is not ActionType.network_request
        and _command_text(raw_arguments) is not None
    ):
        try:
            destination, egress_metadata = _extract_egress_destination(
                _redact_args(raw_arguments), raw_arguments
            )
            base = base.model_copy(
                update={
                    "external_destination": destination,
                    # adapter-supplied metadata is never overridden by the borrowed classifier
                    "metadata": {**egress_metadata, **base.metadata},
                }
            )
        except Exception:  # noqa: BLE001, S110 — a benchmark case must never drop on an
            # extraction raise; keep the base object's destination/metadata untouched
            # (matches the docstring and mirrors the algebra inference's fail-safe below).
            pass
    try:
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
    except Exception:  # noqa: BLE001 — a benchmark case must never drop on an inference
        # raise; keep the base object's conservative default algebra (matches the docstring
        # and mirrors infer_algebra's own internal fail-safe). run_suite would otherwise
        # skip the whole case, silently shrinking the measured corpus.
        return base


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
