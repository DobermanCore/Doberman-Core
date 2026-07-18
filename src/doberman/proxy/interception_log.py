"""Structured, redacted interception logging (one JSON line per action).

Every action that reaches the chokepoint is recorded — by a curated,
redaction-safe field set, never the full :class:`SecurityObject` — and
verdict, keyed by the stable ``action.id`` so later features (decision log,
audit) can correlate. Two hard rules:

1. Logging is best-effort and must NEVER raise into the execution path —
   a logging failure must not alter, block, or crash a decision.
2. Only fields that are redaction-safe *by construction* enter the log
   (ids, enum classifications, the redacted path class, safe metadata
   scalars) — never ``raw_args_redacted``, the raw ``target``, or the raw
   ``external_destination``. ``normalize()``'s heuristic redactor is a
   stopgap, not a guarantee (see :func:`log_action`), so this sink cannot
   rely on it.
"""

import json
import logging
from typing import Any

from doberman.models import SecurityObject, Verdict
from doberman.storage.log import _path_class

LOGGER_NAME = "doberman.interception"

# Pre-built fallback line: if json.dumps itself failed we cannot use it again.
_LOG_FAILED_LINE = '{"event": "interception_log_failed"}'

logger = logging.getLogger(LOGGER_NAME)


def log_action(action: SecurityObject, verdict: Verdict) -> None:
    """Emit one structured JSON log line for an intercepted action.

    Best-effort: any failure is swallowed (after a last-ditch plain-text
    note) — the execution path must never see an exception from here.

    Deliberately swallows ``Exception`` only, never ``BaseException``:
    cancellation (CancelledError), GeneratorExit, and interpreter shutdown
    must propagate — swallowing them here would break structured
    concurrency, and an unwind executes nothing downstream (fail closed).

    Only a curated, redaction-safe field set is emitted — never
    ``action.model_dump()`` / ``raw_args_redacted`` / the raw ``target`` or
    ``external_destination``. ``normalize()``'s redactor is a length- and
    shape-based heuristic stopgap (see ``proxy/normalize.py``), not a
    guarantee: an unshaped, short secret under a non-sensitive argument key
    (e.g. ``content="db_password=Tr0ub4dor&3"``) passes through
    ``raw_args_redacted`` untouched. So this sink must never depend on that
    redaction — it emits only fields that are safe *by construction*: ids,
    enum classifications, the redacted path **class** (mirrors
    ``storage/log.py::build_record``), and ``action.metadata`` (populated
    only by ``normalize()`` with safe scalars — ``target_count`` / a reason
    code list — never raw call content).
    """
    try:
        record: dict[str, Any] = {
            "event": "tool_call_intercepted",
            "verdict": verdict.value,
            "id": action.id,
            "ts": action.ts.isoformat(),
            "agent_role": action.agent_role,
            "action_type": action.action_type.value,
            "source_context": action.source_context.value,
            "tool_name": action.tool_name,
            "target_path_class": _path_class(action),
            "risk": action.risk.value,
            "metadata": action.metadata,
        }
        logger.info(json.dumps(record, default=str, ensure_ascii=False))
    except Exception:  # noqa: BLE001 — logging must never break execution
        try:
            logger.warning(_LOG_FAILED_LINE)
        except Exception:  # noqa: BLE001, S110 — give up silently by design
            pass
