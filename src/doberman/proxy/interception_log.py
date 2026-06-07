"""Structured, redacted interception logging (one JSON line per action).

Every action that reaches the chokepoint is recorded with its redacted
:class:`SecurityObject` and verdict, keyed by the stable ``action.id`` so
later features (decision log, audit) can correlate. Two hard rules:

1. Logging is best-effort and must NEVER raise into the execution path —
   a logging failure must not alter, block, or crash a decision.
2. Only redacted material enters the log: the SecurityObject is already
   redacted by ``normalize()``; nothing else from the raw call is logged.
"""

import json
import logging
from typing import Any

from doberman.models import SecurityObject, Verdict

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
    """
    try:
        record: dict[str, Any] = {
            "event": "tool_call_intercepted",
            "action": action.model_dump(mode="json"),
            "verdict": verdict.value,
        }
        logger.info(json.dumps(record, default=str, ensure_ascii=False))
    except Exception:  # noqa: BLE001 — logging must never break execution
        try:
            logger.warning(_LOG_FAILED_LINE)
        except Exception:  # noqa: BLE001, S110 — give up silently by design
            pass
