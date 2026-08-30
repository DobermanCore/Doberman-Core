"""Minimal custom AuditSink: append one JSON line per record to a file.

This is the worked example for issue #442. It intentionally mirrors the
spirit of the built-in sinks in ``doberman.storage.sinks`` while staying
deliberately hello-world in scope:

* No batching — one ``json.dumps`` + ``file.write`` per ``emit`` call.
* No retries — if the write fails the exception is caught and logged; the
  decision path must never see the error.
* No network — local file only, controlled by ``DOBERMAN_AUDIT_SINK_FILE``.
  Batching, retries, and network delivery are the webhook sink's job, and
  the README says so.

The three invariants every sink must keep:

1. ``emit`` must **never raise** into the caller.
2. ``emit`` must treat the record as **read-only** — do not mutate, enrich,
   or log anything beyond what the record already contains.
3. The record is **already redacted** before it arrives here.  The sink must
   not add raw paths, agent inputs, file contents, or any other payload that
   the redaction layer removed.
"""

from __future__ import annotations

import json
import logging
import os
import pathlib
import threading

#: Environment variable that overrides the output file path.
#: Defaults to a file named ``doberman_audit.jsonl`` in the system temp
#: directory so the example works out of the box without any configuration.
SINK_FILE_ENV = "DOBERMAN_AUDIT_SINK_FILE"

_DEFAULT_FILENAME = "doberman_audit.jsonl"

logger = logging.getLogger(__name__)


def _default_sink_path() -> pathlib.Path:
    import tempfile

    return pathlib.Path(tempfile.gettempdir()) / _DEFAULT_FILENAME


def _sink_path() -> pathlib.Path:
    override = os.environ.get(SINK_FILE_ENV)
    return pathlib.Path(override) if override else _default_sink_path()


class ExampleAuditSink:
    """Append one JSON line per decision record to a local file.

    Implements the :class:`~doberman.storage.sinks.AuditSink` protocol
    (one method: ``emit``). Registered via::

        [project.entry-points."doberman.audit_sinks"]
        example_sink = "example_audit_sink.sinks:ExampleAuditSink"

    **What this sink deliberately does NOT do:**

    - No batching or buffering — every ``emit`` call opens, writes, and closes
      (or appends to an already-open handle).  Use the built-in webhook sink for
      high-throughput delivery.
    - No retries — a failed write is logged at WARNING level and swallowed; the
      decision path must never be blocked by a sink.
    - No network I/O — the file path is local only.

    **Thread safety:** a module-level lock serialises concurrent ``emit`` calls
    so interleaved writes from parallel decisions do not corrupt lines.
    """

    _lock: threading.Lock = threading.Lock()

    def emit(self, record: dict) -> None:
        """Append *record* as a single JSON line to the configured file.

        Never raises: any I/O error is caught, logged at WARNING, and
        swallowed so a broken sink cannot affect the decision outcome.

        The record is treated as read-only; this method does not mutate,
        enrich, or re-log any field.
        """
        try:
            line = json.dumps(record, default=str) + "\n"
            path = _sink_path()
            with self._lock:
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open("a", encoding="utf-8") as fh:
                    fh.write(line)
        except Exception:  # noqa: BLE001 — emit must never raise
            logger.warning(
                "example_audit_sink: emit() failed; record dropped",
                exc_info=True,
            )
