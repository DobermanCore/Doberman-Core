"""The ``AuditSink`` seam (Feature 8, slice 8.4) — the enterprise audit fan-out.

Core's default audit destination is the local SQLite decision log
(:mod:`doberman.storage.log`). Additional destinations — centralized audit,
hosted monitoring, SIEM export — live in separately-installed packages that
register an :class:`AuditSink` through the ``doberman.audit_sinks`` entry-point
group, so core never imports them by name (the repo-boundary rule).

SECURITY: a sink receives **only the already-redacted record** the local log
persists — a path *class*, reason codes, a verdict, ids, timestamps. It can
never request raw data, and it can never block, alter, or fail a decision: every
sink is isolated (a raising/slow sink is logged and skipped), and fan-out is
best-effort and happens *after* the decision is already made and the local row
written. With nothing installed, only the local log runs.
"""

import logging
from typing import Protocol, runtime_checkable

logger = logging.getLogger("doberman.storage.sinks")


@runtime_checkable
class AuditSink(Protocol):
    """A destination for already-redacted decision records.

    ``emit`` must not raise into the caller and must treat the record as
    read-only; it receives exactly the redacted dict the local log stores.
    """

    def emit(self, record: dict) -> None: ...


def _looks_like_audit_sink(obj: object) -> bool:
    """Structural check (the Protocol's isinstance is method-name only)."""
    return callable(getattr(obj, "emit", None))


def emit_to_sinks(record: dict) -> None:
    """Fan a redacted record out to every registered sink, isolating failures.

    Never raises: a sink that is not sink-shaped, or whose ``emit`` raises, is
    logged and skipped. With no sinks installed this is a no-op. The local
    SQLite log is written by the caller (:mod:`doberman.storage.log`), not here —
    this fan-out is for *extra* destinations only.
    """
    # Lazy import: the registry lives in the engine layer.
    from doberman.engine.registry import discover_audit_sinks

    for sink in discover_audit_sinks():
        if not _looks_like_audit_sink(sink):
            logger.warning("skipping audit sink %r: not sink-shaped", sink)
            continue
        try:
            sink.emit(dict(record))  # hand each sink its own copy (read-only intent)
        except Exception:  # noqa: BLE001 — a sink failure must never affect a decision
            logger.warning("audit sink %r raised; skipping", type(sink).__name__)
