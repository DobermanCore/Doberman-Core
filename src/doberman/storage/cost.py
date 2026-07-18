"""Local cost meter (Feature CB.1) + CostObserver plugin seam (CB.2).

Persists redaction-safe :class:`~doberman.models.CostEvent` rows to the
append-only ``cost_events`` ledger and reads them back as aggregate totals —
the raw material for the third boundary (a budget ceiling, platform-side) and
for the CB.3 loop-anomaly detector.

Two non-negotiables, mirrored from the decision log:

* **Off the decision path.** Cost observability is advisory. Recording a cost
  event must never alter or block a PASS/AUTH/BLOCK verdict, so every write is
  inside a failure boundary — ``record_cost_event`` never raises.
* **Redaction-safe.** A ``CostEvent`` holds counts and coarse classes only; no
  prompt/response text or raw role/path ever reaches this table.

The :class:`CostObserver` seam (CB.2) follows the same plugin pattern as
:class:`~doberman.storage.sinks.AuditSink` and
:class:`~doberman.policy.drift.DriftObserver`: observers register via the
``doberman.cost_observers`` entry-point group, receive a copy of every
``CostEvent`` after a successful ledger write, and can never raise into or
block the record path.

This module is policy-core storage and must never import ``doberman.proxy``.
"""

from __future__ import annotations

import logging
from typing import Protocol, runtime_checkable

from doberman.models import CostEvent, CostKind
from doberman.storage.db import open_db

logger = logging.getLogger("doberman.storage.cost")


# --- CostObserver seam (CB.2) ------------------------------------------------


@runtime_checkable
class CostObserver(Protocol):
    """Receives a copy of every :class:`~doberman.models.CostEvent` after it is
    written to the ledger (org-wide cost monitoring / budget enforcement seam).

    Implementations live in installed packages registered via the
    ``doberman.cost_observers`` entry-point group. ``on_cost`` is purely
    observational: it can never alter, block, or prevent a cost record, and must
    not raise into the caller. Observers receive the same frozen
    ``CostEvent`` instance — immutability is the redaction guarantee, not a
    defensive copy.
    """

    def on_cost(self, event: CostEvent) -> None: ...


def _looks_like_cost_observer(obj: object) -> bool:
    """Structural check (the Protocol's isinstance is method-name only)."""
    return callable(getattr(obj, "on_cost", None))


def notify_cost_observers(event: CostEvent) -> None:
    """Fan a :class:`~doberman.models.CostEvent` out to every registered observer.

    Never raises and never affects the ledger write: observers are notified
    *after* a successful commit. A non-observer-shaped or raising observer is
    logged and skipped. With none installed this is a no-op.
    """
    from doberman.engine.registry import discover_cost_observers

    for observer in discover_cost_observers():
        if not _looks_like_cost_observer(observer):
            logger.warning("skipping cost observer %r: not observer-shaped", observer)
            continue
        try:
            observer.on_cost(event)
        except Exception:  # noqa: BLE001 — an observer can never break the record path
            logger.warning("cost observer %r raised; skipping", type(observer).__name__)


_INSERT_COST_EVENT = (
    "INSERT INTO cost_events (ts, action_id, kind, units, model, entity_id) "
    "VALUES (?, ?, ?, ?, ?, ?)"
)


async def record_cost_event(event: CostEvent, *, repo_root: str) -> None:
    """Persist one redacted cost event (best-effort, never raises).

    The build, the open, and the write are all inside the failure boundary: a
    storage error is logged and swallowed so it can never break the execution
    path the cost event merely observes.
    """
    try:
        async with open_db(repo_root) as conn:
            await conn.execute(
                _INSERT_COST_EVENT,
                (
                    event.ts.isoformat(),
                    event.action_id,
                    event.kind.value,
                    int(event.units),
                    event.model,
                    event.entity_id,
                ),
            )
            await conn.commit()
        notify_cost_observers(event)
    except Exception:  # noqa: BLE001 — the cost meter must never break execution
        logger.warning("cost meter write failed for action %s; continuing", event.action_id)


async def read_total(
    repo_root: str,
    *,
    entity_id: str | None = None,
    kind: CostKind | None = None,
) -> int:
    """Sum of ``units`` over the ledger (the meter readout).

    Optionally scoped to one ``entity_id`` and/or one ``kind``. Returns 0 on an
    empty ledger or any read error — a meter read never raises.
    """
    clauses: list[str] = []
    params: list[object] = []
    if entity_id is not None:
        clauses.append("entity_id = ?")
        params.append(entity_id)
    if kind is not None:
        clauses.append("kind = ?")
        params.append(kind.value)
    where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    try:
        async with open_db(repo_root) as conn:
            async with conn.execute(
                f"SELECT COALESCE(SUM(units), 0) FROM cost_events{where}",  # noqa: S608 — fixed clauses, params bound
                params,
            ) as cur:
                row = await cur.fetchone()
        return int(row[0]) if row and row[0] is not None else 0
    except Exception:  # noqa: BLE001 — a meter read must never break a caller
        logger.warning("cost meter read failed; reporting 0")
        return 0


async def read_breakdown(repo_root: str, *, entity_id: str | None = None) -> dict[CostKind, int]:
    """Per-kind ``units`` totals (optionally scoped to one entity).

    Returns an empty mapping on an empty ledger or any read error.
    """
    where = " WHERE entity_id = ?" if entity_id is not None else ""
    params: list[object] = [entity_id] if entity_id is not None else []
    try:
        async with open_db(repo_root) as conn:
            async with conn.execute(
                f"SELECT kind, COALESCE(SUM(units), 0) FROM cost_events{where} GROUP BY kind",  # noqa: S608 — fixed clause, params bound
                params,
            ) as cur:
                rows = await cur.fetchall()
        out: dict[CostKind, int] = {}
        for kind_value, total in rows:
            try:
                out[CostKind(kind_value)] = int(total)
            except ValueError:
                # Unknown kind from a newer writer — skip rather than crash the read.
                continue
        return out
    except Exception:  # noqa: BLE001 — a meter read must never break a caller
        logger.warning("cost meter breakdown read failed; reporting empty")
        return {}
