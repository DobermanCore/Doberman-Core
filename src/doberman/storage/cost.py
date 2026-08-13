"""Local cost meter (Feature CB.1) + CostObserver plugin seam (CB.2).

Persists redaction-safe :class:`~doberman.models.CostEvent` rows to the
append-only ``cost_events`` ledger and reads them back as aggregate totals —
the raw material for the third boundary (a budget ceiling, platform-side) and
for the :func:`detect_loop_anomaly` loop-anomaly detector (CB.3), an advisory
read over the same ledger that flags a runaway/looping token or tool-call burn.

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
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
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


# --- Loop-anomaly detector (CB.3) --------------------------------------------

#: Advisory default thresholds for the loop-anomaly readout, over a rolling
#: window. A runaway agent stuck in a tool-call loop shows up as an abnormal
#: number of actions (``call_burst``) or an abnormal token burn (``token_burst``)
#: in a short span; a human-paced session does not. These are deliberately
#: conservative (few false positives) and fully overridable per call — the
#: readout is advisory, so a caller can tune freely without ever touching a
#: safety verdict.
_DEFAULT_WINDOW_SECONDS = 60
_DEFAULT_MAX_CALLS = 40
_DEFAULT_MAX_UNITS = 200_000

#: Hard cap on rows pulled for a single readout, so a pathologically large
#: ledger can never make an advisory read expensive. Recent rows are read first.
_ANOMALY_ROW_CAP = 5000


@dataclass(frozen=True)
class LoopAnomaly:
    """Advisory read of the cost ledger: is an entity in a runaway/looping burn?

    Redaction-safe by construction — it holds **counts and a coarse signal label
    only**, never a raw role/path (``entity_id`` is already a keyed HMAC upstream
    and is not echoed here) and never any payload. Crucially this is **not a
    verdict**: the cost layer is off the decision path, so a ``LoopAnomaly`` can
    flag a runaway loop for a human, a dashboard, or a ``CostObserver`` — but it
    can never itself block, step up, or otherwise alter a PASS/AUTH/BLOCK.
    """

    #: True when the window's activity crossed an advisory threshold.
    is_anomaly: bool
    #: Which signal tripped: ``""`` (none), ``"call_burst"``, or ``"token_burst"``.
    signal: str
    #: The rolling window examined, in seconds.
    window_seconds: int
    #: Tool-call cost events observed in the window (the loop signal).
    calls: int
    #: Summed token units (``tokens_in`` + ``tokens_out``) observed in the window.
    units: int
    #: One-line, redaction-safe human explanation (counts + classes only).
    explanation: str


def _calm(window_seconds: int) -> LoopAnomaly:
    """A benign (no-anomaly) readout — the fail-safe and empty-ledger result."""
    return LoopAnomaly(
        is_anomaly=False,
        signal="",
        window_seconds=window_seconds,
        calls=0,
        units=0,
        explanation="No runaway cost pattern in the recent window.",
    )


async def detect_loop_anomaly(
    repo_root: str,
    *,
    entity_id: str | None = None,
    now: datetime | None = None,
    window_seconds: int = _DEFAULT_WINDOW_SECONDS,
    max_calls: int = _DEFAULT_MAX_CALLS,
    max_units: int = _DEFAULT_MAX_UNITS,
) -> LoopAnomaly:
    """Advisory: does the cost ledger show a runaway/looping burn for an entity?

    Reads the cost events in ``[now - window_seconds, now]`` (optionally scoped to
    one ``entity_id``) and flags a ``call_burst`` when the number of **tool-call**
    events exceeds ``max_calls`` or a ``token_burst`` when the summed **token**
    units (``tokens_in`` + ``tokens_out``) exceed ``max_units`` (a call burst takes
    precedence in the label). Counting only tool-call rows and summing only token
    units keeps each signal a single, well-defined quantity — one agent action
    emits several ``CostEvent`` rows of different kinds, so counting every row (or
    summing mixed units) would mis-calibrate both thresholds.

    ``now`` defaults to the current UTC time; pass it explicitly for a
    deterministic/historical read.

    **Off the decision path and fail-safe:** the result is advisory only, and any
    read/parse error, an empty ledger, or a non-tz-aware ``now`` yields a calm,
    no-anomaly readout — this detector must never raise into, or gate, the caller.
    """
    if window_seconds <= 0:
        return _calm(window_seconds)
    if now is None:
        now = datetime.now(timezone.utc)
    # Fail-safe on a naive `now`: the ledger stores tz-aware ISO timestamps, so a
    # naive cutoff would raise TypeError on the ``ts`` comparison below. The
    # detector's contract is that it never raises into its caller, so a naive
    # `now` (the natural mistake of passing a bare ``datetime.now()``) returns a
    # calm readout instead of crashing.
    if now.tzinfo is None:
        return _calm(window_seconds)
    cutoff = now - timedelta(seconds=window_seconds)

    where = " WHERE entity_id = ?" if entity_id is not None else ""
    params: list[object] = [entity_id] if entity_id is not None else []
    try:
        async with open_db(repo_root) as conn:
            async with conn.execute(
                # Order by the monotonic AUTOINCREMENT PK (part of idx_cost_events),
                # not the TEXT ``ts``: "most recently recorded first, capped" is then
                # an indexed read, not a full scan + string sort, and is immune to
                # mixed UTC offsets in stored timestamps. This suits the detector's
                # live "is this entity looping right now" use; for a far-historical
                # ``now`` on a ledger with more than the cap of newer rows, in-window
                # rows can be crowded out — an accepted under-count for an advisory
                # readout. The precise window filter runs in Python below.
                f"SELECT kind, ts, units FROM cost_events{where} ORDER BY id DESC LIMIT ?",  # noqa: S608 — fixed clause, params bound
                [*params, _ANOMALY_ROW_CAP],
            ) as cur:
                rows = await cur.fetchall()
    except Exception:  # noqa: BLE001 — an advisory read must never break a caller
        logger.warning("loop-anomaly read failed; reporting calm")
        return _calm(window_seconds)

    _TOKEN_KINDS = (CostKind.tokens_in.value, CostKind.tokens_out.value)
    calls = 0
    units = 0
    for kind_raw, ts_raw, unit_raw in rows:
        try:
            ts = datetime.fromisoformat(ts_raw)
        except (TypeError, ValueError):
            continue  # unparseable row — skip, never crash the readout
        # A legacy/malformed row carrying a *naive* timestamp cannot be compared
        # with the aware cutoff (TypeError) — skip it rather than let the whole
        # read raise. (Current writers always store aware timestamps; this guards
        # a hand-written or pre-migration row.)
        if ts.tzinfo is None:
            continue
        if ts < cutoff or ts > now:
            continue
        # A loop is a burst of *tool calls*; the token burn is measured only on
        # *token* kinds. Other kinds contribute to neither signal.
        if kind_raw == CostKind.tool_call.value:
            calls += 1
        elif kind_raw in _TOKEN_KINDS:
            try:
                units += max(0, int(unit_raw))
            except (TypeError, ValueError):
                continue

    # Ceiling (known, and deliberately named before anything depends on it): the
    # burst signals are scoped per ``entity_id``, so a caller that can rotate the
    # entity id between actions resets the counter and evades the burst. Harmless
    # while this detector is advisory with no production caller; a real wiring
    # (the CB.3 seam in #143) must bound entity rotation before relying on it.
    if calls > max_calls:
        return LoopAnomaly(
            is_anomaly=True,
            signal="call_burst",
            window_seconds=window_seconds,
            calls=calls,
            units=units,
            explanation=(
                f"{calls} tool calls in {window_seconds}s exceed the advisory "
                f"limit of {max_calls}; possible runaway tool-call loop."
            ),
        )
    if units > max_units:
        return LoopAnomaly(
            is_anomaly=True,
            signal="token_burst",
            window_seconds=window_seconds,
            calls=calls,
            units=units,
            explanation=(
                f"{units} tokens in {window_seconds}s exceed the advisory limit of "
                f"{max_units}; possible runaway token burn."
            ),
        )
    return LoopAnomaly(
        is_anomaly=False,
        signal="",
        window_seconds=window_seconds,
        calls=calls,
        units=units,
        explanation="No runaway cost pattern in the recent window.",
    )
