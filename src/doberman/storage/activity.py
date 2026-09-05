"""Ambient activity bus storage (FM.1) — emit, read, and purge.

The ambient bus is a local SQLite append-only log of
:class:`~doberman.models.ActivityEvent` rows.  Three operations are exposed:

* :func:`emit_activity_event` — validate, size-check, and persist one event.
  Never raises; an oversized or invalid event is rejected and counted.
* :func:`read_activity_events` — cursor-based page read.  Returns the next
  batch of events after a caller-supplied ``after_id``, plus the new high-water
  id so the caller can resume without replaying or losing rows.
* :func:`purge_activity_events` — delete rows older than a caller-supplied
  cutoff.  Stops at the lowest saved cursor so a reader that is offline longer
  than the retention window never loses rows it has not yet consumed.

Design invariants (mirrors :mod:`doberman.storage.cost`):

* **Off the decision path.**  Emitting an event must never alter or block a
  PASS / AUTH / BLOCK verdict — every write is inside a failure boundary, so
  ``emit_activity_event`` never raises.
* **Redaction by projection.**  :class:`~doberman.models.ActivityEvent` stores
  the same flat, redacted fields as ``storage.log.build_record``
  (``action_id``, ``agent_role``, ``action_type``, ``target_path_class``,
  ``collector_id``, ``entity_fingerprint``, ``session_fingerprint``, ``ts``).
  No field can carry a raw path, command, or secret.  The ``"hmac:"`` prefix
  validator on both fingerprint fields is an additional construction-time guard.
* **Size-bounded.**  A serialized event that exceeds ``MAX_EVENT_BYTES`` is
  rejected (counted in ``_oversized_count``) rather than written.
* **Cursor-based resume.**  ``read_activity_events`` uses the integer primary
  key (``id``) as a stable cursor, immune to clock skew and concurrent writers.
* **Purge respects cursors.**  ``purge_activity_events`` stops at the lowest
  ``monitor_state.last_id`` so a slow or offline reader never loses unconsumed
  rows.

This module is policy-core storage and must never import ``doberman.proxy``.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from doberman.models import ActivityEvent
from doberman.storage.db import open_db

logger = logging.getLogger("doberman.storage.activity")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

#: Reject events whose serialized JSON exceeds this byte limit.
#: 4 KiB is generous for a flat ActivityEvent — all fields are labels and ids.
MAX_EVENT_BYTES: int = 4096

# ---------------------------------------------------------------------------
# Module-level rejection counter (advisory only)
# ---------------------------------------------------------------------------

#: How many events were rejected because they exceeded MAX_EVENT_BYTES.
#: Informational; never affects the decision path.
_oversized_count: int = 0

# ---------------------------------------------------------------------------
# Emit
# ---------------------------------------------------------------------------

_INSERT_ACTIVITY = (
    "INSERT INTO activity_events "
    "(ts, action_id, agent_role, action_type, target_path_class, "
    " collector_id, entity_fingerprint, session_fingerprint, payload_json) "
    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
)


async def emit_activity_event(event: ActivityEvent, *, repo_root: str) -> None:
    """Persist one :class:`~doberman.models.ActivityEvent` to the bus (best-effort).

    Validates that ``event`` is a proper ``ActivityEvent`` instance (rejected
    silently if not), serializes it to JSON, rejects it if the serialized size
    exceeds :data:`MAX_EVENT_BYTES` (counted in ``_oversized_count``), then
    writes the row.

    Never raises — a storage error is logged and swallowed so a collector
    failure can never break the execution path the bus merely observes.
    """
    global _oversized_count  # noqa: PLW0603 — intentional module-level counter

    if not isinstance(event, ActivityEvent):
        logger.warning(
            "emit_activity_event received a non-ActivityEvent (%s); skipping",
            type(event).__name__,
        )
        return

    try:
        payload = event.model_dump_json()
    except Exception:  # noqa: BLE001
        logger.warning(
            "emit_activity_event: serialization failed for collector %s; skipping",
            getattr(event, "collector_id", "?"),
        )
        return

    if len(payload.encode()) > MAX_EVENT_BYTES:
        _oversized_count += 1
        logger.warning(
            "emit_activity_event: event from collector %s exceeds %d bytes; rejected "
            "(total oversized rejections: %d)",
            event.collector_id,
            MAX_EVENT_BYTES,
            _oversized_count,
        )
        return

    try:
        async with open_db(repo_root) as conn:
            await conn.execute(
                _INSERT_ACTIVITY,
                (
                    event.ts.isoformat(),
                    event.action_id,
                    event.agent_role,
                    event.action_type,
                    event.target_path_class,
                    event.collector_id,
                    event.entity_fingerprint,
                    event.session_fingerprint,
                    payload,
                ),
            )
            await conn.commit()
    except Exception:  # noqa: BLE001
        logger.warning(
            "emit_activity_event: DB write failed for collector %s; continuing",
            event.collector_id,
        )


# ---------------------------------------------------------------------------
# Cursor-based read
# ---------------------------------------------------------------------------


def read_activity_events(
    repo_root: str,
    *,
    after_id: int = 0,
    limit: int = 100,
) -> tuple[list[ActivityEvent], int]:
    """Read the next page of events from the bus, resuming from ``after_id``.

    Returns ``(events, new_cursor)`` where ``new_cursor`` is the highest
    ``activity_events.id`` in the returned page (or ``after_id`` when the page
    is empty, so the caller can call again without losing their position).

    Uses the integer primary key (``id``) as the cursor — not a timestamp —
    so it is immune to clock skew and concurrent writers.  Rows whose
    ``payload_json`` cannot be parsed back into an
    :class:`~doberman.models.ActivityEvent` are logged and skipped; a malformed
    row from a future writer never breaks an older reader.

    Returns ``([], after_id)`` on any error — a read error must never raise
    into the caller.
    """
    import sqlite3

    from doberman.storage.db import db_path

    path = db_path(repo_root)
    if not path.exists():
        return [], after_id

    events: list[ActivityEvent] = []
    new_cursor = after_id

    try:
        with sqlite3.connect(str(path)) as conn:
            conn.execute("PRAGMA busy_timeout = 2000")
            rows = conn.execute(
                "SELECT id, payload_json FROM activity_events WHERE id > ? ORDER BY id ASC LIMIT ?",
                (after_id, limit),
            ).fetchall()

        for row_id, payload_json in rows:
            try:
                event = ActivityEvent.model_validate_json(payload_json)
                events.append(event)
                new_cursor = row_id
            except Exception:  # noqa: BLE001
                logger.warning("read_activity_events: skipping unparseable row id=%d", row_id)
                # Advance cursor past the bad row so we never get stuck on it.
                new_cursor = row_id

    except Exception:  # noqa: BLE001
        logger.warning("read_activity_events: DB read failed; returning empty page")
        return [], after_id

    return events, new_cursor


# ---------------------------------------------------------------------------
# Retention purge (cursor-aware)
# ---------------------------------------------------------------------------


async def purge_activity_events(
    repo_root: str,
    *,
    older_than: datetime,
) -> int:
    """Delete ``activity_events`` rows older than ``older_than``.

    **Cursor-aware:** never deletes rows that any registered reader has not yet
    consumed.  Specifically, purge stops at the lowest ``monitor_state.last_id``
    across all readers so a reader that is offline longer than the retention
    window never silently loses unconsumed rows.  If no readers are registered,
    purge proceeds without a cursor floor.

    ``older_than`` must be tz-aware; naive datetimes are refused (returns 0) so
    a caller mistake can never silently delete all rows.

    Returns the number of rows deleted.  Returns 0 on any error — a purge
    failure is logged but never re-raised.
    """
    if older_than.tzinfo is None:
        logger.warning(
            "purge_activity_events: older_than is naive (no timezone); refusing to purge"
        )
        return 0

    cutoff_iso = older_than.isoformat()
    try:
        async with open_db(repo_root) as conn:
            # Find the lowest cursor across all registered readers so we never
            # delete rows a slow or offline reader has not yet consumed.
            cursor_row = await (
                await conn.execute("SELECT MIN(last_id) FROM monitor_state")
            ).fetchone()
            min_last_id: int | None = cursor_row[0] if cursor_row else None

            if min_last_id is not None:
                cur = await conn.execute(
                    "DELETE FROM activity_events WHERE ts < ? AND id <= ?",
                    (cutoff_iso, min_last_id),
                )
            else:
                # No readers registered — purge only by timestamp.
                cur = await conn.execute(
                    "DELETE FROM activity_events WHERE ts < ?",
                    (cutoff_iso,),
                )

            await conn.commit()
            return cur.rowcount
    except Exception:  # noqa: BLE001
        logger.warning("purge_activity_events: DB purge failed; continuing")
        return 0


# ---------------------------------------------------------------------------
# Monitor-state cursor persistence
# ---------------------------------------------------------------------------


async def save_cursor(repo_root: str, *, reader_id: str, cursor: int) -> None:
    """Persist the read cursor for ``reader_id`` in ``monitor_state``.

    Best-effort: a write failure is logged and swallowed so a cursor-save
    failure never crashes the calling reader.
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    try:
        async with open_db(repo_root) as conn:
            await conn.execute(
                "INSERT OR REPLACE INTO monitor_state (reader_id, last_id, updated_at) "
                "VALUES (?, ?, ?)",
                (reader_id, cursor, now_iso),
            )
            await conn.commit()
    except Exception:  # noqa: BLE001
        logger.warning("save_cursor: failed to save cursor for reader %r", reader_id)


async def load_cursor(repo_root: str, *, reader_id: str) -> int:
    """Return the saved cursor for ``reader_id``, or 0 if not found.

    Returns 0 on any read error so a reader starts from the beginning rather
    than crashing.
    """
    from doberman.storage.db import db_path

    if not db_path(repo_root).exists():
        return 0
    try:
        async with open_db(repo_root) as conn:
            async with conn.execute(
                "SELECT last_id FROM monitor_state WHERE reader_id = ?",
                (reader_id,),
            ) as cur:
                row = await cur.fetchone()
        return int(row[0]) if row else 0
    except Exception:  # noqa: BLE001
        logger.warning("load_cursor: failed to load cursor for reader %r", reader_id)
        return 0
