"""Governance over the per-entity behavioral memory (Subj1).

RAND flags persistent agent memory as a poisoning vector that needs reliable
deletion and a retention limit. The subjective baseline and the revealed
preference store (``doberman.subjective.baseline`` / ``.revealed``) are that
memory here — five entity-keyed tables that otherwise persist across sessions,
monotonically and un-audited. This module is the storage-layer half of the two
governance primitives:

* :func:`reset_memory` — the gated, deliberate wipe behind ``doberman memory
  reset`` (CLI gate mirrors :func:`doberman.storage.taint.clear_taint` / the
  ``doberman taint clear`` command: a possession factor via
  :func:`doberman.policy.drift._verify_possession_factor`, no confirm-only
  path). Like :func:`~doberman.storage.taint.clear_taint`, this INVERTS the
  module-local best-effort discipline used elsewhere in storage: it raises on
  any error instead of swallowing it, because reporting success on a failed
  delete would tell the operator memory is gone when it is not.
* :func:`prune_stale_entities` — the retention-limit maintenance op behind
  ``doberman memory prune``. Not gated (a maintenance decision, not a security
  one) and never touches the ``decisions`` table — the audit trail is not
  behavioral memory and pruning it is out of scope here.

Wiping (or losing) baseline data is raise-SAFE by construction, same as the
v2->v3 re-keying migration in :mod:`doberman.storage.db`: a colder baseline
scores everything as MORE novel — more step-ups, never fewer — until it
relearns. Every output here is a table name (a fixed literal) plus a row
count, or an entity id already used only in its keyed-HMAC form — never raw
baseline content.
"""

from datetime import datetime, timedelta, timezone

from doberman.storage.db import open_db

#: Every table that holds per-entity behavioral memory (Subj1). Order matters
#: only for readability; deletes touch all of them together so an entity's
#: footprint never survives partially in one table after a reset/prune.
BASELINE_TABLES: tuple[str, ...] = (
    "baseline_counts",
    "baseline_transitions",
    "baseline_state",
    "score_history",
    "preference_feedback",
)


async def reset_memory(repo_root: str, entity_id: str | None = None) -> dict[str, int]:
    """Delete this repo's behavioral memory — all entities, or one.

    Returns ``{table: rows_deleted}``. Raises on any storage error (an
    inversion of this package's usual fail-closed-to-empty reads / best-effort
    writes — see the module docstring): the caller (the CLI) must never report
    a reset as successful when it was not. Callers are responsible for gating
    this behind a possession factor first; this function performs no auth
    itself, same division of labor as :func:`~doberman.storage.taint.clear_taint`.
    """
    counts: dict[str, int] = {}
    async with open_db(repo_root) as conn:
        for table in BASELINE_TABLES:
            if entity_id is None:
                cur = await conn.execute(f"DELETE FROM {table}")  # noqa: S608 — table is a fixed literal from BASELINE_TABLES
            else:
                cur = await conn.execute(
                    f"DELETE FROM {table} WHERE entity_id = ?",  # noqa: S608 — table is a fixed literal; value is bound
                    (entity_id,),
                )
            counts[table] = cur.rowcount
        await conn.commit()
    return counts


async def _last_touched_by_entity(conn) -> dict[str, str]:
    """The most recent ``last_touched`` seen for each entity, across all 5 tables.

    ISO-8601 strings compare correctly as plain strings here because every
    stamp in this codebase is written the same way (``datetime.now(timezone.
    utc).isoformat()``) — same offset, same precision — so lexicographic order
    matches chronological order without parsing. NULLs (an entity whose only
    rows predate the v9 migration and had nothing to backfill from — see
    ``_migrate_legacy``) are skipped, never treated as "very old": a missing
    signal must never manufacture staleness.
    """
    latest: dict[str, str] = {}
    for table in BASELINE_TABLES:
        async with conn.execute(
            f"SELECT entity_id, MAX(last_touched) FROM {table} GROUP BY entity_id"  # noqa: S608 — table is a fixed literal
        ) as cur:
            rows = await cur.fetchall()
        for eid, touched in rows:
            if touched is None:
                continue
            if eid not in latest or touched > latest[eid]:
                latest[eid] = touched
    return latest


async def prune_stale_entities(
    repo_root: str, *, older_than_days: int, now: datetime | None = None
) -> dict[str, int]:
    """Drop every table-row belonging to an entity untouched for ``older_than_days``.

    A maintenance op, not a security decision — not gated behind a possession
    factor (see :func:`reset_memory` for the gated wipe) — but still fail-safe:
    an entity with no timestamp anywhere (see :func:`_last_touched_by_entity`)
    is never pruned, and the ``decisions`` table (the audit trail, not
    behavioral memory) is never touched.

    Returns ``{"entities_pruned": N, <table>: rows_deleted, ...}``. Raises on
    any storage error rather than reporting a partial prune as complete.
    """
    when = now or datetime.now(timezone.utc)
    cutoff = (when - timedelta(days=older_than_days)).isoformat()
    counts: dict[str, int] = dict.fromkeys(BASELINE_TABLES, 0)
    async with open_db(repo_root) as conn:
        latest = await _last_touched_by_entity(conn)
        stale = [eid for eid, touched in latest.items() if touched < cutoff]
        for eid in stale:
            for table in BASELINE_TABLES:
                cur = await conn.execute(
                    f"DELETE FROM {table} WHERE entity_id = ?",  # noqa: S608 — table is a fixed literal; value is bound
                    (eid,),
                )
                counts[table] += cur.rowcount
        await conn.commit()
    return {"entities_pruned": len(stale), **counts}
