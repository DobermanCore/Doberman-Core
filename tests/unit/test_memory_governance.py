"""Subj1 — memory governance: gated reset + retention prune of the behavioral
baseline/preference tables (storage layer, no CLI/auth gate involved here —
see ``test_cli_memory_reset.py`` for the gated CLI command).

RAND flags persistent agent memory as a poisoning vector needing reliable
deletion and a retention limit. These tests pin: a reset (scoped or whole-repo)
actually removes rows from every one of the five tables, a scoped reset leaves
other entities untouched, prune drops only entities whose newest row is older
than the cutoff (with the boundary pinned), prune never touches the audit
``decisions`` table, and a storage failure raises rather than reporting a
partial success.
"""

from datetime import datetime, timedelta, timezone

from doberman.storage.db import open_db
from doberman.storage.memory import BASELINE_TABLES, prune_stale_entities, reset_memory

_NOW = datetime(2026, 8, 13, tzinfo=timezone.utc)


async def _seed_entity(root: str, eid: str, touched: datetime) -> None:
    """One row per baseline/preference table for ``eid``, stamped ``touched``."""
    stamp = touched.isoformat()
    async with open_db(root) as conn:
        await conn.execute(
            "INSERT INTO baseline_counts "
            "(entity_id, feature_key, role, count, first_seen, last_seen, last_touched) "
            "VALUES (?, '__total__', 'r', 1, ?, ?, ?)",
            (eid, stamp, stamp, stamp),
        )
        await conn.execute(
            "INSERT INTO baseline_transitions (entity_id, from_state, to_state, count, last_touched) "
            "VALUES (?, '1:x', 'y', 1, ?)",
            (eid, stamp),
        )
        await conn.execute(
            "INSERT INTO baseline_state (entity_id, last_state, prev_state, last_touched) "
            "VALUES (?, 'y', 'x', ?)",
            (eid, stamp),
        )
        await conn.execute(
            "INSERT INTO score_history (entity_id, ts, kind, value, last_touched) "
            "VALUES (?, ?, 'novelty', 0.5, ?)",
            (eid, stamp, stamp),
        )
        await conn.execute(
            "INSERT INTO preference_feedback "
            "(entity_id, dimension, approvals, denials, updated_at, last_touched) "
            "VALUES (?, 'confidentiality', 1, 0, ?, ?)",
            (eid, stamp, stamp),
        )
        await conn.commit()


async def _row_counts(root: str, eid: str) -> dict[str, int]:
    counts = {}
    async with open_db(root) as conn:
        for table in BASELINE_TABLES:
            async with conn.execute(
                f"SELECT COUNT(*) FROM {table} WHERE entity_id = ?",  # noqa: S608
                (eid,),
            ) as cur:
                counts[table] = (await cur.fetchone())[0]
    return counts


# --- reset_memory ------------------------------------------------------------


async def test_reset_all_clears_every_entity_across_every_table(tmp_path):
    root = str(tmp_path)
    await _seed_entity(root, "hmac:aaa", _NOW)
    await _seed_entity(root, "hmac:bbb", _NOW)

    counts = await reset_memory(root, None)

    assert set(counts) == set(BASELINE_TABLES)
    assert all(n == 2 for n in counts.values())  # both entities, one row/table each
    assert all(v == 0 for v in (await _row_counts(root, "hmac:aaa")).values())
    assert all(v == 0 for v in (await _row_counts(root, "hmac:bbb")).values())


async def test_reset_scoped_to_one_entity_leaves_others_untouched(tmp_path):
    root = str(tmp_path)
    await _seed_entity(root, "hmac:aaa", _NOW)
    await _seed_entity(root, "hmac:bbb", _NOW)

    counts = await reset_memory(root, "hmac:aaa")

    assert all(n == 1 for n in counts.values())  # only hmac:aaa's rows
    assert all(v == 0 for v in (await _row_counts(root, "hmac:aaa")).values())
    assert all(v == 1 for v in (await _row_counts(root, "hmac:bbb")).values())


async def test_reset_on_empty_db_deletes_nothing_and_does_not_raise(tmp_path):
    counts = await reset_memory(str(tmp_path), None)
    assert all(n == 0 for n in counts.values())


async def test_reset_raises_rather_than_reporting_a_partial_success(tmp_path):
    # A malformed DB file (not a real SQLite database) must make reset_memory
    # raise — never silently report zero rows as "cleared successfully".
    (tmp_path / ".doberman").mkdir()
    (tmp_path / ".doberman" / "doberman.db").write_bytes(b"not a sqlite database")

    raised = False
    try:
        await reset_memory(str(tmp_path), None)
    except Exception:  # noqa: BLE001 — asserting *some* exception propagates
        raised = True
    assert raised


# --- prune_stale_entities ------------------------------------------------------


async def test_prune_drops_stale_entity_keeps_fresh_entity(tmp_path):
    root = str(tmp_path)
    stale = _NOW - timedelta(days=100)
    fresh = _NOW - timedelta(days=1)
    await _seed_entity(root, "hmac:stale", stale)
    await _seed_entity(root, "hmac:fresh", fresh)

    result = await prune_stale_entities(root, older_than_days=90, now=_NOW)

    assert result["entities_pruned"] == 1
    assert all(v == 0 for v in (await _row_counts(root, "hmac:stale")).values())
    assert all(v == 1 for v in (await _row_counts(root, "hmac:fresh")).values())


async def test_prune_boundary_exact_cutoff_kept_one_second_older_pruned(tmp_path):
    root = str(tmp_path)
    cutoff_exact = _NOW - timedelta(days=90)  # exactly at the boundary -> kept
    just_over = cutoff_exact - timedelta(seconds=1)  # 1s older than the boundary -> pruned
    await _seed_entity(root, "hmac:exact", cutoff_exact)
    await _seed_entity(root, "hmac:over", just_over)

    result = await prune_stale_entities(root, older_than_days=90, now=_NOW)

    assert result["entities_pruned"] == 1
    assert all(v == 1 for v in (await _row_counts(root, "hmac:exact")).values())
    assert all(v == 0 for v in (await _row_counts(root, "hmac:over")).values())


async def test_prune_never_touches_the_decisions_table(tmp_path):
    root = str(tmp_path)
    stale = _NOW - timedelta(days=365)
    await _seed_entity(root, "hmac:stale", stale)
    async with open_db(root) as conn:
        await conn.execute(
            "INSERT INTO decisions (ts, action_id, final_verdict, entity_id) "
            "VALUES (?, 'a1', 'PASS', 'hmac:stale')",
            (stale.isoformat(),),
        )
        await conn.commit()

    await prune_stale_entities(root, older_than_days=1, now=_NOW)

    async with open_db(root) as conn:
        async with conn.execute("SELECT COUNT(*) FROM decisions") as cur:
            assert (await cur.fetchone())[0] == 1  # untouched


async def test_prune_with_no_entities_is_a_no_op(tmp_path):
    result = await prune_stale_entities(str(tmp_path), older_than_days=30, now=_NOW)
    assert result["entities_pruned"] == 0
    assert all(v == 0 for k, v in result.items() if k != "entities_pruned")


async def test_prune_raises_rather_than_reporting_a_partial_success(tmp_path):
    (tmp_path / ".doberman").mkdir()
    (tmp_path / ".doberman" / "doberman.db").write_bytes(b"not a sqlite database")

    raised = False
    try:
        await prune_stale_entities(str(tmp_path), older_than_days=30, now=_NOW)
    except Exception:  # noqa: BLE001 — asserting *some* exception propagates
        raised = True
    assert raised
