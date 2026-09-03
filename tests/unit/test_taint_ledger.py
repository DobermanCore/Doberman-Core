"""HK.5.1: the sticky per-session/entity taint ledger + the v3→v4 migration.

The ledger records the *ingredients* of a multi-step exfiltration (secret-access,
untrusted-read) per scope, monotonically. It has no verdict authority here —
HK.5.2 consumes it. These tests cover the storage API, the additive schema
migration, and redaction (a scope never carries a raw path).
"""

from datetime import datetime, timedelta, timezone

import aiosqlite

from doberman.storage import taint as taint_module
from doberman.storage.db import db_path, open_db
from doberman.storage.taint import (
    TAINT_SECRET_ACCESS,
    TAINT_UNTRUSTED_READ,
    clear_taint,
    entity_scope,
    match_secret_fingerprint,
    match_untrusted_value,
    read_taint,
    record_secret_fingerprints,
    record_taint,
    record_taints,
    record_untrusted_values,
)


async def _columns(conn, table):
    async with conn.execute(f"PRAGMA table_info({table})") as cur:  # noqa: S608 — fixed name
        return [row[1] for row in await cur.fetchall()]


# --- storage API ---


async def test_record_and_read_taint(tmp_path):
    root = str(tmp_path)
    await record_taint(root, "sess-1", TAINT_SECRET_ACCESS)
    assert await read_taint(root, "sess-1") == {TAINT_SECRET_ACCESS: 1}


async def test_taint_is_monotonic(tmp_path):
    root = str(tmp_path)
    await record_taint(root, "sess-1", TAINT_SECRET_ACCESS)
    await record_taint(root, "sess-1", TAINT_SECRET_ACCESS)
    await record_taint(root, "sess-1", TAINT_UNTRUSTED_READ)
    assert await read_taint(root, "sess-1") == {TAINT_SECRET_ACCESS: 2, TAINT_UNTRUSTED_READ: 1}


async def test_record_taints_batch_writes_every_scope_and_kind(tmp_path):
    root = str(tmp_path)
    await record_taints(root, ["sess-1", "repo:x"], [TAINT_SECRET_ACCESS, TAINT_UNTRUSTED_READ])
    both = {TAINT_SECRET_ACCESS: 1, TAINT_UNTRUSTED_READ: 1}
    assert await read_taint(root, "sess-1") == both
    assert await read_taint(root, "repo:x") == both


async def test_record_taints_drops_empty_scopes_and_kinds(tmp_path):
    root = str(tmp_path)
    await record_taints(root, ["", None, "sess-1"], ["", TAINT_SECRET_ACCESS])
    assert await read_taint(root, "sess-1") == {TAINT_SECRET_ACCESS: 1}


async def test_read_taint_fails_closed_when_no_db(tmp_path):
    # No DB created yet → empty, never raises (a storage problem can't clear taint).
    assert await read_taint(str(tmp_path), "sess-1") == {}


async def test_read_taint_unknown_scope_is_empty(tmp_path):
    root = str(tmp_path)
    await record_taint(root, "sess-1", TAINT_SECRET_ACCESS)
    assert await read_taint(root, "nope") == {}


# --- entity scope (redaction) ---


def test_entity_scope_is_deterministic_and_prefixed():
    a = entity_scope(".")
    assert a == entity_scope(".")
    assert a.startswith("repo:")


def test_entity_scope_redacts_the_raw_path(tmp_path):
    scope = entity_scope(str(tmp_path))
    # It's "repo:" + a keyed HMAC — the raw path must not appear.
    assert str(tmp_path) not in scope
    assert tmp_path.name not in scope


# --- v3 → v4 additive migration ---


async def test_migration_adds_session_id_and_taint_table(tmp_path):
    # Simulate a pre-HK.5.1 DB: a decisions table without session_id, no
    # session_taint, with one existing row.
    path = db_path(str(tmp_path))
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = await aiosqlite.connect(str(path))
    await conn.execute(
        "CREATE TABLE decisions (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, "
        "action_id TEXT NOT NULL, final_verdict TEXT NOT NULL, entity_id TEXT)"
    )
    await conn.execute(
        "INSERT INTO decisions (ts, action_id, final_verdict) VALUES ('t','a','PASS')"
    )
    await conn.commit()
    await conn.close()

    # Opening through Doberman triggers the additive migration.
    async with open_db(str(tmp_path)) as conn:
        decision_cols = await _columns(conn, "decisions")
        assert "session_id" in decision_cols  # added by the ALTER
        assert await _columns(conn, "session_taint")  # table created by executescript
        async with conn.execute("SELECT action_id FROM decisions") as cur:
            rows = await cur.fetchall()
        assert [r[0] for r in rows] == ["a"]  # existing data preserved


async def test_fresh_db_has_session_id_and_taint_table(tmp_path):
    # A brand-new DB gets session_id from _SCHEMA (not the ALTER) and the table.
    async with open_db(str(tmp_path)) as conn:
        assert "session_id" in await _columns(conn, "decisions")
        assert "scope" in await _columns(conn, "session_taint")


async def test_reopening_a_migrated_db_is_idempotent(tmp_path):
    # Re-running _ensure_schema / _migrate_legacy on an already-v4 DB must not
    # error, double-add session_id, or lose data.
    root = str(tmp_path)
    await record_taint(root, "sess-1", TAINT_SECRET_ACCESS)  # first open → v4
    async with open_db(root) as conn:  # second open re-runs the migration guards
        cols = await _columns(conn, "decisions")
    assert cols.count("session_id") == 1  # not double-added
    assert await read_taint(root, "sess-1") == {TAINT_SECRET_ACCESS: 1}  # data intact


# --- session_untrusted_value_fingerprints (C1) ---


async def test_record_and_match_untrusted_value(tmp_path):
    root = str(tmp_path)
    await record_untrusted_values(root, ["sess-1"], ["hmac:abc"], "WebFetch")
    assert await match_untrusted_value(root, "sess-1", ["hmac:abc"]) == "WebFetch"


async def test_match_untrusted_value_no_hit_is_none(tmp_path):
    root = str(tmp_path)
    await record_untrusted_values(root, ["sess-1"], ["hmac:abc"], "WebFetch")
    assert await match_untrusted_value(root, "sess-1", ["hmac:zzz"]) is None


async def test_record_untrusted_values_drops_empty_scopes_and_fingerprints(tmp_path):
    root = str(tmp_path)
    await record_untrusted_values(root, ["", None, "sess-1"], [], "WebFetch")
    assert await match_untrusted_value(root, "sess-1", ["hmac:abc"]) is None


async def test_match_untrusted_value_fails_closed_when_no_db(tmp_path):
    assert await match_untrusted_value(str(tmp_path), "sess-1", ["hmac:abc"]) is None


# --- eviction bounds (C1 reviewer follow-up) ---


async def test_record_untrusted_values_evicts_stale_rows_past_ttl(tmp_path):
    # A fingerprint recorded more than _TTL_DAYS before a later write in the same
    # scope is evicted on that write; a fresh one recorded in the same write
    # still matches.
    root = str(tmp_path)
    old = datetime(2024, 1, 1, tzinfo=timezone.utc)
    await record_untrusted_values(root, ["sess-1"], ["hmac:stale"], "WebFetch", now=old)

    later = old + timedelta(days=taint_module._TTL_DAYS + 1)
    await record_untrusted_values(root, ["sess-1"], ["hmac:fresh"], "WebFetch", now=later)

    assert await match_untrusted_value(root, "sess-1", ["hmac:stale"]) is None
    assert await match_untrusted_value(root, "sess-1", ["hmac:fresh"]) == "WebFetch"


async def test_record_untrusted_values_overflow_keeps_newest_rows_by_first_seen(
    tmp_path, monkeypatch
):
    # Recording more than _MAX_ROWS_PER_SCOPE fingerprints in one scope keeps
    # exactly the newest _MAX_ROWS_PER_SCOPE rows (pins the ORDER BY ... DESC
    # direction in _EVICT_OVERFLOW_UNTRUSTED). Monkeypatch the cap down so the
    # test stays fast instead of writing 5000+ real rows.
    monkeypatch.setattr(taint_module, "_MAX_ROWS_PER_SCOPE", 3)
    root = str(tmp_path)
    base = datetime(2024, 1, 1, tzinfo=timezone.utc)
    fps = [f"hmac:{i}" for i in range(5)]
    for i, fp in enumerate(fps):
        await record_untrusted_values(
            root, ["sess-1"], [fp], "WebFetch", now=base + timedelta(seconds=i)
        )

    for fp in fps[:2]:  # oldest two, evicted by the row cap
        assert await match_untrusted_value(root, "sess-1", [fp]) is None
    for fp in fps[2:]:  # newest three, retained
        assert await match_untrusted_value(root, "sess-1", [fp]) == "WebFetch"


# --- final review, CRITICAL: a hard cap on the `IN (...)` query so it can ---
# never itself raise `sqlite3.OperationalError: too many SQL variables`
# (defense-in-depth backstop, independent of any caller-side aggregate cap).
# Synthetic (non-HMAC) fingerprint strings keep this fast — the point is the
# QUERY layer's own size safety, not the extraction pipeline.


async def test_match_secret_fingerprint_survives_a_fingerprint_list_past_the_sqlite_variable_limit(
    tmp_path,
):
    root = str(tmp_path)
    await record_secret_fingerprints(root, ["sess-1"], ["hmac:real-secret"])
    # This box's measured SQLite variable limit is 32766 (default since
    # 3.32.0); comfortably exceed it with cheap synthetic strings.
    huge = ["hmac:real-secret", *(f"hmac:pad{i:06d}" for i in range(40_000))]

    assert await match_secret_fingerprint(root, "sess-1", huge) is True


async def test_match_untrusted_value_survives_a_fingerprint_list_past_the_sqlite_variable_limit(
    tmp_path,
):
    root = str(tmp_path)
    await record_untrusted_values(root, ["sess-1"], ["hmac:real-value"], "WebFetch")
    huge = ["hmac:real-value", *(f"hmac:pad{i:06d}" for i in range(40_000))]

    assert await match_untrusted_value(root, "sess-1", huge) == "WebFetch"


async def test_clear_taint_now_returns_three_counts_and_clears_all_three_tables(tmp_path):
    root = str(tmp_path)
    await record_taint(root, "sess-1", TAINT_SECRET_ACCESS)
    await record_secret_fingerprints(root, ["sess-1"], ["hmac:secret"])
    await record_untrusted_values(root, ["sess-1"], ["hmac:untrusted"], "WebFetch")

    taint_rows, fp_rows, untrusted_rows = await clear_taint(root)

    assert (taint_rows, fp_rows, untrusted_rows) == (1, 1, 1)
    assert await read_taint(root, "sess-1") == {}
    assert await match_secret_fingerprint(root, "sess-1", ["hmac:secret"]) is False
    assert await match_untrusted_value(root, "sess-1", ["hmac:untrusted"]) is None
