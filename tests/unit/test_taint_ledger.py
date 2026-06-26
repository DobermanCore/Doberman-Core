"""HK.5.1: the sticky per-session/entity taint ledger + the v3→v4 migration.

The ledger records the *ingredients* of a multi-step exfiltration (secret-access,
untrusted-read) per scope, monotonically. It has no verdict authority here —
HK.5.2 consumes it. These tests cover the storage API, the additive schema
migration, and redaction (a scope never carries a raw path).
"""

import aiosqlite

from doberman.storage.db import db_path, open_db
from doberman.storage.taint import (
    TAINT_SECRET_ACCESS,
    TAINT_UNTRUSTED_READ,
    entity_scope,
    read_taint,
    record_taint,
    record_taints,
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
