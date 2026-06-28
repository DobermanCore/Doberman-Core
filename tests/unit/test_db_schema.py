"""Slice 8.1 — SQLite schema, migrations, and the no-secret-column guarantee."""

import asyncio
import os
import stat

from doberman.storage.db import SCHEMA_VERSION, db_path, open_db

_EXPECTED_TABLES = {
    "schema_version",
    "elevations",
    "decisions",
    "secret_fingerprints",
    "baseline_counts",
    "policy_changes",
    "cost_events",
}

#: Column names that would (or could) hold raw secret material. The decisions
#: table must contain NONE of these — only a path *class*, codes, and ids.
_FORBIDDEN_COLUMNS = {
    "target",  # the raw path — only target_path_class is allowed
    "raw_args",
    "raw_arguments",
    "arguments",
    "content",
    "secret",
    "prompt",
    "password",
    "payload",
}


async def _table_names(conn) -> set[str]:
    async with conn.execute("SELECT name FROM sqlite_master WHERE type='table'") as cur:
        return {row[0] for row in await cur.fetchall()}


async def _columns(conn, table: str) -> list[str]:
    async with conn.execute(f"PRAGMA table_info({table})") as cur:  # noqa: S608 — fixed table name
        return [row[1] for row in await cur.fetchall()]


async def test_schema_creates_all_tables(tmp_path):
    async with open_db(str(tmp_path)) as conn:
        tables = await _table_names(conn)
    assert _EXPECTED_TABLES <= tables


async def test_version_row_records_current_schema(tmp_path):
    async with open_db(str(tmp_path)) as conn:
        async with conn.execute("SELECT version FROM schema_version") as cur:
            rows = await cur.fetchall()
    assert [r[0] for r in rows] == [SCHEMA_VERSION]


async def test_decisions_table_has_no_secret_bearing_columns(tmp_path):
    async with open_db(str(tmp_path)) as conn:
        cols = set(await _columns(conn, "decisions"))
    assert cols & _FORBIDDEN_COLUMNS == set()
    assert "target_path_class" in cols  # the redacted class IS present


async def test_cost_events_table_has_no_secret_bearing_columns(tmp_path):
    async with open_db(str(tmp_path)) as conn:
        cols = set(await _columns(conn, "cost_events"))
    assert cols & _FORBIDDEN_COLUMNS == set()
    assert {"kind", "units", "entity_id"} <= cols  # counts + coarse class + keyed id only


async def test_schema_creation_is_idempotent(tmp_path):
    root = str(tmp_path)
    async with open_db(root):
        pass
    async with open_db(root) as conn:  # second open must not duplicate or error
        async with conn.execute("SELECT COUNT(*) FROM schema_version") as cur:
            count = (await cur.fetchone())[0]
    assert count == 1


def test_db_file_is_owner_only(tmp_path):
    async def _create():
        async with open_db(str(tmp_path)):
            pass

    asyncio.run(_create())
    path = db_path(str(tmp_path))
    assert path.exists()
    if os.name != "nt":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
