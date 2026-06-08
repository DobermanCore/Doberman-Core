"""Local SQLite storage (Feature 7; extended by Feature 8).

Doberman is local-first: persistent state lives in ``.doberman/doberman.db`` —
a per-repo SQLite database that is **never committed** (``.doberman/`` is
gitignored). Feature 7 introduces it to persist **role elevations** (slice 7.4);
Feature 8 extends the same schema with the decision log and fingerprint store.

This module owns schema creation and the elevation queries. The *matching* logic
(which grant covers which target) lives in :mod:`doberman.auth.elevation` so the
decision engine can reason about elevations without depending on the database.

SECURITY / resilience:

* The DB file is created ``0600`` inside a ``0700`` directory (best-effort;
  Windows ACLs make ``chmod`` a no-op). No elevation row holds a raw secret —
  only a path **glob**, ids, and timestamps.
* Reads **fail closed toward no-elevation**: any error querying active grants
  returns an empty list, so a corrupt/locked DB can only ever cause an action to
  *stay* at ``AUTH`` — never to be silently elevated. Writes surface errors to
  the caller (the proxy treats a failed grant as "not authorized").
* ``busy_timeout`` lets a momentarily-locked DB retry rather than erroring.
"""

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import aiosqlite

from doberman.auth.elevation import DEFAULT_TTL_SECONDS, ElevationGrant

CONFIG_DIR = ".doberman"
DB_FILE = "doberman.db"

#: Current schema version. Feature 8 bumps this when it adds its tables.
SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);

CREATE TABLE IF NOT EXISTS elevations (
    id          TEXT PRIMARY KEY,
    scope_glob  TEXT NOT NULL,
    task_id     TEXT,
    granted_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    revoked     INTEGER NOT NULL DEFAULT 0,
    single_use  INTEGER NOT NULL DEFAULT 0,
    used        INTEGER NOT NULL DEFAULT 0
);
"""


def db_path(repo_root: str = ".") -> Path:
    """Path to the per-repo SQLite database (never committed)."""
    return Path(repo_root) / CONFIG_DIR / DB_FILE


def _restrict_permissions(path: Path) -> None:
    """Best-effort tighten the DB dir/file to owner-only (no-op on Windows ACLs)."""
    try:
        os.chmod(path.parent, 0o700)
        if path.exists():
            os.chmod(path, 0o600)
    except OSError:
        pass


async def _ensure_schema(conn: aiosqlite.Connection) -> None:
    await conn.executescript(_SCHEMA)
    async with conn.execute("SELECT COUNT(*) FROM schema_version") as cur:
        row = await cur.fetchone()
    if row is not None and row[0] == 0:
        await conn.execute("INSERT INTO schema_version (version) VALUES (?)", (SCHEMA_VERSION,))
    await conn.commit()


@asynccontextmanager
async def open_db(repo_root: str = ".") -> AsyncIterator[aiosqlite.Connection]:
    """Open (creating if needed) the repo DB with the schema ensured.

    Creates ``.doberman/`` ``0700`` and the DB file ``0600`` on first use.
    """
    path = db_path(repo_root)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    conn = await aiosqlite.connect(str(path))
    try:
        await conn.execute("PRAGMA busy_timeout = 3000")
        await _ensure_schema(conn)
        _restrict_permissions(path)
        yield conn
    finally:
        await conn.close()


def _parse_dt(value: str) -> datetime:
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _row_to_grant(row: aiosqlite.Row | tuple) -> ElevationGrant:
    return ElevationGrant(
        id=row[0],
        scope_glob=row[1],
        task_id=row[2],
        granted_at=_parse_dt(row[3]),
        expires_at=_parse_dt(row[4]),
        revoked=bool(row[5]),
        single_use=bool(row[6]),
        used=bool(row[7]),
    )


_SELECT_ALL = (
    "SELECT id, scope_glob, task_id, granted_at, expires_at, revoked, single_use, used "
    "FROM elevations"
)


async def grant_elevation(
    repo_root: str,
    scope_glob: str,
    task_id: str | None,
    *,
    now: datetime,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    single_use: bool = False,
) -> ElevationGrant:
    """Persist and return a new narrow, time-limited elevation grant.

    The caller is responsible for ensuring ``scope_glob`` is narrow (a canonical
    single-path glob from :func:`doberman.auth.elevation.scope_for_target`);
    this layer only persists what it is given.
    """
    grant = ElevationGrant(
        id=uuid4().hex,
        scope_glob=scope_glob,
        task_id=task_id,
        granted_at=now,
        expires_at=now + timedelta(seconds=ttl_seconds),
        single_use=single_use,
    )
    async with open_db(repo_root) as conn:
        await conn.execute(
            "INSERT INTO elevations "
            "(id, scope_glob, task_id, granted_at, expires_at, revoked, single_use, used) "
            "VALUES (?, ?, ?, ?, ?, 0, ?, 0)",
            (
                grant.id,
                grant.scope_glob,
                grant.task_id,
                grant.granted_at.isoformat(),
                grant.expires_at.isoformat(),
                int(grant.single_use),
            ),
        )
        await conn.commit()
    return grant


async def active_elevations(repo_root: str, now: datetime) -> list[ElevationGrant]:
    """Return all currently-usable grants (not expired/revoked/spent).

    Fails closed: any storage error returns ``[]`` — no DB problem can ever add
    an elevation, only remove one. Short-circuits (no DB creation) when no
    database exists yet — the overwhelmingly common no-elevation case.
    """
    if not db_path(repo_root).exists():
        return []
    try:
        async with open_db(repo_root) as conn:
            async with conn.execute(_SELECT_ALL) as cur:
                rows = await cur.fetchall()
    except (aiosqlite.Error, OSError, ValueError):
        return []
    grants = [_row_to_grant(row) for row in rows]
    return [g for g in grants if g.is_active(now)]


async def revoke_elevation(repo_root: str, elevation_id: str) -> bool:
    """Mark an elevation revoked. Returns ``True`` if a row was updated."""
    async with open_db(repo_root) as conn:
        cur = await conn.execute("UPDATE elevations SET revoked = 1 WHERE id = ?", (elevation_id,))
        await conn.commit()
        return cur.rowcount > 0


async def mark_used(repo_root: str, elevation_id: str) -> None:
    """Mark a single-use elevation spent (best-effort; never raises into forward)."""
    try:
        async with open_db(repo_root) as conn:
            await conn.execute("UPDATE elevations SET used = 1 WHERE id = ?", (elevation_id,))
            await conn.commit()
    except (aiosqlite.Error, OSError):
        return
