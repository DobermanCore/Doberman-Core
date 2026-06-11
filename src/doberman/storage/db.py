"""Local SQLite storage (Features 7–8).

Doberman is local-first: persistent state lives in ``.doberman/doberman.db`` —
a per-repo SQLite database that is **never committed** (``.doberman/`` is
gitignored). Feature 7 introduced it to persist **role elevations** (slice 7.4);
Feature 8 adds the **decision log** and the **secret-fingerprint store**, plus
the (initially empty) ``baseline_counts`` (F9) and ``policy_changes`` (F10)
tables so later features only ever read/write, never migrate the shape.

This module owns schema creation and the low-level queries. The decision-log
*writer* and its redaction live in :mod:`doberman.storage.log`; the elevation
*matching* logic lives in :mod:`doberman.auth.elevation` — so neither the engine
nor the redaction layer depends on the database internals.

SECURITY / resilience:

* The DB file is created ``0600`` inside a ``0700`` directory (best-effort;
  Windows ACLs make ``chmod`` a no-op).
* **No column can hold a raw secret, a raw path-to-a-secret, a full file, or an
  unredacted prompt** — the schema makes it structurally impossible. The
  ``decisions`` table stores a path *class* (never the raw target), reason
  codes, verdicts, and ids; secrets are represented only by HMAC fingerprints
  in ``secret_fingerprints``.
* Reads **fail closed**: any error querying active grants returns an empty list,
  so a corrupt/locked DB can only ever cause an action to *stay* at ``AUTH`` —
  never to be silently elevated. ``busy_timeout`` lets a locked DB retry.
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

#: Current schema version. Bumped to 2 in Feature 8 (decision log + stores).
SCHEMA_VERSION = 2

# Every table uses CREATE TABLE IF NOT EXISTS so opening an older DB transparently
# adds the new tables (a forward-only, additive migration). No column ever holds
# a raw secret/path/file/prompt — see the module docstring.
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

CREATE TABLE IF NOT EXISTS decisions (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    ts                TEXT NOT NULL,
    action_id         TEXT NOT NULL,
    agent_role        TEXT,
    action_type       TEXT,
    target_path_class TEXT,
    risk              TEXT,
    source_context    TEXT,
    final_verdict     TEXT NOT NULL,
    decided_layer     TEXT,
    reason_codes_json TEXT,
    auth_required     INTEGER NOT NULL DEFAULT 0,
    auth_result       TEXT,
    elevation_id      TEXT
);

CREATE TABLE IF NOT EXISTS secret_fingerprints (
    fingerprint       TEXT PRIMARY KEY,
    label             TEXT,
    first_seen        TEXT,
    last_seen         TEXT,
    source_path_class TEXT
);

CREATE TABLE IF NOT EXISTS baseline_counts (
    feature_key TEXT PRIMARY KEY,
    count       INTEGER NOT NULL DEFAULT 0,
    first_seen  TEXT,
    last_seen   TEXT
);

CREATE TABLE IF NOT EXISTS policy_changes (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              TEXT NOT NULL,
    rule_id         TEXT,
    from_state      TEXT,
    to_state        TEXT,
    classification  TEXT,
    reason          TEXT,
    approval_method TEXT,
    approved        INTEGER,
    approved_by     TEXT
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
    # Additive migration: executescript creates any missing tables on an older
    # DB without touching existing data, then we record the current version
    # (replace the single row so an upgraded DB reflects the new schema).
    await conn.executescript(_SCHEMA)
    await conn.execute("DELETE FROM schema_version")
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
