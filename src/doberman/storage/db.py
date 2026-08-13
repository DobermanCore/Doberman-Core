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

#: Current schema version. Bumped to 2 in Feature 8 (decision log + stores), to 3
#: for the universal subjective layer (SL4/SL6/SL8: baselines re-keyed by entity,
#: transitions, score history, preference feedback), to 4 for the host-hook sticky
#: taint ledger (HK.5.1: decisions.session_id + the session_taint table), to 5 for
#: Feature CB (CB.1: the append-only ``cost_events`` meter ledger), to 6 for the
#: read-vs-send exfil store (HK.5.2b: session_secret_fingerprints), to 7 for the
#: shadow-only adjudication ledger (adaptive-precision Phase 0: shadow_adjudications;
#: additive CREATE TABLE — no legacy migration needed), to 8 for the dashboard's
#: pending-approval queue (D3: pending_approvals; additive CREATE TABLE), and to 9
#: for memory-governance retention stamps (Subj1: a ``last_touched`` ISO-timestamp
#: column on every baseline/preference table — baseline_counts, baseline_transitions,
#: baseline_state, score_history, preference_feedback — additive ALTER, backfilled
#: once from each table's existing timestamp column so ``doberman memory prune``
#: works immediately on data written before this migration), and to 10 for the
#: task-match ledger (D2: session_task_hosts — additive CREATE TABLE; registered-
#: domain tokens extracted from the TRUSTED (typed-only) user prompt at the turn
#: gate, never the raw prompt text).
SCHEMA_VERSION = 10

# Every table uses CREATE TABLE IF NOT EXISTS so opening an older DB transparently
# adds the new tables (a forward-only, additive migration; the one re-shape —
# baseline_counts gaining its entity_id key — is handled by _migrate_legacy). No
# column ever holds a raw secret/path/file/prompt — see the module docstring.
# entity_id values are keyed HMAC fingerprints, never raw role/path strings.
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
    elevation_id      TEXT,
    entity_id         TEXT,
    session_id        TEXT
);

CREATE TABLE IF NOT EXISTS secret_fingerprints (
    fingerprint       TEXT PRIMARY KEY,
    label             TEXT,
    first_seen        TEXT,
    last_seen         TEXT,
    source_path_class TEXT
);

-- Sticky, monotonic taint ledger (HK.5.1): the *ingredients* of a multi-step
-- exfiltration (a secret was accessed, untrusted data was read) accumulated per
-- session or per entity scope. `scope` is an opaque harness session id or a
-- keyed-HMAC entity fingerprint; `kind` is a fixed constant; `count` only ever
-- rises. No raw secret/path/prompt is stored. HK.5.2 consumes it to raise risk.
CREATE TABLE IF NOT EXISTS session_taint (
    scope      TEXT NOT NULL,
    kind       TEXT NOT NULL,
    first_seen TEXT,
    last_seen  TEXT,
    count      INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (scope, kind)
);

-- Read-vs-send exfil store (HK.5.2b): keyed-HMAC fingerprints of the secrets that
-- entered a scope's context (recorded when a tool output is found to carry a
-- secret), so a later egress carrying the SAME value is a *confirmed* exfiltration
-- (-> BLOCK). `scope` is an opaque session id or a keyed-HMAC entity fingerprint;
-- `fingerprint` is a keyed HMAC of the secret token. No raw secret is ever stored.
CREATE TABLE IF NOT EXISTS session_secret_fingerprints (
    scope       TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    first_seen  TEXT,
    PRIMARY KEY (scope, fingerprint)
);

-- Task-match ledger (D2): registered-domain tokens extracted from the TRUSTED,
-- typed-only portion of the user's turn (never a pasted/tool-fetched segment —
-- see turngate/task_tokens.py), scoped by the harness session id (the same
-- HK.5.1 session id session_taint/decisions.session_id already use). Consumed
-- by the C3.1 correlator to soften `correlated_trifecta` for an egress the
-- user's own prompt actually named. `host` is a decoded hostname string, not a
-- secret — the invariant this table preserves is "never the raw prompt", not
-- "never a domain name" (Doberman already ships plaintext trusted hosts in
-- engine/rules/destinations.py's TRUSTED_HOSTS).
CREATE TABLE IF NOT EXISTS session_task_hosts (
    scope      TEXT NOT NULL,
    host       TEXT NOT NULL,
    first_seen TEXT,
    last_seen  TEXT,
    PRIMARY KEY (scope, host)
);

CREATE TABLE IF NOT EXISTS baseline_counts (
    entity_id    TEXT NOT NULL,
    feature_key  TEXT NOT NULL,
    role         TEXT,
    count        INTEGER NOT NULL DEFAULT 0,
    mean         REAL NOT NULL DEFAULT 0,
    m2           REAL NOT NULL DEFAULT 0,
    ewma_var     REAL NOT NULL DEFAULT 0,
    first_seen   TEXT,
    last_seen    TEXT,
    last_touched TEXT,
    PRIMARY KEY (entity_id, feature_key)
);

CREATE TABLE IF NOT EXISTS baseline_transitions (
    entity_id    TEXT NOT NULL,
    from_state   TEXT NOT NULL,
    to_state     TEXT NOT NULL,
    count        INTEGER NOT NULL DEFAULT 0,
    last_touched TEXT,
    PRIMARY KEY (entity_id, from_state, to_state)
);

CREATE TABLE IF NOT EXISTS baseline_state (
    entity_id    TEXT PRIMARY KEY,
    last_state   TEXT,
    prev_state   TEXT,
    last_touched TEXT
);

CREATE TABLE IF NOT EXISTS score_history (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_id    TEXT NOT NULL,
    ts           TEXT NOT NULL,
    kind         TEXT NOT NULL,
    value        REAL NOT NULL,
    last_touched TEXT
);
CREATE INDEX IF NOT EXISTS idx_score_history ON score_history (entity_id, kind, id);

CREATE TABLE IF NOT EXISTS preference_feedback (
    entity_id    TEXT NOT NULL,
    dimension    TEXT NOT NULL,
    approvals    INTEGER NOT NULL DEFAULT 0,
    denials      INTEGER NOT NULL DEFAULT 0,
    updated_at   TEXT,
    last_touched TEXT,
    PRIMARY KEY (entity_id, dimension)
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

CREATE TABLE IF NOT EXISTS cost_events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT NOT NULL,
    action_id TEXT NOT NULL,
    kind      TEXT NOT NULL,
    units     INTEGER NOT NULL DEFAULT 0,
    model     TEXT,
    entity_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_cost_events ON cost_events (entity_id, kind, id);

-- Shadow-only adjudication ledger (adaptive-precision Phase 0): what a
-- second-opinion adjudicator WOULD have recommended for an AUTH decision. It is
-- observability, never the decision path — a row here can never alter a verdict.
-- Redaction-safe by construction: verdict/reason-code CLASSES only, plus the
-- action id, the live verdict, and a keyed-HMAC entity_id. No raw secret/path/
-- prompt is ever stored.
CREATE TABLE IF NOT EXISTS shadow_adjudications (
    id                  INTEGER PRIMARY KEY,
    ts                  TEXT,
    action_id           TEXT,
    live_verdict        TEXT,
    shadow_verdict      TEXT,
    shadow_reason_codes TEXT,
    entity_id           TEXT
);

-- Dashboard pending-approval queue (D3): mediates an AUTH challenge between
-- the decision-path process (which writes a row via DashboardPrompter) and
-- the dash server process (which shows it and posts a resolution) - no HTTP
-- ever touches the decision path itself. Display fields are the SAME
-- redaction-safe vocabulary the terminal/GUI prompters already show a human
-- (action type, risk, reason codes, explanation, path *class*) - never the
-- raw target/arguments. `status` transitions 'pending' -> 'resolved' exactly
-- once (see storage.approvals.resolve's race-safe UPDATE ... WHERE clause).
-- `totp_code` rides the row only because the dash NEVER verifies it - the
-- prompter (decision path) is the sole consumer, via the existing
-- doberman.auth.totp.verify.
CREATE TABLE IF NOT EXISTS pending_approvals (
    id                 TEXT PRIMARY KEY,
    action_id          TEXT NOT NULL,
    created_at         TEXT NOT NULL,
    expires_at         TEXT NOT NULL,
    status             TEXT NOT NULL DEFAULT 'pending',
    tier               TEXT,
    action_type        TEXT,
    risk               TEXT,
    reason_codes_json  TEXT,
    explanation        TEXT,
    target_path_class  TEXT,
    decision           TEXT,
    totp_code          TEXT
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


async def _table_columns(conn: aiosqlite.Connection, table: str) -> list[str]:
    """Column names of ``table`` ([] when the table does not exist)."""
    async with conn.execute(f"PRAGMA table_info({table})") as cur:  # noqa: S608 — fixed names
        rows = await cur.fetchall()
    return [row[1] for row in rows]


async def _migrate_legacy(conn: aiosqlite.Connection) -> None:
    """v2 → v3: baselines become per-entity; decisions gain ``entity_id``.

    The old global ``baseline_counts`` (PK ``feature_key`` only) cannot be
    re-keyed in place, so it is DROPPED and recreated per-entity. Losing the
    learned counts is raise-SAFE by construction: a colder baseline scores
    everything as MORE novel (more step-ups, never fewer) until it relearns.
    """
    counts_cols = await _table_columns(conn, "baseline_counts")
    if counts_cols and "entity_id" not in counts_cols:
        await conn.execute("DROP TABLE baseline_counts")
    decision_cols = await _table_columns(conn, "decisions")
    if decision_cols and "entity_id" not in decision_cols:
        await conn.execute("ALTER TABLE decisions ADD COLUMN entity_id TEXT")
    # v3 → v4: decisions gain ``session_id`` (HK.5.1) so the host-hook taint
    # ledger can correlate calls within one agent session. Additive ALTER on an
    # existing table; fresh DBs get it from _SCHEMA above. session_taint itself is
    # created additively by executescript (CREATE TABLE IF NOT EXISTS).
    if decision_cols and "session_id" not in decision_cols:
        await conn.execute("ALTER TABLE decisions ADD COLUMN session_id TEXT")
    # v8 -> v9: retention stamps (Subj1) — add `last_touched` to every baseline/
    # preference table so `doberman memory prune` can find an entity's most recent
    # activity. Additive ALTER on an existing table; fresh DBs get it from _SCHEMA
    # above. Backfilled ONCE (only when the column was just added) from whichever
    # existing timestamp column that table already has, so prune works immediately
    # on data written before this migration — no invented values. Two tables never
    # had a timestamp at all (baseline_transitions, baseline_state); their rows are
    # left NULL and prune skips an entity whose activity is NULL in every table
    # (never guessing an unknown age, fail-safe) — which in practice never happens
    # for a real entity, since every observe() call also touches baseline_counts.
    for table, backfill_from in (
        ("baseline_counts", "last_seen"),
        ("baseline_transitions", None),
        ("baseline_state", None),
        ("score_history", "ts"),
        ("preference_feedback", "updated_at"),
    ):
        cols = await _table_columns(conn, table)
        if cols and "last_touched" not in cols:
            await conn.execute(f"ALTER TABLE {table} ADD COLUMN last_touched TEXT")  # noqa: S608 — table is a fixed literal above
            if backfill_from:
                await conn.execute(f"UPDATE {table} SET last_touched = {backfill_from}")  # noqa: S608 — fixed literals above


async def _ensure_schema(conn: aiosqlite.Connection) -> None:
    # Additive migration: executescript creates any missing tables on an older
    # DB without touching existing data, then we record the current version
    # (replace the single row so an upgraded DB reflects the new schema).
    # The one non-additive change (per-entity baselines) runs first.
    await _migrate_legacy(conn)
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
