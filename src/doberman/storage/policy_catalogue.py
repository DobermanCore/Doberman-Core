"""Policy catalogue: every policy version that has been in force in this repo.

A **policy version** is a content identity, not a label: ``"pv1:"`` followed by
the SHA-256 of the canonical JSON of a :class:`PolicySnapshotV1` — the exact
inputs the engine reads that a human can change (the saved policy document
minus cosmetic text, the active role's globs, the ledger-verified enforcement
state, and the engine version, which pins the rule set). Two repos with the
same configuration and the same Doberman release get the same id, and anyone
holding the snapshot can recompute it (plain SHA-256, deliberately not the
keyed HMAC in :mod:`doberman.storage.fingerprint`). ADR 0088.

The store (``.doberman/policies.db``, stdlib ``sqlite3``) is **append-only**:
``policy_versions`` holds each canonical snapshot once, ``policy_observations``
records every time the version in force was seen to change. It is a separate
file from ``doberman.db`` so ``decision-log-prune`` never touches it and it can
be exported on its own.

SECURITY / resilience:

* Never on the decision path. Nothing here can alter a verdict; every write is
  best-effort (log + continue) and every read fails closed to nothing.
* Redaction by construction: a snapshot holds enums, numbers, booleans,
  checklist ids, and operator-authored globs — the same material already in
  ``policies.yaml`` / ``role.yaml`` in the same ``0600`` directory. Item and
  role *descriptions*, ``message_tone``, ledger reasons, target paths, secrets,
  and prompts have no field to land in.
* This module is policy core: it never imports ``doberman.proxy``.
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from doberman.policy.checklist import PolicyDoc
from doberman.roles.roles import RoleDefinition

logger = logging.getLogger("doberman.storage.policy_catalogue")

#: Snapshot schema carried inside every canonical snapshot (JSON key ``schema``).
SNAPSHOT_SCHEMA = 1
#: Every version id starts with this; the rest is a 64-char lower-case SHA-256 hex.
VERSION_PREFIX = "pv1:"

_ENFORCEMENT_STATES = ("enforce", "monitor", "off")
#: Keys of ``PolicyDoc.to_mapping()`` that never change a verdict and so never
#: mint a version.
_COSMETIC_DOC_KEYS = ("message_tone",)


class RoleSnapshot(BaseModel):
    """The verdict-relevant part of the active role (globs only, no description)."""

    model_config = ConfigDict(frozen=True)

    name: str
    allowed: tuple[str, ...] = ()
    suspicious: tuple[str, ...] = ()
    blocked: tuple[str, ...] = ()


class PolicySnapshotV1(BaseModel):
    """The exact content a policy version identifies (immutable).

    ``schema_version`` serialises as the JSON key ``schema`` (the field name
    avoids shadowing ``BaseModel.schema``).
    """

    model_config = ConfigDict(frozen=True, populate_by_name=True)

    schema_version: int = Field(default=SNAPSHOT_SCHEMA, alias="schema")
    engine: str
    enforcement_effective: str
    doc: dict[str, Any]
    role: RoleSnapshot | None = None


def snapshot_doc(doc: PolicyDoc) -> dict[str, Any]:
    """``PolicyDoc.to_mapping()`` minus everything that cannot change a verdict."""
    mapping = doc.to_mapping()
    for key in _COSMETIC_DOC_KEYS:
        mapping.pop(key, None)
    mapping["items"] = [
        {key: value for key, value in item.items() if key != "description"}
        for item in mapping.get("items", [])
    ]
    return mapping


def build_snapshot(
    doc: PolicyDoc,
    role: RoleDefinition | None,
    enforcement_effective: str,
    engine: str,
) -> PolicySnapshotV1:
    """Assemble the snapshot; an unrecognised enforcement state records as ``enforce``."""
    state = str(enforcement_effective).strip().lower()
    if state not in _ENFORCEMENT_STATES:
        state = "enforce"
    role_snapshot = (
        None
        if role is None
        else RoleSnapshot(
            name=role.name,
            allowed=role.allowed,
            suspicious=role.suspicious,
            blocked=role.blocked,
        )
    )
    return PolicySnapshotV1(
        engine=str(engine),
        enforcement_effective=state,
        doc=snapshot_doc(doc),
        role=role_snapshot,
    )


def canonical_json(snapshot: PolicySnapshotV1) -> str:
    """The bytes that are hashed: sorted keys, no whitespace, UTF-8 kept as-is."""
    return json.dumps(
        snapshot.model_dump(mode="json", by_alias=True),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def policy_version(snapshot: PolicySnapshotV1) -> str:
    """``pv1:`` + SHA-256 hex of :func:`canonical_json`."""
    digest = hashlib.sha256(canonical_json(snapshot).encode("utf-8")).hexdigest()
    return VERSION_PREFIX + digest


def effective_enforcement_at_save(doc: PolicyDoc, now: datetime) -> str:
    """The enforcement state a just-saved policy is acting under (pure timer rule).

    Used on the save path only: the gate has just run, so the on-disk state is
    ledger-legitimate by construction and only the soften timer needs applying.
    Mirrors the clamp in :func:`doberman.policy.drift.effective_enforcement`
    without its ledger read (which fails closed inside a running event loop).
    """
    state = str(doc.enforcement).strip().lower()
    if state == "enforce" or state not in _ENFORCEMENT_STATES:
        return "enforce"
    expires_at = doc.enforcement_expires_at
    if expires_at is not None and now.timestamp() >= expires_at:
        revert = str(doc.enforcement_revert).strip().lower()
        return revert if revert in ("enforce", "monitor") else "enforce"
    return state


# --- The store: .doberman/policies.db --------------------------------------

CONFIG_DIR = ".doberman"
CATALOGUE_FILE = "policies.db"
#: Bumped only for an additive change; a hashed-content change bumps SNAPSHOT_SCHEMA.
CATALOGUE_SCHEMA_VERSION = 1

ORIGIN_CHANGE = "change"  # written by save_policy right after a gated/ledgered write
ORIGIN_OBSERVED = "observed"  # doctor / policy-versions saw this version in force

_SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);

CREATE TABLE IF NOT EXISTS policy_versions (
    version    TEXT PRIMARY KEY,
    canonical  TEXT NOT NULL,
    first_seen TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS policy_observations (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT NOT NULL,
    version   TEXT NOT NULL REFERENCES policy_versions(version),
    origin    TEXT NOT NULL,
    ledger_ts TEXT
);
CREATE INDEX IF NOT EXISTS idx_policy_observations_ts ON policy_observations (ts, id);
"""


def catalogue_path(repo_root: str = ".") -> Path:
    """Path to the per-repo catalogue (never committed; sibling of ``doberman.db``)."""
    return Path(repo_root) / CONFIG_DIR / CATALOGUE_FILE


def _connect(repo_root: str) -> sqlite3.Connection:
    """Open (creating if needed) the catalogue in autocommit mode with the schema ensured."""
    from doberman.storage.db import _restrict_permissions

    path = catalogue_path(repo_root)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    conn = sqlite3.connect(str(path), timeout=3.0, isolation_level=None)
    conn.execute("PRAGMA busy_timeout = 3000")
    conn.executescript(_SCHEMA)
    # Insert-if-absent keeps this module free of mutating SQL (append-only, literally).
    conn.execute(
        "INSERT INTO schema_version (version) SELECT ? "
        "WHERE NOT EXISTS (SELECT 1 FROM schema_version)",
        (CATALOGUE_SCHEMA_VERSION,),
    )
    _restrict_permissions(path)
    return conn


def record_version(
    repo_root: str,
    snapshot: PolicySnapshotV1,
    *,
    origin: str,
    ledger_ts: str | None = None,
    now: datetime | None = None,
) -> str:
    """Store ``snapshot`` once and append an observation if the version in force changed.

    Returns the version id (computed without I/O, so it is returned even when
    the write fails). ``BEGIN IMMEDIATE`` serialises concurrent writers so two
    hook processes cannot both decide "the latest observation differs".
    """
    version = policy_version(snapshot)
    stamp = (now or datetime.now(timezone.utc)).isoformat()
    try:
        conn = _connect(repo_root)
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "INSERT OR IGNORE INTO policy_versions (version, canonical, first_seen) "
                "VALUES (?, ?, ?)",
                (version, canonical_json(snapshot), stamp),
            )
            latest = conn.execute(
                "SELECT version FROM policy_observations ORDER BY id DESC LIMIT 1"
            ).fetchone()
            if latest is None or latest[0] != version:
                conn.execute(
                    "INSERT INTO policy_observations (ts, version, origin, ledger_ts) "
                    "VALUES (?, ?, ?, ?)",
                    (stamp, version, origin, ledger_ts),
                )
            conn.execute("COMMIT")
        finally:
            conn.close()
    except Exception as exc:  # noqa: BLE001 — observational; the caller's work is already done
        logger.warning("policy catalogue write failed; continuing: %s", exc)
    return version


def current_snapshot(
    repo_root: str = ".", *, enforcement_effective: str | None = None
) -> PolicySnapshotV1 | None:
    """The snapshot of the policy in force right now, or ``None`` if it cannot be built.

    With no saved policy the recommended defaults *are* the policy in force.
    ``enforcement_effective`` lets a caller that already resolved the state pass
    it in; otherwise the ledger-verified sync resolver is used (fine for the
    CLI/doctor, which run with no event loop).
    """
    try:
        from doberman import __version__
        from doberman.config import load_active_role, load_policy, resolve_enforcement_sync
        from doberman.policy.checklist import recommend_policy

        doc = load_policy(repo_root) or recommend_policy()
        role = load_active_role(repo_root)
        state = (
            enforcement_effective
            if enforcement_effective is not None
            else resolve_enforcement_sync(repo_root)
        )
        return build_snapshot(doc, role, state, __version__)
    except Exception as exc:  # noqa: BLE001 — never raise into a caller for a snapshot
        logger.warning("policy catalogue: could not build the current policy snapshot: %s", exc)
        return None


def observe_current(
    repo_root: str = ".",
    *,
    origin: str,
    ledger_ts: str | None = None,
    enforcement_effective: str | None = None,
    now: datetime | None = None,
) -> str | None:
    """Record the policy in force right now; returns its version id (``None`` if unbuildable)."""
    snapshot = current_snapshot(repo_root, enforcement_effective=enforcement_effective)
    if snapshot is None:
        return None
    return record_version(repo_root, snapshot, origin=origin, ledger_ts=ledger_ts, now=now)


def _read(repo_root: str, sql: str, params: tuple = ()) -> list[tuple]:
    """Read-only query; a missing or unreadable catalogue yields ``[]`` (fail closed)."""
    path = catalogue_path(repo_root)
    if not path.exists():
        return []
    try:
        conn = sqlite3.connect(str(path), timeout=3.0)
        try:
            return conn.execute(sql, params).fetchall()
        finally:
            conn.close()
    except Exception as exc:  # noqa: BLE001 — a broken catalogue reads as empty, never as a guess
        logger.warning("policy catalogue read failed: %s", exc)
        return []


def _meta(canonical: str) -> dict[str, Any]:
    try:
        data = json.loads(canonical)
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def read_versions(repo_root: str = ".") -> list[dict[str, Any]]:
    """Every stored version, newest first: ``{version, first_seen, engine, schema}`` (no content)."""
    rows = _read(
        repo_root,
        "SELECT version, canonical, first_seen FROM policy_versions "
        "ORDER BY first_seen DESC, version",
    )
    out: list[dict[str, Any]] = []
    for version, canonical, first_seen in rows:
        meta = _meta(canonical)
        out.append(
            {
                "version": version,
                "first_seen": first_seen,
                "engine": meta.get("engine"),
                "schema": meta.get("schema"),
            }
        )
    return out


def read_snapshot(repo_root: str, version: str) -> dict[str, Any] | None:
    """The parsed canonical snapshot of one version, or ``None``."""
    rows = _read(repo_root, "SELECT canonical FROM policy_versions WHERE version = ?", (version,))
    if not rows:
        return None
    return _meta(rows[0][0]) or None


def read_observations(repo_root: str = ".", *, limit: int | None = None) -> list[dict[str, Any]]:
    """Observations newest first: ``{ts, version, origin, ledger_ts}``."""
    sql = "SELECT ts, version, origin, ledger_ts FROM policy_observations ORDER BY id DESC"
    params: tuple = ()
    if limit is not None:
        sql += " LIMIT ?"
        params = (max(0, int(limit)),)
    return [
        {"ts": ts, "version": version, "origin": origin, "ledger_ts": ledger_ts}
        for ts, version, origin, ledger_ts in _read(repo_root, sql, params)
    ]


def version_at(repo_root: str, ts: str) -> str | None:
    """The version in force at ISO-8601 UTC ``ts``: the latest observation at or before it."""
    rows = _read(
        repo_root,
        "SELECT version FROM policy_observations WHERE ts <= ? ORDER BY ts DESC, id DESC LIMIT 1",
        (ts,),
    )
    return rows[0][0] if rows else None


def find_versions(repo_root: str, hex_prefix: str) -> list[str]:
    """Versions whose id starts with ``hex_prefix`` (with or without ``pv1:``)."""
    needle = (
        hex_prefix[len(VERSION_PREFIX) :] if hex_prefix.startswith(VERSION_PREFIX) else hex_prefix
    )
    needle = needle.strip().lower()
    if not needle or any(ch not in "0123456789abcdef" for ch in needle):
        return []
    rows = _read(
        repo_root,
        "SELECT version FROM policy_versions WHERE version LIKE ? ORDER BY version",
        (VERSION_PREFIX + needle + "%",),
    )
    return [row[0] for row in rows]


def verify_catalogue(repo_root: str = ".") -> dict[str, Any]:
    """Recompute every stored digest and compare the on-disk policy with the last observation.

    ``status``: ``ok`` · ``mismatch`` (a stored canonical no longer hashes to its
    id — the store was altered) · ``drift`` (the policy on disk is not the last
    recorded version — a change nobody has observed yet, or no catalogue at all).
    Read-only: it never records anything.
    """
    rows = _read(repo_root, "SELECT version, canonical FROM policy_versions")
    mismatched = [
        version
        for version, canonical in rows
        if VERSION_PREFIX + hashlib.sha256(canonical.encode("utf-8")).hexdigest() != version
    ]
    snapshot = current_snapshot(repo_root)
    current = policy_version(snapshot) if snapshot is not None else None
    latest = read_observations(repo_root, limit=1)
    recorded = latest[0]["version"] if latest else None
    if mismatched:
        status = "mismatch"
    elif current is None or current != recorded:
        status = "drift"
    else:
        status = "ok"
    return {
        "status": status,
        "versions": len(rows),
        "mismatched": mismatched,
        "current": current,
        "recorded": recorded,
    }
