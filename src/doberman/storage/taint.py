"""Sticky per-session / per-entity taint ledger (HK.5.1).

Records the *ingredients* of a multi-step exfiltration — that a secret was
accessed, and/or untrusted data was read — under a session scope (the harness
session id) and an entity scope (a keyed-HMAC of the repo root), so a later
egress decision can ask "has this scope already accumulated the trifecta?"
(HK.5.2 consumes this; HK.5.1 only records — it has **no verdict authority**).

Design:

* **Sticky / monotonic (raise-only):** a ``(scope, kind)`` counter only ever
  rises; nothing here clears a flag. A secret read at the start of a session
  taints it for the rest of that session — a bounded time/count window is a
  bypass an attacker just waits out (ADR 0024, structural truth #3).
* **Redaction-safe:** a ``scope`` is an opaque harness session id (a UUID) or a
  keyed-HMAC entity fingerprint; a ``kind`` is one of the fixed constants below.
  No raw secret, path, or prompt is ever stored.
* **Best-effort:** writes never raise into the execution path; reads fail closed
  to an empty result (a corrupt/locked DB can never *clear* taint).
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path

from doberman.storage.db import db_path, open_db
from doberman.storage.fingerprint import fingerprint

#: A secret / sensitive credential entered the agent's context (read into a tool
#: output, or accessed locally) — the "sensitive data" leg of the trifecta.
TAINT_SECRET_ACCESS = "secret_access"  # noqa: S105 — a taint-kind label, not a credential
#: Untrusted external data entered the agent's context (a web fetch / search) —
#: the "untrusted provenance" leg of the trifecta.
TAINT_UNTRUSTED_READ = "untrusted_read"

_UPSERT_TAINT = (
    "INSERT INTO session_taint (scope, kind, first_seen, last_seen, count) "
    "VALUES (?, ?, ?, ?, 1) "
    "ON CONFLICT(scope, kind) DO UPDATE SET last_seen = excluded.last_seen, count = count + 1"
)

_SELECT_TAINT = "SELECT kind, count FROM session_taint WHERE scope = ?"


def entity_scope(repo_root: str) -> str:
    """A stable, redaction-safe per-repo scope: ``"repo:" + HMAC(resolved root)``.

    A coarse backstop to the harness session id so taint survives a session
    rotation (read a secret in session A, exfiltrate in session B — same repo).
    Uses the same keyed-HMAC helper as every other fingerprint, so the raw path
    never appears.
    """
    try:
        resolved = str(Path(repo_root).resolve())
    except Exception:  # noqa: BLE001 — an odd root must not break taint recording
        resolved = repo_root or "."
    return "repo:" + fingerprint(resolved)


async def record_taints(
    repo_root: str,
    scopes: list[str],
    kinds: list[str],
    *,
    now: datetime | None = None,
) -> None:
    """Bump the ``(scope, kind)`` counter for every scope × kind (best-effort).

    Empty/falsy scopes and kinds are dropped. Never raises — a taint-write
    failure must never affect a verdict (the action has already been decided).
    """
    scopes = [s for s in scopes if s]
    kinds = [k for k in kinds if k]
    if not scopes or not kinds:
        return
    ts = (now or datetime.now(timezone.utc)).isoformat()
    try:
        async with open_db(repo_root) as conn:
            for scope in scopes:
                for kind in kinds:
                    await conn.execute(_UPSERT_TAINT, (scope, kind, ts, ts))
            await conn.commit()
    except Exception:  # noqa: BLE001 — taint recording must never break execution
        return


async def record_taint(
    repo_root: str, scope: str, kind: str, *, now: datetime | None = None
) -> None:
    """Convenience single-``(scope, kind)`` wrapper over :func:`record_taints`."""
    await record_taints(repo_root, [scope], [kind], now=now)


async def read_taint(repo_root: str, scope: str) -> dict[str, int]:
    """Return ``{kind: count}`` accumulated under ``scope``. Fails closed to ``{}``.

    A missing DB, a locked DB, or any read error yields ``{}`` — taint can never
    be *cleared* by a storage problem, only fail to be *seen* (which leaves the
    per-call objective floor as the protection, never silently lowering it).
    """
    if not scope or not db_path(repo_root).exists():
        return {}
    try:
        async with open_db(repo_root) as conn:
            async with conn.execute(_SELECT_TAINT, (scope,)) as cur:
                rows = await cur.fetchall()
    except Exception:  # noqa: BLE001 — a read failure must never crash a decision
        return {}
    return {row[0]: int(row[1]) for row in rows}


# ---------------------------------------------------------------------------
# Read-vs-send exfil store (HK.5.2b) — keyed-HMAC fingerprints of secrets that
# entered a scope's context, matched against a later egress for a *confirmed*
# read-then-send exfiltration. Same scope keying + best-effort discipline as the
# taint ledger above; no raw secret is ever stored (fingerprints only).
# ---------------------------------------------------------------------------

_INSERT_FINGERPRINT = (
    "INSERT INTO session_secret_fingerprints (scope, fingerprint, first_seen) "
    "VALUES (?, ?, ?) ON CONFLICT(scope, fingerprint) DO NOTHING"
)


async def record_secret_fingerprints(
    repo_root: str,
    scopes: list[str],
    fingerprints: list[str],
    *,
    now: datetime | None = None,
) -> None:
    """Store keyed-HMAC ``fingerprints`` of secrets that entered each scope's
    context (best-effort). Empty/falsy scopes and fingerprints are dropped; never
    raises — a write failure must never affect a verdict (the action is decided).
    """
    scopes = [s for s in scopes if s]
    fps = [f for f in fingerprints if f]
    if not scopes or not fps:
        return
    ts = (now or datetime.now(timezone.utc)).isoformat()
    try:
        async with open_db(repo_root) as conn:
            for scope in scopes:
                for fp in fps:
                    await conn.execute(_INSERT_FINGERPRINT, (scope, fp, ts))
            await conn.commit()
    except Exception:  # noqa: BLE001 — fingerprint recording must never break execution
        return


async def match_secret_fingerprint(repo_root: str, scope: str, fingerprints: list[str]) -> bool:
    """True iff any of ``fingerprints`` was previously recorded under ``scope`` — a
    confirmed read-then-send. Fails closed to ``False``: a missing/locked DB or a
    read error never *fabricates* a match (the taint floor still governs).
    """
    fps = [f for f in fingerprints if f]
    if not scope or not fps or not db_path(repo_root).exists():
        return False
    placeholders = ",".join("?" for _ in fps)
    # `placeholders` is only bound '?' params; the values go through execute(), never
    # string-interpolated into the SQL.
    sql = (
        "SELECT 1 FROM session_secret_fingerprints "  # noqa: S608 — bound '?' params, not interpolated
        f"WHERE scope = ? AND fingerprint IN ({placeholders}) LIMIT 1"
    )
    try:
        async with open_db(repo_root) as conn:
            async with conn.execute(sql, (scope, *fps)) as cur:
                return await cur.fetchone() is not None
    except Exception:  # noqa: BLE001 — a read failure must never crash a decision
        return False


_TTL_DAYS = 7
_MAX_ROWS_PER_SCOPE = 5000

_INSERT_UNTRUSTED_VALUE = (
    "INSERT INTO session_untrusted_value_fingerprints (scope, fingerprint, source_class, first_seen) "
    "VALUES (?, ?, ?, ?) ON CONFLICT(scope, fingerprint) DO NOTHING"
)
_EVICT_STALE_UNTRUSTED = (
    "DELETE FROM session_untrusted_value_fingerprints WHERE scope = ? AND first_seen < ?"
)
_EVICT_OVERFLOW_UNTRUSTED = (
    "DELETE FROM session_untrusted_value_fingerprints WHERE scope = ? AND fingerprint NOT IN ("  # noqa: S608
    "SELECT fingerprint FROM session_untrusted_value_fingerprints WHERE scope = ? "
    "ORDER BY first_seen DESC LIMIT ?)"
)


async def record_untrusted_values(
    repo_root: str,
    scopes: list[str],
    fingerprints: list[str],
    source_class: str,
    *,
    now: datetime | None = None,
) -> None:
    """Store keyed-HMAC ``fingerprints`` of untrusted host/URL/email VALUES that
    entered each scope's context from ``source_class`` (e.g. ``"WebFetch"``) —
    best-effort, bounded (C1). Empty/falsy scopes and fingerprints are dropped;
    never raises — a write failure must never affect a verdict.

    Bounded (invariant: no unbounded scanner/store): each scope is capped at
    :data:`_MAX_ROWS_PER_SCOPE` rows and rows older than :data:`_TTL_DAYS` are
    evicted on every write. This is a DELIBERATE divergence from the sticky-
    forever secret ledger above (``session_secret_fingerprints``): untrusted-
    value recall decays over a session's life in a way a secret's sensitivity
    does not. Eviction only ever REMOVES rows — it can never un-fire a match
    that already happened, and it can never fabricate one either.
    """
    scopes = [s for s in scopes if s]
    fps = [f for f in fingerprints if f]
    if not scopes or not fps:
        return
    when = now or datetime.now(timezone.utc)
    ts = when.isoformat()
    cutoff = (when - timedelta(days=_TTL_DAYS)).isoformat()
    try:
        async with open_db(repo_root) as conn:
            for scope in scopes:
                for fp in fps:
                    await conn.execute(_INSERT_UNTRUSTED_VALUE, (scope, fp, source_class, ts))
                await conn.execute(_EVICT_STALE_UNTRUSTED, (scope, cutoff))
                await conn.execute(_EVICT_OVERFLOW_UNTRUSTED, (scope, scope, _MAX_ROWS_PER_SCOPE))
            await conn.commit()
    except Exception:  # noqa: BLE001 — fingerprint recording must never break execution
        return


async def match_untrusted_value(repo_root: str, scope: str, fingerprints: list[str]) -> str | None:
    """The ``source_class`` recorded for the first matching fingerprint under
    ``scope`` — a confirmed untrusted-value echo — or ``None``. Fails closed to
    ``None``: a missing/locked DB or a read error never fabricates a match.
    """
    fps = [f for f in fingerprints if f]
    if not scope or not fps or not db_path(repo_root).exists():
        return None
    placeholders = ",".join("?" for _ in fps)
    sql = (
        "SELECT source_class FROM session_untrusted_value_fingerprints "  # noqa: S608 — bound '?' params
        f"WHERE scope = ? AND fingerprint IN ({placeholders}) LIMIT 1"
    )
    try:
        async with open_db(repo_root) as conn:
            async with conn.execute(sql, (scope, *fps)) as cur:
                row = await cur.fetchone()
                return row[0] if row else None
    except Exception:  # noqa: BLE001 — a read failure must never crash a decision
        return None


async def clear_taint(repo_root: str) -> tuple[int, int, int]:
    """Wipe ALL sticky taint for this repo's DB — ``session_taint``,
    ``session_secret_fingerprints``, AND ``session_untrusted_value_fingerprints``
    — and return ``(taint_rows_cleared, fingerprint_rows_cleared,
    untrusted_value_rows_cleared)``.

    This is the deliberate, human-gated recovery path (``doberman taint clear``):
    the DB is already per-repo (``.doberman/doberman.db``), so there is no
    narrower scope to target — every row in all three tables belongs to this
    repo. Clearing only some of the three would leave the others armed, so the
    matching floor (HK.5.2b's secret match, or C1's echo tripwire) would still
    raise the next egress — all three tables must go together.

    INVERSION from every other function in this module: reads above fail closed
    to empty/``False``/``None`` and writes are best-effort, because a storage
    hiccup must never *fabricate* or *clear* taint on its own. A *deliberate*
    clear is the opposite risk — reporting success on a failed clear would tell
    the caller protection is restored when it isn't — so this raises on any
    storage error instead of swallowing it; the CLI must not report success on
    a failure.
    """
    async with open_db(repo_root) as conn:
        taint_cur = await conn.execute("DELETE FROM session_taint")
        fingerprint_cur = await conn.execute("DELETE FROM session_secret_fingerprints")
        untrusted_cur = await conn.execute("DELETE FROM session_untrusted_value_fingerprints")
        await conn.commit()
        return taint_cur.rowcount, fingerprint_cur.rowcount, untrusted_cur.rowcount
