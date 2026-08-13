"""D2 — the task-match ledger: destination tokens derived from the TRUSTED,
pre-inference user prompt (the turn gate — see ``turngate/task_tokens.py``),
consumed by the C3.1 session correlator (:mod:`doberman.engine.correlator`) to
soften ``correlated_trifecta`` for an egress destination the user's own turn
actually named.

Scoped by the harness session id ONLY (the same HK.5.1 id
``session_taint``/``decisions.session_id`` already use, and the exact scope
:func:`doberman.storage.log.recent_session_decisions` reads for the
correlator's own history) — deliberately no entity/repo-scope fallback like
``storage.taint``'s dual-scope taint ledger. Task-match *suppresses* a raise,
so it must stay as narrow as the correlator's own read: a broader fallback
would let a task token named in one session soften an unrelated session's
egress in the same repo. With no session id there is nothing to key it to and
the leg is simply dormant (the correlator sees no task hosts, behaves exactly
as before this feature).

Redaction: ``host`` is a decoded hostname string (see
``turngate/task_tokens.py``'s regex + IDNA-decode extraction), never the raw
prompt or any other prompt substring. A hostname is not secret content —
Doberman already ships a plaintext ``TRUSTED_HOSTS`` allowlist in
``engine/rules/destinations.py`` — so storing decoded host strings (as opposed
to opaque fingerprints) does not violate the "never a raw secret/prompt"
invariant; it is exactly as sensitive as the target_path_class already stored
in the decisions table.
"""

from datetime import datetime, timezone

from doberman.storage.db import db_path, open_db

#: Bound on how many task hosts ride under one scope. The real cap is enforced
#: at extraction time (turngate/task_tokens.py's MAX_TASK_HOSTS); this is the
#: storage-layer backstop against a caller that forgot to bound its input.
MAX_TASK_HOSTS = 20

_UPSERT_TASK_HOST = (
    "INSERT INTO session_task_hosts (scope, host, first_seen, last_seen) "
    "VALUES (?, ?, ?, ?) "
    "ON CONFLICT(scope, host) DO UPDATE SET last_seen = excluded.last_seen"
)
_SELECT_TASK_HOSTS = "SELECT host FROM session_task_hosts WHERE scope = ?"


async def record_task_hosts(
    repo_root: str, scope: str, hosts: list[str], *, now: datetime | None = None
) -> None:
    """Persist ``hosts`` (deduped, capped) under ``scope`` (best-effort).

    Empty/falsy scope or hosts are dropped. Never raises — a write failure
    must never affect a verdict (this only ever softens a later raise, never
    causes one on its own).
    """
    deduped = [h for h in dict.fromkeys(hosts) if h][:MAX_TASK_HOSTS]
    if not scope or not deduped:
        return
    ts = (now or datetime.now(timezone.utc)).isoformat()
    try:
        async with open_db(repo_root) as conn:
            for host in deduped:
                await conn.execute(_UPSERT_TASK_HOST, (scope, host, ts, ts))
            await conn.commit()
    except Exception:  # noqa: BLE001 — task-host recording must never break execution
        return


async def task_hosts_for(repo_root: str, scope: str) -> list[str]:
    """Return the host tokens recorded under ``scope``. Fails closed to ``[]``.

    A missing DB, a locked DB, or any read error yields ``[]`` — a storage
    problem can only ever cause the trifecta to fire as if this feature did
    not exist, never to be silently suppressed.
    """
    if not scope or not db_path(repo_root).exists():
        return []
    try:
        async with open_db(repo_root) as conn:
            async with conn.execute(_SELECT_TASK_HOSTS, (scope,)) as cur:
                rows = await cur.fetchall()
    except Exception:  # noqa: BLE001 — a read failure must never crash a decision
        return []
    return [row[0] for row in rows]
