"""Per-entity streaming baseline + transition model (SL4.1).

Learns what is *normal* for one **deployment instance** — this agent role on
this repo/workspace, never the application type — as class-level counts over
the action algebra, plus running numeric stats (Welford mean/M2 + EWMA
variance) and a 1st/2nd-order Markov transition table over
``capability×target_class`` states. Entity scoping is what makes one universal
engine sharp in practice: two agents on different projects get different
baselines.

Invariants (same as the legacy F9 baseline, now per entity):

* **Update on ALLOW only.** :func:`observe` is called by the proxy after a
  successful forward — a blocked/denied attempt never teaches "normal".
* **Classes, never payloads.** Feature keys are coarse classes (algebra
  members, path classes, command verbs, destination hosts); the ``entity_id``
  itself is a keyed HMAC fingerprint, never a raw role/path string.
* **Bounded cardinality.** Past :data:`MAX_FEATURE_KEYS` distinct keys per
  entity, new keys aggregate into an overflow bucket — no attacker-driven
  table blow-up.
* **A changed tool is a new tool.** :func:`reset_tool_contribution` drops a
  tool's familiarity when its pinned schema changes (the MCP rug-pull tie-in),
  so "familiar" status never survives a schema diff.

This module is policy core: it may import ``doberman.storage`` but never
``doberman.proxy``.
"""

import logging
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from doberman.models import ActionType, SecurityObject
from doberman.storage.db import open_db
from doberman.storage.fingerprint import fingerprint

logger = logging.getLogger("doberman.subjective.baseline")

#: Total observed (allowed) actions for an entity — the cold-start denominator.
TOTAL_KEY = "__total__"

#: Overflow bucket for the cardinality bound.
OVERFLOW_KEY = "__overflow__"

#: Distinct feature keys an entity may accumulate before new keys aggregate.
MAX_FEATURE_KEYS = 256

#: Fallback entity id when the local HMAC key is unavailable. A shared bucket
#: is conservative for scoring (mixed habits look noisier, never calmer) and
#: still contains only class-level keys.
UNKEYED_ENTITY = "entity:unkeyed"

#: EWMA smoothing factor for the per-observation variance estimate.
EWMA_ALPHA = 0.1

_PATH_ACTIONS = frozenset({ActionType.file_read, ActionType.file_write, ActionType.file_delete})

_UPSERT_COUNT = (
    "INSERT INTO baseline_counts (entity_id, feature_key, role, count, first_seen, last_seen) "
    "VALUES (?, ?, ?, 1, ?, ?) "
    "ON CONFLICT(entity_id, feature_key) "
    "DO UPDATE SET count = count + 1, last_seen = excluded.last_seen"
)

_UPSERT_TRANSITION = (
    "INSERT INTO baseline_transitions (entity_id, from_state, to_state, count) "
    "VALUES (?, ?, ?, 1) "
    "ON CONFLICT(entity_id, from_state, to_state) DO UPDATE SET count = count + 1"
)


def entity_id(agent_role: str, repo_root: str) -> str:
    """The deployment-instance identity: a keyed fingerprint of role + workspace.

    Deterministic per install (same role on the same resolved root always maps
    to the same id) and redaction-safe (an HMAC hex, never the raw path). If
    the local HMAC key cannot be obtained the shared :data:`UNKEYED_ENTITY`
    bucket is used — degraded sharpness, never degraded protection.
    """
    try:
        resolved = str(Path(repo_root).resolve())
        return fingerprint(f"{agent_role}|{resolved}")
    except Exception:  # noqa: BLE001 — identity failure must not break the path
        logger.warning("entity fingerprint unavailable; using the shared unkeyed bucket")
        return UNKEYED_ENTITY


def _path_bucket(action: SecurityObject) -> str | None:
    """Coarse path class for a file action: directory + extension, filename dropped."""
    if action.action_type not in _PATH_ACTIONS or not action.target:
        return None
    pure = PurePosixPath(str(action.target).replace("\\", "/"))
    parent = pure.parent.as_posix()
    parent = "" if parent == "." else parent
    stem_class = f"*{pure.suffix}" if pure.suffix else pure.name
    return f"{parent}/{stem_class}" if parent else stem_class


def scoring_keys(action: SecurityObject) -> list[str]:
    """Class-level feature keys characterizing ``action`` for its entity baseline.

    Algebra members (capability/target/destination/blast), the tool name (so a
    schema-changed tool can be forgotten as a unit), and the legacy class
    buckets (path class, destination host, command verb). Never a raw payload.
    """
    algebra = action.algebra
    keys = [
        f"capability:{algebra.capability}",
        f"target:{algebra.target_class}",
        f"dest:{algebra.destination_class}",
        f"blast:{algebra.blast_radius}",
        f"tool:{action.tool_name}",
    ]
    bucket = _path_bucket(action)
    if bucket:
        keys.append(f"path_class:{bucket}")
    if action.external_destination:
        keys.append(f"destination:{action.external_destination}")
    if action.action_type is ActionType.shell_exec and action.target:
        verb = str(action.target).strip().split()[0] if str(action.target).strip() else ""
        if verb:
            keys.append(f"command:{verb}")
    return keys


def markov_state(action: SecurityObject) -> str:
    """The sequence-model state for ``action``: ``capability|target_class``."""
    return f"{action.algebra.capability}|{action.algebra.target_class}"


def _volume(action: SecurityObject) -> float:
    """The action's numeric volume signal (targets touched), default 1."""
    count = 1
    meta = action.metadata if isinstance(action.metadata, dict) else {}
    raw = meta.get("target_count")
    if isinstance(raw, int) and raw > 0:
        count = raw
    return float(count)


async def _bounded_keys(conn, eid: str, keys: list[str]) -> list[str]:
    """Apply the cardinality bound: unseen keys past the cap → overflow bucket."""
    async with conn.execute(
        "SELECT feature_key FROM baseline_counts WHERE entity_id = ?", (eid,)
    ) as cur:
        existing = {row[0] for row in await cur.fetchall()}
    if len(existing) < MAX_FEATURE_KEYS:
        return keys
    return [key if key in existing else OVERFLOW_KEY for key in keys]


async def _update_numeric(conn, eid: str, key: str, value: float, role: str, stamp: str) -> None:
    """Welford mean/M2 + EWMA variance for a numeric stream (read-modify-write)."""
    async with conn.execute(
        "SELECT count, mean, m2, ewma_var FROM baseline_counts "
        "WHERE entity_id = ? AND feature_key = ?",
        (eid, key),
    ) as cur:
        row = await cur.fetchone()
    if row is None:
        await conn.execute(
            "INSERT INTO baseline_counts "
            "(entity_id, feature_key, role, count, mean, m2, ewma_var, first_seen, last_seen) "
            "VALUES (?, ?, ?, 1, ?, 0, 0, ?, ?)",
            (eid, key, role, value, stamp, stamp),
        )
        return
    count, mean, m2, ewma_var = int(row[0]) + 1, float(row[1]), float(row[2]), float(row[3])
    delta = value - mean
    mean += delta / count
    m2 += delta * (value - mean)
    ewma_var = EWMA_ALPHA * (delta * delta) + (1 - EWMA_ALPHA) * ewma_var
    await conn.execute(
        "UPDATE baseline_counts SET count = ?, mean = ?, m2 = ?, ewma_var = ?, last_seen = ? "
        "WHERE entity_id = ? AND feature_key = ?",
        (count, mean, m2, ewma_var, stamp, eid, key),
    )


async def _advance_transitions(conn, eid: str, state: str) -> None:
    """Record 1st- and 2nd-order transitions and advance the entity's state."""
    async with conn.execute(
        "SELECT last_state, prev_state FROM baseline_state WHERE entity_id = ?", (eid,)
    ) as cur:
        row = await cur.fetchone()
    last, prev = (row[0], row[1]) if row else (None, None)
    if last:
        await conn.execute(_UPSERT_TRANSITION, (eid, f"1:{last}", state))
        if prev:
            await conn.execute(_UPSERT_TRANSITION, (eid, f"2:{prev}>{last}", state))
    await conn.execute(
        "INSERT INTO baseline_state (entity_id, last_state, prev_state) VALUES (?, ?, ?) "
        "ON CONFLICT(entity_id) DO UPDATE SET last_state = excluded.last_state, "
        "prev_state = excluded.prev_state",
        (eid, state, last),
    )


async def observe(
    action: SecurityObject,
    *,
    entity_id: str,
    repo_root: str,
    now: datetime | None = None,
) -> None:
    """Record one **allowed** action in its entity's baseline (never raises).

    Increments the entity's total + class-level keys (cardinality-bounded),
    updates the numeric volume stats, and advances the transition model. MUST
    only be called for actions that were actually allowed/forwarded.
    """
    stamp = (now or datetime.now(timezone.utc)).isoformat()
    role = action.agent_role
    try:
        async with open_db(repo_root) as conn:
            keys = await _bounded_keys(conn, entity_id, scoring_keys(action))
            for key in [TOTAL_KEY, *keys]:
                await conn.execute(_UPSERT_COUNT, (entity_id, key, role, stamp, stamp))
            await _update_numeric(conn, entity_id, "num:volume", _volume(action), role, stamp)
            await _advance_transitions(conn, entity_id, markov_state(action))
            await conn.commit()
    except Exception:  # noqa: BLE001 — learning must never break the execution path
        logger.warning("baseline observe failed (entity %s); continuing", entity_id[:12])


async def frequency(key: str, *, entity_id: str, repo_root: str) -> int:
    """How many times ``key`` was observed for ``entity_id`` (0 on any failure)."""
    try:
        async with open_db(repo_root) as conn:
            async with conn.execute(
                "SELECT count FROM baseline_counts WHERE entity_id = ? AND feature_key = ?",
                (entity_id, key),
            ) as cur:
                row = await cur.fetchone()
    except Exception:  # noqa: BLE001 — a read failure must never crash the decision path
        return 0
    return int(row[0]) if row else 0


async def total_observations(*, entity_id: str, repo_root: str) -> int:
    """The entity's total observed (allowed) action count."""
    return await frequency(TOTAL_KEY, entity_id=entity_id, repo_root=repo_root)


async def transition_counts(from_state: str, *, entity_id: str, repo_root: str) -> dict[str, int]:
    """Observed ``to_state`` counts out of ``from_state`` for this entity."""
    try:
        async with open_db(repo_root) as conn:
            async with conn.execute(
                "SELECT to_state, count FROM baseline_transitions "
                "WHERE entity_id = ? AND from_state = ?",
                (entity_id, from_state),
            ) as cur:
                rows = await cur.fetchall()
    except Exception:  # noqa: BLE001 — a read failure must never crash the decision path
        return {}
    return {str(row[0]): int(row[1]) for row in rows}


async def numeric_stats(
    key: str, *, entity_id: str, repo_root: str
) -> tuple[int, float, float, float] | None:
    """``(count, mean, m2, ewma_var)`` for a numeric key, or ``None``."""
    try:
        async with open_db(repo_root) as conn:
            async with conn.execute(
                "SELECT count, mean, m2, ewma_var FROM baseline_counts "
                "WHERE entity_id = ? AND feature_key = ?",
                (entity_id, key),
            ) as cur:
                row = await cur.fetchone()
    except Exception:  # noqa: BLE001 — a read failure must never crash the decision path
        return None
    if row is None:
        return None
    return int(row[0]), float(row[1]), float(row[2]), float(row[3])


async def reset_tool_contribution(tool_name: str, *, entity_id: str, repo_root: str) -> None:
    """Forget a tool's familiarity after a pinned-schema change (rug-pull tie-in).

    Deletes the tool's feature row so the changed tool scores as fully novel
    again. Coarse aggregate keys (capability/target tiers) keep their counts —
    the per-tool familiarity is the signal that must reset. Never raises.
    """
    try:
        async with open_db(repo_root) as conn:
            await conn.execute(
                "DELETE FROM baseline_counts WHERE entity_id = ? AND feature_key = ?",
                (entity_id, f"tool:{tool_name}"),
            )
            await conn.commit()
    except Exception:  # noqa: BLE001 — best-effort hygiene must never crash the path
        logger.warning("tool-contribution reset failed (entity %s); continuing", entity_id[:12])
