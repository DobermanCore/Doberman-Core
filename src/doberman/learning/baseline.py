"""Workflow baseline + abnormality scorer (Feature 9, slices 9.1–9.2).

Learns what is *normal* for this repo/role/workflow as **class-level** counts
(path classes, command classes, destination hosts — never raw paths, prompts, or
secrets) and scores how unusual a new action is. The subjective guardrail
(``engine/subjective.py``) turns a high score into an ``AUTH``.

Two invariants make this safe:

* **Update on ALLOW only.** :func:`observe` is called by the proxy *after* an
  action is forwarded — a blocked or denied attempt can never teach the baseline
  that it is "normal" (otherwise an attacker could train the system to accept the
  very thing it should escalate). Raise-only in spirit.
* **Classes, not payloads.** Feature keys are coarse classes (``path_class:…``,
  ``command:<verb>``, ``destination:<host>``), so the store holds habits, never
  raw targets or secret material.

The store lives in the SQLite ``baseline_counts`` table (created in F8). All I/O
is async; the proxy precomputes the score and hands it to the (synchronous)
engine via ``EvalContext.metadata['abnormality']`` — mirroring how elevations
are threaded in — so the decision engine never depends on the database.

This module is policy core: it may import ``doberman.storage`` but never
``doberman.proxy``.
"""

from datetime import datetime, timezone
from pathlib import PurePosixPath

from doberman.models import ActionType, SecurityObject
from doberman.storage.db import db_path, open_db

#: A dedicated key holding the total number of observed (allowed) actions — the
#: denominator for "is the baseline established yet?".
_TOTAL_KEY = "__total__"

#: Below this many observations the baseline is too sparse to judge novelty, so
#: the scorer stays conservative (mild only for clearly sensitive surfaces) to
#: avoid an approval-fatigue storm on a brand-new repo.
_COLD_START_MIN = 5

#: A class seen at least this many times is considered fully "normal" (novelty 0);
#: between 1 and this it decays linearly from novel→normal.
_FAMILIAR_AT = 3

_PATH_ACTIONS = frozenset({ActionType.file_read, ActionType.file_write, ActionType.file_delete})

# Transitional (until SL9.1 replaces this module with the per-entity baseline
# in doberman.subjective.baseline): the legacy global baseline lives under a
# fixed entity bucket in the now entity-keyed table.
_LEGACY_ENTITY = "__global__"

_UPSERT_COUNT = (
    "INSERT INTO baseline_counts (entity_id, feature_key, count, first_seen, last_seen) "
    "VALUES (?, ?, 1, ?, ?) "
    "ON CONFLICT(entity_id, feature_key) "
    "DO UPDATE SET count = count + 1, last_seen = excluded.last_seen"
)


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
    """The class-level feature keys that characterize ``action`` for the baseline.

    File actions contribute a path class; network actions a destination host;
    shell actions a command verb. These are the signals whose novelty the scorer
    weighs (and that :func:`observe` increments). Returns ``[]`` for an action
    with no class-level signal.
    """
    keys: list[str] = []
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


async def observe(action: SecurityObject, *, repo_root: str, now: datetime | None = None) -> None:
    """Record one **allowed** action in the baseline (best-effort, never raises).

    Increments the total counter plus each of the action's class-level keys.
    MUST only be called for actions that were actually allowed/forwarded.
    """
    stamp = (now or datetime.now(timezone.utc)).isoformat()
    keys = [_TOTAL_KEY, *scoring_keys(action)]
    try:
        async with open_db(repo_root) as conn:
            for key in keys:
                await conn.execute(_UPSERT_COUNT, (_LEGACY_ENTITY, key, stamp, stamp))
            await conn.commit()
    except Exception:  # noqa: BLE001 — learning must never break the execution path
        return


async def frequency(key: str, *, repo_root: str) -> int:
    """How many times ``key`` has been observed (0 if never / no DB)."""
    if not db_path(repo_root).exists():
        return 0
    try:
        async with open_db(repo_root) as conn:
            async with conn.execute(
                "SELECT count FROM baseline_counts WHERE entity_id = ? AND feature_key = ?",
                (_LEGACY_ENTITY, key),
            ) as cur:
                row = await cur.fetchone()
    except Exception:  # noqa: BLE001 — a read failure must never crash the decision path
        return 0
    return int(row[0]) if row else 0


def _novelty(freq: int) -> float:
    """Map an observed frequency to a novelty score in [0, 1] (never-seen = 1.0)."""
    if freq <= 0:
        return 1.0
    if freq >= _FAMILIAR_AT:
        return 0.0
    return max(0.0, 1.0 - freq / _FAMILIAR_AT)


async def abnormality(
    action: SecurityObject, *, repo_root: str, now: datetime | None = None
) -> float:
    """Score how unusual ``action`` is for the learned workflow, in [0, 1].

    Cold start (sparse baseline) is **conservative but not paranoid**: a mild
    signal only for clearly sensitive surfaces, zero otherwise, so a fresh repo
    is not a storm of prompts. Once the baseline is established, the score is the
    **strongest** novelty across the action's class-level keys — a never-seen
    path class / destination / command is fully novel (1.0); a familiar one is 0.
    Never raises into the decision path (any error → 0.0).
    """
    keys = scoring_keys(action)
    if not keys:
        return 0.0
    if not db_path(repo_root).exists():
        return _cold_start_score(action)

    total = await frequency(_TOTAL_KEY, repo_root=repo_root)
    if total < _COLD_START_MIN:
        return _cold_start_score(action)

    novelties = [_novelty(await frequency(key, repo_root=repo_root)) for key in keys]
    return min(1.0, max(novelties)) if novelties else 0.0


def _cold_start_score(action: SecurityObject) -> float:
    """Mild signal for sensitive surfaces on a sparse baseline; 0 otherwise."""
    return 0.3 if (action.sensitive_asset or action.external_destination) else 0.0
