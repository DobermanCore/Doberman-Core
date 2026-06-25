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
import math
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from river import anomaly

from doberman.models import (
    BLAST_RADIUS_ORDER,
    TARGET_CLASS_ORDER,
    ActionType,
    Reversibility,
    SecurityObject,
)
from doberman.storage.db import open_db
from doberman.storage.fingerprint import fingerprint
from doberman.subjective.infer import novelty_bonus

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
    updates the numeric volume stats, advances the transition model, records
    the action's raw sub-scores in the calibration history (the pre-update
    view, so calibration data is also allowed-only), and teaches the in-process
    HST. MUST only be called for actions that were actually allowed/forwarded.
    """
    stamp = (now or datetime.now(timezone.utc)).isoformat()
    role = action.agent_role
    try:
        async with open_db(repo_root) as conn:
            raw_scores = await _raw_sub_scores(conn, entity_id, action)
            await _persist_score_history(conn, entity_id, raw_scores, stamp)
            keys = await _bounded_keys(conn, entity_id, scoring_keys(action))
            for key in [TOTAL_KEY, *keys]:
                await conn.execute(_UPSERT_COUNT, (entity_id, key, role, stamp, stamp))
            await _update_numeric(conn, entity_id, "num:volume", _volume(action), role, stamp)
            await _advance_transitions(conn, entity_id, markov_state(action))
            await conn.commit()
    except Exception:  # noqa: BLE001 — learning must never break the execution path
        logger.warning("baseline observe failed (entity %s); continuing", entity_id[:12])
        return
    try:
        _hst_for(entity_id).learn_one(encode_algebra(action))
        _HST_LEARN_COUNTS[entity_id] = _HST_LEARN_COUNTS.get(entity_id, 0) + 1
    except Exception:  # noqa: BLE001 — model learning must never break the path
        logger.warning("HST learn failed (entity %s); continuing", entity_id[:12])


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


# --- surprise scorer (SL4.2): HST + surprisal + robust z, calibrated ------------
#
# Ensemble of independent sub-scorers, each mapped to an (empirical-CDF)
# calibrated [0,1] score over THIS entity's own history, then averaged.
# Calibration is what makes scores comparable across application types — the
# reason one threshold policy can hold everywhere (Half-Space Trees: Tan, Ting
# & Liu, IJCAI 2011).
#
# The HST and its windowed state are PROCESS-LIFETIME (the proxy is a
# long-running server): counts/transitions/score-history persist in SQLite, so
# after a restart the frequency-novelty, surprisal, and robust-z members keep
# their memory while the HST warms back up over ~window_size actions — the
# ensemble degrades gracefully, it never fails open.

#: River Half-Space-Trees parameters (per the subjective-layer skill).
HST_TREES = 25
HST_HEIGHT = 15
HST_WINDOW = 250
HST_SEED = 42

#: A feature class seen at least this many times is fully familiar.
FAMILIAR_AT = 3

#: Below this many calibration samples a raw sub-score is used as-is.
MIN_CALIBRATION_SAMPLES = 20

#: Rows of score history kept per (entity, kind).
SCORE_HISTORY_KEEP = 500

#: Bits of surprisal that map to a fully-surprising (1.0) raw sequence score.
SURPRISAL_FULL_BITS = 8.0

#: Robust-z value that maps to a fully-surprising (1.0) raw numeric score.
Z_FULL_AT = 6.0

#: Sliding step-up budget defaults: at most ``BUDGET_K`` subjective step-ups
#: per ``BUDGET_N`` decided actions per entity (the ≤1-in-20 fatigue target).
BUDGET_K = 1
BUDGET_N = 20

#: Severity of (ir)reversibility for the ordinal encoding: low = hardest to
#: undo = most severe.
_REVERSIBILITY_SEVERITY: dict[Reversibility, float] = {
    Reversibility.high: 0.0,
    Reversibility.medium: 0.5,
    Reversibility.low: 1.0,
}

#: In-process per-entity Half-Space-Trees models (rebuilt empty on restart).
_HST_MODELS: dict[str, anomaly.HalfSpaceTrees] = {}

#: Observations each entity's HST has learned this process (warm-up tracking).
_HST_LEARN_COUNTS: dict[str, int] = {}

#: The HST abstains from the ensemble until it has learned a full window —
#: its scores are not meaningful before the first reference window completes.
HST_WARMUP = HST_WINDOW


def encode_algebra(action: SecurityObject) -> dict[str, float]:
    """Encode an action's algebra as a [0,1] feature vector for the HST.

    Mandatory encoding discipline (River HST assumes inputs in [0,1]): one-hot
    for the UNORDERED enums (capability, provenance, destination_class),
    ordinal-scaled for the genuinely ORDERED tiers (target_class, blast_radius,
    reversibility). Never feeds a raw enum.
    """
    algebra = action.algebra
    features: dict[str, float] = {}
    for member in type(algebra.capability):
        features[f"cap={member.value}"] = 1.0 if algebra.capability is member else 0.0
    for member in type(algebra.provenance):
        features[f"prov={member.value}"] = 1.0 if algebra.provenance is member else 0.0
    for member in type(algebra.destination_class):
        features[f"dest={member.value}"] = 1.0 if algebra.destination_class is member else 0.0
    features["target_tier"] = TARGET_CLASS_ORDER[algebra.target_class] / max(
        TARGET_CLASS_ORDER.values()
    )
    features["blast_tier"] = BLAST_RADIUS_ORDER[algebra.blast_radius] / max(
        BLAST_RADIUS_ORDER.values()
    )
    features["irreversibility"] = _REVERSIBILITY_SEVERITY[action.reversibility]
    features["confidence"] = max(0.0, min(1.0, action.algebra.classification_confidence))
    return features


def _hst_for(entity: str) -> anomaly.HalfSpaceTrees:
    model = _HST_MODELS.get(entity)
    if model is None:
        model = anomaly.HalfSpaceTrees(
            n_trees=HST_TREES, height=HST_HEIGHT, window_size=HST_WINDOW, seed=HST_SEED
        )
        _HST_MODELS[entity] = model
    return model


def reset_hst(entity: str | None = None) -> None:
    """Drop the in-process HST state (one entity, or all). Used by drift refresh."""
    if entity is None:
        _HST_MODELS.clear()
        _HST_LEARN_COUNTS.clear()
    else:
        _HST_MODELS.pop(entity, None)
        _HST_LEARN_COUNTS.pop(entity, None)


def _novelty(freq: int) -> float:
    """Frequency → novelty in [0,1] (never seen = 1.0, familiar = 0.0)."""
    if freq <= 0:
        return 1.0
    if freq >= FAMILIAR_AT:
        return 0.0
    return max(0.0, 1.0 - freq / FAMILIAR_AT)


async def _novelty_score(conn, eid: str, action: SecurityObject) -> float:
    """Max frequency-novelty across the action's class keys (pre-update view)."""
    worst = 0.0
    for key in scoring_keys(action):
        async with conn.execute(
            "SELECT count FROM baseline_counts WHERE entity_id = ? AND feature_key = ?",
            (eid, key),
        ) as cur:
            row = await cur.fetchone()
        worst = max(worst, _novelty(int(row[0]) if row else 0))
    return worst


async def novelty_score(action: SecurityObject, *, entity_id: str, repo_root: str) -> float:
    """Public frequency-novelty read for ``action`` (drift monitoring input).

    Pure read; failure → 1.0 (fail toward caution).
    """
    try:
        async with open_db(repo_root) as conn:
            return await _novelty_score(conn, entity_id, action)
    except Exception:  # noqa: BLE001 — a read failure must never crash the path
        return 1.0


async def _surprisal_score(conn, eid: str, action: SecurityObject) -> float | None:
    """Markov sequence surprisal −log₂P(state|last), scaled to [0,1].

    ``None`` (abstain) when the entity has no sequence history yet — a first
    action is the novelty scorer's job, not the sequence model's.
    """
    async with conn.execute(
        "SELECT last_state FROM baseline_state WHERE entity_id = ?", (eid,)
    ) as cur:
        row = await cur.fetchone()
    last = row[0] if row else None
    if not last:
        return None
    async with conn.execute(
        "SELECT to_state, count FROM baseline_transitions WHERE entity_id = ? AND from_state = ?",
        (eid, f"1:{last}"),
    ) as cur:
        rows = await cur.fetchall()
    if not rows:
        return None
    counts = {str(r[0]): int(r[1]) for r in rows}
    total = sum(counts.values())
    vocabulary = len(counts) + 1
    observed = counts.get(markov_state(action), 0)
    probability = (observed + 1) / (total + vocabulary)  # Laplace smoothing
    surprisal_bits = -math.log2(probability)
    return min(1.0, surprisal_bits / SURPRISAL_FULL_BITS)


async def _volume_z_score(conn, eid: str, action: SecurityObject) -> float | None:
    """Robust z of the action's volume against the entity's EWMA variance."""
    async with conn.execute(
        "SELECT count, mean, ewma_var FROM baseline_counts WHERE entity_id = ? AND feature_key = ?",
        (eid, "num:volume"),
    ) as cur:
        row = await cur.fetchone()
    if row is None or int(row[0]) < FAMILIAR_AT:
        return None
    mean, ewma_var = float(row[1]), float(row[2])
    spread = math.sqrt(max(ewma_var, 1e-6))
    z = abs(_volume(action) - mean) / spread
    return min(1.0, z / Z_FULL_AT)


async def _calibrated(conn, eid: str, kind: str, raw: float) -> float:
    """Quantile-weight ``raw`` against this entity's own score history.

    The empirical (midrank) CDF says how extreme ``raw`` is *for this entity*;
    multiplying it back into the raw score keeps the result monotone in both —
    a low raw stays low, a high-and-rare raw stays high, and a high-but-typical
    raw is tempered. This per-entity calibration is what makes scores
    comparable across application types. With fewer than
    :data:`MIN_CALIBRATION_SAMPLES` stored values the raw score stands as-is
    (warn-leaning until history exists).
    """
    async with conn.execute(
        "SELECT value FROM score_history WHERE entity_id = ? AND kind = ? ORDER BY id DESC LIMIT ?",
        (eid, kind, SCORE_HISTORY_KEEP),
    ) as cur:
        rows = await cur.fetchall()
    values = [float(r[0]) for r in rows]
    if len(values) < MIN_CALIBRATION_SAMPLES:
        return raw
    less = sum(1 for v in values if v < raw)
    equal = sum(1 for v in values if v == raw)
    midrank_cdf = (less + 0.5 * equal) / len(values)
    return raw * midrank_cdf


async def _raw_sub_scores(conn, eid: str, action: SecurityObject) -> dict[str, float]:
    """Every available raw sub-score for ``action`` (absent = abstained)."""
    raw: dict[str, float] = {}
    try:
        raw["novelty"] = await _novelty_score(conn, eid, action)
    except Exception:  # noqa: BLE001 — one failed member is dropped, never fatal
        logger.warning("novelty sub-scorer failed; dropping it from the ensemble")
    try:
        if _HST_LEARN_COUNTS.get(eid, 0) >= HST_WARMUP:
            raw["hst"] = float(_hst_for(eid).score_one(encode_algebra(action)))
    except Exception:  # noqa: BLE001 — one failed member is dropped, never fatal
        logger.warning("HST sub-scorer failed; dropping it from the ensemble")
    try:
        surprisal = await _surprisal_score(conn, eid, action)
        if surprisal is not None:
            raw["surprisal"] = surprisal
    except Exception:  # noqa: BLE001 — one failed member is dropped, never fatal
        logger.warning("surprisal sub-scorer failed; dropping it from the ensemble")
    try:
        z = await _volume_z_score(conn, eid, action)
        if z is not None:
            raw["volume_z"] = z
    except Exception:  # noqa: BLE001 — one failed member is dropped, never fatal
        logger.warning("volume-z sub-scorer failed; dropping it from the ensemble")
    return raw


async def surprise(action: SecurityObject, *, entity_id: str, repo_root: str) -> float:
    """Calibrated surprise for ``action`` against its entity baseline, in [0,1].

    Mean of the calibrated sub-scores (frequency novelty, Half-Space Trees,
    Markov surprisal, robust volume-z) plus the bounded SL3.2 novelty bonus
    for unclassified actions. Pure READ — nothing here updates any model or
    history (learning happens in :func:`observe`, on allowed actions only).
    Every sub-scorer failing → 1.0 (fail toward caution).
    """
    try:
        async with open_db(repo_root) as conn:
            raw = await _raw_sub_scores(conn, entity_id, action)
            if not raw:
                return 1.0
            calibrated = [await _calibrated(conn, entity_id, k, v) for k, v in raw.items()]
    except Exception:  # noqa: BLE001 — scoring failure fails toward caution
        logger.warning("surprise scoring failed (entity %s); scoring 1.0", entity_id[:12])
        return 1.0
    score = sum(calibrated) / len(calibrated) + novelty_bonus(action.algebra)
    return max(0.0, min(1.0, score))


async def _persist_score_history(conn, eid: str, raw: dict[str, float], stamp: str) -> None:
    """Append raw sub-scores to the calibration history, pruned per kind."""
    for kind, value in raw.items():
        await conn.execute(
            "INSERT INTO score_history (entity_id, ts, kind, value) VALUES (?, ?, ?, ?)",
            (eid, stamp, kind, float(value)),
        )
        await conn.execute(
            "DELETE FROM score_history WHERE entity_id = ? AND kind = ? AND id NOT IN ("
            "SELECT id FROM score_history WHERE entity_id = ? AND kind = ? "
            "ORDER BY id DESC LIMIT ?)",
            (eid, kind, eid, kind, SCORE_HISTORY_KEEP),
        )


async def budget_allows_step_up(
    *, entity_id: str, repo_root: str, k: int = BUDGET_K, n: int = BUDGET_N
) -> bool:
    """Sliding step-up budget: at most ``k`` subjective step-ups per ``n`` actions.

    Multiple sub-scorers per action otherwise inflate the family-wise flag rate
    past the approval-fatigue target. Counts AUTH decisions the subjective
    layer participated in (``decided_layer='combined'``) among the entity's
    last ``n`` decisions.

    RAISE-ONLY guard: a window containing a **denied** subjective step-up never
    exhausts the budget — the operator's denial means protection is doing its
    job, and suppressing the next ask would silently allow the very thing that
    was just refused. Only answered-or-approved nuisance asks count toward
    fatigue. Failure → ``True`` (on doubt the step-up surfaces — more caution,
    never less). NEVER consulted for the trifecta floor or detector verdicts.
    """
    try:
        async with open_db(repo_root) as conn:
            async with conn.execute(
                "SELECT final_verdict, decided_layer, auth_result FROM decisions "
                "WHERE entity_id = ? ORDER BY id DESC LIMIT ?",
                (entity_id, n),
            ) as cur:
                rows = await cur.fetchall()
    except Exception:  # noqa: BLE001 — budget read failure must not suppress a step-up
        return True
    step_ups = [row for row in rows if row[0] == "AUTH" and row[1] == "combined"]
    if any(row[2] == "denied" for row in step_ups):
        return True
    return len(step_ups) < k


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
