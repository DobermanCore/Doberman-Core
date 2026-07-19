"""Slice TG3.2 — the per-entity prompt-style baseline (the SL feature buckets).

Learns how *this entity's* prompts normally look — coarse scalar style buckets
only (length, word shape, punctuation/case/digit density), **never any prompt
text** — and answers one question: *how extreme is this turn's style for this
entity?* as an empirical-CDF p-value, exactly the SL4 calibration idea applied
to prompt style instead of the action algebra.

Storage reuses the SL4 numeric machinery (no schema migration, matching the F11
"no new tables" decision): per-feature Welford/EWMA stats live in
``baseline_counts`` under ``turnstyle:<feature>`` keys, and the per-turn style
*distance* stream lives in ``score_history`` under ``turnstyle:distance``.

Invariants (mirroring the SL4 baseline):

* **Update on RELEASE only.** :func:`observe_style` is called by the hook after
  a turn is released to the model — a blocked/denied turn never teaches
  "normal".
* **Classes, never payloads.** Only scalar aggregates are computed and only
  floats are persisted; the raw text never leaves memory.
* **Cold start = inert.** :func:`style_pvalue` returns ``None`` until the
  entity's prompt baseline has :data:`STYLE_MATURITY` observations — the same
  maturity rule as the SL baselines (``K_OBSERVATIONS``). Tier 0 does not
  depend on this module and is active from turn one.
* **Failure = abstain.** Any storage/scoring failure returns ``None`` (the
  stylometric gate simply does not run). This is deliberate defense-in-depth
  posture: failing toward AUTH here would step up *every* sensitive turn on a
  storage bug — a prompt storm — while abstaining degrades to exactly the
  TG3.1 behavior, with Tier 0 and the action gate still fully active.

Known limitations (documented, by design):

* **Device/language switches** look like style drift. The co-occurrence
  requirement absorbs this: an outlier alone is only ever *tagged* (TG3.3
  hands the tag to the action stage); it never gates.
* **Shared accounts** blend several typists into one entity baseline, so the
  style signal degrades toward noise. Co-occurrence keeps the worst case at
  one extra human tap on sensitive turns — never a denial.

This module is a turn-gate adapter: it may import storage and the subjective
baseline helpers, never ``doberman.proxy``.
"""

import logging
import math
import string
from datetime import datetime, timezone

from doberman.storage.db import open_db
from doberman.subjective.baseline import (
    FAMILIAR_AT,
    Z_FULL_AT,
    _persist_score_history,
    _update_numeric,
    numeric_stats,
)
from doberman.subjective.drift import K_OBSERVATIONS

logger = logging.getLogger("doberman.turngate.stylometry")

#: Prompt-baseline observations required before stylometric gating activates —
#: the SAME maturity rule as the SL entity baselines (cold start = inert).
STYLE_MATURITY = K_OBSERVATIONS

#: ``baseline_counts`` key prefix for the per-feature style stats.
_FEATURE_PREFIX = "turnstyle:"

#: ``score_history`` kind for the per-turn style-distance stream.
_DISTANCE_KIND = "turnstyle:distance"

#: Role recorded on style rows (matches the turn log's discriminator and never
#: collides with action-role peer queries).
_ROLE = "(turn)"

#: The reference feature whose Welford count is the baseline's observation total.
_TOTAL_FEATURE = "chars"

#: Per-feature |z| cap — one wild bucket saturates, it cannot dominate alone.
_Z_CAP = Z_FULL_AT

_PUNCTUATION = set(string.punctuation)


def style_features(text: str) -> dict[str, float]:
    """Coarse scalar style buckets for one prompt (aggregates only, no content).

    Buckets: log-length, mean word length, punctuation density, uppercase
    ratio (over letters), digit density. Each is a single float — nothing here
    can reconstruct any part of the text.
    """
    n = len(text)
    words = text.split()
    letters = [ch for ch in text if ch.isalpha()]
    return {
        "chars": math.log1p(n),
        "word_len": (sum(len(w) for w in words) / len(words)) if words else 0.0,
        "punct": (sum(1 for ch in text if ch in _PUNCTUATION) / n) if n else 0.0,
        "upper": (sum(1 for ch in letters if ch.isupper()) / len(letters)) if letters else 0.0,
        "digit": (sum(1 for ch in text if ch.isdigit()) / n) if n else 0.0,
    }


async def _feature_stats(conn, eid: str) -> dict[str, tuple[int, float, float, float]]:
    """``feature → (count, mean, m2, ewma_var)`` for the entity's style keys."""
    stats: dict[str, tuple[int, float, float, float]] = {}
    async with conn.execute(
        "SELECT feature_key, count, mean, m2, ewma_var FROM baseline_counts "
        "WHERE entity_id = ? AND feature_key LIKE ?",
        (eid, f"{_FEATURE_PREFIX}%"),
    ) as cur:
        rows = await cur.fetchall()
    for row in rows:
        key = str(row[0])
        if key.startswith(_FEATURE_PREFIX) and key != _DISTANCE_KIND:
            stats[key[len(_FEATURE_PREFIX) :]] = (
                int(row[1]),
                float(row[2]),
                float(row[3]),
                float(row[4]),
            )
    return stats


def _distance(
    features: dict[str, float], stats: dict[str, tuple[int, float, float, float]]
) -> float | None:
    """Mean capped robust-z of the turn's style against the entity's stats.

    Only features with at least :data:`FAMILIAR_AT` observations contribute
    (same familiarity bar as the SL4 volume-z). ``None`` when no feature
    qualifies yet — there is nothing meaningful to compare against.
    """
    zs: list[float] = []
    for name, value in features.items():
        row = stats.get(name)
        if row is None or row[0] < FAMILIAR_AT:
            continue
        _, mean, _, ewma_var = row
        spread = math.sqrt(max(ewma_var, 1e-6))
        zs.append(min(_Z_CAP, abs(value - mean) / spread))
    if not zs:
        return None
    return sum(zs) / len(zs)


async def observe_style(
    text: str, *, entity_id: str, repo_root: str, now: datetime | None = None
) -> None:
    """Record one **released** turn's style in its entity baseline (never raises).

    Appends the turn's pre-update style distance to the calibration history
    (so the p-value reference is also released-only) and updates each feature's
    running stats. MUST only be called for turns that actually reached the
    model — the hook enforces this.
    """
    stamp = (now or datetime.now(timezone.utc)).isoformat()
    try:
        features = style_features(text)
        async with open_db(repo_root) as conn:
            stats = await _feature_stats(conn, entity_id)
            distance = _distance(features, stats)
            if distance is not None:
                await _persist_score_history(conn, entity_id, {_DISTANCE_KIND: distance}, stamp)
            for name, value in features.items():
                await _update_numeric(
                    conn, entity_id, f"{_FEATURE_PREFIX}{name}", value, _ROLE, stamp
                )
            await conn.commit()
    except Exception:  # noqa: BLE001 — learning must never break the turn path
        logger.warning("style observe failed (entity %s); continuing", entity_id[:12])


async def style_pvalue(text: str, *, entity_id: str, repo_root: str) -> float | None:
    """Upper-tail empirical p-value of this turn's style distance, or ``None``.

    ``None`` means *abstain*: the baseline is immature (cold start), there is
    no usable history, or storage failed — in every case the stylometric gate
    simply does not run (see the module docstring for why abstain, not AUTH).
    Pure READ — nothing here updates any stats or history.
    """
    try:
        total = await numeric_stats(
            f"{_FEATURE_PREFIX}{_TOTAL_FEATURE}", entity_id=entity_id, repo_root=repo_root
        )
        if total is None or total[0] < STYLE_MATURITY:
            return None
        async with open_db(repo_root) as conn:
            stats = await _feature_stats(conn, entity_id)
            distance = _distance(style_features(text), stats)
            if distance is None:
                return None
            async with conn.execute(
                "SELECT value FROM score_history WHERE entity_id = ? AND kind = ?",
                (entity_id, _DISTANCE_KIND),
            ) as cur:
                rows = await cur.fetchall()
        history = [float(r[0]) for r in rows]
        if not history:
            return None
        at_least = sum(1 for h in history if h >= distance)
        return (at_least + 1) / (len(history) + 1)
    except Exception:  # noqa: BLE001 — a scoring failure abstains (defense-in-depth)
        logger.warning("style p-value failed (entity %s); abstaining", entity_id[:12])
        return None
