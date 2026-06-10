"""Peer-group cold-start + ADWIN drift handling (SL4.3).

Two complements to the per-entity baseline:

* **Cold start.** Until an entity has :data:`K_OBSERVATIONS` of its own
  history, its surprise blends with a **peer-group prior** — the pooled
  baselines of entities sharing its agent role — and, with no peers at all,
  with a conservative warn-leaning global prior. A brand-new deployment is
  cautious, not blind and not a prompt storm.
* **Drift.** A River ADWIN detector (Bifet & Gavaldà, SDM 2007) watches each
  entity's novelty stream (allowed actions only). On detected drift the
  baseline is REFRESHED — counts discounted, variance and calibration history
  reset, the in-process HST dropped — rather than blindly accumulated.
  Refresh only ever discounts familiarity, so it tightens or holds protection;
  it can never loosen it.

This module is policy core: it must never import ``doberman.proxy``.
"""

import logging

from river import drift as _river_drift

from doberman.models import SecurityObject
from doberman.storage.db import open_db
from doberman.subjective.baseline import (
    _novelty as _frequency_novelty,
)
from doberman.subjective.baseline import (
    novelty_score,
    reset_hst,
    scoring_keys,
    surprise,
    total_observations,
)

logger = logging.getLogger("doberman.subjective.drift")

#: Observations an entity needs before its own baseline fully takes over.
K_OBSERVATIONS = 100

#: The conservative, warn-leaning prior when an entity has no peers at all.
GLOBAL_PRIOR = 0.5

#: In-process ADWIN detectors, one per entity (rebuilt empty on restart, like
#: the HST — the persisted counts keep their memory; the detector re-warms).
_ADWIN: dict[str, _river_drift.ADWIN] = {}


def reset_adwin(entity: str | None = None) -> None:
    """Drop in-process drift-detector state (one entity, or all)."""
    if entity is None:
        _ADWIN.clear()
    else:
        _ADWIN.pop(entity, None)


def feed_drift_value(entity_id: str, value: float) -> bool:
    """Feed one observation into the entity's ADWIN; True when drift is detected.

    In-memory and synchronous. On detection the detector is reset so a single
    regime change fires once, not on every subsequent observation.
    """
    detector = _ADWIN.get(entity_id)
    if detector is None:
        detector = _river_drift.ADWIN()
        _ADWIN[entity_id] = detector
    detector.update(value)
    if detector.drift_detected:
        _ADWIN[entity_id] = _river_drift.ADWIN()
        return True
    return False


async def refresh_baseline(entity_id: str, *, repo_root: str) -> None:
    """Refresh (discount) an entity's baseline after drift. Raise-safe, never raises.

    Counts are halved — including the entity's total, which re-engages the
    cold-start peer/global prior — so familiarity only ever DECREASES. The
    sequence model (transitions + state), numeric variance, and the calibration
    history are reset outright (a halved Markov table would paradoxically make
    unseen transitions LESS surprising under Laplace smoothing), and the
    in-process HST window is dropped. Nothing here can make a familiar shape
    more familiar or suppress a step-up that would have fired before.
    """
    try:
        async with open_db(repo_root) as conn:
            await conn.execute(
                "UPDATE baseline_counts SET count = count / 2, m2 = 0, ewma_var = 0 "
                "WHERE entity_id = ?",
                (entity_id,),
            )
            await conn.execute("DELETE FROM baseline_transitions WHERE entity_id = ?", (entity_id,))
            await conn.execute("DELETE FROM baseline_state WHERE entity_id = ?", (entity_id,))
            await conn.execute("DELETE FROM score_history WHERE entity_id = ?", (entity_id,))
            await conn.commit()
    except Exception:  # noqa: BLE001 — refresh is hygiene; failure must not crash the path
        logger.warning("baseline refresh failed (entity %s); continuing", entity_id[:12])
        return
    reset_hst(entity_id)
    reset_adwin(entity_id)
    logger.info("baseline refreshed after drift (entity %s)", entity_id[:12])


async def note_allowed(action: SecurityObject, *, entity_id: str, repo_root: str) -> bool:
    """Post-allow drift hook: feed the novelty stream; refresh on drift.

    Called by the proxy AFTER :func:`doberman.subjective.baseline.observe`
    (allowed actions only — denied attempts feed nothing). Returns whether a
    refresh happened. Never raises.
    """
    try:
        value = await novelty_score(action, entity_id=entity_id, repo_root=repo_root)
        if feed_drift_value(entity_id, value):
            await refresh_baseline(entity_id, repo_root=repo_root)
            return True
    except Exception:  # noqa: BLE001 — drift monitoring must never break the path
        logger.warning("drift monitoring failed (entity %s); continuing", entity_id[:12])
    return False


async def _peer_novelty(action: SecurityObject, *, entity_id: str, repo_root: str) -> float | None:
    """Frequency novelty against the POOLED baselines of same-role peers.

    ``None`` when the entity has no peers (the caller falls back to the global
    prior). The pool excludes the entity itself.
    """
    role = action.agent_role
    try:
        async with open_db(repo_root) as conn:
            async with conn.execute(
                "SELECT COUNT(DISTINCT entity_id) FROM baseline_counts "
                "WHERE role = ? AND entity_id != ?",
                (role, entity_id),
            ) as cur:
                peers = int((await cur.fetchone())[0])
            if peers == 0:
                return None
            worst = 0.0
            for key in scoring_keys(action):
                async with conn.execute(
                    "SELECT COALESCE(SUM(count), 0) FROM baseline_counts "
                    "WHERE role = ? AND entity_id != ? AND feature_key = ?",
                    (role, entity_id, key),
                ) as cur:
                    pooled = int((await cur.fetchone())[0])
                worst = max(worst, _frequency_novelty(pooled))
    except Exception:  # noqa: BLE001 — peer lookup failure falls back to the global prior
        return None
    return worst


async def surprise_blended(action: SecurityObject, *, entity_id: str, repo_root: str) -> float:
    """Cold-start-aware surprise: blend own baseline with the peer prior.

    ``w = min(1, own_observations / K_OBSERVATIONS)`` weights the entity's own
    calibrated surprise against its peer cohort's novelty (or the conservative
    :data:`GLOBAL_PRIOR` with no peers). A mature entity (≥ K) is scored purely
    on its own baseline. Never raises; failure → 1.0 (fail toward caution).
    """
    try:
        own = await surprise(action, entity_id=entity_id, repo_root=repo_root)
        observed = await total_observations(entity_id=entity_id, repo_root=repo_root)
        weight = min(1.0, observed / K_OBSERVATIONS)
        if weight >= 1.0:
            return own
        prior = await _peer_novelty(action, entity_id=entity_id, repo_root=repo_root)
        if prior is None:
            prior = GLOBAL_PRIOR
        return max(0.0, min(1.0, weight * own + (1.0 - weight) * prior))
    except Exception:  # noqa: BLE001 — scoring failure fails toward caution
        logger.warning("blended surprise failed (entity %s); scoring 1.0", entity_id[:12])
        return 1.0
