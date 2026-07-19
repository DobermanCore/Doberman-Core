"""Martingale belief-entrenchment self-monitor + self-improvement guard (SL8).

A learned baseline can silently lock in a belief about an entity ("operating
normally") and stop responding to evidence — a failure ordinary drift
detection (input shift) does not catch. The **Martingale Score** detects this
irrational non-updating directly and needs no ground truth:

    Under rational Bayesian updating the expected belief update is zero
    conditional on the prior — ``E[Δb | b_prior] = 0`` — so belief updates
    must be UNPREDICTABLE from the current belief. Regress
    ``Δb = β₁·b_prior + β₀ + ε`` by OLS over a recent window: a significantly
    POSITIVE β̂₁ means the belief is updating toward its prior rather than
    toward evidence (entrenchment); significantly negative means
    over-correction.

    — He, Z. et al., *Martingale Score: An Unsupervised Metric for Bayesian
    Rationality in LLM Reasoning*, NeurIPS 2025 (arXiv:2512.02914). The
    foundational martingale ≡ Bayesian-rationality result is Molavi 2021
    (arXiv:2109.07007); the martingale lens on in-context updating is Falck
    et al. 2024 (arXiv:2406.00793).

Here ``b = 1 − calibrated surprise`` — the layer's own belief that the entity
is operating normally, recorded on allowed actions (the revealed-belief
methodology: audit observable outputs, not internal state).

How findings are acted on (NEVER auto-loosening):

* Entrenched toward **safe** (high mean belief) → the dangerous case, a
  baseline that stopped escalating → trigger the raise-safe SL4.3 baseline
  refresh (colder baseline, more step-ups, lean on the peer prior).
* Entrenched toward **risky** (low mean belief) → surface for operator review
  (avoid silent over-blocking) but HOLD protection.
* Findings require statistical significance AND persistence across
  consecutive windows — consistent genuine evidence can produce a nonzero
  score, so the score is a diagnostic flag, never an automatic verdict change.
* The **self-improvement guard** (SL8.2) blocks any proposed self-update whose
  driving belief stream is entrenched (prior-predictable rather than
  evidence-driven), or whose evidence is insufficient — regardless of the
  update's direction. A weakening that passes the guard STILL hits the F10
  gate.

Pure local statistics over numbers the layer already produces; no training.
This module is policy core: it must never import ``doberman.proxy``.
"""

import logging
from dataclasses import dataclass
from datetime import datetime, timezone

import numpy as np
from scipy import stats as _scipy_stats

from doberman.storage.db import open_db
from doberman.subjective.baseline import SCORE_HISTORY_KEEP

logger = logging.getLogger("doberman.subjective.martingale")

#: Minimum beliefs in a window before any score is computed (no flag below).
MIN_WINDOW = 30

#: Two-sided significance threshold for the β̂₁ t-test.
P_THRESHOLD = 0.05

#: Consecutive flagged windows required before the monitor ACTS on a finding.
PERSISTENCE = 2

#: The proxy runs the monitor every this-many observed (allowed) actions.
MONITOR_EVERY = 50

#: Mean belief at/above which an entrenchment counts as "entrenched toward
#: safe" (the dangerous, refresh-triggering case).
SAFE_BELIEF = 0.7

_KIND_BELIEF = "belief"
_KIND_FLAG = "martingale_flag"
_KIND_CLEAR = "martingale_clear"
_KIND_REVIEW = "martingale_review"


@dataclass(frozen=True)
class MartingaleResult:
    """One window's score: ``M = β̂₁`` with its significance and sample size."""

    beta: float
    p_value: float
    n: int

    @property
    def entrenched(self) -> bool:
        """Significantly positive β̂₁ on a sufficient window."""
        return self.n >= MIN_WINDOW and self.beta > 0 and self.p_value < P_THRESHOLD

    @property
    def over_correcting(self) -> bool:
        """Significantly negative β̂₁ on a sufficient window."""
        return self.n >= MIN_WINDOW and self.beta < 0 and self.p_value < P_THRESHOLD


@dataclass(frozen=True)
class GuardOutcome:
    """The self-improvement guard's verdict on a proposed update."""

    allowed: bool
    reason: str
    result: MartingaleResult | None = None


def martingale_score(beliefs: list[float] | tuple[float, ...]) -> MartingaleResult:
    """OLS of ``Δb`` on ``b_prior`` over the window: ``M = β̂₁`` + t-test p.

    Degenerate windows (too short, or a constant prior with nothing to regress
    on) score ``(0, p=1)`` — no flag, never a crash.
    """
    series = np.asarray(beliefs, dtype=float)
    n = len(series)
    if n < MIN_WINDOW + 1:
        return MartingaleResult(beta=0.0, p_value=1.0, n=n)
    prior = series[:-1]
    delta = np.diff(series)
    x_centered = prior - prior.mean()
    sxx = float(np.dot(x_centered, x_centered))
    if sxx < 1e-12:
        # A literally-invariant belief window is entrenchment's extreme case:
        # the belief stopped updating entirely, which OLS can't express (no
        # regressor variance to regress on) so it would otherwise score "no
        # signal". Flag it directly — but ONLY when the frozen belief is HIGH
        # (the dangerous "stopped escalating / desensitized" case, which
        # run_monitor routes to the raise-safe baseline refresh). A frozen LOW
        # belief stays unflagged, exactly as before (raise-only: never
        # auto-refreshes a cautious baseline).
        if float(prior.mean()) >= SAFE_BELIEF:
            return MartingaleResult(beta=1.0, p_value=0.0, n=n)
        return MartingaleResult(beta=0.0, p_value=1.0, n=n)
    beta = float(np.dot(x_centered, delta - delta.mean()) / sxx)
    intercept = float(delta.mean() - beta * prior.mean())
    residuals = delta - (intercept + beta * prior)
    dof = len(delta) - 2
    sse = float(np.dot(residuals, residuals))
    if dof <= 0:
        return MartingaleResult(beta=beta, p_value=1.0, n=n)
    se_sq = (sse / dof) / sxx
    if se_sq < 1e-18:
        p_value = 0.0 if abs(beta) > 1e-12 else 1.0
    else:
        t_stat = beta / float(np.sqrt(se_sq))
        p_value = float(2.0 * _scipy_stats.t.sf(abs(t_stat), dof))
    return MartingaleResult(beta=beta, p_value=p_value, n=n)


async def _append(conn, entity_id: str, kind: str, value: float, stamp: str) -> None:
    await conn.execute(
        "INSERT INTO score_history (entity_id, ts, kind, value) VALUES (?, ?, ?, ?)",
        (entity_id, stamp, kind, float(value)),
    )
    await conn.execute(
        "DELETE FROM score_history WHERE entity_id = ? AND kind = ? AND id NOT IN ("
        "SELECT id FROM score_history WHERE entity_id = ? AND kind = ? "
        "ORDER BY id DESC LIMIT ?)",
        (entity_id, kind, entity_id, kind, SCORE_HISTORY_KEEP),
    )


async def note_belief(
    entity_id: str, belief: float, *, repo_root: str, now: datetime | None = None
) -> None:
    """Append one belief observation (``1 − calibrated surprise``). Never raises."""
    stamp = (now or datetime.now(timezone.utc)).isoformat()
    try:
        async with open_db(repo_root) as conn:
            await _append(conn, entity_id, _KIND_BELIEF, max(0.0, min(1.0, belief)), stamp)
            await conn.commit()
    except Exception:  # noqa: BLE001 — monitoring must never break the path
        logger.warning("belief append failed (entity %s); continuing", entity_id[:12])


async def read_beliefs(entity_id: str, *, repo_root: str) -> list[float]:
    """The entity's recent belief window, OLDEST FIRST ([] on any failure)."""
    try:
        async with open_db(repo_root) as conn:
            async with conn.execute(
                "SELECT value FROM score_history WHERE entity_id = ? AND kind = ? "
                "ORDER BY id DESC LIMIT ?",
                (entity_id, _KIND_BELIEF, SCORE_HISTORY_KEEP),
            ) as cur:
                rows = await cur.fetchall()
    except Exception:  # noqa: BLE001 — a read failure simply means no audit data
        return []
    return [float(r[0]) for r in reversed(rows)]


async def _consecutive_flags(conn, entity_id: str) -> int:
    """How many of the most recent monitor verdicts (flag/clear) were flags."""
    async with conn.execute(
        "SELECT kind FROM score_history WHERE entity_id = ? AND kind IN (?, ?) "
        "ORDER BY id DESC LIMIT ?",
        (entity_id, _KIND_FLAG, _KIND_CLEAR, PERSISTENCE),
    ) as cur:
        rows = await cur.fetchall()
    streak = 0
    for (kind,) in rows:
        if kind != _KIND_FLAG:
            break
        streak += 1
    return streak


async def run_monitor(entity_id: str, *, repo_root: str, now: datetime | None = None) -> str | None:
    """One monitor pass over the entity's belief window. Never raises.

    Returns the action taken: ``"refresh"`` (entrenched toward safe → the
    raise-safe baseline refresh), ``"review"`` (entrenched toward risky →
    surfaced, protection HELD), or ``None``. Requires significance AND
    :data:`PERSISTENCE` consecutive flagged windows before acting.
    """
    stamp = (now or datetime.now(timezone.utc)).isoformat()
    try:
        beliefs = await read_beliefs(entity_id, repo_root=repo_root)
        result = martingale_score(beliefs)
        async with open_db(repo_root) as conn:
            if not result.entrenched:
                await _append(conn, entity_id, _KIND_CLEAR, result.beta, stamp)
                await conn.commit()
                return None
            await _append(conn, entity_id, _KIND_FLAG, result.beta, stamp)
            await conn.commit()
            streak = await _consecutive_flags(conn, entity_id)
        if streak < PERSISTENCE:
            return None

        mean_belief = float(np.mean(beliefs[-MIN_WINDOW:]))
        if mean_belief >= SAFE_BELIEF:
            # The dangerous case: a baseline that stopped escalating. Refresh
            # is strictly MORE conservative (colder baseline, peer prior).
            from doberman.subjective.drift import refresh_baseline

            logger.warning(
                "belief entrenched toward safe (entity %s, beta=%.3f); refreshing baseline",
                entity_id[:12],
                result.beta,
            )
            await refresh_baseline(entity_id, repo_root=repo_root)
            return "refresh"

        # Entrenched toward risky: surface for review, HOLD protection.
        logger.warning(
            "belief entrenched toward risky (entity %s, beta=%.3f); surfaced for review",
            entity_id[:12],
            result.beta,
        )
        async with open_db(repo_root) as conn:
            await _append(conn, entity_id, _KIND_REVIEW, result.beta, stamp)
            await conn.commit()
        return "review"
    except Exception:  # noqa: BLE001 — the monitor must never break the path
        logger.warning("martingale monitor failed (entity %s); continuing", entity_id[:12])
        return None


def guard_self_update(beliefs: list[float] | tuple[float, ...]) -> GuardOutcome:
    """SL8.2: gate a proposed self-update on evidence-driven updating.

    BLOCKS (never auto-approves) when the driving belief stream is too short
    (insufficient evidence) or significantly prior-predictable (entrenched —
    the proposal reflects the learner's prior, not the replay evidence),
    regardless of the update's direction. An allowed WEAKENING still has to
    pass the F10 gate afterwards.
    """
    if len(beliefs) < MIN_WINDOW + 1:
        return GuardOutcome(
            allowed=False,
            reason=f"insufficient evidence ({len(beliefs)} beliefs; need > {MIN_WINDOW})",
        )
    result = martingale_score(beliefs)
    if result.entrenched:
        return GuardOutcome(
            allowed=False,
            reason=f"belief stream is entrenched (beta={result.beta:.3f}, p={result.p_value:.4f})",
            result=result,
        )
    return GuardOutcome(allowed=True, reason="evidence-driven", result=result)
