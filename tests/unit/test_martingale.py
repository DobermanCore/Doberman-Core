"""Slice SL8.1 — the Martingale belief-entrenchment self-monitor.

Load-bearing properties: a prior-predictable (entrenched) belief stream is
flagged; a rational (martingale) stream and a steadily-trending stream are
not; findings need significance AND persistence before acting; entrenchment
toward "safe" triggers the raise-safe refresh while entrenchment toward
"risky" is surfaced with protection HELD — nothing here ever auto-loosens.
All streams are deterministic (fixed arrays / seeded RNG, injected clocks).
"""

from datetime import datetime, timezone

import numpy as np

from doberman.storage.db import open_db
from doberman.subjective.baseline import frequency, observe, reset_hst
from doberman.subjective.drift import reset_adwin
from doberman.subjective.martingale import (
    MIN_WINDOW,
    GuardOutcome,
    guard_self_update,
    martingale_score,
    note_belief,
    read_beliefs,
    run_monitor,
)

_NOW = datetime(2026, 6, 9, tzinfo=timezone.utc)
_EID = "hmac:martingale-test"


def _entrenched_stream(start=0.5, growth=1.019, n=36, wiggle=0.001):
    """Updates proportional to the prior (rich-get-richer): β₁ > 0.

    The default lands in "entrenched toward SAFE" territory (high mean
    belief); ``start=0.05, growth=1.08`` gives the risky-side variant.
    """
    beliefs, b = [], start
    for i in range(n):
        beliefs.append(min(0.99, b + wiggle * (-1) ** i))
        b = min(0.99, b * growth)
    return beliefs


def _rational_stream(n=60):
    """A seeded random walk: updates unpredictable from the prior (β₁ ≈ 0)."""
    deltas = np.random.default_rng(42).normal(0.0, 0.02, n)
    return list(np.clip(0.5 + np.cumsum(deltas), 0.01, 0.99))


def _trending_stream(n=40):
    """Steady drift under CONSISTENT evidence: constant updates, β₁ = 0."""
    return list(np.linspace(0.2, 0.8, n))


def _mean_reverting_stream(n=40):
    """Over-correction: updates pull back toward the middle (β₁ < 0)."""
    beliefs, b = [], 0.95
    for i in range(n):
        beliefs.append(b + 0.003 * (-1) ** i)
        b = b + 0.4 * (0.5 - b)
    return beliefs


# --- the score ----------------------------------------------------------------


def test_entrenched_stream_is_flagged():
    result = martingale_score(_entrenched_stream())
    assert result.beta > 0
    assert result.p_value < 0.05
    assert result.entrenched


def test_rational_stream_is_not_flagged():
    result = martingale_score(_rational_stream())
    assert not result.entrenched
    assert result.p_value >= 0.05


def test_trending_under_consistent_evidence_is_not_flagged():
    result = martingale_score(_trending_stream())
    assert abs(result.beta) < 1e-9
    assert not result.entrenched


def test_mean_reversion_is_over_correction_not_entrenchment():
    result = martingale_score(_mean_reverting_stream())
    assert result.over_correcting
    assert not result.entrenched


def test_short_and_degenerate_windows_never_flag():
    assert not martingale_score(_entrenched_stream(start=0.3, n=10)).entrenched  # too short
    # A constant window BELOW SAFE_BELIEF: nothing to regress on, and not the
    # dangerous frozen-HIGH case, so it stays unflagged (see
    # test_frozen_high_belief_is_flagged_entrenched below for the HIGH side).
    constant = [0.5] * (MIN_WINDOW + 5)
    result = martingale_score(constant)
    assert result.beta == 0.0
    assert result.p_value == 1.0


def test_frozen_high_belief_is_flagged_entrenched():
    # A belief window that stopped updating entirely at a HIGH (safe) value is
    # entrenchment's most extreme case — the zero-variance OLS blind spot.
    result = martingale_score([0.9] * (MIN_WINDOW + 2))
    assert result.beta > 0
    assert result.p_value < 0.05
    assert result.entrenched


def test_frozen_low_belief_not_flagged():
    # A frozen LOW (cautious) belief is unchanged behavior: raise-only means
    # this never auto-refreshes toward a warmer baseline.
    result = martingale_score([0.3] * (MIN_WINDOW + 2))
    assert not result.entrenched


# --- the monitor ----------------------------------------------------------------


async def _seed_beliefs(root, stream, eid=_EID):
    for value in stream:
        await note_belief(eid, float(value), repo_root=root, now=_NOW)


async def test_monitor_requires_persistence_before_acting(tmp_path):
    root = str(tmp_path)
    await _seed_beliefs(root, _entrenched_stream())
    first = await run_monitor(_EID, repo_root=root, now=_NOW)
    assert first is None  # one flagged window is not yet actionable
    second = await run_monitor(_EID, repo_root=root, now=_NOW)
    assert second == "refresh"  # persistence reached; mean belief is high (safe)


async def test_entrenched_toward_safe_refreshes_never_relaxes(tmp_path):
    root = str(tmp_path)
    reset_hst()
    reset_adwin()
    # Give the entity some familiarity, then an entrenched-toward-safe belief.
    from doberman.models import ActionType, Algebra, Capability, SecurityObject, TargetClass

    action = SecurityObject(
        id="mt-1",
        ts=_NOW,
        agent_role="frontend",
        action_type=ActionType.file_write,
        tool_name="fs_write",
        target="src/app.py",
        algebra=Algebra(
            capability=Capability.mutate,
            target_class=TargetClass.internal,
            classification_confidence=0.8,
        ),
    )
    for _ in range(8):
        await observe(action, entity_id=_EID, repo_root=root, now=_NOW)
    count_before = await frequency("target:internal", entity_id=_EID, repo_root=root)
    await _seed_beliefs(root, _entrenched_stream())  # high-mean entrenchment (safe side)
    await run_monitor(_EID, repo_root=root, now=_NOW)
    acted = await run_monitor(_EID, repo_root=root, now=_NOW)
    assert acted == "refresh"
    count_after = await frequency("target:internal", entity_id=_EID, repo_root=root)
    assert count_after < count_before  # familiarity discounted — MORE conservative
    assert await read_beliefs(_EID, repo_root=root) == []  # window reset with the refresh
    reset_hst()
    reset_adwin()


async def test_entrenched_toward_risky_is_surfaced_and_protection_held(tmp_path):
    root = str(tmp_path)
    # Same entrenchment shape, but at LOW belief (the layer keeps escalating).
    await _seed_beliefs(root, _entrenched_stream(start=0.05, growth=1.08))
    await run_monitor(_EID, repo_root=root, now=_NOW)
    acted = await run_monitor(_EID, repo_root=root, now=_NOW)
    assert acted == "review"
    async with open_db(root) as conn:
        async with conn.execute(
            "SELECT COUNT(*) FROM score_history WHERE entity_id = ? AND kind = ?",
            (_EID, "martingale_review"),
        ) as cur:
            reviews = (await cur.fetchone())[0]
    assert reviews >= 1  # surfaced for the operator
    assert await read_beliefs(_EID, repo_root=root)  # beliefs NOT wiped: held, not refreshed


async def test_frozen_high_stream_persists_to_refresh(tmp_path):
    root = str(tmp_path)
    await _seed_beliefs(root, [0.9] * (MIN_WINDOW + 2))
    first = await run_monitor(_EID, repo_root=root, now=_NOW)
    assert first is None  # one flagged window is not yet actionable
    second = await run_monitor(_EID, repo_root=root, now=_NOW)
    assert second == "refresh"  # persistence reached; frozen HIGH belief is the safe/dangerous case


async def test_frozen_low_stream_never_refreshes(tmp_path):
    root = str(tmp_path)
    eid = "hmac:martingale-frozen-low-test"
    await _seed_beliefs(root, [0.3] * (MIN_WINDOW + 2), eid=eid)
    for _ in range(2):
        assert await run_monitor(eid, repo_root=root, now=_NOW) is None


async def test_rational_stream_never_triggers_an_action(tmp_path):
    root = str(tmp_path)
    await _seed_beliefs(root, _rational_stream())
    for _ in range(4):
        assert await run_monitor(_EID, repo_root=root, now=_NOW) is None


async def test_monitor_never_raises_on_a_broken_db(tmp_path, monkeypatch):
    import doberman.subjective.martingale as mt

    def _boom(*args, **kwargs):
        raise OSError("db gone")

    monkeypatch.setattr(mt, "open_db", _boom)
    assert await run_monitor(_EID, repo_root=str(tmp_path), now=_NOW) is None
    await note_belief(_EID, 0.5, repo_root=str(tmp_path), now=_NOW)  # must not raise


# --- the guard (SL8.2 core mechanics) ----------------------------------------------


def test_guard_blocks_entrenched_and_insufficient_allows_rational():
    blocked = guard_self_update(_entrenched_stream())
    assert isinstance(blocked, GuardOutcome)
    assert not blocked.allowed
    assert "entrenched" in blocked.reason

    short = guard_self_update(_rational_stream(n=10))
    assert not short.allowed
    assert "insufficient" in short.reason

    allowed = guard_self_update(_rational_stream())
    assert allowed.allowed


def test_frozen_high_stream_blocks_self_update():
    # Tightens the self-improvement guard too: a fully frozen HIGH belief
    # stream is entrenched, so a proposed self-update driven by it is blocked.
    blocked = guard_self_update([0.9] * (MIN_WINDOW + 2))
    assert not blocked.allowed
