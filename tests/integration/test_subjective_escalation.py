"""Slice SL9.1 — end-to-end subjective escalation on the real decision path.

The full SL pipeline through the executor: normalize infers the algebra, the
proxy precomputes the per-entity blended surprise + fatigue budget, and the
engine combines surprise × sensitivity × care. A mature baseline (≥ K own
observations, seeded in balanced mode, then tightened to strict — the
realistic operator flow) lets a familiar action PASS while a jointly-risky
novel action (an irreversible glob delete) escalates; a denied attempt is
never learned AND never exhausts the budget (denial holds protection).
"""

from datetime import datetime, timezone

from doberman.auth.challenge import AuthResult, AuthTier
from doberman.config import save_mode
from doberman.proxy import executor
from doberman.subjective.baseline import reset_hst
from doberman.subjective.drift import K_OBSERVATIONS, reset_adwin

from .test_proxy_passthrough import proxied_session


def _deny(
    decision, action, *, prompter=None, at=None, message_tone=None, repo_root=None, session_id=None
):
    return AuthResult(
        approved=False,
        tier=AuthTier.local_auth,
        method="denied",
        at=datetime.now(timezone.utc),
        action_id=action.id,
    )


async def _seed_habit(agent, count=K_OBSERVATIONS):
    """Establish a frontend-editing habit (enough to outgrow the peer prior)."""
    for i in range(count):
        ok = await agent.call_tool("fs_write", {"path": f"frontend/c{i % 25}.tsx", "content": "x"})
        assert not ok.isError


async def test_unusual_risky_action_escalates_familiar_action_passes(monkeypatch):
    monkeypatch.setattr(executor, "run_auth_challenge", _deny)
    reset_hst()
    reset_adwin()
    async with proxied_session() as (fake, agent):
        await _seed_habit(agent)
        # The operator tightens the dial once the workflow has settled.
        save_mode("strict", executor.REPO_ROOT)

        # A familiar frontend edit still PASSes (the class is normal now).
        familiar = await agent.call_tool("fs_write", {"path": "frontend/Hero.tsx", "content": "x"})
        assert not familiar.isError
        forwarded_before = len(fake.calls)

        # A never-seen, hard-to-undo, high-blast shape (glob delete) for this
        # workflow → subjective AUTH → the denied challenge forwards nothing.
        unusual = await agent.call_tool("fs_delete", {"path": "src/*.py"})
        assert unusual.isError
        assert "authentication required" in unusual.content[0].text
        assert len(fake.calls) == forwarded_before  # the unusual action did NOT run


async def test_denied_attempt_neither_teaches_nor_exhausts_the_budget(monkeypatch):
    # A denied (un-forwarded) unusual action must not be recorded as "normal",
    # and the denial must not consume the fatigue budget — repeating the very
    # action that was just refused still escalates (raise-only).
    monkeypatch.setattr(executor, "run_auth_challenge", _deny)
    reset_hst()
    reset_adwin()
    async with proxied_session() as (fake, agent):
        await _seed_habit(agent)
        save_mode("strict", executor.REPO_ROOT)
        first = await agent.call_tool("fs_delete", {"path": "src/*.py"})
        second = await agent.call_tool("fs_delete", {"path": "src/*.py"})
        assert first.isError and second.isError  # still escalating, never learned
        assert all(name != "fs_delete" for name, _ in fake.calls)
