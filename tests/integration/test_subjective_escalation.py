"""Slice 9.3 — end-to-end: an unusual action escalates after a baseline forms."""

from datetime import datetime, timezone

from doberman.auth.challenge import AuthResult, AuthTier
from doberman.learning.baseline import _COLD_START_MIN
from doberman.proxy import executor

from .test_proxy_passthrough import proxied_session


def _deny(decision, action, *, prompter=None, at=None):
    return AuthResult(
        approved=False,
        tier=AuthTier.local_auth,
        method="denied",
        at=datetime.now(timezone.utc),
        action_id=action.id,
    )


async def test_unusual_action_escalates_normal_action_passes(monkeypatch):
    monkeypatch.setattr(executor, "run_auth_challenge", _deny)
    async with proxied_session() as (fake, agent):
        # Establish a frontend-editing habit (>= the cold-start minimum).
        for i in range(_COLD_START_MIN + 1):
            ok = await agent.call_tool("fs_write", {"path": f"frontend/c{i}.tsx", "content": "x"})
            assert not ok.isError

        # A familiar frontend edit still PASSes (the class is normal now).
        familiar = await agent.call_tool("fs_write", {"path": "frontend/Hero.tsx", "content": "x"})
        assert not familiar.isError
        forwarded_before = len(fake.calls)

        # A never-seen path class for this workflow → subjective AUTH → the
        # denied challenge forwards nothing.
        unusual = await agent.call_tool("fs_write", {"path": "backend/api.ts", "content": "x"})
        assert unusual.isError
        assert "authentication required" in unusual.content[0].text
        assert "unusual_for_workflow" in unusual.content[0].text
        assert len(fake.calls) == forwarded_before  # the unusual action did NOT run


async def test_blocked_attempt_does_not_teach_the_baseline(monkeypatch):
    # A denied (un-forwarded) unusual action must not be recorded as "normal":
    # repeating it still escalates rather than being learned as routine.
    monkeypatch.setattr(executor, "run_auth_challenge", _deny)
    async with proxied_session() as (fake, agent):
        for i in range(_COLD_START_MIN + 1):
            await agent.call_tool("fs_write", {"path": f"frontend/c{i}.tsx", "content": "x"})
        first = await agent.call_tool("fs_write", {"path": "backend/api.ts", "content": "x"})
        second = await agent.call_tool("fs_write", {"path": "backend/api.ts", "content": "x"})
        assert first.isError and second.isError  # still escalating, never learned
