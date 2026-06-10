"""SL7 (transitional) — end-to-end subjective escalation through the executor.

Until SL9 wires the per-entity surprise + algebra inference into the proxy,
the executor still hands the engine the legacy abnormality score and a
default (unclassified) algebra. In STRICT mode an unusual action's
jointly-elevated terms (full novelty × unclassified-elevated sensitivity ×
strict care) clear the threshold, so the F9 end-to-end properties still hold:
an unusual action escalates, a familiar one passes, and a denied attempt
never teaches the baseline. SL9 finalizes this test against the full path.
"""

from datetime import datetime, timezone

from doberman.auth.challenge import AuthResult, AuthTier
from doberman.config import save_mode
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
    save_mode("strict", executor.REPO_ROOT)
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
        assert "unusual" in unusual.content[0].text
        assert len(fake.calls) == forwarded_before  # the unusual action did NOT run


async def test_blocked_attempt_does_not_teach_the_baseline(monkeypatch):
    # A denied (un-forwarded) unusual action must not be recorded as "normal":
    # repeating it still escalates rather than being learned as routine.
    monkeypatch.setattr(executor, "run_auth_challenge", _deny)
    save_mode("strict", executor.REPO_ROOT)
    async with proxied_session() as (fake, agent):
        for i in range(_COLD_START_MIN + 1):
            await agent.call_tool("fs_write", {"path": f"frontend/c{i}.tsx", "content": "x"})
        first = await agent.call_tool("fs_write", {"path": "backend/api.ts", "content": "x"})
        second = await agent.call_tool("fs_write", {"path": "backend/api.ts", "content": "x"})
        assert first.isError and second.isError  # still escalating, never learned
