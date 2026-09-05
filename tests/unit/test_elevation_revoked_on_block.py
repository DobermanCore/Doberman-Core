"""Issue #557 — a post-approval synthetic BLOCK must revoke the elevation
grant it followed.

``_handle_auth`` grants a role elevation, then re-checks the action twice
before releasing it: a TOCTOU redecision, and (for delete-class commands)
C2's effect-set-divergence recompute. Both re-checks used to return their
synthetic BLOCK without revoking the elevation just granted a moment earlier
— the grant stayed active for its full TTL, so an immediate retry of the
same target could ride the leaked elevation straight to PASS (no effect
recompute, single-use claimed and released). These tests reproduce both
paths and prove the grant no longer survives either BLOCK, and that a
revoke failure still fails closed (the BLOCK stands regardless).
"""

from datetime import datetime, timezone

from doberman.auth.challenge import AuthResult, AuthTier
from doberman.engine.decision_engine import StaticGuardrail
from doberman.models import GuardrailResult, ReasonCode, Risk, Verdict
from doberman.proxy import executor
from doberman.storage.db import active_elevations
from tests.integration.test_proxy_passthrough import proxied_session


def _approve_role_elevation(calls=None):
    def challenge(
        decision,
        action,
        *,
        prompter=None,
        at=None,
        message_tone=None,
        repo_root=None,
        session_id=None,
    ):
        if calls is not None:
            calls["n"] += 1
        return AuthResult(
            approved=True,
            tier=AuthTier.role_elevation,
            method="test",
            at=datetime.now(timezone.utc),
            action_id=action.id,
        )

    return challenge


class _FlipToBlock:
    """AUTH on the first evaluation, BLOCK on every one after — a TOCTOU redecision."""

    def __init__(self):
        self._seen = 0

    def evaluate(self, action, ctx):
        self._seen += 1
        if self._seen == 1:
            return GuardrailResult(
                verdict=Verdict.AUTH,
                risk=Risk.high,
                reason_codes=[ReasonCode.sensitive_path_access],
                explanation="first look: auth",
            )
        return GuardrailResult(
            verdict=Verdict.BLOCK,
            risk=Risk.critical,
            reason_codes=[ReasonCode.protected_path_blocked],
            explanation="second look: blocked",
        )


async def test_toctou_block_after_elevation_grant_revokes_it(
    monkeypatch, isolated_executor_repo_root
):
    """The TOCTOU redecision-BLOCK path revokes the elevation it followed."""
    monkeypatch.setattr(executor, "DEFAULT_OBJECTIVE", _FlipToBlock())
    monkeypatch.setattr(executor, "run_auth_challenge", _approve_role_elevation())
    async with proxied_session() as (fake, agent):
        result = await agent.call_tool("fs_write", {"path": "backend/api.ts", "content": "x"})

    # The BLOCK's own reason codes/explanation are untouched by the revoke.
    assert result.isError
    text = result.content[0].text
    assert "blocked by policy" in text
    assert ReasonCode.protected_path_blocked.value in text
    assert fake.calls == []  # never forwarded

    # The grant made moments earlier must not have survived the BLOCK.
    root = str(isolated_executor_repo_root)
    grants = await active_elevations(root, datetime.now(timezone.utc))
    assert grants == []


async def test_effect_set_diverged_after_elevation_grant_revokes_it(
    monkeypatch, isolated_executor_repo_root
):
    """C2's effect-set-divergence BLOCK path revokes the elevation it followed."""
    target = isolated_executor_repo_root / "fixture"
    target.mkdir()
    (target / "a.txt").write_text("x", encoding="utf-8")

    def approve_and_race(decision, action, **kwargs):
        # The filesystem changes WHILE the (mocked) human looks at the challenge,
        # same race as test_blast_radius_preview's TOCTOU tests, but this time the
        # approval is a role elevation, so a grant exists to leak.
        (target / "b.txt").write_text("x", encoding="utf-8")
        return AuthResult(
            approved=True,
            tier=AuthTier.role_elevation,
            method="test",
            at=datetime.now(timezone.utc),
            action_id=action.id,
        )

    monkeypatch.setattr(
        executor,
        "DEFAULT_OBJECTIVE",
        StaticGuardrail(
            GuardrailResult(
                verdict=Verdict.AUTH,
                risk=Risk.high,
                reason_codes=[ReasonCode.destructive_command],
                explanation="test auth",
            )
        ),
    )
    monkeypatch.setattr(executor, "run_auth_challenge", approve_and_race)
    async with proxied_session() as (fake, agent):
        result = await agent.call_tool("shell_exec", {"command": "rm -rf fixture"})

    assert result.isError
    text = result.content[0].text
    assert "blocked by policy" in text
    assert ReasonCode.effect_set_diverged.value in text
    assert fake.calls == []  # never forwarded

    root = str(isolated_executor_repo_root)
    grants = await active_elevations(root, datetime.now(timezone.utc))
    assert grants == []


async def test_revoke_failure_after_block_still_fails_closed(
    monkeypatch, isolated_executor_repo_root, caplog
):
    """A revoke error must never crash the path or soften the BLOCK it followed."""
    import logging

    monkeypatch.setattr(executor, "DEFAULT_OBJECTIVE", _FlipToBlock())
    monkeypatch.setattr(executor, "run_auth_challenge", _approve_role_elevation())

    def boom_revoke(repo_root, elevation_id):
        raise RuntimeError("db exploded")

    monkeypatch.setattr(executor, "revoke_elevation", boom_revoke)
    with caplog.at_level(logging.WARNING, logger="doberman.proxy.engine"):
        async with proxied_session() as (fake, agent):
            result = await agent.call_tool("fs_write", {"path": "backend/api.ts", "content": "x"})

    # The BLOCK stands regardless of the revoke's own failure — fail closed.
    assert result.isError
    text = result.content[0].text
    assert "blocked by policy" in text
    assert ReasonCode.protected_path_blocked.value in text
    assert fake.calls == []
    assert any("elevation revoke failed" in r.message for r in caplog.records)


async def test_single_use_unclaimable_after_elevation_grant_revokes_it(
    monkeypatch, isolated_executor_repo_root
):
    """The single-use-unclaimable BLOCK path — a storage error mid-claim, not a
    policy re-decision — revokes the elevation it followed too."""
    monkeypatch.setattr(
        executor,
        "DEFAULT_OBJECTIVE",
        StaticGuardrail(
            GuardrailResult(
                verdict=Verdict.AUTH,
                risk=Risk.high,
                reason_codes=[ReasonCode.sensitive_path_access],
                explanation="test auth",
            )
        ),
    )
    monkeypatch.setattr(executor, "run_auth_challenge", _approve_role_elevation())

    def boom_claim_single_use(repo_root, elevation_id):
        raise RuntimeError("db exploded")

    monkeypatch.setattr(executor, "claim_single_use", boom_claim_single_use)
    async with proxied_session() as (fake, agent):
        result = await agent.call_tool("fs_delete", {"path": "backend/api.ts"})

    # The claim raises BEFORE the forward — the downstream must never see it.
    assert result.isError
    text = result.content[0].text
    assert "blocked by policy" in text
    assert ReasonCode.single_use_elevation_unclaimable.value in text
    assert fake.calls == []

    # The grant made moments earlier must not have survived the BLOCK.
    root = str(isolated_executor_repo_root)
    grants = await active_elevations(root, datetime.now(timezone.utc))
    assert grants == []
