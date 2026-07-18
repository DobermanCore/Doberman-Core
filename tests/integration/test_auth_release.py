"""Slice 7.5 — actions are released only after a successful, bound auth."""

import logging
from datetime import datetime, timezone

from doberman.auth.challenge import AuthResult, AuthTier
from doberman.engine.decision_engine import StaticGuardrail
from doberman.models import GuardrailResult, ReasonCode, Risk, Verdict
from doberman.proxy import executor

from .test_proxy_passthrough import proxied_session

_AUTHING = StaticGuardrail(
    GuardrailResult(
        verdict=Verdict.AUTH,
        risk=Risk.high,
        reason_codes=[ReasonCode.sensitive_path_access],
        explanation="Stub objective requires authentication.",
    )
)


def _approve(tier=AuthTier.local_auth):
    def challenge(decision, action, *, prompter=None, at=None):
        return AuthResult(
            approved=True,
            tier=tier,
            method="test",
            at=datetime.now(timezone.utc),
            action_id=action.id,
        )

    return challenge


def _deny(decision, action, *, prompter=None, at=None):
    return AuthResult(
        approved=False,
        tier=AuthTier.local_auth,
        method="denied",
        at=datetime.now(timezone.utc),
        action_id=action.id,
    )


def _approve_for_wrong_action(decision, action, *, prompter=None, at=None):
    return AuthResult(
        approved=True,
        tier=AuthTier.local_auth,
        method="test",
        at=datetime.now(timezone.utc),
        action_id="some-other-action",
    )


def _write_role(repo_root):
    cfg = repo_root / ".doberman"
    cfg.mkdir(parents=True, exist_ok=True)
    (cfg / "role.yaml").write_text(
        'name: webdev\nallowed:\n  - "frontend/**"\nsuspicious:\n  - "backend/**"\n',
        encoding="utf-8",
    )


async def test_approved_auth_forwards_and_records(monkeypatch):
    monkeypatch.setattr(executor, "DEFAULT_OBJECTIVE", _AUTHING)
    monkeypatch.setattr(executor, "run_auth_challenge", _approve())
    async with proxied_session() as (fake, agent):
        result = await agent.call_tool("fs_write", {"path": "a.txt", "content": "x"})
        assert not result.isError
        assert fake.calls == [("fs_write", {"path": "a.txt", "content": "x"})]


async def test_denied_auth_forwards_nothing(monkeypatch):
    monkeypatch.setattr(executor, "DEFAULT_OBJECTIVE", _AUTHING)
    monkeypatch.setattr(executor, "run_auth_challenge", _deny)
    async with proxied_session() as (fake, agent):
        result = await agent.call_tool("fs_write", {"path": "a.txt", "content": "x"})
        assert result.isError
        assert "authentication required" in result.content[0].text
        assert fake.calls == []


async def test_approval_must_be_bound_to_this_action_id(monkeypatch):
    monkeypatch.setattr(executor, "DEFAULT_OBJECTIVE", _AUTHING)
    monkeypatch.setattr(executor, "run_auth_challenge", _approve_for_wrong_action)
    async with proxied_session() as (fake, agent):
        result = await agent.call_tool("fs_write", {"path": "a.txt", "content": "x"})
        # Approval for a different action id must not release THIS one.
        assert result.isError
        assert fake.calls == []


async def test_toctou_redecision_to_block_is_honored(monkeypatch):
    class FlipToBlock:
        """AUTH on the first evaluation, BLOCK on every one after (a TOCTOU change)."""

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

    monkeypatch.setattr(executor, "DEFAULT_OBJECTIVE", FlipToBlock())
    monkeypatch.setattr(executor, "run_auth_challenge", _approve())
    async with proxied_session() as (fake, agent):
        result = await agent.call_tool("fs_write", {"path": "a.txt", "content": "x"})
        # Approved, but the re-decision flipped to BLOCK → never forwarded.
        assert result.isError
        assert "blocked by policy" in result.content[0].text
        assert fake.calls == []


async def test_role_elevation_grants_then_covered_file_passes(
    monkeypatch, isolated_executor_repo_root
):
    _write_role(isolated_executor_repo_root)
    calls = {"n": 0}

    def approve_elev(decision, action, *, prompter=None, at=None):
        calls["n"] += 1
        return AuthResult(
            approved=True,
            tier=AuthTier.role_elevation,
            method="test",
            at=datetime.now(timezone.utc),
            action_id=action.id,
        )

    monkeypatch.setattr(executor, "run_auth_challenge", approve_elev)
    async with proxied_session() as (fake, agent):
        # 1) out-of-scope backend file → AUTH → elevation granted → forwards.
        r1 = await agent.call_tool("fs_write", {"path": "backend/api.ts", "content": "x"})
        assert not r1.isError
        assert calls["n"] == 1
        # 2) SAME file again → covered by the (reusable) elevation → no new challenge.
        r2 = await agent.call_tool("fs_write", {"path": "backend/api.ts", "content": "y"})
        assert not r2.isError
        assert calls["n"] == 1
        # 3) a DIFFERENT backend file is NOT covered → a fresh challenge.
        r3 = await agent.call_tool("fs_write", {"path": "backend/other.ts", "content": "z"})
        assert not r3.isError
        assert calls["n"] == 2
        assert [name for name, _ in fake.calls] == ["fs_write", "fs_write", "fs_write"]


async def test_destructive_elevation_is_single_use(monkeypatch, isolated_executor_repo_root):
    _write_role(isolated_executor_repo_root)
    calls = {"n": 0}

    def approve_elev(decision, action, *, prompter=None, at=None):
        calls["n"] += 1
        return AuthResult(
            approved=True,
            tier=AuthTier.role_elevation,
            method="test",
            at=datetime.now(timezone.utc),
            action_id=action.id,
        )

    monkeypatch.setattr(executor, "run_auth_challenge", approve_elev)
    async with proxied_session() as (fake, agent):
        r1 = await agent.call_tool("fs_delete", {"path": "backend/api.ts"})
        assert not r1.isError
        assert calls["n"] == 1
        # The single-use grant was consumed by the delete → a second delete of
        # the SAME file challenges again.
        r2 = await agent.call_tool("fs_delete", {"path": "backend/api.ts"})
        assert not r2.isError
        assert calls["n"] == 2


async def test_auth_challenge_raising_fails_closed_and_sanitized(monkeypatch):
    """A `run_auth_challenge` crash must deny — never crash the proxy or leak."""
    monkeypatch.setattr(executor, "DEFAULT_OBJECTIVE", _AUTHING)

    def boom(decision, action, *, prompter=None, at=None):
        raise RuntimeError("challenge backend exploded: leaked-internal-detail")

    monkeypatch.setattr(executor, "run_auth_challenge", boom)
    async with proxied_session() as (fake, agent):
        result = await agent.call_tool("fs_write", {"path": "a.txt", "content": "x"})
        # Fail-closed denial, shaped exactly like an ordinary AUTH denial.
        assert result.isError
        text = result.content[0].text
        assert "authentication required" in text
        # The raw exception must never reach the agent — sanitized like every
        # other error path in the proxy.
        assert "leaked-internal-detail" not in text
        assert "RuntimeError" not in text
        # Nothing was forwarded — the challenge failed before release.
        assert fake.calls == []


async def test_mark_used_failure_does_not_corrupt_successful_forward(
    monkeypatch, isolated_executor_repo_root, caplog
):
    """A `mark_used` crash after a successful forward must not turn it into an error."""
    _write_role(isolated_executor_repo_root)

    def approve_elev(decision, action, *, prompter=None, at=None):
        return AuthResult(
            approved=True,
            tier=AuthTier.role_elevation,
            method="test",
            at=datetime.now(timezone.utc),
            action_id=action.id,
        )

    def boom_mark_used(repo_root, elevation_id):
        raise RuntimeError("db exploded")

    monkeypatch.setattr(executor, "run_auth_challenge", approve_elev)
    monkeypatch.setattr(executor, "mark_used", boom_mark_used)
    with caplog.at_level(logging.WARNING, logger="doberman.proxy.engine"):
        async with proxied_session() as (fake, agent):
            result = await agent.call_tool("fs_delete", {"path": "backend/api.ts"})
    # The downstream delete already succeeded — a broken mark_used must not
    # turn that real success into an isError result.
    assert not result.isError
    assert fake.calls == [("fs_delete", {"path": "backend/api.ts"})]
    # The residual (grant may still be marked unused) is surfaced, not silent.
    assert any("single-use elevation consumption failed" in r.message for r in caplog.records)
