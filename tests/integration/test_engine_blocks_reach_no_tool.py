"""Slice 2.4 — verdicts are enforced: a BLOCK means the tool NEVER runs.

Feature 7 makes an ``AUTH`` run a challenge; these tests pin the challenge to a
deterministic *denial* (no real stdin) so they keep asserting the F2 behavior:
an un-approved AUTH forwards nothing.
"""

import json
import logging
from datetime import datetime, timezone

import pytest

from doberman.auth.challenge import AuthResult, AuthTier
from doberman.engine.decision_engine import StaticGuardrail
from doberman.models import GuardrailResult, ReasonCode, Risk, Verdict
from doberman.proxy import executor
from doberman.proxy.interception_log import LOGGER_NAME

from .test_proxy_passthrough import proxied_session


def _deny_challenge(decision, action, *, prompter=None, at=None):
    """A deterministic denied AuthResult (stands in for confirm/2FA failure)."""
    return AuthResult(
        approved=False,
        tier=AuthTier.local_auth,
        method="denied",
        at=datetime.now(timezone.utc),
        action_id=action.id,
    )


BLOCKING = StaticGuardrail(
    GuardrailResult(
        verdict=Verdict.BLOCK,
        risk=Risk.critical,
        reason_codes=[ReasonCode.unknown_tool],
        explanation="Stub objective blocks everything.",
    )
)

AUTHING = StaticGuardrail(
    GuardrailResult(
        verdict=Verdict.AUTH,
        risk=Risk.high,
        reason_codes=[ReasonCode.unknown_tool],
        explanation="Stub objective requires authentication.",
    )
)

SUBJECTIVE_BLOCKING = StaticGuardrail(
    GuardrailResult(
        verdict=Verdict.BLOCK,
        risk=Risk.high,
        reason_codes=[ReasonCode.unknown_tool],
        explanation="Stub subjective wants a hard block.",
    )
)


async def test_pass_forwards_and_records():
    async with proxied_session() as (fake, agent):
        result = await agent.call_tool("fs_write", {"path": "a.txt", "content": "x"})
        assert not result.isError
        assert fake.calls == [("fs_write", {"path": "a.txt", "content": "x"})]


@pytest.mark.guarantee("destructive-command-gate", host="mcp-proxy")
async def test_block_returns_error_and_nothing_recorded(monkeypatch):
    monkeypatch.setattr(executor, "DEFAULT_OBJECTIVE", BLOCKING)
    async with proxied_session() as (fake, agent):
        result = await agent.call_tool("fs_delete", {"path": "a.txt"})
        assert result.isError
        text = result.content[0].text
        assert "blocked by policy" in text
        assert "unknown_tool" in text  # reason codes are agent-visible
        assert "Stub objective blocks everything." in text  # explanation too
        # THE protective property: the fake downstream recorded NOTHING.
        assert fake.calls == []


async def test_auth_returns_error_and_nothing_recorded(monkeypatch):
    monkeypatch.setattr(executor, "DEFAULT_OBJECTIVE", AUTHING)
    monkeypatch.setattr(executor, "run_auth_challenge", _deny_challenge)
    async with proxied_session() as (fake, agent):
        result = await agent.call_tool("shell_exec", {"command": "echo hi"})
        assert result.isError
        assert "authentication required" in result.content[0].text
        assert fake.calls == []


async def test_engine_exception_fails_closed(monkeypatch):
    def exploding_decide(*args, **kwargs):
        raise RuntimeError("engine exploded")

    # Patches the from-import binding in executor.py — if executor ever
    # switches to module-attribute calls (engine.decide), update this target.
    monkeypatch.setattr(executor, "decide", exploding_decide)
    async with proxied_session() as (fake, agent):
        result = await agent.call_tool("fs_write", {"path": "a.txt", "content": "x"})
        assert result.isError
        assert "blocked by policy" in result.content[0].text
        assert "failing closed" in result.content[0].text.lower()
        assert fake.calls == []


async def test_subjective_block_clamps_to_auth_end_to_end(monkeypatch):
    monkeypatch.setattr(executor, "DEFAULT_SUBJECTIVE", SUBJECTIVE_BLOCKING)
    monkeypatch.setattr(executor, "run_auth_challenge", _deny_challenge)
    async with proxied_session() as (fake, agent):
        # A fetch to a TRUSTED host so the real objective guardrail (F3) PASSes
        # and the subjective guardrail actually runs (and is then clamped). With
        # an unknown host the objective would AUTH and short-circuit instead.
        result = await agent.call_tool("net_get", {"url": "https://github.com/owner/repo"})
        assert result.isError
        text = result.content[0].text
        # Clamped: authentication, not a hard block.
        assert "authentication required" in text
        assert "subjective_block_clamped" in text
        assert fake.calls == []


async def test_log_records_real_verdict(monkeypatch, caplog):
    caplog.set_level(logging.INFO, logger=LOGGER_NAME)
    monkeypatch.setattr(executor, "DEFAULT_OBJECTIVE", BLOCKING)
    async with proxied_session() as (_, agent):
        await agent.call_tool("fs_delete", {"path": "a.txt"})
    records = [json.loads(r.message) for r in caplog.records if r.name == LOGGER_NAME]
    assert len(records) == 1
    assert records[0]["verdict"] == "BLOCK"  # not the old hardcoded PASS


async def test_block_error_never_echoes_arguments(monkeypatch):
    monkeypatch.setattr(executor, "DEFAULT_OBJECTIVE", BLOCKING)
    secret = "AKIA-FAKE-BLOCKED-SECRET-99"  # noqa: S105 — synthetic test value
    async with proxied_session() as (fake, agent):
        result = await agent.call_tool("fs_write", {"path": "x", "content": secret})
        assert result.isError
        assert all(secret not in block.text for block in result.content)
        assert fake.calls == []
