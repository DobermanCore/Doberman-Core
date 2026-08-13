"""Slice 8.2 — append-only, redacted decision-log writer (wired into the proxy)."""

import inspect
from datetime import datetime, timezone

from doberman.auth.challenge import AuthResult, AuthTier
from doberman.models import (
    ActionType,
    Decision,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    Verdict,
)
from doberman.proxy import executor
from doberman.storage.db import open_db
from doberman.storage.log import read_decisions, recent_session_decisions, record_decision

from .test_proxy_passthrough import proxied_session


def _deny(decision, action, *, prompter=None, at=None):
    return AuthResult(
        approved=False,
        tier=AuthTier.two_factor,
        method="denied",
        at=datetime.now(timezone.utc),
        action_id=action.id,
    )


async def test_one_redacted_row_per_decision():
    async with proxied_session() as (fake, agent):
        await agent.call_tool("fs_write", {"path": "a.txt", "content": "x"})
        await agent.call_tool("net_get", {"url": "https://github.com/owner/repo"})
    rows = await read_decisions(executor.REPO_ROOT)
    assert len(rows) == 2
    assert {r["final_verdict"] for r in rows} == {"PASS"}
    # Reasons column is populated (empty list for a clean PASS, not NULL).
    assert all(r["reason_codes_json"] is not None for r in rows)


async def test_fake_secret_never_appears_in_any_column(monkeypatch):
    secret = "AKIA-FAKE-DECISIONLOG-SECRET-7777"  # noqa: S105 — synthetic test value
    monkeypatch.setattr(executor, "run_auth_challenge", _deny)
    async with proxied_session() as (_, agent):
        # Writing to .env is a protected-path BLOCK; the secret-shaped content is
        # fingerprinted, never stored raw.
        await agent.call_tool("fs_write", {"path": ".env", "content": f"API_KEY={secret}"})

    async with open_db(executor.REPO_ROOT) as conn:
        async with conn.execute("SELECT * FROM decisions") as cur:
            decisions = await cur.fetchall()
        async with conn.execute("SELECT * FROM secret_fingerprints") as cur:
            fingerprints = await cur.fetchall()

    blob = " ".join(str(v) for row in (*decisions, *fingerprints) for v in row)
    assert secret not in blob  # the raw secret is in NO column
    assert decisions  # ...but the decision WAS recorded

    verdicts = await read_decisions(executor.REPO_ROOT)
    assert any(r["final_verdict"] == "BLOCK" for r in verdicts)


async def test_logging_failure_never_changes_the_verdict(monkeypatch):
    async def boom(*args, **kwargs):
        raise RuntimeError("decision DB is on fire")

    monkeypatch.setattr(executor, "record_decision", boom)
    async with proxied_session() as (fake, agent):
        result = await agent.call_tool("fs_write", {"path": "a.txt", "content": "x"})
        # The forward still happened and the call still succeeded.
        assert not result.isError
        assert fake.calls == [("fs_write", {"path": "a.txt", "content": "x"})]


def test_writer_has_no_update_or_delete_path_for_decisions():
    # Append-only by construction: the writer module never updates/deletes a
    # decision row (it only INSERTs, and upserts last_seen on fingerprints).
    import doberman.storage.log as log_module

    src = inspect.getsource(log_module)
    assert "UPDATE decisions" not in src
    assert "DELETE FROM decisions" not in src


def _decision_and_action(verdict: Verdict, action_id: str) -> tuple[Decision, SecurityObject]:
    reasons = [] if verdict is Verdict.PASS else [ReasonCode.sensitive_secret_access]
    now = datetime.now(timezone.utc)
    objective = GuardrailResult(
        verdict=verdict, risk=Risk.low, reason_codes=reasons, explanation="x"
    )
    decision = Decision(
        action_id=action_id,
        final_verdict=verdict,
        final_risk=Risk.low,
        objective=objective,
        reason_codes=reasons,
        explanation="x",
        decided_at=now,
    )
    action = SecurityObject(
        id=action_id,
        ts=now,
        agent_role="backend",
        action_type=ActionType.file_read,
        tool_name="fs_read",
    )
    return decision, action


async def test_recent_session_decisions_reads_last_n_newest_first():
    # C3.1: the session correlator's history read. Three rows across two
    # sessions; only "s1"'s rows come back, newest first, capped at n.
    d1, a1 = _decision_and_action(Verdict.PASS, "a1")
    d2, a2 = _decision_and_action(Verdict.AUTH, "a2")
    d3, a3 = _decision_and_action(Verdict.PASS, "a3")
    await record_decision(d1, a1, repo_root=executor.REPO_ROOT, session_id="s1")
    await record_decision(d2, a2, repo_root=executor.REPO_ROOT, session_id="s1")
    await record_decision(d3, a3, repo_root=executor.REPO_ROOT, session_id="s2")

    rows = await recent_session_decisions(executor.REPO_ROOT, "s1", 10)

    assert len(rows) == 2
    assert rows[0]["final_verdict"] == "AUTH"  # newest first
    assert rows[0]["reason_codes"] == ["sensitive_secret_access"]
    assert rows[1]["final_verdict"] == "PASS"

    capped = await recent_session_decisions(executor.REPO_ROOT, "s1", 1)
    assert len(capped) == 1
    assert capped[0]["final_verdict"] == "AUTH"


async def test_recent_session_decisions_fails_closed():
    assert await recent_session_decisions(executor.REPO_ROOT, None, 10) == []
    assert await recent_session_decisions(executor.REPO_ROOT, "no-such-session", 10) == []
    # No DB has been created at all in this repo root yet.
    assert await recent_session_decisions(str(executor.REPO_ROOT) + "-missing", "s1", 10) == []
