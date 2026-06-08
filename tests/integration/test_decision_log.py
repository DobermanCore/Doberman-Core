"""Slice 8.2 — append-only, redacted decision-log writer (wired into the proxy)."""

import inspect

from doberman.auth.challenge import AuthResult, AuthTier
from doberman.proxy import executor
from doberman.storage.db import open_db
from doberman.storage.log import read_decisions

from .test_proxy_passthrough import proxied_session


def _deny(decision, action, *, prompter=None, at=None):
    from datetime import datetime, timezone

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
