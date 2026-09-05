"""Slice 8.2 — append-only, redacted decision-log writer (wired into the proxy)."""

import inspect
from datetime import datetime, timedelta, timezone

from doberman.auth.challenge import AuthResult, AuthTier
from doberman.engine.effects import compute_delete_effects
from doberman.models import (
    ActionType,
    Decision,
    EffectSet,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    Verdict,
)
from doberman.proxy import executor
from doberman.storage.db import open_db
from doberman.storage.log import (
    prune_decisions,
    read_decisions,
    recent_session_decisions,
    record_decision,
)

from .test_proxy_passthrough import proxied_session


def _deny(decision, action, *, prompter=None, at=None, message_tone=None):
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

    for name in ("build_record", "record_decision", "record_shadow"):
        source = inspect.getsource(getattr(log_module, name))
        assert "UPDATE decisions" not in source
        assert "DELETE FROM decisions" not in source


def _decision_and_action(
    verdict: Verdict, action_id: str, *, effects: EffectSet | None = None
) -> tuple[Decision, SecurityObject]:
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
        effects=effects,
    )
    action = SecurityObject(
        id=action_id,
        ts=now,
        agent_role="backend",
        action_type=ActionType.file_read,
        tool_name="fs_read",
    )
    return decision, action


# --- EffectSet audit-row fields (#556) --------------------------------------

_EFFECTS = EffectSet(
    file_count=5,
    dir_count=2,
    capped=False,
    hits_git=True,
    hits_outside_repo=False,
    digest="deadbeef" * 8,
)


async def test_decision_with_effect_set_persists_exact_counts_and_booleans(tmp_path):
    root = str(tmp_path)
    decision, action = _decision_and_action(Verdict.PASS, "with-effects", effects=_EFFECTS)

    await record_decision(decision, action, repo_root=root)

    rows = await read_decisions(root)
    assert len(rows) == 1
    row = rows[0]
    assert row["effects_file_count"] == 5
    assert row["effects_dir_count"] == 2
    assert bool(row["effects_capped"]) is False
    assert bool(row["effects_hits_git"]) is True
    assert bool(row["effects_hits_outside_repo"]) is False
    # The digest constraint (#556): the plain sha256 digest never reaches the
    # row as-is — only a keyed HMAC fingerprint of it does.
    assert row["effects_digest_fp"] is not None
    assert row["effects_digest_fp"] != _EFFECTS.digest
    assert row["effects_digest_fp"].startswith("hmac:")


async def test_decision_without_effect_set_persists_null_not_zero(tmp_path):
    root = str(tmp_path)
    decision, action = _decision_and_action(Verdict.PASS, "no-effects")

    await record_decision(decision, action, repo_root=root)

    rows = await read_decisions(root)
    assert len(rows) == 1
    row = rows[0]
    for column in (
        "effects_file_count",
        "effects_dir_count",
        "effects_capped",
        "effects_hits_git",
        "effects_hits_outside_repo",
        "effects_digest_fp",
    ):
        assert row[column] is None  # "unknown/no preview", never a fabricated 0/False


async def test_effect_set_from_real_walk_never_leaks_secret_or_raw_path(tmp_path):
    # A synthetic secret AND a raw absolute path both live in the delete-class
    # operand this EffectSet was computed from. Neither may reach any column.
    secret = "AKIA-FAKE-EFFECTSET-SECRET-9999"  # noqa: S105 — synthetic test value
    target_dir = tmp_path / f"{secret}-dir"
    target_dir.mkdir()
    (target_dir / "file.txt").write_text("x")
    absolute_operand = str(target_dir)

    effects = compute_delete_effects([absolute_operand], repo_root=str(tmp_path))
    root = str(tmp_path)
    decision, action = _decision_and_action(Verdict.PASS, "real-walk-effects", effects=effects)

    await record_decision(decision, action, repo_root=root)

    async with open_db(root) as conn:
        async with conn.execute("SELECT * FROM decisions") as cur:
            rows = await cur.fetchall()
    blob = " ".join(str(v) for row in rows for v in row)
    assert secret not in blob
    assert absolute_operand not in blob
    assert str(tmp_path) not in blob


async def test_fingerprint_failure_loses_only_the_digest_column_not_the_row(tmp_path, monkeypatch):
    # Review fix (Important): fingerprint() fails closed (raises) when the
    # local HMAC key can't be read. Before this fix, that exception propagated
    # out of _effects_fields() -> build_record() -> record_decision()'s outer
    # except, which dropped the WHOLE row (verdict, reason codes, everything),
    # not just the effects_digest_fp column.
    import doberman.storage.log as log_module

    def boom(value):
        raise PermissionError("key file unreadable")  # noqa: EM101 — test-only message

    monkeypatch.setattr(log_module, "fingerprint", boom)
    root = str(tmp_path)
    decision, action = _decision_and_action(Verdict.AUTH, "fp-fail", effects=_EFFECTS)

    await record_decision(decision, action, repo_root=root)

    rows = await read_decisions(root)
    assert len(rows) == 1
    row = rows[0]
    assert row["final_verdict"] == "AUTH"
    assert row["reason_codes_json"] is not None
    assert row["effects_file_count"] == 5
    assert row["effects_dir_count"] == 2
    assert bool(row["effects_capped"]) is False
    assert bool(row["effects_hits_git"]) is True
    assert bool(row["effects_hits_outside_repo"]) is False
    assert row["effects_digest_fp"] is None


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


async def _seed_decision(root: str, action_id: str, ts: datetime) -> None:
    decision, action = _decision_and_action(Verdict.PASS, action_id)
    await record_decision(decision, action, repo_root=root, now=ts)


async def _decision_verdicts_and_count(root: str) -> tuple[int, set[str]]:
    rows = await read_decisions(root)
    return len(rows), {row["final_verdict"] for row in rows}


async def test_prune_by_age_keeps_new_resolved_and_never_touches_a_verdict(tmp_path):
    root = str(tmp_path)
    now = datetime.now(timezone.utc)
    await _seed_decision(root, "old", now - timedelta(days=90, seconds=1))
    await _seed_decision(root, "boundary", now - timedelta(days=90))
    await _seed_decision(root, "fresh", now - timedelta(days=1))

    before_count, before_verdicts = await _decision_verdicts_and_count(root)
    assert before_count == 3
    assert before_verdicts == {"PASS"}

    result = await prune_decisions(root, older_than_days=90, now=now)

    rows = await read_decisions(root)
    count, verdicts = await _decision_verdicts_and_count(root)
    assert result == {"age_deleted": 1, "overflow_deleted": 0}
    assert count == 2
    assert {row["action_id"] for row in rows} == {"boundary", "fresh"}
    # A decision's persisted verdict is the same whether pruning is due or not.
    assert verdicts == {"PASS"}
    assert verdicts == before_verdicts


async def test_prune_by_max_rows_keeps_newest_resolved_only(tmp_path):
    root = str(tmp_path)
    now = datetime.now(timezone.utc)
    await _seed_decision(root, "old", now - timedelta(days=3))
    await _seed_decision(root, "newer", now - timedelta(days=2))
    await _seed_decision(root, "newest", now - timedelta(days=1))

    result = await prune_decisions(root, max_rows=2, now=now)

    actions = [row["action_id"] for row in await read_decisions(root)]
    assert result == {"age_deleted": 0, "overflow_deleted": 1}
    assert set(actions) == {"newer", "newest"}


async def test_prune_never_deletes_unresolved_auth(tmp_path):
    root = str(tmp_path)
    now = datetime.now(timezone.utc)
    decision, action = _decision_and_action(Verdict.AUTH, "pending-auth")
    await record_decision(
        decision,
        action,
        repo_root=root,
        now=now - timedelta(days=365),
    )

    result = await prune_decisions(root, older_than_days=1, max_rows=0, now=now)

    rows = await read_decisions(root)
    assert result == {"age_deleted": 0, "overflow_deleted": 0}
    assert len(rows) == 1
    assert rows[0]["final_verdict"] == "AUTH"


async def test_prune_deletes_resolved_auth(tmp_path):
    root = str(tmp_path)
    now = datetime.now(timezone.utc)
    decision, action = _decision_and_action(Verdict.AUTH, "approved-auth")
    await record_decision(
        decision,
        action,
        repo_root=root,
        auth_result="approved",
        now=now - timedelta(days=365),
    )

    result = await prune_decisions(root, older_than_days=1, max_rows=0, now=now)

    assert result == {"age_deleted": 1, "overflow_deleted": 0}
    assert await read_decisions(root) == []


async def test_prune_deletes_auth_rows_with_any_recorded_outcome(tmp_path):
    # The real proxy/executor/hosthooks vocabulary is far wider than the three
    # literal values ("approved", "denied", "executed") the predicate used to
    # check for: successful auth persists the tier/method name (e.g.
    # "soft_confirm"), and failure paths persist "blocked"/"error". Any of
    # those is an explicit outcome and should be prunable; only a NULL
    # auth_result (still pending) must be kept.
    root = str(tmp_path)
    now = datetime.now(timezone.utc)
    old = now - timedelta(days=365)

    for action_id, auth_result in (
        ("soft-confirm-auth", "soft_confirm"),
        ("blocked-auth", "blocked"),
        ("pending-auth", None),
    ):
        decision, action = _decision_and_action(Verdict.AUTH, action_id)
        await record_decision(decision, action, repo_root=root, auth_result=auth_result, now=old)

    result = await prune_decisions(root, older_than_days=1, now=now)

    rows = await read_decisions(root)
    assert result == {"age_deleted": 2, "overflow_deleted": 0}
    assert {row["action_id"] for row in rows} == {"pending-auth"}
    assert rows[0]["auth_result"] is None


async def test_prune_requires_at_least_one_policy(tmp_path):
    raised = False
    try:
        await prune_decisions(str(tmp_path))
    except ValueError:
        raised = True
    assert raised
