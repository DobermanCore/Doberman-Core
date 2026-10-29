"""#515: turn rows name their evaluation snapshot only after catalogue commit."""

import json
import sqlite3
from datetime import datetime, timezone

import pytest

from doberman.auth.challenge import AuthResult, AuthTier
from doberman.config import save_policy
from doberman.models import GuardrailResult, ReasonCode, Risk, Verdict
from doberman.policy.checklist import recommend_policy
from doberman.storage import policy_catalogue as catalogue
from doberman.storage.log import read_decisions
from doberman.turngate import hook, repeat
from doberman.turngate.log import record_turn_decision
from doberman.turngate.normalize import normalize_turn

_TS = datetime(2026, 6, 10, tzinfo=timezone.utc)
_PROMPT = "Please review this parser."


@pytest.fixture(autouse=True)
def isolate_turn_gate(monkeypatch):
    repeat.clear_repeat_cache()
    monkeypatch.delenv("DOBERMAN_TURN_GATE", raising=False)
    yield
    repeat.clear_repeat_cache()


class StaticTurnGuardrail:
    def __init__(self, verdict):
        self.verdict = verdict

    def evaluate(self, turn, ctx):
        return GuardrailResult(
            verdict=self.verdict,
            risk=Risk.low if self.verdict is Verdict.PASS else Risk.high,
            reason_codes=[]
            if self.verdict is Verdict.PASS
            else [ReasonCode.instruction_nullification],
            explanation="Synthetic turn guardrail",
        )


def _auth_result(action_id, approved):
    return AuthResult(
        action_id=action_id,
        approved=approved,
        tier=AuthTier.two_factor,
        method="confirm" if approved else "denied",
        at=_TS,
    )


async def _gate(root, verdict=Verdict.PASS, **kwargs):
    return await hook.gate_turn(
        _PROMPT,
        entity_id="turn-entity",
        repo_root=root,
        ts=_TS,
        tier0=StaticTurnGuardrail(verdict),
        tier1=StaticTurnGuardrail(Verdict.PASS),
        **kwargs,
    )


@pytest.mark.parametrize(
    "stage,verdict,approved",
    [
        ("turn_pass", Verdict.PASS, True),
        ("turn_block", Verdict.BLOCK, False),
        ("turn_auth", Verdict.AUTH, True),
        ("turn_auth", Verdict.AUTH, False),
        ("turn_repeat_approved", Verdict.BLOCK, True),
        ("turn_repeat_denied", Verdict.BLOCK, False),
        ("turn_lockout", Verdict.BLOCK, False),
    ],
)
async def test_turn_stamps_every_logged_stage(tmp_path, monkeypatch, stage, verdict, approved):
    root = str(tmp_path)
    # The turn gate stays fully enforced even if the action dial says off.
    doc = recommend_policy().with_mode("strict").with_enforcement("off")
    if stage.startswith("turn_repeat") or stage == "turn_lockout":
        first = await _gate(root, Verdict.BLOCK)
        assert not first.released
        if stage == "turn_lockout":
            turn, _ = normalize_turn(_PROMPT, entity_id="turn-entity", ts=_TS)
            repeat.note_denied(turn.entity_id, turn.prompt_fingerprint, now=_TS)
    save_policy(doc, root)
    expected = catalogue.current_snapshot(root, enforcement_effective="enforce")
    monkeypatch.setattr(
        hook,
        "run_auth_challenge",
        lambda decision, action, **kwargs: _auth_result(action.id, approved),
    )
    monkeypatch.setattr(
        repeat, "challenge_repeat", lambda turn, record, **kwargs: _auth_result(turn.id, approved)
    )

    outcome = await _gate(root, verdict)

    assert outcome.released is approved
    (row,) = [row for row in await read_decisions(root) if row["decided_layer"] == stage]
    assert row["action_type"] == "turn"
    assert row["policy_version"] == catalogue.policy_version(expected)
    assert catalogue.read_snapshot(root, row["policy_version"]) == json.loads(
        catalogue.canonical_json(expected)
    )
    assert _PROMPT not in json.dumps(row)
    assert _PROMPT not in json.dumps(catalogue.read_snapshot(root, row["policy_version"]))
    assert catalogue.read_observations(root, limit=1)[0]["origin"] == catalogue.ORIGIN_DECISION


async def test_turn_keeps_snapshot_when_policy_changes_during_evaluation(tmp_path):
    root = str(tmp_path)
    original = recommend_policy().with_mode("strict")
    save_policy(original, root)
    expected = catalogue.current_snapshot(root, enforcement_effective="enforce")

    class ChangingGuardrail(StaticTurnGuardrail):
        def evaluate(self, turn, ctx):
            assert ctx.mode == "strict"
            save_policy(original.with_mode("light"), root)
            return super().evaluate(turn, ctx)

    outcome = await hook.gate_turn(
        _PROMPT,
        entity_id="turn-entity",
        repo_root=root,
        ts=_TS,
        tier0=ChangingGuardrail(Verdict.PASS),
        tier1=StaticTurnGuardrail(Verdict.PASS),
    )

    assert outcome.released
    (row,) = await read_decisions(root)
    assert row["policy_version"] == catalogue.policy_version(expected)
    assert row["policy_version"] != catalogue.policy_version(catalogue.current_snapshot(root))


async def test_turn_auth_keeps_snapshot_across_approval_wait(tmp_path, monkeypatch):
    root = str(tmp_path)
    original = recommend_policy().with_mode("strict")
    save_policy(original, root)
    expected = catalogue.current_snapshot(root, enforcement_effective="enforce")

    def challenge(decision, action, **kwargs):
        save_policy(original.with_mode("light"), root)
        return _auth_result(action.id, True)

    monkeypatch.setattr(hook, "run_auth_challenge", challenge)
    outcome = await _gate(root, Verdict.AUTH)

    assert outcome.released
    (row,) = await read_decisions(root)
    assert row["final_verdict"] == "AUTH"
    assert row["auth_result"] == "approved"
    assert row["policy_version"] == catalogue.policy_version(expected)


@pytest.mark.parametrize("failure", ["snapshot_insert", "observation_insert", "commit"])
@pytest.mark.parametrize("verdict", [Verdict.PASS, Verdict.AUTH, Verdict.BLOCK])
async def test_catalogue_sqlite_failure_preserves_turn_and_retry(
    tmp_path, monkeypatch, failure, verdict
):
    root = str(tmp_path)
    expected = catalogue.current_snapshot(root, enforcement_effective="enforce")
    connect = catalogue._connect
    failures = []
    monkeypatch.setattr(
        hook,
        "run_auth_challenge",
        lambda decision, action, **kwargs: _auth_result(action.id, False),
    )
    monkeypatch.setattr(
        repeat, "challenge_repeat", lambda turn, record, **kwargs: _auth_result(turn.id, False)
    )

    def failing_connect(repo_root):
        conn = connect(repo_root)

        def authorize(operation, arg1, arg2, database, trigger):
            denied = (
                operation == sqlite3.SQLITE_INSERT
                and arg1
                == {
                    "snapshot_insert": "policy_versions",
                    "observation_insert": "policy_observations",
                }.get(failure)
            ) or (
                failure == "commit" and operation == sqlite3.SQLITE_TRANSACTION and arg1 == "COMMIT"
            )
            if denied:
                failures.append(failure)
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK

        conn.set_authorizer(authorize)
        return conn

    with monkeypatch.context() as patch:
        patch.setattr(catalogue, "_connect", failing_connect)
        outcome = await _gate(root, verdict)

    assert outcome.released is (verdict is Verdict.PASS)
    assert failures == [failure]
    (row,) = await read_decisions(root)
    assert row["policy_version"] is None
    assert row["final_verdict"] == verdict.value
    assert catalogue.read_versions(root) == []
    assert catalogue.read_observations(root) == []

    assert (await _gate(root, verdict)).released is (verdict is Verdict.PASS)
    rows = await read_decisions(root)
    assert len(rows) == 2
    assert sum(row["policy_version"] is None for row in rows) == 1
    assert sum(row["policy_version"] == catalogue.policy_version(expected) for row in rows) == 1


@pytest.mark.parametrize("failure", ["load", "capture", "none"])
async def test_unavailable_turn_snapshot_keeps_decision(tmp_path, monkeypatch, failure):
    def unavailable(*args, **kwargs):
        if failure == "none":
            return None
        raise RuntimeError("snapshot unavailable")

    monkeypatch.setattr(
        hook, "load_evaluation_policy" if failure == "load" else "evaluation_snapshot", unavailable
    )
    outcome = await _gate(str(tmp_path))
    assert outcome.released
    (row,) = await read_decisions(str(tmp_path))
    assert row["policy_version"] is None
    assert row["final_verdict"] == "PASS"


@pytest.mark.parametrize("with_snapshot", [False, True])
async def test_turn_writer_never_reloads_policy(tmp_path, monkeypatch, with_snapshot):
    def unexpected_read(*args, **kwargs):
        pytest.fail("Turn logging must never reconstruct the evaluation snapshot")

    from doberman import config

    snapshot = catalogue.current_snapshot(str(tmp_path)) if with_snapshot else None
    monkeypatch.setattr(config, "load_policy", unexpected_read)
    monkeypatch.setattr(catalogue, "current_snapshot", unexpected_read)
    turn, _ = normalize_turn(_PROMPT, entity_id="turn-entity", ts=_TS)
    decision = hook._pass_decision(turn, _TS)
    await record_turn_decision(turn, decision, repo_root=str(tmp_path), policy_snapshot=snapshot)

    (row,) = await read_decisions(str(tmp_path))
    assert row["policy_version"] == (
        catalogue.policy_version(snapshot) if snapshot is not None else None
    )
    assert row["final_verdict"] == "PASS"
