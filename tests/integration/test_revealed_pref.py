"""Slice SL6.1 — revealed-preference learning, bounded by the F10 gate.

Load-bearing properties: approve history can lower NUISANCE asks only through
the 2FA-gated weakening path (denied attempts recorded in the ledger, nothing
applied); deny history tightens automatically (raise-only); small samples and
hysteresis are no-ops; evidence is never reused; scope tokens are TTL'd,
session-only, suppress only the score path, and are refused for the trifecta.
"""

from datetime import datetime, timedelta, timezone

import numpy as np
import pyotp

from doberman.auth import totp
from doberman.config import load_preferences, save_mode
from doberman.engine.subjective import SubjectiveGuardrail
from doberman.models import (
    ActionType,
    Algebra,
    BlastRadius,
    Capability,
    DestinationClass,
    EvalContext,
    Provenance,
    Reversibility,
    SecurityObject,
    TargetClass,
    Verdict,
)
from doberman.policy.drift import read_policy_changes
from doberman.proxy import executor
from doberman.subjective.baseline import reset_hst
from doberman.subjective.drift import K_OBSERVATIONS, reset_adwin
from doberman.subjective.revealed import (
    MIN_SAMPLES,
    STEP,
    clear_scope_tokens,
    grant_scope_token,
    has_scope_token,
    maybe_nudge,
    record_feedback,
)

from .test_proxy_passthrough import proxied_session

_NOW = datetime(2026, 6, 9, tzinfo=timezone.utc)
_EID = "hmac:revealed-test"


class ScriptedPrompter:
    def __init__(self, *, confirm=True, code=""):
        self._confirm, self._code = confirm, code
        self.diffs: list[str] = []

    def confirm(self, message):
        self.diffs.append(message)
        return self._confirm

    def read_code(self, message):
        return self._code


def _enrolled_code() -> str:
    totp.enroll()
    return pyotp.TOTP(totp._read_secret()).now()


def _confidentiality_action(i=0):
    """Exercises ONLY the confidentiality dimension (reversible, single)."""
    return SecurityObject(
        id=f"rp-{i}",
        ts=_NOW,
        agent_role="frontend",
        action_type=ActionType.file_read,
        tool_name="crm_read",
        target="record-1",
        reversibility=Reversibility.high,
        algebra=Algebra(
            capability=Capability.read,
            target_class=TargetClass.secret,
            destination_class=DestinationClass.none,
            blast_radius=BlastRadius.single,
            provenance=Provenance.trusted_instruction,
            classification_confidence=0.9,
        ),
    )


async def _feed(root, approved, times):
    for i in range(times):
        await record_feedback(
            _confidentiality_action(i), approved, entity_id=_EID, repo_root=root, now=_NOW
        )


async def _seed_rational_beliefs(root, eid=_EID, n=60):
    """A seeded, evidence-driven (martingale) belief stream so the SL8.2
    self-improvement guard lets the nudge through to the F10 gate."""
    from doberman.subjective.martingale import note_belief

    deltas = np.random.default_rng(42).normal(0.0, 0.02, n)
    beliefs = np.clip(0.5 + np.cumsum(deltas), 0.01, 0.99)
    for value in beliefs:
        await note_belief(eid, float(value), repo_root=root, now=_NOW)


# --- gated nudges -----------------------------------------------------------------


async def test_approve_history_lowers_nuisance_asks_only_via_the_gate(tmp_path):
    root = str(tmp_path)
    await _feed(root, True, MIN_SAMPLES + 5)
    await _seed_rational_beliefs(root)
    code = _enrolled_code()
    prompter = ScriptedPrompter(confirm=True, code=code)
    updated = await maybe_nudge(entity_id=_EID, repo_root=root, prompter=prompter, now=_NOW)
    assert updated is not None
    assert updated.confidentiality == 0.5 - STEP
    assert load_preferences(root).confidentiality == 0.5 - STEP
    assert prompter.diffs and "WEAKENING" in prompter.diffs[0]
    rows = await read_policy_changes(root)
    assert any(r["rule_id"] == "pref.confidentiality" and r["approved"] for r in rows)
    from doberman.storage.policy_catalogue import read_observations

    newest_obs = read_observations(root)[0]
    assert newest_obs["origin"] == "change"
    assert newest_obs["ledger_ts"] == rows[0]["ts"]


async def test_denied_weakening_changes_nothing_but_is_ledgered(tmp_path):
    root = str(tmp_path)
    await _feed(root, True, MIN_SAMPLES + 5)
    await _seed_rational_beliefs(root)
    updated = await maybe_nudge(
        entity_id=_EID, repo_root=root, prompter=ScriptedPrompter(confirm=False), now=_NOW
    )
    assert updated is None
    assert load_preferences(root).confidentiality == 0.5  # untouched
    rows = await read_policy_changes(root)
    assert any(
        r["rule_id"] == "pref.confidentiality" and not r["approved"] for r in rows
    )  # the denied poisoning-relevant attempt is on the record


async def test_deny_history_tightens_automatically_without_a_prompt(tmp_path):
    root = str(tmp_path)
    await _feed(root, False, MIN_SAMPLES + 5)
    await _seed_rational_beliefs(root)
    prompter = ScriptedPrompter(confirm=False)  # would refuse if ever consulted
    updated = await maybe_nudge(entity_id=_EID, repo_root=root, prompter=prompter, now=_NOW)
    assert updated is not None
    assert updated.confidentiality == 0.5 + STEP  # raise-only: tightening is free
    assert prompter.diffs == []  # strengthen never needed the gate prompt


async def test_small_samples_and_hysteresis_are_no_ops(tmp_path):
    root = str(tmp_path)
    await _feed(root, True, MIN_SAMPLES - 1)
    assert await maybe_nudge(entity_id=_EID, repo_root=root, now=_NOW) is None

    # 55% approve rate sits inside the hysteresis band → no oscillation.
    root2 = str(tmp_path / "h")
    await _feed(root2, True, 11)
    await _feed(root2, False, 9)
    assert await maybe_nudge(entity_id=_EID, repo_root=root2, now=_NOW) is None


async def test_evidence_is_never_reused_after_a_nudge(tmp_path):
    root = str(tmp_path)
    await _feed(root, False, MIN_SAMPLES + 5)
    await _seed_rational_beliefs(root)
    first = await maybe_nudge(entity_id=_EID, repo_root=root, now=_NOW)
    assert first is not None
    # The counters were reset: the same evidence cannot drive a second nudge.
    second = await maybe_nudge(entity_id=_EID, repo_root=root, now=_NOW)
    assert second is None


# --- scope tokens -----------------------------------------------------------------


def test_scope_token_grants_lives_and_expires():
    clear_scope_tokens()
    action = _confidentiality_action()
    assert grant_scope_token(action, [], entity_id=_EID, now=_NOW)
    assert has_scope_token(action, entity_id=_EID, now=_NOW + timedelta(minutes=5))
    assert not has_scope_token(action, entity_id=_EID, now=_NOW + timedelta(minutes=20))
    clear_scope_tokens()


def test_scope_token_is_refused_for_the_trifecta():
    from doberman.models import ReasonCode

    clear_scope_tokens()
    action = _confidentiality_action()
    assert not grant_scope_token(action, [ReasonCode.lethal_trifecta], entity_id=_EID, now=_NOW)
    assert not has_scope_token(action, entity_id=_EID, now=_NOW)


def test_scope_token_suppresses_the_score_path_but_never_the_floor():
    engine = SubjectiveGuardrail(load_plugins=False)
    risky = _confidentiality_action()  # secret target, jointly high with surprise 1.0
    asked = engine.evaluate(risky, EvalContext(metadata={"surprise": 1.0}))
    assert asked.verdict is Verdict.AUTH
    suppressed = engine.evaluate(
        risky, EvalContext(metadata={"surprise": 1.0, "scope_token": True})
    )
    assert suppressed.verdict is Verdict.PASS
    trifecta = risky.model_copy(
        update={
            "algebra": risky.algebra.model_copy(
                update={
                    "destination_class": DestinationClass.unknown_external,
                    "provenance": Provenance.untrusted_data,
                }
            )
        }
    )
    floored = engine.evaluate(
        trifecta, EvalContext(metadata={"surprise": 0.0, "scope_token": True})
    )
    assert floored.verdict is Verdict.AUTH  # the floor ignores every comfort mechanism


# --- end-to-end: approve once, then no repeat ask within the session ----------------


async def test_approval_grants_a_session_token_and_stops_repeat_asks(monkeypatch):
    from doberman.auth.challenge import AuthResult, AuthTier

    challenges = []

    def _approve(
        decision,
        action,
        *,
        prompter=None,
        at=None,
        message_tone=None,
        repo_root=None,
        session_id=None,
    ):
        challenges.append(action.id)
        return AuthResult(
            approved=True,
            tier=AuthTier.local_auth,
            method="confirm",
            at=datetime.now(timezone.utc),
            action_id=action.id,
        )

    monkeypatch.setattr(executor, "run_auth_challenge", _approve)
    reset_hst()
    reset_adwin()
    clear_scope_tokens()
    async with proxied_session() as (fake, agent):
        for i in range(K_OBSERVATIONS):
            ok = await agent.call_tool(
                "fs_write", {"path": f"frontend/c{i % 25}.tsx", "content": "x"}
            )
            assert not ok.isError
        save_mode("strict", executor.REPO_ROOT)

        first = await agent.call_tool("fs_delete", {"path": "src/*.py"})
        assert not first.isError  # approved, forwarded
        assert len(challenges) == 1

        # Same algebra point, same session, inside the TTL: no second ask.
        second = await agent.call_tool("fs_delete", {"path": "src/*.py"})
        assert not second.isError
        assert len(challenges) == 1  # the token absorbed the repeat
    clear_scope_tokens()
