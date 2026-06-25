"""Slice SL8.2 — the self-improvement loop is gated on evidence-driven updating.

Load-bearing properties: a preference nudge proposed while the entity's
belief stream is ENTRENCHED (prior-predictable, not evidence-driven) is
blocked and surfaced for review — regardless of direction, before the F10
gate is even consulted; insufficient evidence blocks too; an evidence-driven
update passes the guard, and a weakening that passes it STILL needs 2FA.
"""

from datetime import datetime, timezone

import numpy as np
import pyotp

from doberman.auth import totp
from doberman.config import load_preferences
from doberman.models import (
    ActionType,
    Algebra,
    BlastRadius,
    Capability,
    DestinationClass,
    Provenance,
    Reversibility,
    SecurityObject,
    TargetClass,
)
from doberman.policy.drift import read_policy_changes
from doberman.storage.db import open_db
from doberman.subjective.martingale import note_belief
from doberman.subjective.revealed import MIN_SAMPLES, STEP, maybe_nudge, record_feedback

_NOW = datetime(2026, 6, 9, tzinfo=timezone.utc)
_EID = "hmac:guard-test"


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


def _action(i=0):
    return SecurityObject(
        id=f"sg-{i}",
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
        await record_feedback(_action(i), approved, entity_id=_EID, repo_root=root, now=_NOW)


async def _seed_beliefs(root, values):
    for value in values:
        await note_belief(_EID, float(value), repo_root=root, now=_NOW)


def _entrenched(start=0.5, growth=1.019, n=36, wiggle=0.001):
    out, b = [], start
    for i in range(n):
        out.append(min(0.99, b + wiggle * (-1) ** i))
        b = min(0.99, b * growth)
    return out


def _rational(n=60):
    deltas = np.random.default_rng(42).normal(0.0, 0.02, n)
    return list(np.clip(0.5 + np.cumsum(deltas), 0.01, 0.99))


async def test_entrenched_evidence_blocks_the_update_before_the_gate(tmp_path):
    root = str(tmp_path)
    await _feed(root, True, MIN_SAMPLES + 5)  # would propose a weakening
    await _seed_beliefs(root, _entrenched())
    prompter = ScriptedPrompter(confirm=True, code="000000")
    updated = await maybe_nudge(entity_id=_EID, repo_root=root, prompter=prompter, now=_NOW)
    assert updated is None
    assert load_preferences(root).confidentiality == 0.5  # untouched
    assert prompter.diffs == []  # the F10 gate was never even consulted
    rows = await read_policy_changes(root)
    assert not any(str(r["rule_id"]).startswith("pref.") for r in rows)
    # The blocked proposal was surfaced for review (redacted marker).
    async with open_db(root) as conn:
        async with conn.execute(
            "SELECT COUNT(*) FROM score_history WHERE entity_id = ? AND kind = ?",
            (_EID, "martingale_review"),
        ) as cur:
            assert (await cur.fetchone())[0] >= 1


async def test_entrenchment_blocks_strengthenings_too(tmp_path):
    # "Regardless of direction": even a tightening proposal is blocked when it
    # is not evidence-driven (it would still be an unsound self-update).
    root = str(tmp_path)
    await _feed(root, False, MIN_SAMPLES + 5)  # would propose a strengthening
    await _seed_beliefs(root, _entrenched())
    updated = await maybe_nudge(entity_id=_EID, repo_root=root, now=_NOW)
    assert updated is None
    assert load_preferences(root).confidentiality == 0.5


async def test_insufficient_evidence_blocks(tmp_path):
    root = str(tmp_path)
    await _feed(root, True, MIN_SAMPLES + 5)
    await _seed_beliefs(root, _rational(n=10))  # far too short a window
    updated = await maybe_nudge(entity_id=_EID, repo_root=root, now=_NOW)
    assert updated is None
    assert load_preferences(root).confidentiality == 0.5


async def test_evidence_driven_update_passes_the_guard_and_still_hits_f10(tmp_path):
    root = str(tmp_path)
    await _feed(root, True, MIN_SAMPLES + 5)
    await _seed_beliefs(root, _rational())
    code = _enrolled_code()
    prompter = ScriptedPrompter(confirm=True, code=code)
    updated = await maybe_nudge(entity_id=_EID, repo_root=root, prompter=prompter, now=_NOW)
    assert updated is not None  # guard passed on rational evidence...
    assert updated.confidentiality == 0.5 - STEP
    assert prompter.diffs and "WEAKENING" in prompter.diffs[0]  # ...and F10 still gated it
