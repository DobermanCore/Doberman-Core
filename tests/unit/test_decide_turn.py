"""Slice TG1.3 — routing a `TurnObject` through the decision engine.

One engine, two invocation points: ``decide_turn`` mirrors the action-path
execution rule. Tier 0 (deterministic, BLOCK-capable) runs first and a non-PASS
verdict is **final** (short-circuit — Tier 1 never runs). Tier 0 PASS → run
Tier 1 (heuristic), which is structurally incapable of BLOCK: any Tier 1 BLOCK
is clamped to AUTH. AUTH-first posture: an internal guardrail error fails toward
the human (AUTH), never toward silent PASS or a hard BLOCK.
"""

from datetime import datetime, timezone

from doberman.engine.decision_engine import decide_turn
from doberman.models import (
    EvalContext,
    GuardrailResult,
    ReasonCode,
    Risk,
    TurnObject,
    Verdict,
)

_TS = datetime(2026, 6, 10, tzinfo=timezone.utc)


def _turn():
    return TurnObject(id="turn-1", ts=_TS, entity_id="e", prompt_fingerprint="hmac:x")


class _Static:
    def __init__(self, result):
        self._result = result

    def evaluate(self, turn, ctx):
        return self._result


class _Raises:
    def evaluate(self, turn, ctx):
        raise RuntimeError("boom")


def _block(reason=ReasonCode.instruction_nullification):
    return GuardrailResult(
        verdict=Verdict.BLOCK, risk=Risk.high, reason_codes=[reason], explanation="blocked"
    )


def _auth(reason=ReasonCode.embedded_instruction):
    return GuardrailResult(
        verdict=Verdict.AUTH, risk=Risk.medium, reason_codes=[reason], explanation="step up"
    )


_PASS = GuardrailResult(verdict=Verdict.PASS, risk=Risk.low)


def test_tier0_block_short_circuits_tier1():
    # Tier 1 would AUTH, but a Tier 0 BLOCK is final and Tier 1 never runs.
    decision = decide_turn(_turn(), _Static(_block()), _Static(_auth()), EvalContext())
    assert decision.final_verdict is Verdict.BLOCK
    assert decision.subjective is None
    assert ReasonCode.instruction_nullification in decision.reason_codes


def test_tier0_auth_short_circuits_tier1():
    decision = decide_turn(_turn(), _Static(_auth()), _Static(_block()), EvalContext())
    assert decision.final_verdict is Verdict.AUTH
    assert decision.subjective is None


def test_tier0_pass_then_tier1_auth_combines_to_auth():
    decision = decide_turn(_turn(), _Static(_PASS), _Static(_auth()), EvalContext())
    assert decision.final_verdict is Verdict.AUTH
    assert decision.subjective is not None
    assert ReasonCode.embedded_instruction in decision.reason_codes


def test_both_pass_is_pass():
    decision = decide_turn(_turn(), _Static(_PASS), _Static(_PASS), EvalContext())
    assert decision.final_verdict is Verdict.PASS


def test_tier1_cannot_block_it_is_clamped_to_auth():
    # A Tier 1 guardrail that (wrongly) returns BLOCK must never hard-block a
    # turn — the engine clamps it to AUTH (mirror of the subjective clamp).
    decision = decide_turn(_turn(), _Static(_PASS), _Static(_block()), EvalContext())
    assert decision.final_verdict is Verdict.AUTH
    assert ReasonCode.subjective_block_clamped in decision.reason_codes


def test_tier0_error_fails_to_auth_not_block_or_pass():
    # AUTH-first: an internal Tier 0 failure defers to the human, never a silent
    # pass and never a hard block (which has no escape hatch on an error).
    decision = decide_turn(_turn(), _Raises(), _Static(_PASS), EvalContext())
    assert decision.final_verdict is Verdict.AUTH
    assert ReasonCode.turn_gate_error in decision.reason_codes


def test_tier1_error_fails_to_auth():
    decision = decide_turn(_turn(), _Static(_PASS), _Raises(), EvalContext())
    assert decision.final_verdict is Verdict.AUTH
    assert ReasonCode.turn_gate_error in decision.reason_codes


def test_decision_action_id_is_the_turn_id():
    decision = decide_turn(_turn(), _Static(_PASS), _Static(_PASS), EvalContext())
    assert decision.action_id == "turn-1"
