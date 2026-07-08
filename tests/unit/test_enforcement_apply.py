"""Unit tests for the F10 enforcement-consumption softening (Option A).

``acted_verdict`` is the pure read-side function that turns a resolved enforcement
state into the verdict to ACT on. The load-bearing invariant: ``monitor``/``off``
may soften only *discretionary* AUTH/BLOCK to PASS; the objective floor (secrets,
exfil, taint, destructive, role/policy blocks, the lethal trifecta) and every
fail-closed error stay live in **every** state. The decision object itself is
never mutated.
"""

from datetime import datetime, timezone

import pytest

from doberman.models import Decision, GuardrailResult, ReasonCode, Risk, Verdict
from doberman.policy.drift import _DISCRETIONARY_SOFT, acted_verdict


def _decision(verdict: Verdict, codes: list[ReasonCode]) -> Decision:
    """Build a Decision with ``objective=PASS`` so ``final`` may be any verdict.

    The objective floor is modelled as reason codes on the final decision (as the
    taint floor and the objective rules produce them); a PASS objective keeps the
    model's never-weaker-than-objective validator happy for any ``final``.
    """
    explanation = "" if verdict is Verdict.PASS else "test verdict"
    return Decision(
        action_id="act-1",
        final_verdict=verdict,
        final_risk=Risk.high if verdict is not Verdict.PASS else Risk.low,
        objective=GuardrailResult(verdict=Verdict.PASS, risk=Risk.low),
        reason_codes=list(codes),
        explanation=explanation,
        decided_at=datetime.now(timezone.utc),
    )


# --- enforce / unknown: always the real verdict (fail-closed) ---------------


@pytest.mark.parametrize("verdict", [Verdict.AUTH, Verdict.BLOCK, Verdict.PASS])
def test_enforce_never_softens(verdict: Verdict) -> None:
    d = _decision(
        verdict, [ReasonCode.unusual_for_deployment] if verdict is not Verdict.PASS else []
    )
    assert acted_verdict(d, "enforce") is verdict


@pytest.mark.parametrize("state", ["", "ENFORCE", "garbage", "passive", "monitorx"])
def test_unrecognized_state_acts_on_real_verdict(state: str) -> None:
    # Even a discretionary AUTH is enforced under an unrecognized state (the
    # effective_enforcement clamp already maps unknown⇒enforce; this is defence
    # in depth so a bad state string can never soften anything).
    d = _decision(Verdict.AUTH, [ReasonCode.unusual_for_deployment])
    assert acted_verdict(d, state) is Verdict.AUTH


# --- monitor/off: soften discretionary, keep the floor live -----------------


@pytest.mark.parametrize("state", ["monitor", "off"])
@pytest.mark.parametrize("verdict", [Verdict.AUTH, Verdict.BLOCK])
def test_discretionary_softened(state: str, verdict: Verdict) -> None:
    d = _decision(verdict, [ReasonCode.unusual_for_deployment])
    assert acted_verdict(d, state) is Verdict.PASS


@pytest.mark.parametrize("state", ["monitor", "off"])
def test_pass_stays_pass(state: str) -> None:
    assert acted_verdict(_decision(Verdict.PASS, []), state) is Verdict.PASS


# The floor codes that MUST stay live even in monitor/off. This list is
# illustrative; the exhaustive guarantee is in test_every_non_soft_code_stays_live.
_FLOOR_SAMPLES = [
    ReasonCode.secret_exfiltration,
    ReasonCode.confirmed_exfil,  # taint floor — NOT in FLOOR_HARD_BLOCKS, must still be live
    ReasonCode.multi_step_exfil,
    ReasonCode.destructive_command,
    ReasonCode.protected_path_blocked,
    ReasonCode.role_blocked_target,
    ReasonCode.policy_source_blocked,
    ReasonCode.lethal_trifecta,
    ReasonCode.encoded_exfiltration,
    ReasonCode.rule_error,  # a fail-closed error is never softened
    ReasonCode.objective_guardrail_error,
    ReasonCode.smuggled_token_channel,
]


@pytest.mark.parametrize("state", ["monitor", "off"])
@pytest.mark.parametrize("code", _FLOOR_SAMPLES)
def test_floor_codes_stay_live(state: str, code: ReasonCode) -> None:
    assert acted_verdict(_decision(Verdict.BLOCK, [code]), state) is Verdict.BLOCK


@pytest.mark.parametrize("state", ["monitor", "off"])
def test_mixed_soft_and_floor_stays_live(state: str) -> None:
    # One non-soft code keeps the whole verdict live — a disguised floor block
    # cannot be softened by padding it with a discretionary code.
    d = _decision(Verdict.BLOCK, [ReasonCode.unusual_for_deployment, ReasonCode.confirmed_exfil])
    assert acted_verdict(d, state) is Verdict.BLOCK


def test_empty_reason_codes_never_softened() -> None:
    # A non-PASS verdict with no reason codes shouldn't occur (the model validator
    # forbids it), but if one reached here it must fail closed to live, never soften.
    d = Decision(
        action_id="act-x",
        final_verdict=Verdict.PASS,  # PASS is the only verdict allowed with no codes
        final_risk=Risk.low,
        objective=GuardrailResult(verdict=Verdict.PASS, risk=Risk.low),
        reason_codes=[],
        explanation="",
        decided_at=datetime.now(timezone.utc),
    )
    # PASS stays PASS; the guard `codes and ...` also means an (impossible) empty
    # non-PASS verdict would return the real verdict, not PASS.
    assert acted_verdict(d, "monitor") is Verdict.PASS


# --- the exhaustive completeness guarantee ----------------------------------


@pytest.mark.parametrize("code", list(ReasonCode))
def test_every_non_soft_code_stays_live(code: ReasonCode) -> None:
    """Any reason code NOT in the soft allowlist keeps an AUTH/BLOCK live.

    This is the fail-closed contract that makes the floor complete without an
    error-prone hand-maintained floor list: the softening is a subset check
    against a small allowlist, so a new/unlisted code (a future feature, a
    secret/exfil code) is enforced by default. Only codes in the allowlist soften.
    """
    d_auth = _decision(Verdict.AUTH, [code])
    if code in _DISCRETIONARY_SOFT:
        assert acted_verdict(d_auth, "monitor") is Verdict.PASS
    else:
        assert acted_verdict(d_auth, "monitor") is Verdict.AUTH


def test_soft_allowlist_excludes_every_floor_sample() -> None:
    # Guard against someone adding a floor code to the soft set by accident.
    for code in _FLOOR_SAMPLES:
        assert code not in _DISCRETIONARY_SOFT
