"""Slice 7.1 — auth-tier selection from the final decision."""

from datetime import datetime, timezone

import pytest

from doberman.auth.challenge import AuthTier, select_tier
from doberman.models import Decision, GuardrailResult, ReasonCode, Risk, Verdict


def _decision(verdict, risk, reasons):
    objective = GuardrailResult(
        verdict=verdict, risk=risk, reason_codes=list(reasons), explanation="x"
    )
    return Decision(
        action_id="a1",
        final_verdict=verdict,
        final_risk=risk,
        objective=objective,
        reason_codes=list(reasons),
        explanation="x",
        decided_at=datetime.now(timezone.utc),
    )


def _auth(risk, reasons):
    return _decision(Verdict.AUTH, risk, reasons)


def test_low_risk_minor_reason_is_soft_confirm():
    assert select_tier(_auth(Risk.low, [ReasonCode.unknown_tool])) is AuthTier.soft_confirm


def test_unknown_destination_maps_to_local_auth():
    tier = select_tier(_auth(Risk.low, [ReasonCode.unknown_external_destination]))
    assert tier is AuthTier.local_auth


def test_sensitive_secret_access_maps_to_two_factor():
    tier = select_tier(_auth(Risk.low, [ReasonCode.sensitive_secret_access]))
    assert tier is AuthTier.two_factor


def test_role_out_of_scope_routes_to_role_elevation():
    tier = select_tier(_auth(Risk.medium, [ReasonCode.role_out_of_scope]))
    assert tier is AuthTier.role_elevation


def test_high_risk_base_is_two_factor():
    # A sensitive delete: high risk + sensitive_path_access → two_factor.
    tier = select_tier(_auth(Risk.high, [ReasonCode.sensitive_path_access]))
    assert tier is AuthTier.two_factor


def test_strongest_reason_wins():
    tier = select_tier(
        _auth(
            Risk.low,
            [ReasonCode.unknown_external_destination, ReasonCode.sensitive_secret_access],
        )
    )
    assert tier is AuthTier.two_factor


def test_role_elevation_outranks_two_factor():
    tier = select_tier(
        _auth(Risk.high, [ReasonCode.sensitive_secret_access, ReasonCode.role_out_of_scope])
    )
    assert tier is AuthTier.role_elevation


def test_hard_block_never_maps_to_a_challenge():
    block = _decision(Verdict.BLOCK, Risk.critical, [ReasonCode.secret_exfiltration])
    with pytest.raises(ValueError, match="AUTH"):
        select_tier(block)


def test_pass_never_maps_to_a_challenge():
    # A PASS carries no reasons; build it directly (the validator allows that).
    objective = GuardrailResult(verdict=Verdict.PASS, risk=Risk.low)
    decision = Decision(
        action_id="a1",
        final_verdict=Verdict.PASS,
        final_risk=Risk.low,
        objective=objective,
        decided_at=datetime.now(timezone.utc),
    )
    with pytest.raises(ValueError, match="AUTH"):
        select_tier(decision)
