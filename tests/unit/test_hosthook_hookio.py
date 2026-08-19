"""Tests for ``hosthooks.hookio`` — the host-generic hook-output shaping +
in-process action-bound AUTH challenge (extracted from ``claude_code.py``,
W1.0b) so a second host adapter (Codex) can reuse it instead of copying it.

Ports the relevant cases from ``test_hosthook_auth_challenge.py`` onto the
new, event-parametric seams. These tests inject a headless fake prompter so
nothing pops a real dialog.
"""

from datetime import datetime, timezone

import pytest

from doberman.auth.challenge import AuthResult, AuthTier
from doberman.auth.gui_prompter import PrompterUnavailableError
from doberman.hosthooks import hookio
from doberman.models import Decision, GuardrailResult, ReasonCode, Risk, SecurityObject, Verdict


class _Approve:
    """A local human who is present and says yes (confirm-only tiers)."""

    def confirm(self, message):
        return True

    def read_code(self, message):
        return "000000"


class _Decline:
    def confirm(self, message):
        return False

    def read_code(self, message):
        raise AssertionError("read_code must not be reached after a declined confirm")


class _NoChannel:
    def confirm(self, message):
        raise PrompterUnavailableError("no channel in test")

    def read_code(self, message):
        raise PrompterUnavailableError("no channel in test")


@pytest.fixture
def sample_action():
    # A WebFetch to a raw IP -> AUTH (unknown_external_destination) at the
    # local_auth tier (confirm only, no TOTP) — mirrors test_hosthook_auth_challenge.py.
    return SecurityObject(
        id="action-1",
        ts=datetime.now(timezone.utc),
        agent_role="default",
        action_type="network_request",
        tool_name="WebFetch",
        target="https://93.184.216.34/",
        external_destination="93.184.216.34",
    )


@pytest.fixture
def sample_auth_decision(sample_action):
    objective = GuardrailResult(
        verdict=Verdict.AUTH,
        risk=Risk.medium,
        reason_codes=[ReasonCode.unknown_external_destination],
        explanation="destination is not a known/allowlisted host",
    )
    return Decision(
        action_id=sample_action.id,
        final_verdict=Verdict.AUTH,
        final_risk=Risk.medium,
        objective=objective,
        reason_codes=[ReasonCode.unknown_external_destination],
        explanation="destination is not a known/allowlisted host",
        decided_at=datetime.now(timezone.utc),
    )


@pytest.fixture
def approving_prompter_for_other_action(monkeypatch):
    """An "approved" challenge result bound to a DIFFERENT action id —
    resolve_auth must never honor it (single-use, action-bound approval)."""

    def _fake_challenge(decision, action, *, prompter=None, at=None, message_tone=None):
        return AuthResult(
            approved=True,
            tier=AuthTier.local_auth,
            method="local_auth",
            at=datetime.now(timezone.utc),
            action_id="some-other-action",
        )

    monkeypatch.setattr("doberman.auth.challenge.run_auth_challenge", _fake_challenge)
    return _Approve()


def test_hook_output_shape_is_event_parametric():
    out = hookio.hook_output("PreToolUse", "deny", "why")
    assert out["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert out["hookSpecificOutput"]["permissionDecisionReason"] == "why"

    out2 = hookio.hook_output("SomeFutureEvent", "deny", "why")
    assert out2["hookSpecificOutput"]["hookEventName"] == "SomeFutureEvent"


def test_deny_uses_failsafe_reason_by_default():
    out = hookio.deny("PreToolUse")
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert out["hookSpecificOutput"]["permissionDecisionReason"] == hookio.FAILSAFE_REASON


def test_resolve_auth_approves_and_allows(sample_auth_decision, sample_action):
    out = hookio.resolve_auth(
        sample_auth_decision, sample_action, event="PreToolUse", prompter=_Approve()
    )
    assert out["hookSpecificOutput"]["permissionDecision"] == "allow"
    assert "action-bound authentication" in out["hookSpecificOutput"]["permissionDecisionReason"]


def test_resolve_auth_denies_on_decline(sample_auth_decision, sample_action):
    out = hookio.resolve_auth(
        sample_auth_decision, sample_action, event="PreToolUse", prompter=_Decline()
    )
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_resolve_auth_denies_on_prompter_error(sample_auth_decision, sample_action):
    out = hookio.resolve_auth(
        sample_auth_decision, sample_action, event="PreToolUse", prompter=_NoChannel()
    )
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"  # fail closed
    assert "could not be shown" in out["hookSpecificOutput"]["permissionDecisionReason"]


def test_resolve_auth_binds_to_action_id(
    sample_auth_decision, sample_action, approving_prompter_for_other_action
):
    out = hookio.resolve_auth(
        sample_auth_decision,
        sample_action,
        event="PreToolUse",
        prompter=approving_prompter_for_other_action,
    )
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_resolve_auth_is_event_parametric(sample_auth_decision, sample_action):
    out = hookio.resolve_auth(
        sample_auth_decision, sample_action, event="SomeFutureEvent", prompter=_Approve()
    )
    assert out["hookSpecificOutput"]["hookEventName"] == "SomeFutureEvent"


def test_decision_payload_is_event_parametric(sample_action):
    objective = GuardrailResult(
        verdict=Verdict.BLOCK,
        risk=Risk.high,
        reason_codes=[ReasonCode.unknown_external_destination],
        explanation="blocked for test",
    )
    decision = Decision(
        action_id=sample_action.id,
        final_verdict=Verdict.BLOCK,
        final_risk=Risk.high,
        objective=objective,
        reason_codes=[ReasonCode.unknown_external_destination],
        explanation="blocked for test",
        decided_at=datetime.now(timezone.utc),
    )
    out = hookio.decision_payload(decision, event="SomeFutureEvent")
    assert out["hookSpecificOutput"]["hookEventName"] == "SomeFutureEvent"
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_format_reason_includes_verdict_and_action_id(sample_auth_decision):
    reason = hookio.format_reason(sample_auth_decision, "AUTH")
    assert "AUTH" in reason
    assert sample_auth_decision.action_id in reason
