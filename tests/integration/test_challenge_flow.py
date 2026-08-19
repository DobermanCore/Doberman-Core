"""Slice 7.3 — the action-specific challenge, end-to-end through run_auth_challenge."""

from datetime import datetime, timezone

import pyotp

from doberman.auth import totp
from doberman.auth.challenge import run_auth_challenge
from doberman.models import (
    ActionType,
    Decision,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    Verdict,
)

_NOW = datetime(2026, 6, 8, tzinfo=timezone.utc)


class ScriptedPrompter:
    def __init__(self, *, confirm=True, code="", raises=None):
        self._confirm, self._code, self._raises = confirm, code, raises
        self.messages: list[str] = []

    def confirm(self, message):
        self.messages.append(message)
        if self._raises is not None:
            raise self._raises
        return self._confirm

    def read_code(self, message):
        return self._code


def _action(target="backend/api.ts"):
    return SecurityObject(
        id="act-1",
        ts=_NOW,
        agent_role="webdev",
        action_type=ActionType.file_write,
        tool_name="fs_write",
        target=target,
    )


def _auth_decision(reasons, risk=Risk.low):
    objective = GuardrailResult(
        verdict=Verdict.AUTH, risk=risk, reason_codes=list(reasons), explanation="why"
    )
    return Decision(
        action_id="act-1",
        final_verdict=Verdict.AUTH,
        final_risk=risk,
        objective=objective,
        reason_codes=list(reasons),
        explanation="why",
        decided_at=_NOW,
    )


def test_prompt_names_the_specific_target_and_reason():
    # "technical" tone: the raw reason code is asserted verbatim; the "human"
    # default's plain-language rendering of the same facts is covered by
    # test_auth_provider.py's own tone tests.
    prompter = ScriptedPrompter(confirm=False)
    run_auth_challenge(
        _auth_decision([ReasonCode.unknown_tool]),
        _action("backend/api.ts"),
        prompter=prompter,
        message_tone="technical",
    )
    msg = prompter.messages[0]
    assert "backend/api.ts" in msg
    assert "unknown_tool" in msg


def test_soft_confirm_approval():
    result = run_auth_challenge(
        _auth_decision([ReasonCode.unknown_tool]),
        _action(),
        prompter=ScriptedPrompter(confirm=True),
    )
    assert result.approved is True
    assert result.action_id == "act-1"


def test_denial_is_not_approved():
    result = run_auth_challenge(
        _auth_decision([ReasonCode.unknown_tool]),
        _action(),
        prompter=ScriptedPrompter(confirm=False),
    )
    assert result.approved is False


def test_timeout_denies_fail_closed():
    result = run_auth_challenge(
        _auth_decision([ReasonCode.unknown_tool]),
        _action(),
        prompter=ScriptedPrompter(raises=TimeoutError("walked away")),
    )
    assert result.approved is False


def test_two_factor_decision_requires_a_valid_code():
    totp.enroll()
    code = pyotp.TOTP(totp._read_secret()).now()
    # sensitive_secret_access selects the two_factor tier.
    decision = _auth_decision([ReasonCode.sensitive_secret_access])
    ok = run_auth_challenge(decision, _action(), prompter=ScriptedPrompter(confirm=True, code=code))
    assert ok.tier.value == "two_factor"
    assert ok.approved is True

    bad = run_auth_challenge(
        decision, _action(), prompter=ScriptedPrompter(confirm=True, code="000000")
    )
    assert bad.approved is False
