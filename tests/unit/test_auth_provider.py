"""Slices 7.3 / 7.6 — the local provider and the AuthProvider seam."""

from datetime import datetime, timezone

import pyotp

from doberman.auth import totp
from doberman.auth.challenge import AuthResult, AuthTier
from doberman.auth.provider import LocalAuthProvider, active_provider
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


class FakePrompter:
    """Canned answers; records the message shown so tests can inspect it."""

    def __init__(self, *, confirm=True, code="", raises=None):
        self._confirm = confirm
        self._code = code
        self._raises = raises
        self.messages: list[str] = []

    def confirm(self, message: str) -> bool:
        self.messages.append(message)
        if self._raises is not None:
            raise self._raises
        return self._confirm

    def read_code(self, message: str) -> str:
        return self._code


def _action(target="backend/api.ts"):
    return SecurityObject(
        id="act-7",
        ts=_NOW,
        agent_role="webdev",
        action_type=ActionType.file_write,
        tool_name="fs_write",
        target=target,
    )


def _auth_decision(reasons=(ReasonCode.role_out_of_scope,), risk: Risk = Risk.medium):
    objective = GuardrailResult(
        verdict=Verdict.AUTH, risk=risk, reason_codes=list(reasons), explanation="why"
    )
    return Decision(
        action_id="act-7",
        final_verdict=Verdict.AUTH,
        final_risk=risk,
        objective=objective,
        reason_codes=list(reasons),
        explanation="why",
        decided_at=_NOW,
    )


def test_default_provider_is_local():
    assert isinstance(active_provider(), LocalAuthProvider)


def test_soft_confirm_approves_on_yes():
    result = LocalAuthProvider().authenticate(
        _auth_decision(), _action(), AuthTier.soft_confirm, prompter=FakePrompter(confirm=True)
    )
    assert isinstance(result, AuthResult)
    assert result.approved is True
    assert result.tier is AuthTier.soft_confirm
    assert result.action_id == "act-7"  # bound to the action


def test_soft_confirm_denies_on_no():
    result = LocalAuthProvider().authenticate(
        _auth_decision(), _action(), AuthTier.soft_confirm, prompter=FakePrompter(confirm=False)
    )
    assert result.approved is False
    assert result.tier is AuthTier.soft_confirm  # provider never changes the tier


def test_two_factor_requires_confirm_and_valid_code():
    totp.enroll()
    secret = totp._read_secret()
    code = pyotp.TOTP(secret).now()
    ok = LocalAuthProvider().authenticate(
        _auth_decision(),
        _action(),
        AuthTier.two_factor,
        prompter=FakePrompter(confirm=True, code=code),
    )
    assert ok.approved is True

    bad = LocalAuthProvider().authenticate(
        _auth_decision(),
        _action(),
        AuthTier.two_factor,
        prompter=FakePrompter(confirm=True, code="000000"),
    )
    assert bad.approved is False


def test_two_factor_denied_when_presence_refused():
    totp.enroll()
    result = LocalAuthProvider().authenticate(
        _auth_decision(), _action(), AuthTier.two_factor, prompter=FakePrompter(confirm=False)
    )
    assert result.approved is False


def test_prompter_failure_denies_fail_closed():
    result = LocalAuthProvider().authenticate(
        _auth_decision(),
        _action(),
        AuthTier.local_auth,
        prompter=FakePrompter(raises=TimeoutError("walked away")),
    )
    assert result.approved is False


def test_challenge_message_names_target_and_reason():
    # "technical" tone: the original detailed format, pinned exactly (the
    # "human" default is covered separately below).
    prompter = FakePrompter(confirm=False)
    LocalAuthProvider().authenticate(
        _auth_decision(),
        _action("backend/api.ts"),
        AuthTier.soft_confirm,
        prompter=prompter,
        message_tone="technical",
    )
    message = prompter.messages[0]
    assert "backend/api.ts" in message  # the EXACT target
    assert "role_out_of_scope" in message  # the reason
    assert "webdev" in message  # the role


def test_challenge_message_includes_risk_badge():
    prompter = FakePrompter(confirm=False)
    LocalAuthProvider().authenticate(
        _auth_decision(risk=Risk.critical),
        _action("backend/api.ts"),
        AuthTier.soft_confirm,
        prompter=prompter,
        message_tone="technical",
    )
    message = prompter.messages[0]
    assert "RISK: CRITICAL" in message  # the badge is additive, not a replacement
    assert "webdev" in message  # the role
    assert "backend/api.ts" in message  # the target
    assert "role_out_of_scope" in message  # the reason


def test_challenge_message_low_risk_renders_cleanly():
    prompter = FakePrompter(confirm=False)
    LocalAuthProvider().authenticate(
        _auth_decision(risk=Risk.low),
        _action("backend/api.ts"),
        AuthTier.soft_confirm,
        prompter=prompter,
        message_tone="technical",
    )
    message = prompter.messages[0]
    assert "RISK: LOW" in message
    assert "webdev" in message  # the role
    assert "backend/api.ts" in message  # the target
    assert "role_out_of_scope" in message  # the reason


def test_challenge_message_is_ascii_and_cp1252_safe():
    """_challenge_message output must be ASCII and cp1252-safe for legacy Windows consoles,
    in BOTH tones (the default "human" tone and the original "technical" one)."""
    from doberman.auth.provider import _challenge_message

    for tone in ("human", "technical"):
        msg = _challenge_message(_auth_decision(), _action(), AuthTier.soft_confirm, tone)
        assert msg.isascii(), f"non-ASCII in {tone} challenge prompt: {msg!r}"
        msg.encode("ascii")  # raises UnicodeEncodeError if non-ASCII


def test_challenge_message_human_tone_is_plain_and_names_target_and_reason():
    """S1: the "human" tone (the default) is plain-worded but states the same facts —
    the exact target and the reason, in plain language, without the raw code or the
    technical [RISK:]/role:/reason: scaffolding."""
    prompter = FakePrompter(confirm=False)
    LocalAuthProvider().authenticate(
        _auth_decision(), _action("backend/api.ts"), AuthTier.soft_confirm, prompter=prompter
    )
    message = prompter.messages[0]
    assert "    backend/api.ts" in message  # the exact target, indented
    assert "role_out_of_scope" not in message  # no raw reason code
    assert "[RISK:" not in message  # no technical badge
    assert "role:" not in message
    assert "Approve this exact action?" in message
    assert "outside" in message and "scope" in message  # the plain-language reason


def test_registered_provider_is_preferred(monkeypatch):
    sentinel = object()

    class StubProvider:
        def authenticate(self, decision, action, tier, *, prompter=None, at=None):
            return sentinel

    monkeypatch.setattr(
        "doberman.engine.registry.discover_auth_providers", lambda: [StubProvider()]
    )
    assert isinstance(active_provider(), StubProvider)


def test_non_provider_shaped_registration_is_skipped(monkeypatch):
    monkeypatch.setattr("doberman.engine.registry.discover_auth_providers", lambda: [object()])
    assert isinstance(active_provider(), LocalAuthProvider)
