"""Slices 7.3 / 7.6 — the local provider and the AuthProvider seam."""

from datetime import datetime, timezone

import pyotp

from doberman.auth import totp
from doberman.auth.challenge import AuthResult, AuthTier
from doberman.auth.provider import (
    AUTH_PROVIDER_ENV,
    LOCAL_PROVIDER,
    CoGatedProvider,
    LocalAuthProvider,
    active_provider,
)
from doberman.engine import registry
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


class _StubProvider:
    """A fake ``AuthProvider`` returning a canned result, recording every call."""

    def __init__(self, *, approved=True, method="stub", action_id="act-7"):
        self._approved = approved
        self._method = method
        self._action_id = action_id
        self.calls: list[AuthTier] = []

    def authenticate(self, decision, action, tier, *, prompter=None, at=None, message_tone="human"):
        self.calls.append(tier)
        return AuthResult(
            approved=self._approved,
            tier=tier,
            method=self._method,
            at=at or _NOW,
            action_id=self._action_id,
        )


class _BoomProvider:
    def authenticate(self, decision, action, tier, *, prompter=None, at=None, message_tone="human"):
        raise RuntimeError("plugin exploded")


class _FakeAuthEntryPoint:
    def __init__(self, name, loader):
        self.name = name
        self._loader = loader

    def load(self):
        return self._loader()


class _FakeAuthEntryPoints:
    """Mimics importlib.metadata.entry_points() with a .select(group=...)."""

    def __init__(self, entries):
        self._entries = list(entries)

    def select(self, *, group):
        return list(self._entries) if group == registry.AUTH_PROVIDER_GROUP else []


def test_registered_provider_is_preferred(monkeypatch):
    stub = _StubProvider()
    monkeypatch.setattr("doberman.engine.registry.discover_auth_providers", lambda names: [stub])

    # env var unset -> the registered provider is ignored entirely.
    monkeypatch.delenv(AUTH_PROVIDER_ENV, raising=False)
    assert active_provider() is LOCAL_PROVIDER

    # opted in by name -> wrapped in CoGatedProvider, wrapping the discovered stub.
    monkeypatch.setenv(AUTH_PROVIDER_ENV, "stub")
    provider = active_provider()
    assert isinstance(provider, CoGatedProvider)
    assert provider.inner is stub


def test_non_provider_shaped_registration_is_skipped(monkeypatch):
    monkeypatch.setenv(AUTH_PROVIDER_ENV, "bogus")
    monkeypatch.setattr(
        "doberman.engine.registry.discover_auth_providers", lambda names: [object()]
    )
    assert isinstance(active_provider(), LocalAuthProvider)


def test_disallowed_provider_entry_point_is_never_loaded(monkeypatch):
    def _must_not_load():
        raise AssertionError("a non-allowed entry point must never be loaded")

    allowed_ep = _FakeAuthEntryPoint("allowed", _StubProvider)
    disallowed_ep = _FakeAuthEntryPoint("not-allowed", _must_not_load)
    monkeypatch.setattr(
        registry, "entry_points", lambda: _FakeAuthEntryPoints([allowed_ep, disallowed_ep])
    )

    result = registry.discover_auth_providers(["allowed"])
    assert len(result) == 1
    assert isinstance(result[0], _StubProvider)


def test_empty_allowlist_returns_nothing_without_loading(monkeypatch):
    def _must_not_load():
        raise AssertionError("nothing may load when the allowlist is empty")

    monkeypatch.setattr(
        registry,
        "entry_points",
        lambda: _FakeAuthEntryPoints([_FakeAuthEntryPoint("x", _must_not_load)]),
    )
    assert registry.discover_auth_providers([]) == []


def test_malformed_env_value_is_ignored(monkeypatch):
    monkeypatch.setenv(AUTH_PROVIDER_ENV, "bad name;rm")
    assert isinstance(active_provider(), LocalAuthProvider)


def test_role_elevation_requires_local_consent_too():
    totp.enroll()
    secret = totp._read_secret()
    code = pyotp.TOTP(secret).now()

    plugin = _StubProvider(approved=True, method="sso")
    gated = CoGatedProvider(plugin)

    # plugin approves, but the local human declines -> not approved.
    denied = gated.authenticate(
        _auth_decision(), _action(), AuthTier.role_elevation, prompter=FakePrompter(confirm=False)
    )
    assert denied.approved is False

    # plugin approves AND local approves (confirm + valid TOTP) -> approved.
    approved = gated.authenticate(
        _auth_decision(),
        _action(),
        AuthTier.role_elevation,
        prompter=FakePrompter(confirm=True, code=code),
    )
    assert approved.approved is True
    assert approved.method == "sso+local"


def test_two_factor_uses_the_plugin_result_alone():
    plugin = _StubProvider(approved=True, method="sso")
    gated = CoGatedProvider(plugin)
    # A prompter that would deny locally must not even be consulted for two_factor.
    result = gated.authenticate(
        _auth_decision(), _action(), AuthTier.two_factor, prompter=FakePrompter(confirm=False)
    )
    assert result.approved is True
    assert result.method == "sso"


def test_plugin_raising_is_denied_with_error_method():
    gated = CoGatedProvider(_BoomProvider())
    result = gated.authenticate(
        _auth_decision(), _action(), AuthTier.soft_confirm, prompter=FakePrompter()
    )
    assert result.approved is False
    assert result.method == "error"


def test_plugin_approving_a_different_action_id_is_denied():
    plugin = _StubProvider(approved=True, method="sso", action_id="some-other-action")
    gated = CoGatedProvider(plugin)
    result = gated.authenticate(
        _auth_decision(), _action(), AuthTier.soft_confirm, prompter=FakePrompter()
    )
    assert result.approved is False
