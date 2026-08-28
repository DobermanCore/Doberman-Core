"""Pluggable approval methods: fail-closed contract, opt-in config, and the 2FA
tier wiring (a biometric/push tap replaces the TOTP code, with TOTP fallback).

No real biometric or network here — a fake :class:`ApprovalMethod` exercises every
path. The security-critical properties pinned: an error/timeout/non-answer never
approves; ``unavailable`` never bypasses the second factor (it defers to TOTP);
and with nothing enabled the flow is byte-for-byte the old confirm + TOTP.
"""

import sys

import pytest

from doberman.auth import approval_config
from doberman.auth.approval import (
    ApprovalOutcome,
    request_approval,
    resolve_approval_method,
)
from doberman.auth.challenge import AuthTier
from doberman.auth.methods.windows_hello import WindowsHelloMethod
from doberman.auth.provider import LocalAuthProvider


# --------------------------------------------------------------------------- #
# Fakes                                                                         #
# --------------------------------------------------------------------------- #
class FakeMethod:
    def __init__(self, name="fake", available=True, outcome=ApprovalOutcome.approved):
        self.name = name
        self._available = available
        self._outcome = outcome
        self.requests: list[tuple[str, str]] = []

    def is_available(self) -> bool:
        return self._available

    def request(self, prompt, *, action_id, timeout_s):
        self.requests.append((prompt, action_id))
        return self._outcome


class RaisingMethod:
    name = "boom"

    def is_available(self) -> bool:
        return True

    def request(self, prompt, *, action_id, timeout_s):
        raise RuntimeError("backend blew up")


class FakePrompter:
    def __init__(self, confirm=True, code="123456"):
        self._confirm = confirm
        self._code = code
        self.confirm_calls = 0
        self.code_calls = 0

    def confirm(self, message) -> bool:
        self.confirm_calls += 1
        return self._confirm

    def read_code(self, message) -> str:
        self.code_calls += 1
        return self._code


# --------------------------------------------------------------------------- #
# request_approval — fail closed                                               #
# --------------------------------------------------------------------------- #
def test_request_approval_passes_through_approved_and_denied():
    assert (
        request_approval(FakeMethod(outcome=ApprovalOutcome.approved), "p", action_id="a")
        is ApprovalOutcome.approved
    )
    assert (
        request_approval(FakeMethod(outcome=ApprovalOutcome.denied), "p", action_id="a")
        is ApprovalOutcome.denied
    )


def test_a_raising_method_is_denied_not_approved():
    assert request_approval(RaisingMethod(), "p", action_id="a") is ApprovalOutcome.denied


def test_a_non_outcome_return_is_denied():
    class Weird:
        name = "weird"

        def is_available(self):
            return True

        def request(self, prompt, *, action_id, timeout_s):
            return "yes please"  # not an ApprovalOutcome

    assert request_approval(Weird(), "p", action_id="a") is ApprovalOutcome.denied


def test_unavailable_method_short_circuits_without_being_asked():
    m = FakeMethod(available=False)
    assert request_approval(m, "p", action_id="a") is ApprovalOutcome.unavailable
    assert m.requests == []  # request() never called when unavailable


def test_request_is_action_bound():
    m = FakeMethod()
    request_approval(m, "approve THIS", action_id="action-xyz")
    assert m.requests == [("approve THIS", "action-xyz")]


# --------------------------------------------------------------------------- #
# Config — opt-in, order-preserving, fail-safe                                 #
# --------------------------------------------------------------------------- #
@pytest.fixture
def cfg(tmp_path, monkeypatch):
    monkeypatch.setenv(approval_config.APPROVAL_FILE_ENV, str(tmp_path / "approval.json"))
    return tmp_path


def test_nothing_enabled_by_default(cfg):
    assert approval_config.enabled_methods() == []


def test_enable_disable_and_order(cfg):
    approval_config.enable("windows_hello")
    approval_config.enable("duo")
    assert approval_config.enabled_methods() == ["windows_hello", "duo"]
    assert approval_config.is_enabled("duo") is True
    approval_config.set_order(["duo", "windows_hello"])
    assert approval_config.enabled_methods() == ["duo", "windows_hello"]
    approval_config.disable("duo")
    assert approval_config.enabled_methods() == ["windows_hello"]


def test_enable_rejects_a_malformed_name(cfg):
    with pytest.raises(ValueError):
        approval_config.enable("Not A Name!")


def test_a_malformed_config_file_reads_as_empty(cfg):
    (cfg / "approval.json").write_text("}{ not json", encoding="utf-8")
    assert approval_config.enabled_methods() == []  # fail-safe -> TOTP


# --------------------------------------------------------------------------- #
# resolve_approval_method — preference + availability                          #
# --------------------------------------------------------------------------- #
def test_resolve_returns_none_when_nothing_enabled(cfg):
    assert resolve_approval_method() is None


def test_resolve_picks_first_enabled_and_available(cfg, monkeypatch):
    a = FakeMethod(name="a", available=False)
    b = FakeMethod(name="b", available=True)
    monkeypatch.setattr(
        "doberman.auth.approval.discover_approval_methods", lambda: [a, b], raising=False
    )
    # patch where resolve looks it up (imported lazily inside the function)
    import doberman.engine.registry as reg

    monkeypatch.setattr(reg, "discover_approval_methods", lambda: [a, b])
    approval_config.set_order(["a", "b"])  # a preferred but unavailable -> b
    assert resolve_approval_method() is b


def test_resolve_skips_all_when_enabled_but_unavailable(cfg, monkeypatch):
    a = FakeMethod(name="a", available=False)
    import doberman.engine.registry as reg

    monkeypatch.setattr(reg, "discover_approval_methods", lambda: [a])
    approval_config.set_order(["a"])
    assert resolve_approval_method() is None  # -> TOTP fallback


# --------------------------------------------------------------------------- #
# Windows Hello — conservative availability                                    #
# --------------------------------------------------------------------------- #
def test_windows_hello_is_unavailable_off_windows():
    avail = WindowsHelloMethod().is_available()
    assert isinstance(avail, bool)
    if sys.platform != "win32":
        assert avail is False


# --------------------------------------------------------------------------- #
# _run_tier wiring — the biometric/push tap replaces the code; TOTP fallback   #
# --------------------------------------------------------------------------- #
def _patch_method(monkeypatch, method):
    monkeypatch.setattr("doberman.auth.provider.resolve_approval_method", lambda: method)


def test_confirm_tiers_never_consult_an_approval_method(monkeypatch):
    m = FakeMethod()
    _patch_method(monkeypatch, m)
    p = FakePrompter(confirm=True)
    approved, label = LocalAuthProvider._run_tier(AuthTier.local_auth, "msg", p, "act")
    assert approved is True and label == "local_auth"
    assert m.requests == []  # method not used for confirm tiers


def test_approved_method_satisfies_2fa_without_totp(monkeypatch):
    m = FakeMethod(name="windows_hello", outcome=ApprovalOutcome.approved)
    _patch_method(monkeypatch, m)
    called = {"totp": False}
    monkeypatch.setattr(
        "doberman.auth.provider.totp.verify",
        lambda *a, **k: called.__setitem__("totp", True) or True,
    )
    p = FakePrompter()
    approved, label = LocalAuthProvider._run_tier(AuthTier.two_factor, "run cmd X", p, "act-1")
    assert approved is True and label == "windows_hello"
    assert p.code_calls == 0 and called["totp"] is False  # TOTP never touched
    assert m.requests == [("run cmd X", "act-1")]  # action-bound


def test_denied_method_denies_without_totp(monkeypatch):
    m = FakeMethod(outcome=ApprovalOutcome.denied)
    _patch_method(monkeypatch, m)
    p = FakePrompter()
    approved, label = LocalAuthProvider._run_tier(AuthTier.two_factor, "msg", p, "act")
    assert approved is False and label == "denied"
    assert p.code_calls == 0


def test_unavailable_method_falls_back_to_confirm_plus_totp(monkeypatch):
    m = FakeMethod(available=False)
    _patch_method(monkeypatch, m)
    monkeypatch.setattr("doberman.auth.provider.totp.verify", lambda *a, **k: True)
    p = FakePrompter(confirm=True)
    approved, label = LocalAuthProvider._run_tier(AuthTier.two_factor, "msg", p, "act")
    assert approved is True and label == "totp"
    assert p.confirm_calls == 1 and p.code_calls == 1  # TOTP path exercised


def test_no_method_enabled_is_the_old_confirm_plus_totp(monkeypatch):
    _patch_method(monkeypatch, None)  # resolve returns None
    monkeypatch.setattr("doberman.auth.provider.totp.verify", lambda *a, **k: True)
    p = FakePrompter(confirm=True)
    approved, label = LocalAuthProvider._run_tier(AuthTier.two_factor, "msg", p, "act")
    assert approved is True and label == "totp"
    assert p.confirm_calls == 1 and p.code_calls == 1


def test_elevation_tier_labels_the_method(monkeypatch):
    m = FakeMethod(name="windows_hello", outcome=ApprovalOutcome.approved)
    _patch_method(monkeypatch, m)
    approved, label = LocalAuthProvider._run_tier(
        AuthTier.role_elevation, "msg", FakePrompter(), "act"
    )
    assert approved is True and label == "windows_hello+elevation"


def test_method_approve_but_a_denied_confirm_never_reached(monkeypatch):
    # An approved method must NOT then require confirm (single tap = presence+possession).
    m = FakeMethod(outcome=ApprovalOutcome.approved)
    _patch_method(monkeypatch, m)
    p = FakePrompter(confirm=False)  # would deny if consulted
    approved, _ = LocalAuthProvider._run_tier(AuthTier.two_factor, "msg", p, "act")
    assert approved is True
    assert p.confirm_calls == 0  # method approval alone carried the tier


# --------------------------------------------------------------------------- #
# CLI — doberman 2fa methods                                                    #
# --------------------------------------------------------------------------- #
def test_cli_methods_list_and_status(cfg):
    from typer.testing import CliRunner

    from doberman.cli.main import app

    runner = CliRunner()
    res = runner.invoke(app, ["2fa", "methods", "list"])
    assert res.exit_code == 0 and "windows_hello" in res.output
    res = runner.invoke(app, ["2fa", "methods", "status"])
    assert res.exit_code == 0 and "TOTP" in res.output


def test_cli_methods_enable_then_disable(cfg):
    from typer.testing import CliRunner

    from doberman.cli.main import app

    runner = CliRunner()
    assert runner.invoke(app, ["2fa", "methods", "enable", "windows_hello"]).exit_code == 0
    assert approval_config.is_enabled("windows_hello") is True
    assert runner.invoke(app, ["2fa", "methods", "disable", "windows_hello"]).exit_code == 0
    assert approval_config.is_enabled("windows_hello") is False


def test_cli_enable_unknown_method_is_rejected(cfg):
    from typer.testing import CliRunner

    from doberman.cli.main import app

    runner = CliRunner()
    res = runner.invoke(app, ["2fa", "methods", "enable", "duo"])  # not installed yet
    assert res.exit_code == 1  # unknown method -> non-zero, nothing persisted
    assert approval_config.enabled_methods() == []
