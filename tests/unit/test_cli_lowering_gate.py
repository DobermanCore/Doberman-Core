"""C1 slice 2 — CLI coverage for permanent mode/preference weakenings.

Lowering requires confirmation plus the strongest enrolled possession factor:
TOTP when enrolled, otherwise the local password. With neither factor enrolled
the change fails closed; strengthening and first-run setup remain frictionless.
"""

import asyncio

import pyotp
import pytest
from typer.testing import CliRunner

from doberman.auth import password, totp
from doberman.cli import main as cli_main
from doberman.cli.main import app
from doberman.config import load_mode, load_policy, load_preferences
from doberman.policy.drift import read_policy_changes

runner = CliRunner()

_PASSWORD = "correct horse battery staple"  # noqa: S105 — synthetic test credential


class _Decline:
    def confirm(self, message):
        return False

    def read_code(self, message):  # pragma: no cover -- never reached after a decline
        raise AssertionError("read_code must not be reached after a declined confirm")


class _Boom:
    """Any prompt is a failure — proves a raise is never gated."""

    def confirm(self, message):
        raise AssertionError("a raise must not prompt")

    def read_code(self, message):
        raise AssertionError("a raise must not prompt")


class _Approve:
    """Present operator: confirms and supplies one out-of-band factor."""

    def __init__(self, code):
        self._code = code

    def confirm(self, message):
        return True

    def read_code(self, message):
        return self._code


class _ConfirmOnly:
    """No-factor path must return before asking for an unavailable secret."""

    def confirm(self, message):
        return True

    def read_code(self, message):
        raise AssertionError("no factor is enrolled, so no secret prompt is valid")


class _CodeSequence:
    def __init__(self, *codes):
        self._codes = iter(codes)

    def read_code(self, message):
        return next(self._codes)


def _use_prompter(monkeypatch, prompter_factory):
    # apply_change / apply_preferences_change lazily construct this name only on
    # the weaken path (same pattern as test_cli_enforcement.py).
    monkeypatch.setattr("doberman.auth.provider.CliPrompter", prompter_factory)


def _enrolled_code() -> str:
    totp.enroll()
    secret = totp._read_secret()
    assert secret is not None
    return pyotp.TOTP(secret).now()


def _invoke_lowering(kind: str, root: str):
    if kind == "mode":
        return runner.invoke(app, ["mode", "light", "--path", root])
    return runner.invoke(app, ["prefs", "confidentiality", "0.1", "--path", root])


def _assert_lowering_state(kind: str, root: str, *, applied: bool) -> None:
    if kind == "mode":
        assert load_mode(root) == ("light" if applied else "balanced")
    else:
        expected = 0.1 if applied else 0.5
        assert load_preferences(root).confidentiality == expected
    if not applied:
        assert load_policy(root) is None


def _assert_single_ledger_method(root: str, method: str, *, approved: int) -> None:
    rows = asyncio.run(read_policy_changes(root))
    assert len(rows) == 1
    assert rows[0]["approval_method"] == method
    assert rows[0]["approved"] == approved


@pytest.mark.parametrize("kind", ["mode", "prefs"])
def test_lowering_with_enrolled_2fa_requires_valid_totp_and_persists(kind, tmp_path, monkeypatch):
    root = str(tmp_path)
    password.enroll(_PASSWORD)  # TOTP must win when both factors are enrolled.
    code = _enrolled_code()
    _use_prompter(monkeypatch, lambda: _Approve(code))

    result = _invoke_lowering(kind, root)

    assert result.exit_code == 0, result.output
    _assert_lowering_state(kind, root, applied=True)
    _assert_single_ledger_method(root, "two_factor", approved=1)


@pytest.mark.parametrize("kind", ["mode", "prefs"])
@pytest.mark.parametrize("prompter", [_Decline(), _Approve(_PASSWORD)])
def test_lowering_with_enrolled_2fa_decline_or_non_totp_factor_is_denied(
    kind, prompter, tmp_path, monkeypatch
):
    root = str(tmp_path)
    password.enroll(_PASSWORD)
    _enrolled_code()
    _use_prompter(monkeypatch, lambda: prompter)

    result = _invoke_lowering(kind, root)

    assert result.exit_code == 1
    assert result.stderr.startswith("error: ")
    _assert_lowering_state(kind, root, applied=False)
    _assert_single_ledger_method(root, "denied", approved=0)


@pytest.mark.parametrize("kind", ["mode", "prefs"])
def test_lowering_with_password_only_accepts_password(kind, tmp_path, monkeypatch):
    root = str(tmp_path)
    password.enroll(_PASSWORD)
    _use_prompter(monkeypatch, lambda: _Approve(_PASSWORD))

    result = _invoke_lowering(kind, root)

    assert result.exit_code == 0, result.output
    _assert_lowering_state(kind, root, applied=True)
    _assert_single_ledger_method(root, "password", approved=1)


@pytest.mark.parametrize("kind", ["mode", "prefs"])
def test_lowering_with_password_only_rejects_wrong_password(kind, tmp_path, monkeypatch):
    root = str(tmp_path)
    password.enroll(_PASSWORD)
    _use_prompter(monkeypatch, lambda: _Approve("this is the wrong password"))

    result = _invoke_lowering(kind, root)

    assert result.exit_code == 1
    _assert_lowering_state(kind, root, applied=False)
    _assert_single_ledger_method(root, "denied", approved=0)


@pytest.mark.parametrize("kind", ["mode", "prefs"])
def test_lowering_with_no_factor_enrolled_fails_closed(kind, tmp_path, monkeypatch):
    root = str(tmp_path)
    _use_prompter(monkeypatch, _ConfirmOnly)

    result = _invoke_lowering(kind, root)

    assert result.exit_code == 1
    _assert_lowering_state(kind, root, applied=False)
    _assert_single_ledger_method(root, "no_factor_enrolled", approved=0)


def test_mode_raising_never_prompts_and_applies(tmp_path, monkeypatch):
    root = str(tmp_path)
    _use_prompter(monkeypatch, _Boom)

    result = runner.invoke(app, ["mode", "strict", "--path", root])

    assert result.exit_code == 0, result.output
    assert load_mode(root) == "strict"
    _assert_single_ledger_method(root, "auto", approved=1)


def test_prefs_raising_never_prompts_and_applies(tmp_path, monkeypatch):
    root = str(tmp_path)
    _use_prompter(monkeypatch, _Boom)

    result = runner.invoke(app, ["prefs", "confidentiality", "0.9", "--path", root])

    assert result.exit_code == 0, result.output
    assert load_preferences(root).confidentiality == 0.9
    _assert_single_ledger_method(root, "auto", approved=1)


def test_setup_can_establish_initial_mode_without_a_factor(tmp_path, monkeypatch):
    root = str(tmp_path)
    _use_prompter(monkeypatch, _Boom)

    result = runner.invoke(app, ["setup", "--yes", "--mode", "light", "--path", root])

    assert result.exit_code == 0, result.output
    assert load_mode(root) == "light"


def test_password_set_command_enrolls_matching_password(tmp_path, monkeypatch):
    prompter = _CodeSequence(_PASSWORD, _PASSWORD)
    monkeypatch.setattr(cli_main, "CliPrompter", lambda: prompter)

    result = runner.invoke(app, ["password", "set"])

    assert result.exit_code == 0, result.output
    assert password.verify(_PASSWORD) is True
    assert _PASSWORD not in result.output


def test_password_set_command_rejects_mismatch(tmp_path, monkeypatch):
    prompter = _CodeSequence(_PASSWORD, "different password")
    monkeypatch.setattr(cli_main, "CliPrompter", lambda: prompter)

    result = runner.invoke(app, ["password", "set"])

    assert result.exit_code == 1
    assert password.is_enrolled() is False
    assert _PASSWORD not in result.output


def test_password_set_force_requires_current_password(tmp_path, monkeypatch):
    password.enroll(_PASSWORD)
    rotated = "new correct horse battery staple"
    prompter = _CodeSequence(_PASSWORD, rotated, rotated)
    monkeypatch.setattr(cli_main, "CliPrompter", lambda: prompter)

    result = runner.invoke(app, ["password", "set", "--force"])

    assert result.exit_code == 0, result.output
    assert password.verify(rotated) is True
    assert _PASSWORD not in result.output
