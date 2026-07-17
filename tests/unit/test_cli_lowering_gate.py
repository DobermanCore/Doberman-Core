"""C1 slice 2 — CLI-level coverage for the mode/prefs mandatory-2FA lowering
gate: ``doberman mode`` and ``doberman prefs`` now route through
:func:`doberman.policy.drift.apply_change` / :func:`apply_preferences_change`
instead of the old frictionless (mode, ``log_change``) / entirely-ungated
(prefs) paths. Raising stays frictionless (never prompts); lowering requires a
possession-factor 2FA code with **no confirm-only escape hatch** — unlike
``doberman enforcement``'s deliberate safety valve for unenrolled users, mode
and prefs are not the safety valve, so an unenrolled user cannot lower them.
"""

import pyotp
from typer.testing import CliRunner

from doberman.auth import totp
from doberman.cli.main import app
from doberman.config import load_mode, load_preferences

runner = CliRunner()


class _Decline:
    def confirm(self, message):
        return False

    def read_code(self, message):  # pragma: no cover -- never reached after a decline
        raise AssertionError("read_code must not be reached after a declined confirm")


class _Boom:
    """Any prompt is a failure -- proves a raise is never gated."""

    def confirm(self, message):
        raise AssertionError("a raise must not prompt")

    def read_code(self, message):
        raise AssertionError("a raise must not prompt")


class _Approve:
    """Present operator: confirms and supplies a currently-valid 2FA code."""

    def __init__(self, code):
        self._code = code

    def confirm(self, message):
        return True

    def read_code(self, message):
        return self._code


def _use_prompter(monkeypatch, prompter_factory):
    # apply_change / apply_preferences_change lazily do
    # `from doberman.auth.provider import CliPrompter` only on the weaken path,
    # so patch the name it constructs there (same pattern as test_cli_enforcement.py).
    monkeypatch.setattr("doberman.auth.provider.CliPrompter", prompter_factory)


def _enrolled_code() -> str:
    totp.enroll()
    return pyotp.TOTP(totp._read_secret()).now()


# --- mode --------------------------------------------------------------------


def test_mode_lowering_with_valid_2fa_is_approved_and_persisted(tmp_path, monkeypatch):
    root = str(tmp_path)
    code = _enrolled_code()
    _use_prompter(monkeypatch, lambda: _Approve(code))
    # Default is "balanced"; "light" is a downgrade.
    result = runner.invoke(app, ["mode", "light", "--path", root])
    assert result.exit_code == 0, result.output
    assert "mode set to light" in result.output
    assert load_mode(root) == "light"


def test_mode_lowering_not_enrolled_is_denied_and_unchanged(tmp_path, monkeypatch):
    root = str(tmp_path)
    _use_prompter(monkeypatch, _Decline)  # not enrolled; a decline still proves fail-closed
    result = runner.invoke(app, ["mode", "light", "--path", root])
    assert result.exit_code == 1
    assert "denied" in result.output.lower()
    assert load_mode(root) == "balanced"


def test_mode_raising_never_prompts_and_applies(tmp_path, monkeypatch):
    root = str(tmp_path)
    _use_prompter(monkeypatch, _Boom)
    result = runner.invoke(app, ["mode", "strict", "--path", root])
    assert result.exit_code == 0, result.output
    assert "mode set to strict" in result.output
    assert load_mode(root) == "strict"


# --- prefs ---------------------------------------------------------------------


def test_prefs_lowering_without_2fa_is_denied_and_unchanged(tmp_path, monkeypatch):
    root = str(tmp_path)
    _use_prompter(monkeypatch, _Decline)
    result = runner.invoke(app, ["prefs", "confidentiality", "0.1", "--path", root])
    assert result.exit_code == 1
    assert "denied" in result.output.lower()
    assert load_preferences(root).confidentiality == 0.5  # balanced preset default, unchanged


def test_prefs_lowering_with_valid_2fa_is_approved_and_persisted(tmp_path, monkeypatch):
    root = str(tmp_path)
    code = _enrolled_code()
    _use_prompter(monkeypatch, lambda: _Approve(code))
    result = runner.invoke(app, ["prefs", "confidentiality", "0.1", "--path", root])
    assert result.exit_code == 0, result.output
    assert "confidentiality set to 0.10" in result.output
    assert load_preferences(root).confidentiality == 0.1


def test_prefs_raising_never_prompts_and_applies(tmp_path, monkeypatch):
    root = str(tmp_path)
    _use_prompter(monkeypatch, _Boom)
    result = runner.invoke(app, ["prefs", "confidentiality", "0.9", "--path", root])
    assert result.exit_code == 0, result.output
    assert "confidentiality set to 0.90" in result.output
    assert load_preferences(root).confidentiality == 0.9
