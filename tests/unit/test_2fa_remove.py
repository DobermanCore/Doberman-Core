"""Removing the TOTP factor — a weakening, so it is gated on the current code.

Dropping 2FA is the one auth operation that *reduces* protection, so every test
here pins the fail-closed direction: without a valid current code (or while the
rate limiter is tripped) the enrollment must survive untouched.
"""

import pyotp
import pytest
from typer.testing import CliRunner

from doberman.auth import password, totp
from doberman.cli.main import app

runner = CliRunner()

#: A fixed reference time (epoch seconds) for the rate-limiter probes.
_T0 = 1_700_000_000


def _current_code() -> str:
    """A code for the live enrollment on the real clock.

    ``unenroll`` proves possession through ``verify()`` with no ``at`` injection
    point (same as rotation in ``enroll``), so the proof must use ``.now()``.
    """
    secret = totp._read_secret()
    assert secret is not None
    return pyotp.TOTP(secret).now()


# --- totp.unenroll ---------------------------------------------------------


def test_unenroll_not_enrolled_raises():
    with pytest.raises(RuntimeError, match="not enrolled"):
        totp.unenroll(current_code="000000")


def test_unenroll_removes_secret_and_lockout_state(isolated_totp_secret):
    totp.enroll()
    lockout = totp._lockout_path(isolated_totp_secret)
    totp._save_lockout(lockout, 3, 1.0)
    assert lockout.exists()

    totp.unenroll(current_code=_current_code())

    assert totp.is_enrolled() is False
    assert isolated_totp_secret.exists() is False
    # No orphaned lockout: a stale file would otherwise greet a re-enrollment.
    assert lockout.exists() is False


def test_unenroll_wrong_code_keeps_enrollment():
    totp.enroll()
    before = totp._read_secret()

    with pytest.raises(RuntimeError, match="current 2FA code"):
        totp.unenroll(current_code="000000")

    assert totp.is_enrolled() is True
    assert totp._read_secret() == before


def test_unenroll_wrong_code_shares_rate_limiter():
    """Removal's proof must route through verify()'s persisted lockout, not a
    direct un-rate-limited pyotp check — symmetric with rotation."""
    totp.enroll()
    correct = _current_code()
    for _ in range(5):
        with pytest.raises(RuntimeError, match="current 2FA code"):
            totp.unenroll(current_code="000000")

    assert totp.verify(correct) is False


def test_unenroll_blocked_while_locked_out():
    totp.enroll()
    correct = _current_code()
    for _ in range(5):
        assert totp.verify("000000", at=_T0) is False

    # Locked out: even the CORRECT code must not drop the factor.
    with pytest.raises(RuntimeError, match="current 2FA code"):
        totp.unenroll(current_code=correct)

    assert totp.is_enrolled() is True


def test_unenroll_never_logs_the_code_or_secret(caplog):
    totp.enroll()
    secret = totp._read_secret()
    code = _current_code()

    with caplog.at_level(0):
        totp.unenroll(current_code=code)

    logged = "\n".join(record.getMessage() for record in caplog.records)
    assert secret not in logged
    assert code not in logged


# --- doberman 2fa remove ---------------------------------------------------


def test_cli_remove_unenrolls_after_confirmation_and_code():
    totp.enroll()

    result = runner.invoke(app, ["2fa", "remove"], input=f"y\n{_current_code()}\n")

    assert result.exit_code == 0, result.output
    assert totp.is_enrolled() is False


def test_cli_remove_aborts_on_declined_confirmation():
    totp.enroll()

    result = runner.invoke(app, ["2fa", "remove"], input="n\n")

    assert result.exit_code == 1
    assert totp.is_enrolled() is True


def test_cli_remove_rejects_a_wrong_code():
    totp.enroll()

    result = runner.invoke(app, ["2fa", "remove"], input="y\nnot-a-code\n")

    assert result.exit_code == 1
    assert "current 2FA code" in result.stderr
    assert totp.is_enrolled() is True


def test_cli_remove_errors_when_not_enrolled():
    result = runner.invoke(app, ["2fa", "remove"])

    assert result.exit_code == 1
    assert "not enrolled" in result.stderr


def test_cli_remove_warns_when_no_possession_factor_remains():
    totp.enroll()
    assert password.is_enrolled() is False  # isolated by the autouse fixture

    result = runner.invoke(app, ["2fa", "remove"], input=f"y\n{_current_code()}\n")

    assert result.exit_code == 0
    # Removing the last factor makes every weakening fail closed — say so, and
    # name the way back.
    assert "doberman password set" in result.stderr


def test_cli_remove_never_echoes_the_secret():
    totp.enroll()
    secret = totp._read_secret()

    result = runner.invoke(app, ["2fa", "remove"], input=f"y\n{_current_code()}\n")

    assert secret is not None
    assert secret not in result.output
