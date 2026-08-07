"""Clearing the TOTP lockout early - gated on the password, never on 2FA.

The locked-out factor cannot verify itself (verify() denies during a lockout
regardless of code correctness), so the reset is proven with the password. Every
test pins that gate: without a valid password the lockout survives, and with no
password enrolled the command refuses instead of falling back to 2FA.
"""

import pyotp
from typer.testing import CliRunner

from doberman.auth import password, totp
from doberman.cli.main import app

runner = CliRunner()

_PASSWORD = "correct horse battery staple"  # noqa: S105 — synthetic test credential
_T0 = 1_700_000_000


def _current_code() -> str:
    secret = totp._read_secret()
    assert secret is not None
    return pyotp.TOTP(secret).now()


def _trip_lockout() -> None:
    """Five wrong codes trip the persisted rate-limit lockout."""
    for _ in range(5):
        assert totp.verify("000000", at=_T0) is False


def test_reset_lockout_clears_after_correct_password():
    totp.enroll()
    password.enroll(_PASSWORD)
    _trip_lockout()
    assert totp.verify(_current_code()) is False  # locked out: correct code denied

    result = runner.invoke(app, ["2fa", "reset-lockout"], input=f"{_PASSWORD}\n")

    assert result.exit_code == 0, result.output
    assert totp.verify(_current_code()) is True  # lockout cleared, code verifies


def test_reset_lockout_rejects_wrong_password():
    totp.enroll()
    password.enroll(_PASSWORD)
    _trip_lockout()

    result = runner.invoke(app, ["2fa", "reset-lockout"], input="wrong-password\n")

    assert result.exit_code == 1
    assert "incorrect password" in result.stderr
    assert totp.verify(_current_code()) is False  # still locked out


def test_reset_lockout_errors_when_2fa_not_enrolled():
    password.enroll(_PASSWORD)

    result = runner.invoke(app, ["2fa", "reset-lockout"])

    assert result.exit_code == 1
    assert "not enrolled" in result.stderr


def test_reset_lockout_refuses_when_no_password_enrolled():
    totp.enroll()
    assert password.is_enrolled() is False  # isolated by the autouse fixture
    _trip_lockout()

    result = runner.invoke(app, ["2fa", "reset-lockout"])

    assert result.exit_code == 1
    # Never falls through to a 2FA gate; the message names the password path.
    assert "password" in result.stderr.lower()
    assert totp.verify(_current_code()) is False  # untouched, still locked out


def test_reset_lockout_never_echoes_the_password():
    totp.enroll()
    password.enroll(_PASSWORD)
    _trip_lockout()

    result = runner.invoke(app, ["2fa", "reset-lockout"], input=f"{_PASSWORD}\n")

    assert _PASSWORD not in result.output
