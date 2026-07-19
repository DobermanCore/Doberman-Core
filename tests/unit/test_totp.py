"""Slice 7.2 — TOTP enrollment and verification (deterministic, no real time)."""

import pyotp
import pytest

from doberman.auth import totp

#: A fixed reference time (epoch seconds) so code generation is deterministic.
_T0 = 1_700_000_000


def _current_code(at: int = _T0) -> str:
    secret = totp._read_secret()
    assert secret is not None
    return pyotp.TOTP(secret).at(at)


def test_not_enrolled_verify_fails_closed():
    assert totp.is_enrolled() is False
    assert totp.verify("000000") is False  # no enrollment → no no-auth fallback


def test_enroll_then_verify_current_code():
    uri = totp.enroll()
    assert uri.startswith("otpauth://")
    assert totp.is_enrolled() is True
    assert totp.verify(_current_code(), at=_T0) is True


def test_skew_window_accepts_adjacent_step_rejects_far():
    totp.enroll()
    code = _current_code(_T0)
    assert totp.verify(code, at=_T0 + 30) is True  # ±1 step tolerated
    assert totp.verify(code, at=_T0 - 30) is True
    totp.reset_attempts()
    assert totp.verify(code, at=_T0 + 90) is False  # 3 steps away → rejected


def test_wrong_code_rejected():
    totp.enroll()
    assert totp.verify("000000", at=_T0) is False


def test_rate_limited_after_repeated_failures():
    totp.enroll()
    for _ in range(5):
        assert totp.verify("000000", at=_T0) is False
    # Even a CORRECT code is now refused until the counter is reset.
    assert totp.verify(_current_code(_T0), at=_T0) is False
    totp.reset_attempts()
    assert totp.verify(_current_code(_T0), at=_T0) is True


def test_enroll_refuses_silent_overwrite():
    totp.enroll()
    first = totp._read_secret()
    with pytest.raises(RuntimeError):
        totp.enroll()
    assert totp._read_secret() == first  # unchanged


def test_enroll_rotation_requires_current_code():
    totp.enroll()
    first = totp._read_secret()
    with pytest.raises(RuntimeError, match="current 2FA code"):
        totp.enroll(force=True)
    assert totp._read_secret() == first


def test_enroll_rotation_rejects_wrong_current_code():
    totp.enroll()
    first = totp._read_secret()
    with pytest.raises(RuntimeError, match="current 2FA code"):
        totp.enroll(force=True, current_code="not-a-code")
    assert totp._read_secret() == first


def test_enroll_rotation_accepts_current_code_without_logging_credentials(caplog):
    caplog.set_level("DEBUG")
    first_uri = totp.enroll()
    first = totp._read_secret()
    assert first is not None
    current_code = pyotp.TOTP(first).now()

    rotated_uri = totp.enroll(force=True, current_code=current_code)
    rotated = totp._read_secret()

    assert rotated_uri.startswith("otpauth://")
    assert rotated_uri != first_uri
    assert rotated is not None and rotated != first
    for sensitive_value in (first, rotated, current_code, first_uri, rotated_uri):
        assert sensitive_value not in caplog.text


def test_enroll_rotation_wrong_code_shares_rate_limiter():
    """H5a: rotation's current_code proof must route through verify()'s
    _failures lockout, not a direct un-rate-limited pyotp check."""
    totp.enroll()
    correct = _current_code(_T0)
    for _ in range(5):
        with pytest.raises(RuntimeError, match="current 2FA code"):
            totp.enroll(force=True, current_code="000000")
    # 5 wrong rotation attempts tripped the same limiter a normal verify() uses.
    assert totp.verify(correct, at=_T0) is False


def test_enroll_rotation_correct_code_succeeds_and_resets_counter():
    # enroll()'s rotation proof checks the CURRENT wall clock (no `at` injection
    # point), so prove it with `.now()` like the existing rotation test does.
    totp.enroll()
    first = totp._read_secret()
    correct = pyotp.TOTP(first).now()

    rotated_uri = totp.enroll(force=True, current_code=correct)

    assert rotated_uri.startswith("otpauth://")
    rotated = totp._read_secret()
    assert rotated is not None and rotated != first
    # Counter reset by the successful verify(): a fresh wrong attempt is just one failure.
    assert totp.verify("000000", at=_T0) is False
    assert totp.verify(pyotp.TOTP(rotated).at(_T0), at=_T0) is True


def test_enroll_rotation_blocked_while_locked_out():
    totp.enroll()
    first = totp._read_secret()
    correct = pyotp.TOTP(first).now()
    for _ in range(5):
        assert totp.verify("000000", at=_T0) is False
    # Locked out: even the CORRECT current code must not rotate the secret.
    with pytest.raises(RuntimeError, match="current 2FA code"):
        totp.enroll(force=True, current_code=correct)
    assert totp._read_secret() == first


def test_secret_file_is_owner_only(isolated_totp_secret):
    import os
    import stat

    totp.enroll()
    if os.name != "nt":  # POSIX permission bits are meaningful
        mode = stat.S_IMODE(isolated_totp_secret.stat().st_mode)
        assert mode == 0o600
