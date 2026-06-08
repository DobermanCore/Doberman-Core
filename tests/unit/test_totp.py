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
    totp.enroll(force=True)
    assert totp._read_secret() != first  # rotated only with force


def test_secret_file_is_owner_only(isolated_totp_secret):
    import os
    import stat

    totp.enroll()
    if os.name != "nt":  # POSIX permission bits are meaningful
        mode = stat.S_IMODE(isolated_totp_secret.stat().st_mode)
        assert mode == 0o600
