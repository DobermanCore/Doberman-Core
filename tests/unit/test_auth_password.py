"""C1 slice 2 — local password possession-factor enrollment and verification."""

import os
import stat

import pytest

from doberman.auth import password

_PASSWORD = "correct horse battery staple"  # noqa: S105 — synthetic test credential
_ROTATED_PASSWORD = "troubador batteries corrected"  # noqa: S105 — synthetic test credential


def test_enroll_then_verify_password():
    password.enroll(_PASSWORD)

    assert password.is_enrolled() is True
    assert password.verify(_PASSWORD) is True


def test_wrong_password_is_rejected():
    password.enroll(_PASSWORD)

    assert password.verify("this is the wrong password") is False


def test_not_enrolled_fails_closed():
    assert password.is_enrolled() is False
    assert password.verify(_PASSWORD) is False


def test_malformed_hash_is_not_enrolled_and_verify_fails_closed(isolated_password_hash):
    isolated_password_hash.write_text("not-a-password-hash", encoding="utf-8")

    assert password.is_enrolled() is False
    assert password.verify(_PASSWORD) is False


def test_rate_limited_after_five_consecutive_failures():
    password.enroll(_PASSWORD)
    for _ in range(5):
        assert password.verify("this is the wrong password") is False

    assert password.verify(_PASSWORD) is False
    password.reset_attempts()
    assert password.verify(_PASSWORD) is True


def test_enroll_refuses_overwrite_without_force(isolated_password_hash):
    password.enroll(_PASSWORD)
    original = isolated_password_hash.read_text(encoding="utf-8")

    with pytest.raises(RuntimeError):
        password.enroll(_ROTATED_PASSWORD)

    assert isolated_password_hash.read_text(encoding="utf-8") == original


def test_rotation_refuses_wrong_current_password(isolated_password_hash):
    password.enroll(_PASSWORD)
    original = isolated_password_hash.read_text(encoding="utf-8")

    with pytest.raises(RuntimeError, match="current password"):
        password.enroll(
            _ROTATED_PASSWORD,
            force=True,
            current_password="this is the wrong password",  # noqa: S106 — synthetic
        )

    assert isolated_password_hash.read_text(encoding="utf-8") == original


def test_rotation_accepts_correct_current_password():
    password.enroll(_PASSWORD)

    password.enroll(_ROTATED_PASSWORD, force=True, current_password=_PASSWORD)

    assert password.verify(_ROTATED_PASSWORD) is True
    assert password.verify(_PASSWORD) is False


@pytest.mark.parametrize("secret", ["", "short", "1234567"])
def test_enroll_rejects_empty_or_too_short_password(secret):
    with pytest.raises(ValueError, match="at least 8"):
        password.enroll(secret)


def test_stored_file_contains_only_salted_hash(isolated_password_hash):
    password.enroll(_PASSWORD)

    stored = isolated_password_hash.read_text(encoding="utf-8")
    assert _PASSWORD not in stored
    assert stored.startswith("pbkdf2_sha256$600000$")
    assert len(stored.split("$")) == 4


@pytest.mark.parametrize("candidate", [None, object(), b"bytes", ["not", "a", "password"]])
def test_verify_never_raises_for_non_string_input(candidate):
    password.enroll(_PASSWORD)

    assert password.verify(candidate) is False


def test_verify_fails_closed_when_reading_the_hash_raises(monkeypatch):
    def _boom():
        raise RuntimeError("storage failure")

    monkeypatch.setattr(password, "_read_record", _boom)

    assert password.verify(_PASSWORD) is False


def test_password_hash_file_is_owner_only(isolated_password_hash):
    password.enroll(_PASSWORD)

    if os.name != "nt":
        assert stat.S_IMODE(isolated_password_hash.stat().st_mode) == 0o600
