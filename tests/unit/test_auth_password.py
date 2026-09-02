"""C1 slice 2 — local password possession-factor enrollment and verification."""

import hashlib
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


def test_lockout_persists_to_disk(isolated_password_hash):
    """No in-memory counter left: the lockout survives on the lockout file
    alone, and the module carries no ``_failures`` dict any more."""
    assert not hasattr(password, "_failures")

    password.enroll(_PASSWORD)
    for _ in range(5):
        assert password.verify("this is the wrong password") is False

    lockout_path = isolated_password_hash.with_name(isolated_password_hash.name + ".lockout")
    assert lockout_path.exists()
    assert password.verify(_PASSWORD) is False


def test_cooldown_elapsed_allows_retry_and_clears_the_file(monkeypatch, isolated_password_hash):
    t0 = 1_700_000_000
    monkeypatch.setattr(password, "_now", lambda: t0)
    password.enroll(_PASSWORD)
    for _ in range(5):
        assert password.verify("this is the wrong password") is False

    lockout_path = isolated_password_hash.with_name(isolated_password_hash.name + ".lockout")
    assert lockout_path.exists()

    monkeypatch.setattr(password, "_now", lambda: t0 + 15 * 60 + 1)
    assert password.verify(_PASSWORD) is True
    assert not lockout_path.exists()


def test_denied_attempt_during_lockout_does_not_extend_it_or_run_the_kdf(
    monkeypatch, isolated_password_hash
):
    t0 = 1_700_000_000
    monkeypatch.setattr(password, "_now", lambda: t0)
    password.enroll(_PASSWORD)
    for _ in range(5):
        assert password.verify("this is the wrong password") is False

    lockout_path = isolated_password_hash.with_name(isolated_password_hash.name + ".lockout")
    before = lockout_path.read_text(encoding="utf-8")

    calls: list[int] = []
    real_pbkdf2_hmac = hashlib.pbkdf2_hmac

    def _counting(*args, **kwargs):
        calls.append(1)
        return real_pbkdf2_hmac(*args, **kwargs)

    monkeypatch.setattr(hashlib, "pbkdf2_hmac", _counting)
    monkeypatch.setattr(password, "_now", lambda: t0 + 60)  # still within the cooldown

    assert password.verify(_PASSWORD) is False  # correct password, still denied
    assert calls == []  # the KDF never ran while locked out
    after = lockout_path.read_text(encoding="utf-8")
    assert before == after  # no rewrite: the window did not move


def test_reset_attempts_clears_the_lockout_file(isolated_password_hash):
    lockout_path = isolated_password_hash.with_name(isolated_password_hash.name + ".lockout")

    password.enroll(_PASSWORD)
    for _ in range(5):
        assert password.verify("this is the wrong password") is False
    assert lockout_path.exists()

    password.reset_attempts()
    assert not lockout_path.exists()
    assert password.verify(_PASSWORD) is True


def test_forced_enroll_clears_the_lockout_file(monkeypatch, isolated_password_hash):
    lockout_path = isolated_password_hash.with_name(isolated_password_hash.name + ".lockout")
    t0 = 1_700_000_000
    monkeypatch.setattr(password, "_now", lambda: t0)
    password.enroll(_PASSWORD)
    for _ in range(4):  # stay under the lockout threshold so the rotation proof below verifies
        assert password.verify("this is the wrong password") is False
    assert lockout_path.exists()

    password.enroll(_ROTATED_PASSWORD, force=True, current_password=_PASSWORD)
    assert not lockout_path.exists()
    assert password.verify(_ROTATED_PASSWORD) is True


def test_corrupt_lockout_file_fails_closed_then_recovers(monkeypatch, isolated_password_hash):
    t0 = 1_700_000_000
    password.enroll(_PASSWORD)
    lockout_path = isolated_password_hash.with_name(isolated_password_hash.name + ".lockout")
    lockout_path.parent.mkdir(parents=True, exist_ok=True)
    lockout_path.write_text("not json{{{", encoding="utf-8")

    monkeypatch.setattr(password, "_now", lambda: t0)
    assert password.verify(_PASSWORD) is False  # corrupt -> treated as locked now

    monkeypatch.setattr(password, "_now", lambda: t0 + 15 * 60 + 1)
    assert password.verify(_PASSWORD) is True  # bounded: recovers after the cooldown


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


def test_attempt_is_counted_before_the_kdf_runs(isolated_password_hash, monkeypatch):
    password.enroll("correct-horse")
    lockout = password._lockout_path(isolated_password_hash)

    def kdf_explodes(*args, **kwargs):
        raise RuntimeError("kdf crashed mid-verify")

    monkeypatch.setattr(password.hashlib, "pbkdf2_hmac", kdf_explodes)
    assert password.verify("correct-horse") is False
    # The attempt landed on disk even though the KDF never finished.
    assert password._load_lockout(lockout, now=password._now())[0] == 1


def test_unrecordable_attempt_is_denied(isolated_password_hash, monkeypatch):
    password.enroll("correct-horse")
    monkeypatch.setattr(password, "_save_lockout", lambda *a, **k: False)
    # Even the right password is refused when the attempt cannot be counted.
    assert password.verify("correct-horse") is False
