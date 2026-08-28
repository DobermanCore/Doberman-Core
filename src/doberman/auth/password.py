"""Local password possession-factor verification (C1, slice 2).

The password tier proves a *human* is present for a permanent policy weakening
when TOTP is not enrolled. Doberman stores only a salted PBKDF2-SHA256 hash,
never the password itself, so the out-of-band factor cannot be recovered from
the enrollment file.

Secret handling (SECURITY):

* Location is ``$DOBERMAN_PASSWORD_FILE`` if set, else a per-user config dir
  (``%LOCALAPPDATA%`` / ``$XDG_CONFIG_HOME`` / ``~/.config``) — outside any repo.
* Written ``0600`` in a ``0700`` dir using restrictive permissions from file
  creation, mirroring :mod:`doberman.auth.totp`.
* Verification uses a salted 600,000-iteration PBKDF2-SHA256 hash and
  :func:`hmac.compare_digest` for constant-time comparison.
* Verification is rate-limited: too many consecutive failures lock further
  attempts until a reset, blunting online guessing.
* If a password is **not enrolled**, :func:`verify` returns ``False`` — there
  is no confirm-only or no-auth fallback. Any malformed state fails closed.

Passwords and stored hashes are never logged or returned.
"""

import hashlib
import hmac
import os
from pathlib import Path

#: Env var overriding the password-hash file location (tests inject a temp path).
PASSWORD_FILE_ENV = "DOBERMAN_PASSWORD_FILE"  # noqa: S105 — env-var name, not a secret

_ALGORITHM = "pbkdf2_sha256"
_PBKDF2_ITERATIONS = 600_000
_SALT_BYTES = 16
_HASH_BYTES = 32
_MIN_PASSWORD_LENGTH = 8

#: Consecutive failed verifications before further attempts are locked out
#: (until :func:`reset_attempts` or a successful verify).
_MAX_CONSECUTIVE_FAILURES = 5

#: Per-password-file consecutive-failure counters (isolated by path so
#: distinct enrollments — and distinct tests — never share rate-limit state).
_failures: dict[str, int] = {}


def _default_secret_path() -> Path:
    """Per-user password-hash path OUTSIDE any repository (never committed)."""
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.path.join(
            os.path.expanduser("~"), "AppData", "Local"
        )
    else:
        base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return Path(base) / "doberman" / "password.hash"


def _secret_path() -> Path:
    override = os.environ.get(PASSWORD_FILE_ENV)
    return Path(override) if override else _default_secret_path()


def resolve_path() -> Path:
    """Resolve the active password enrollment file, including env overrides."""
    return _secret_path()


def _read_record() -> tuple[int, bytes, bytes] | None:
    """Return ``(iterations, salt, hash)`` or ``None`` if absent/malformed."""
    path = _secret_path()
    try:
        if not path.exists():
            return None
        parts = path.read_text(encoding="utf-8").strip().split("$")
        if len(parts) != 4 or parts[0] != _ALGORITHM:
            return None
        iterations = int(parts[1])
        salt = bytes.fromhex(parts[2])
        stored_hash = bytes.fromhex(parts[3])
        if iterations <= 0 or len(salt) != _SALT_BYTES or len(stored_hash) != _HASH_BYTES:
            return None
        return iterations, salt, stored_hash
    except (OSError, UnicodeError, ValueError):
        return None


def is_enrolled() -> bool:
    """True only when a parseable password-hash record is present."""
    return _read_record() is not None


def enroll(
    secret: str,
    *,
    force: bool = False,
    current_password: str | None = None,
) -> None:
    """Hash and store ``secret``, guarding any rotation with the old password.

    Refuses to overwrite an existing file unless ``force=True`` and
    ``current_password`` verifies against that existing record. The new password
    must contain at least eight characters. Neither password nor hash is returned.
    """
    if not isinstance(secret, str) or len(secret) < _MIN_PASSWORD_LENGTH:
        raise ValueError("password must be at least 8 characters")

    path = _secret_path()
    if path.exists():
        if not force:
            raise RuntimeError(
                "password is already enrolled; pass force=True to deliberately rotate it"
            )
        if current_password is None or not verify(current_password):
            raise RuntimeError("a valid current password is required to rotate the password")

    salt = os.urandom(_SALT_BYTES)
    derived = hashlib.pbkdf2_hmac(
        "sha256",
        secret.encode("utf-8"),
        salt,
        _PBKDF2_ITERATIONS,
    )
    record = f"{_ALGORITHM}${_PBKDF2_ITERATIONS}${salt.hex()}${derived.hex()}"

    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(str(path), flags, 0o600)
    try:
        os.write(fd, record.encode("ascii"))
    finally:
        os.close(fd)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass

    _failures.pop(str(path), None)


def reset_attempts() -> None:
    """Clear the consecutive-failure counter for the active password file."""
    _failures.pop(str(_secret_path()), None)


def verify(secret: str) -> bool:
    """Verify ``secret`` against the stored hash without ever raising.

    Fails closed: not enrolled, malformed input/storage, KDF errors, or a
    rate-limit lockout all return ``False``. A successful verification resets
    the counter; each failed comparison or verification error increments it.
    """
    try:
        record = _read_record()
    except Exception:  # noqa: BLE001 — storage/read errors deny, never escape
        return False
    if record is None:
        return False

    key = str(_secret_path())
    if _failures.get(key, 0) >= _MAX_CONSECUTIVE_FAILURES:
        return False

    try:
        if not isinstance(secret, str):
            raise TypeError("password must be text")
        iterations, salt, stored_hash = record
        candidate_hash = hashlib.pbkdf2_hmac(
            "sha256",
            secret.encode("utf-8"),
            salt,
            iterations,
        )
        ok = hmac.compare_digest(candidate_hash, stored_hash)
    except Exception:  # noqa: BLE001 — any verify error is failed auth, never a pass
        ok = False

    if ok:
        _failures.pop(key, None)
    else:
        _failures[key] = _failures.get(key, 0) + 1
    return ok
