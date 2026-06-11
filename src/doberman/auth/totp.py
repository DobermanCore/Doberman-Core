"""TOTP-based two-factor verification (Feature 7, slice 7.2).

The 2FA tier proves a *human* is present for a high-risk action. We use standard
TOTP (RFC 6238) via ``pyotp`` so any authenticator app works. The shared secret
is generated once at enrollment and stored locally, **never** in the repo, a
log, or any returned value — exactly like the HMAC fingerprint key
(:mod:`doberman.storage.fingerprint`), and for the same reason.

Secret handling (SECURITY):

* Location is ``$DOBERMAN_TOTP_FILE`` if set, else a per-user config dir
  (``%LOCALAPPDATA%`` / ``$XDG_CONFIG_HOME`` / ``~/.config``) — outside any repo.
* Written ``0600`` in a ``0700`` dir; the directory and file mirror the
  fingerprint key's restrictive permissions.
* Verification is **constant-time** (``pyotp`` uses ``hmac.compare_digest``),
  allows a ±1 step skew, and is **rate-limited**: too many consecutive failures
  locks further attempts until a reset, blunting online brute force.
* If 2FA is **not enrolled**, :func:`verify` returns ``False`` — there is no
  "no-auth fallback". A challenge that needs 2FA fails closed when none exists.

Codes and the secret are never logged. The provisioning URI returned by
:func:`enroll` necessarily embeds the secret; it is shown to the enrolling user
once (their own machine, their own secret) and must not be logged or persisted
by callers.
"""

import os
from pathlib import Path

import pyotp

#: Env var overriding the secret-file location (tests inject a temp path).
TOTP_FILE_ENV = "DOBERMAN_TOTP_FILE"

#: Accept the current code plus one step on either side (±30s) for clock skew.
_VALID_WINDOW = 1

#: Consecutive failed verifications before further attempts are locked out
#: (until :func:`reset_attempts` or a successful verify). A deliberately small
#: bound — online TOTP guessing needs many tries to matter.
_MAX_CONSECUTIVE_FAILURES = 5

#: Per-secret-file consecutive-failure counters (isolated by path so distinct
#: enrollments — and distinct tests — never share rate-limit state).
_failures: dict[str, int] = {}


def _default_secret_path() -> Path:
    """Per-user secret path OUTSIDE any repository (never committed)."""
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.path.join(
            os.path.expanduser("~"), "AppData", "Local"
        )
    else:
        base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return Path(base) / "doberman" / "totp.secret"


def _secret_path() -> Path:
    override = os.environ.get(TOTP_FILE_ENV)
    return Path(override) if override else _default_secret_path()


def _read_secret() -> str | None:
    """Return the stored base32 secret, or ``None`` if not enrolled/unreadable."""
    path = _secret_path()
    try:
        if not path.exists():
            return None
        secret = path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return secret or None


def is_enrolled() -> bool:
    """True if a TOTP secret is present and readable."""
    return _read_secret() is not None


def enroll(*, issuer: str = "Doberman", account: str = "local", force: bool = False) -> str:
    """Generate and store a new TOTP secret; return its provisioning URI.

    Refuses to overwrite an existing enrollment unless ``force=True`` (so a
    second ``2fa setup`` cannot silently rotate the secret out from under an
    authenticator app). The returned URI embeds the secret for QR/manual entry
    and MUST NOT be logged by the caller.
    """
    path = _secret_path()
    if path.exists() and not force:
        raise RuntimeError(
            "TOTP is already enrolled; pass force=True to deliberately rotate the secret"
        )

    secret = pyotp.random_base32()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Write the secret with restrictive perms from creation. base32 text has no
    # newline/control bytes, so text-mode translation cannot corrupt it.
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(str(path), flags, 0o600)
    try:
        os.write(fd, secret.encode("ascii"))
    finally:
        os.close(fd)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass

    _failures.pop(str(path), None)
    return pyotp.TOTP(secret).provisioning_uri(name=account, issuer_name=issuer)


def reset_attempts() -> None:
    """Clear the consecutive-failure counter for the active secret file."""
    _failures.pop(str(_secret_path()), None)


def verify(code: str, *, at: int | None = None) -> bool:
    """Verify a TOTP ``code``; return ``True`` only on a valid, in-window code.

    Fails closed: not enrolled, a non-numeric/garbage code, or a rate-limit
    lockout all return ``False`` without ever raising into the decision path.
    ``at`` (integer epoch seconds) is injectable so tests are deterministic;
    production uses the current time. A successful verify resets the counter.
    """
    secret = _read_secret()
    if secret is None:
        return False

    key = str(_secret_path())
    if _failures.get(key, 0) >= _MAX_CONSECUTIVE_FAILURES:
        return False

    try:
        ok = pyotp.TOTP(secret).verify(str(code), valid_window=_VALID_WINDOW, for_time=at)
    except Exception:  # noqa: BLE001 — any verify error is a failed auth, never a pass
        ok = False

    if ok:
        _failures.pop(key, None)
    else:
        _failures[key] = _failures.get(key, 0) + 1
    return ok
