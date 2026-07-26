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
  locks further attempts until a cooldown TTL elapses (or a reset), blunting
  online brute force. The lockout state is **persisted to disk** alongside the
  secret (H5), so it survives a process restart — a fresh process (e.g. a
  per-invocation host-hook adapter) can no longer bypass it — while the
  cooldown bounds the lockout instead of leaving it permanent in a
  long-running process (W2).
* If 2FA is **not enrolled**, :func:`verify` returns ``False`` — there is no
  "no-auth fallback". A challenge that needs 2FA fails closed when none exists.

Codes and the secret are never logged. The provisioning URI returned by
:func:`enroll` necessarily embeds the secret; it is shown to the enrolling user
once (their own machine, their own secret) and must not be logged or persisted
by callers.
"""

import json
import os
import tempfile
import time
from pathlib import Path

import pyotp

#: Env var overriding the secret-file location (tests inject a temp path).
TOTP_FILE_ENV = "DOBERMAN_TOTP_FILE"

#: Accept the current code plus one step on either side (±30s) for clock skew.
_VALID_WINDOW = 1

#: Consecutive failed verifications before further attempts are locked out
#: (until the cooldown TTL elapses or :func:`reset_attempts` runs). A
#: deliberately small bound — online TOTP guessing needs many tries to matter.
_MAX_CONSECUTIVE_FAILURES = 5

#: How long a lockout persists after the last failure, in seconds, before the
#: next attempt is allowed to proceed again. Bounds the "permanent softlock"
#: (W2) without weakening the guard: a locked-out attacker still has to wait
#: out the full window, and a denied attempt during the window never extends
#: it (see :func:`verify`).
_LOCKOUT_COOLDOWN_SECONDS = 15 * 60


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


def _lockout_path(secret_path: Path) -> Path:
    """Lockout-state file colocated with the secret (same dir, same isolation).

    Sibling of the secret file rather than a new env var, so it inherits the
    secret's per-user/per-test location automatically (including
    ``$DOBERMAN_TOTP_FILE`` overrides in tests).
    """
    return secret_path.with_name(secret_path.name + ".lockout")


def _now() -> float:
    """Epoch-seconds time source. A module-level seam tests monkeypatch so
    cooldown expiry never depends on real sleeps."""
    return time.time()


def _load_lockout(path: Path) -> tuple[int, float]:
    """Return persisted ``(consecutive_failures, last_failure_time)``.

    No file yet (never failed, or a fresh enrollment) → ``(0, 0.0)``, i.e. not
    locked. A present-but-unreadable/corrupt file fails **closed**: it is
    treated as a brand-new lockout anchored to *this* moment and immediately
    rewritten as clean state (so a repeated read doesn't keep re-anchoring
    "now" and turn a corrupt file into a lockout that never expires) — bounded
    recovery within one cooldown window, never a silent bypass.
    """
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return (int(data["failures"]), float(data["last_failure_time"]))
    except FileNotFoundError:
        return (0, 0.0)
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError):
        now = _now()
        _save_lockout(path, _MAX_CONSECUTIVE_FAILURES, now)
        return (_MAX_CONSECUTIVE_FAILURES, now)


def _save_lockout(path: Path, failures: int, last_failure_time: float) -> None:
    """Atomically persist lockout state; never raises into a caller.

    Same write-then-``os.replace`` pattern as the secret file: a crash or
    concurrent read never observes a half-written state file.
    """
    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        payload = json.dumps({"failures": failures, "last_failure_time": last_failure_time})
        fd, tmp_name = tempfile.mkstemp(
            dir=str(path.parent), prefix=".totp-lockout-", suffix=".tmp"
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(payload)
            try:
                os.chmod(tmp_name, 0o600)
            except OSError:
                pass
            os.replace(tmp_name, path)
        except OSError:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise
    except OSError:
        pass  # best-effort: an unwritable lockout file must never crash verify()


def _clear_lockout(secret_path: Path) -> None:
    """Remove any persisted lockout state for ``secret_path`` (best-effort)."""
    try:
        _lockout_path(secret_path).unlink()
    except OSError:
        pass


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


def enroll(
    *,
    issuer: str = "Doberman",
    account: str = "local",
    force: bool = False,
    current_code: str | None = None,
) -> str:
    """Generate and store a new TOTP secret; return its provisioning URI.

    Refuses to overwrite an existing enrollment unless ``force=True`` (so a
    second ``2fa setup`` cannot silently rotate the secret out from under an
    authenticator app). Rotation also requires a valid ``current_code`` proved
    against the existing secret. The returned URI embeds the secret for
    QR/manual entry and MUST NOT be logged by the caller.
    """
    path = _secret_path()
    if path.exists():
        if not force:
            raise RuntimeError(
                "TOTP is already enrolled; pass force=True to deliberately rotate the secret"
            )
        # Route the rotation proof through the rate-limited verify() (not a direct
        # pyotp check) so repeated wrong-code rotation attempts trip the same
        # persisted lockout as a normal auth attempt — symmetric with password.py.
        verified = current_code is not None and verify(str(current_code))
        if not verified:
            raise RuntimeError("a valid current 2FA code is required to rotate TOTP")

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

    _clear_lockout(path)
    return pyotp.TOTP(secret).provisioning_uri(name=account, issuer_name=issuer)


def unenroll(*, current_code: str) -> None:
    """Delete the stored TOTP secret after proving possession of it.

    Dropping a possession factor is a **weakening**, so it is gated on a valid
    ``current_code`` proved through the rate-limited :func:`verify` — not a
    direct pyotp check — so repeated wrong-code removal attempts trip the same
    persisted lockout as any other auth attempt (symmetric with rotation in
    :func:`enroll`). Not enrolled, a wrong code, or an active lockout all leave
    the enrollment intact and raise.
    """
    path = _secret_path()
    if not is_enrolled():
        raise RuntimeError("TOTP is not enrolled; nothing to remove")
    if not verify(str(current_code)):
        raise RuntimeError("a valid current 2FA code is required to remove TOTP")
    try:
        path.unlink()
    except OSError as exc:
        # Fail closed: the factor is still enrolled, so say so rather than
        # letting a caller believe it was dropped.
        raise RuntimeError("could not remove the TOTP secret file") from exc
    _clear_lockout(path)


def reset_attempts() -> None:
    """Clear the persisted consecutive-failure/lockout state for the active
    secret file (future ``doberman 2fa reset-lockout`` calls this)."""
    _clear_lockout(_secret_path())


def verify(code: str, *, at: int | None = None) -> bool:
    """Verify a TOTP ``code``; return ``True`` only on a valid, in-window code.

    Fails closed: not enrolled, a non-numeric/garbage code, or an active
    rate-limit lockout all return ``False`` without ever raising into the
    decision path. ``at`` (integer epoch seconds) is injectable so *code*
    validation is deterministic in tests; the lockout clock uses the separate
    :func:`_now` seam so tests can advance it independently (e.g. past the
    cooldown) without faking the TOTP time step. A successful verify clears
    the persisted lockout state.

    Lockout semantics (H5b): once ``_MAX_CONSECUTIVE_FAILURES`` consecutive
    failures accrue, further attempts are denied until
    ``_LOCKOUT_COOLDOWN_SECONDS`` have elapsed since the *last* failure. A
    denied attempt made while already locked out is a no-op — it neither
    checks the code nor rewrites the failure timestamp, so it can never
    extend the cooldown window (only a fresh failure *after* the window
    elapses starts a new one). State is persisted to disk, so the lockout
    survives a process restart (H5) instead of resetting for free, and the
    cooldown gives it a bounded, self-service recovery instead of the
    previous in-process design's permanent softlock (W2).
    """
    secret = _read_secret()
    if secret is None:
        return False

    secret_path = _secret_path()
    lockout_path = _lockout_path(secret_path)
    failures, last_failure_time = _load_lockout(lockout_path)
    now = _now()

    if failures >= _MAX_CONSECUTIVE_FAILURES:
        if now - last_failure_time < _LOCKOUT_COOLDOWN_SECONDS:
            return False  # still locked: deny without touching state or the code
        failures = 0  # cooldown elapsed: this attempt starts a fresh window

    try:
        ok = pyotp.TOTP(secret).verify(str(code), valid_window=_VALID_WINDOW, for_time=at)
    except Exception:  # noqa: BLE001 — any verify error is a failed auth, never a pass
        ok = False

    if ok:
        _clear_lockout(secret_path)
    else:
        _save_lockout(lockout_path, failures + 1, now)
    return ok
