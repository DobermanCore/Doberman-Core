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
  allows a ±1 step skew, accepts each code **once** (the last accepted time
  step is recorded next to the secret under a cross-process lock, and a code
  for that step or an older one is refused), and is **rate-limited**: too many consecutive failures
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

import datetime
import json
import os
import tempfile
import time
from pathlib import Path

import pyotp
import pyotp.utils

from doberman.auth.lockout import (
    _LOCKOUT_COOLDOWN_SECONDS,
    _MAX_CONSECUTIVE_FAILURES,
    _clear_lockout,
    _load_lockout,
    _lockout_path,
    _now,
    _save_lockout,
)

#: Env var overriding the secret-file location (tests inject a temp path).
TOTP_FILE_ENV = "DOBERMAN_TOTP_FILE"

#: Accept the current code plus one step on either side (±30s) for clock skew.
_VALID_WINDOW = 1

#: How long ``verify`` waits for another process's used-step lock before it
#: denies, and how old a lock file has to be before it is treated as left
#: behind by a crashed holder. A holder only reads and rewrites one small file.
_STEP_LOCK_TIMEOUT_SECONDS = 2.0
_STEP_LOCK_STALE_SECONDS = 10.0


def _used_step_path(secret_path: Path) -> Path:
    """Last accepted time step, colocated with ``secret_path`` like the lockout."""
    return secret_path.with_name(secret_path.name + ".used-step")


def _used_step_lock_path(secret_path: Path) -> Path:
    return secret_path.with_name(secret_path.name + ".used-step.lock")


def _acquire_step_lock(lock_path: Path) -> bool:
    """Claim ``lock_path`` with an atomic ``O_CREAT | O_EXCL`` create.

    The same portable primitive the monitor daemon's lock and the fingerprint
    key use, so the hooks, the MCP proxy and the CLI share one lock on every
    platform. Waits up to ``_STEP_LOCK_TIMEOUT_SECONDS``; a lock older than
    ``_STEP_LOCK_STALE_SECONDS`` is removed once, since its holder crashed.
    ``False`` means the lock was not won and the caller must deny.
    """
    deadline = time.monotonic() + _STEP_LOCK_TIMEOUT_SECONDS
    while True:
        try:
            lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd = os.open(str(lock_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(fd)
            return True
        except FileExistsError:
            try:
                age = time.time() - lock_path.stat().st_mtime
            except OSError:
                age = 0.0  # vanished between the create and the stat: just retry
            if age > _STEP_LOCK_STALE_SECONDS:
                try:
                    lock_path.unlink()
                except OSError:
                    pass
                continue
        except OSError:
            return False
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.005)


def _release_step_lock(lock_path: Path) -> None:
    try:
        lock_path.unlink()
    except OSError:
        pass


def _load_used_step(path: Path) -> int | None:
    """Return the last accepted step; ``None`` when no code was accepted yet.

    Raises ``ValueError`` for a present but unreadable or corrupt record, so
    the caller can deny instead of treating it as "nothing used".
    """
    try:
        return int(json.loads(path.read_text(encoding="utf-8"))["step"])
    except FileNotFoundError:
        return None
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        raise ValueError("unreadable TOTP used-step record") from exc


def _save_used_step(path: Path, step: int) -> bool:
    """Atomically persist ``step`` (write-then-``os.replace``); ``False`` on failure."""
    try:
        fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=".used-step-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(json.dumps({"step": step}))
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
        return False
    return True


def _clear_used_step(secret_path: Path) -> None:
    """Forget the used step (best-effort): it belongs to the secret it was proved against."""
    try:
        _used_step_path(secret_path).unlink()
    except OSError:
        pass


def _current_step(totp: pyotp.TOTP, at: int | None) -> int:
    """The time step for ``at`` (epoch seconds), or for now, as ``pyotp`` counts it."""
    when = datetime.datetime.fromtimestamp(int(at)) if at is not None else datetime.datetime.now()
    return totp.timecode(when)


def _matching_step(totp: pyotp.TOTP, code: str, current: int) -> int | None:
    """The step within ``_VALID_WINDOW`` of ``current`` that ``code`` is for, or ``None``.

    ``pyotp``'s own ``verify`` only answers yes or no, so this repeats its
    comparison (``strings_equal``, constant-time) step by step to learn which
    step matched.
    """
    for offset in range(-_VALID_WINDOW, _VALID_WINDOW + 1):
        if pyotp.utils.strings_equal(code, str(totp.generate_otp(current + offset))):
            return current + offset
    return None


def _claim_step(secret_path: Path, step: int, *, current: int) -> bool:
    """Record ``step`` as used unless it, or a later step, already was.

    Runs under the used-step lock, so two processes verifying the same code
    can never both get ``True``. Denies when the lock cannot be won or the
    record cannot be read or written. A corrupt record is rewritten to the
    newest step any code can match right now, so the denial lasts at most one
    window instead of locking 2FA out until someone deletes the file.
    """
    lock_path = _used_step_lock_path(secret_path)
    if not _acquire_step_lock(lock_path):
        return False
    try:
        path = _used_step_path(secret_path)
        try:
            last = _load_used_step(path)
        except ValueError:
            _save_used_step(path, current + _VALID_WINDOW)
            return False
        if last is not None and step <= last:
            return False
        return _save_used_step(path, step)
    finally:
        _release_step_lock(lock_path)


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


def resolve_path() -> Path:
    """Resolve the active TOTP enrollment file, including env overrides."""
    return _secret_path()


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
    _clear_used_step(path)
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
    _clear_used_step(path)


def reset_attempts() -> None:
    """Clear the persisted consecutive-failure/lockout state for the active
    secret file (future ``doberman 2fa reset-lockout`` calls this)."""
    _clear_lockout(_secret_path())


def verify(code: str, *, at: int | None = None) -> bool:
    """Verify a TOTP ``code``; return ``True`` only on a valid, in-window code.

    Fails closed: not enrolled, a non-numeric/garbage code, an active
    rate-limit lockout, a code whose time step was already accepted (or is
    older than the last accepted one), or a used-step record that cannot be
    read, written or locked all return ``False`` without ever raising into the
    decision path. ``at`` (integer epoch seconds) is injectable so *code*
    validation is deterministic in tests; the lockout clock uses the separate
    :func:`_now` seam so tests can advance it independently (e.g. past the
    cooldown) without faking the TOTP time step. A successful verify clears
    the persisted lockout state. Every attempt is counted on disk BEFORE
    ``pyotp`` runs (mirrors :func:`doberman.auth.password.verify`), so a guess
    is on the record before the verifier runs — the read-modify-write is
    still unlocked, so this shrinks the concurrent-guess window rather than
    closing it; an attempt that cannot be recorded is denied.

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
    now = _now()
    failures, last_failure_time = _load_lockout(lockout_path, now=now)

    if failures >= _MAX_CONSECUTIVE_FAILURES:
        if now - last_failure_time < _LOCKOUT_COOLDOWN_SECONDS:
            return False  # still locked: deny without touching state or the code
        failures = 0  # cooldown elapsed: this attempt starts a fresh window

    # Count the attempt BEFORE verify() runs, so concurrent guesses cannot all
    # read the same pre-attempt count and overwrite each other after it; an
    # attempt that cannot be recorded is denied rather than run unaccounted
    # (mirrors doberman.auth.password.verify).
    if not _save_lockout(lockout_path, failures + 1, now):
        return False

    try:
        otp = pyotp.TOTP(secret)
        current = _current_step(otp, at)
        step = _matching_step(otp, str(code), current)
    except Exception:  # noqa: BLE001 — any verify error is a failed auth, never a pass
        step = None

    # A code is single-use: its step must be newer than the last one accepted,
    # or a code read over a shoulder (or out of a pending approval row) could
    # approve a second action while it is still in the window.
    ok = step is not None and _claim_step(secret_path, step, current=current)

    if ok:
        _clear_lockout(secret_path)
    return ok  # a failure was already counted above
