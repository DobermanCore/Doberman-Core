"""Shared persisted lockout state for the possession factors (H5b).

TOTP (:mod:`doberman.auth.totp`) and password (:mod:`doberman.auth.password`)
verification both rate-limit consecutive failures and need that limit to
survive a process restart (a per-invocation host-hook adapter is a fresh
process every time, so an in-memory counter never actually bounds it there).
This module is the one place that logic lives; each factor's ``verify()``
loads/saves lockout state next to its own secret file.

The lockout file is a **sibling of the secret it protects** (same directory,
same per-user/per-test isolation) rather than a new env var per factor, so it
inherits whatever override relocates that factor's secret in tests. A
present-but-unreadable/corrupt file fails **closed**: it is treated as a
brand-new full lockout anchored to the caller-supplied ``now`` and immediately
rewritten as clean state, so a repeated read doesn't keep re-anchoring "now"
and turn a corrupt file into a lockout that never expires.
"""

import json
import os
import tempfile
import time
from pathlib import Path

#: Consecutive failed verifications before further attempts are locked out
#: (until the cooldown TTL elapses or the caller clears the lockout). A
#: deliberately small bound — online guessing needs many tries to matter.
_MAX_CONSECUTIVE_FAILURES = 5

#: How long a lockout persists after the last failure, in seconds, before the
#: next attempt is allowed to proceed again. Bounds the "permanent softlock"
#: without weakening the guard: a locked-out attacker still has to wait out
#: the full window, and a denied attempt during the window never extends it.
_LOCKOUT_COOLDOWN_SECONDS = 15 * 60


def _lockout_path(secret_path: Path) -> Path:
    """Lockout-state file colocated with ``secret_path`` (same dir, same isolation)."""
    return secret_path.with_name(secret_path.name + ".lockout")


def _now() -> float:
    """Epoch-seconds time source. A module-level seam tests monkeypatch so
    cooldown expiry never depends on real sleeps."""
    return time.time()


def _load_lockout(path: Path, *, now: float) -> tuple[int, float]:
    """Return persisted ``(consecutive_failures, last_failure_time)``.

    No file yet (never failed, or a fresh enrollment) → ``(0, 0.0)``, i.e. not
    locked. A present-but-unreadable/corrupt file fails **closed**: it is
    treated as a brand-new lockout anchored to ``now`` (the caller's own
    ``_now`` seam, so a monkeypatched clock still governs this anchor) and
    immediately rewritten as clean state — bounded recovery within one
    cooldown window, never a silent bypass.
    """
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return (int(data["failures"]), float(data["last_failure_time"]))
    except FileNotFoundError:
        return (0, 0.0)
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError):
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
        fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=".lockout-", suffix=".tmp")
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
