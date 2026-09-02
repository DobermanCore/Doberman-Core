"""H5b — TOTP lockout persists across restarts and self-expires via a cooldown TTL.

The audit found two bugs in the previous in-memory-only `_failures` counter:
  H5 — a process restart clears it, and the Claude Code host-hook adapter runs
       as a FRESH PROCESS per invocation, so the limit never actually bound there.
  W2 — in a long-running process (the MCP proxy) the lockout was permanent in
       that process, with no self-service recovery.

The fix persists (consecutive_failures, last_failure_time) to a small JSON
file colocated with the TOTP secret, and adds a cooldown TTL so the lockout
expires on its own. This is strictly TIGHTENING vs. today (today a restart
clears the lockout instantly; now it survives) while bounding the W2 softlock.
"""

import importlib
import json

import pyotp
import pytest

from doberman.auth import totp

#: A fixed reference time (epoch seconds) so code generation is deterministic.
_T0 = 1_700_000_000


def _current_code(at: int = _T0) -> str:
    secret = totp._read_secret()
    assert secret is not None
    return pyotp.TOTP(secret).at(at)


def _lockout_path():
    return totp._lockout_path(totp._secret_path())


def _freeze_now(monkeypatch, moment: float) -> None:
    monkeypatch.setattr(totp, "_now", lambda: moment)


def test_failures_persist_across_simulated_process_restart(monkeypatch):
    totp.enroll()
    _freeze_now(monkeypatch, _T0)
    for _ in range(5):
        assert totp.verify("000000", at=_T0) is False

    # Simulate a fresh process by reloading the module: nothing in this design
    # keeps failure state in memory, but reloading proves the guard doesn't
    # quietly depend on anything the reload would wipe — only the file on disk.
    importlib.reload(totp)
    monkeypatch.setattr(totp, "_now", lambda: _T0)  # reload restores the real _now
    assert totp.verify(_current_code(_T0), at=_T0) is False  # still locked


def test_locked_verify_denies_without_consuming_a_code_check(monkeypatch):
    totp.enroll()
    _freeze_now(monkeypatch, _T0)
    for _ in range(5):
        assert totp.verify("000000", at=_T0) is False
    before = _lockout_path().read_text(encoding="utf-8")

    # Even the CORRECT code is refused while locked, and the attempt is a
    # complete no-op on disk: no rewrite, no timestamp refresh.
    assert totp.verify(_current_code(_T0), at=_T0) is False
    after = _lockout_path().read_text(encoding="utf-8")
    assert before == after


def test_denied_attempt_during_lockout_does_not_extend_the_window(monkeypatch):
    totp.enroll()
    _freeze_now(monkeypatch, _T0)
    for _ in range(5):
        assert totp.verify("000000", at=_T0) is False

    # A wrong attempt partway through the cooldown must not push the window out.
    _freeze_now(monkeypatch, _T0 + totp._LOCKOUT_COOLDOWN_SECONDS - 1)
    assert totp.verify("000000", at=_T0) is False

    # The window still expires relative to the ORIGINAL last failure at _T0,
    # not the denied attempt above.
    _freeze_now(monkeypatch, _T0 + totp._LOCKOUT_COOLDOWN_SECONDS + 1)
    assert totp.verify(_current_code(_T0), at=_T0) is True


def test_cooldown_elapsed_allows_retry_and_a_fresh_failure_starts_over(monkeypatch):
    totp.enroll()
    _freeze_now(monkeypatch, _T0)
    for _ in range(5):
        assert totp.verify("000000", at=_T0) is False

    _freeze_now(monkeypatch, _T0 + totp._LOCKOUT_COOLDOWN_SECONDS + 1)
    assert totp.verify(_current_code(_T0), at=_T0) is True
    assert not _lockout_path().exists()  # success clears persisted state

    # A single fresh wrong guess afterwards is just ONE failure, not still six.
    assert totp.verify("000000", at=_T0) is False
    data = json.loads(_lockout_path().read_text(encoding="utf-8"))
    assert data["failures"] == 1


def test_success_resets_count_in_memory_and_on_disk(monkeypatch):
    totp.enroll()
    _freeze_now(monkeypatch, _T0)
    for _ in range(3):  # under the lockout threshold
        assert totp.verify("000000", at=_T0) is False
    assert json.loads(_lockout_path().read_text(encoding="utf-8"))["failures"] == 3

    assert totp.verify(_current_code(_T0), at=_T0) is True
    assert not _lockout_path().exists()


def test_reset_attempts_clears_disk_state(monkeypatch):
    totp.enroll()
    _freeze_now(monkeypatch, _T0)
    for _ in range(5):
        assert totp.verify("000000", at=_T0) is False
    assert _lockout_path().exists()

    totp.reset_attempts()
    assert not _lockout_path().exists()
    assert totp.verify(_current_code(_T0), at=_T0) is True


def test_corrupt_state_file_fails_closed_with_bounded_ttl(monkeypatch):
    totp.enroll()
    path = _lockout_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("not json{{{", encoding="utf-8")

    _freeze_now(monkeypatch, _T0)
    # Corrupt file -> treated as a fresh lockout, denied even with the right code.
    assert totp.verify(_current_code(_T0), at=_T0) is False

    # ...but bounded: one cooldown window later it self-heals.
    _freeze_now(monkeypatch, _T0 + totp._LOCKOUT_COOLDOWN_SECONDS + 1)
    assert totp.verify(_current_code(_T0), at=_T0) is True


def test_lockout_file_never_contains_the_secret_or_codes(monkeypatch):
    totp.enroll()
    secret = totp._read_secret()
    assert secret is not None
    _freeze_now(monkeypatch, _T0)
    wrong_code = "654321"
    for _ in range(5):
        assert totp.verify(wrong_code, at=_T0) is False

    raw = _lockout_path().read_text(encoding="utf-8")
    assert secret not in raw
    assert wrong_code not in raw
    data = json.loads(raw)
    assert set(data.keys()) == {"failures", "last_failure_time"}


def test_rotation_proof_inherits_the_persisted_lockout(monkeypatch):
    """PR #117 routes enroll()'s rotation proof through verify(); confirm it
    also inherits the PERSISTED lockout, not just the (removed) in-memory one."""
    totp.enroll()
    correct = pyotp.TOTP(totp._read_secret()).now()
    _freeze_now(monkeypatch, _T0)
    for _ in range(5):
        assert totp.verify("000000", at=_T0) is False
    assert _lockout_path().exists()

    with pytest.raises(RuntimeError, match="current 2FA code"):
        totp.enroll(force=True, current_code=correct)


def test_attempt_is_counted_even_if_pyotp_verify_raises(monkeypatch):
    """The failure count must land on disk BEFORE pyotp runs, mirroring
    doberman.auth.password.verify — so a crash mid-verify still counts."""
    totp.enroll()
    _freeze_now(monkeypatch, _T0)

    def verify_explodes(*args, **kwargs):
        raise RuntimeError("pyotp crashed mid-verify")

    monkeypatch.setattr(pyotp.TOTP, "verify", verify_explodes)
    assert totp.verify(_current_code(_T0), at=_T0) is False
    # The attempt landed on disk even though pyotp never finished.
    assert totp._load_lockout(_lockout_path(), now=totp._now())[0] == 1


def test_unrecordable_attempt_is_denied(monkeypatch):
    totp.enroll()
    _freeze_now(monkeypatch, _T0)
    monkeypatch.setattr(totp, "_save_lockout", lambda *a, **k: False)
    # Even the right code is refused when the attempt cannot be counted.
    assert totp.verify(_current_code(_T0), at=_T0) is False
