"""A TOTP code is single-use (#768).

``verify`` used to accept a code for any step in its ±1 window as often as it
was offered, so one code could approve two different actions for up to ~90 s.
It now records the last accepted time step next to the secret, under a lock
the hooks, the proxy and the CLI share, and refuses that step or an older one.
"""

import os
import subprocess
import sys
import threading

import pyotp
import pytest

from doberman.auth import totp

#: A fixed reference time (epoch seconds) so code generation is deterministic.
_T0 = 1_700_000_000


def _code(at: int = _T0) -> str:
    secret = totp._read_secret()
    assert secret is not None
    return pyotp.TOTP(secret).at(at)


def _used_step_path():
    return totp._used_step_path(totp._secret_path())


def test_the_same_code_is_accepted_once():
    totp.enroll()
    code = _code(_T0)
    assert totp.verify(code, at=_T0) is True
    assert totp.verify(code, at=_T0) is False
    # Still refused from a later moment while it is inside the window.
    assert totp.verify(code, at=_T0 + 30) is False


def test_a_code_older_than_the_recorded_step_is_refused():
    totp.enroll()
    assert totp.verify(_code(_T0), at=_T0) is True
    # The previous step's code is still in the ±1 window, but it is older.
    assert totp.verify(_code(_T0 - 30), at=_T0) is False


def test_a_fresh_code_on_the_next_step_is_accepted():
    totp.enroll()
    assert totp.verify(_code(_T0), at=_T0) is True
    assert totp.verify(_code(_T0 + 30), at=_T0 + 30) is True


def test_a_refused_replay_counts_as_a_failed_attempt():
    totp.enroll()
    code = _code(_T0)
    assert totp.verify(code, at=_T0) is True
    assert totp.verify(code, at=_T0) is False
    lockout = totp._lockout_path(totp._secret_path())
    assert totp._load_lockout(lockout, now=totp._now())[0] == 1


def test_an_unreadable_record_denies_then_recovers_after_the_window():
    totp.enroll()
    _used_step_path().write_text("not json", encoding="utf-8")
    assert totp.verify(_code(_T0), at=_T0) is False
    # The corrupt record was replaced by the newest step any code matches now,
    # so every code still in this window stays refused...
    assert totp.verify(_code(_T0 + 30), at=_T0) is False
    # ...and a code from past that window gets through, so 2FA is not bricked.
    assert totp.verify(_code(_T0 + 60), at=_T0 + 60) is True


def test_an_unwritable_record_denies(monkeypatch):
    totp.enroll()
    monkeypatch.setattr(totp, "_save_used_step", lambda *a, **k: False)
    assert totp.verify(_code(_T0), at=_T0) is False


def test_a_held_lock_denies_instead_of_skipping_the_record(monkeypatch):
    totp.enroll()
    monkeypatch.setattr(totp, "_STEP_LOCK_TIMEOUT_SECONDS", 0.05)
    lock = totp._used_step_lock_path(totp._secret_path())
    lock.write_text("", encoding="utf-8")
    assert totp.verify(_code(_T0), at=_T0) is False
    lock.unlink()
    assert totp.verify(_code(_T0), at=_T0) is True


def test_a_stale_lock_left_by_a_crashed_holder_is_taken_over():
    totp.enroll()
    lock = totp._used_step_lock_path(totp._secret_path())
    lock.write_text("", encoding="utf-8")
    old = lock.stat().st_mtime - totp._STEP_LOCK_STALE_SECONDS - 1
    os.utime(lock, (old, old))
    assert totp.verify(_code(_T0), at=_T0) is True
    assert not lock.exists()


def test_two_threads_never_both_accept_one_code():
    totp.enroll()
    code = _code(_T0)
    for _ in range(20):
        totp._clear_used_step(totp._secret_path())
        totp.reset_attempts()
        barrier = threading.Barrier(2)
        results: list[bool] = []

        def attempt(barrier: threading.Barrier, results: list[bool]) -> None:
            barrier.wait()
            results.append(totp.verify(code, at=_T0))

        threads = [threading.Thread(target=attempt, args=(barrier, results)) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert sorted(results) == [False, True]


_CHILD = """
import sys
from doberman.auth import totp
print(totp.verify(sys.argv[1], at=int(sys.argv[2])))
"""


def test_two_processes_never_both_accept_one_code(isolated_totp_secret):
    totp.enroll()
    code = _code(_T0)
    env = {**os.environ, totp.TOTP_FILE_ENV: str(isolated_totp_secret)}
    procs = [
        subprocess.Popen(  # noqa: S603 — fixed interpreter and script, no shell
            [sys.executable, "-c", _CHILD, code, str(_T0)],
            env=env,
            stdout=subprocess.PIPE,
            text=True,
        )
        for _ in range(4)
    ]
    outputs = [p.communicate(timeout=60)[0].strip() for p in procs]
    assert sorted(outputs) == ["False", "False", "False", "True"]


@pytest.mark.parametrize("action", ["rotate", "remove"])
def test_rotating_or_removing_the_secret_forgets_the_used_step(action):
    totp.enroll()
    # enroll()/unenroll() verify against the real clock, so use the real code.
    current = pyotp.TOTP(totp._read_secret()).now()
    if action == "rotate":
        totp.enroll(force=True, current_code=current)
    else:
        totp.unenroll(current_code=current)
    assert not _used_step_path().exists()
