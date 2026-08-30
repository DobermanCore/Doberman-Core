"""Update-check notice: version compare, cache/TTL, fail-open network, kill
switches, and the ``doberman update`` CLI. No real network or clock — a fake
``fetch_latest`` and a temp home exercise every path.

The security-relevant properties pinned: the check is best-effort and never
raises into the CLI; a disabled check (DO_NOT_TRACK / CI / opt-out) touches no
network and shows no notice; and it never blocks the caller.
"""

import json
import threading
import time

import pytest

from doberman import __version__, update_check


@pytest.fixture(autouse=True)
def _enable_by_default(monkeypatch):
    # CI runners set CI=true (a kill switch). Clear the switches so the enabled
    # path is the default; disabled-path tests set them explicitly.
    for var in ("CI", "DO_NOT_TRACK", "DOBERMAN_UPDATE_CHECK"):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def home(tmp_path):
    return tmp_path


def _write_cache(home, latest, checked_at="2999-01-01T00:00:00Z"):
    path = home / ".doberman" / "update-check.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"checked_at": checked_at, "latest": latest}), encoding="utf-8")


# --------------------------------------------------------------------------- #
# version comparison                                                            #
# --------------------------------------------------------------------------- #
def test_is_newer_orders_releases():
    assert update_check.is_newer("0.18.3", "0.18.1")
    assert update_check.is_newer("1.0.0", "0.99.99")
    assert not update_check.is_newer("0.18.1", "0.18.1")
    assert not update_check.is_newer("0.18.0", "0.18.1")


def test_is_newer_is_fail_safe_on_garbage():
    assert not update_check.is_newer("garbage", "0.18.1")
    assert not update_check.is_newer("", "0.18.1")
    # a pre-release suffix is treated as its numeric prefix (never nag toward rc)
    assert update_check._parse("1.2.0rc1") == (1, 2, 0)


def test_is_newer_is_silent_on_unknown_current_version():
    # an all-zero parse, or an "unknown" marker, is never a comparison base
    assert not update_check.is_newer("1.0.0", "0.0.0")
    assert not update_check.is_newer("999.0.0", "0.0.0+unknown")


# --------------------------------------------------------------------------- #
# pending_notice — cache-only, no network                                       #
# --------------------------------------------------------------------------- #
def test_notice_when_cache_is_newer(home, monkeypatch):
    # Pin a real comparison version -- this box's real __version__ is
    # "0.0.0+unknown" (no dist metadata), which is_newer now always treats as
    # unknown/silent.
    monkeypatch.setattr(update_check, "__version__", "1.0.0")
    _write_cache(home, "999.0.0")
    notice = update_check.pending_notice(home)
    assert notice is not None
    assert "999.0.0" in notice and update_check.UPGRADE_HINT in notice


def test_no_notice_when_current_or_unknown(home, monkeypatch):
    # Pin the installed version the module compares against instead of relying
    # on the real install (this box builds with no dist metadata, so the real
    # __version__ is already "0.0.0+unknown" -- exercise both cases directly).
    monkeypatch.setattr(update_check, "__version__", "1.2.3")
    assert update_check.pending_notice(home) is None  # no cache
    _write_cache(home, "1.2.3")
    assert update_check.pending_notice(home) is None  # same version
    _write_cache(home, "0.0.1")
    assert update_check.pending_notice(home) is None  # older

    monkeypatch.setattr(update_check, "__version__", "0.0.0+unknown")
    _write_cache(home, "999.0.0")
    assert update_check.pending_notice(home) is None  # unknown installed version -> silent


def test_pending_notice_never_hits_network(home, monkeypatch):
    monkeypatch.setattr(update_check, "__version__", "1.0.0")
    _write_cache(home, "999.0.0")
    monkeypatch.setattr(
        update_check, "fetch_latest", lambda: pytest.fail("pending_notice must not fetch")
    )
    assert update_check.pending_notice(home) is not None


# --------------------------------------------------------------------------- #
# refresh — TTL + fail-open                                                      #
# --------------------------------------------------------------------------- #
def test_refresh_fetches_and_caches_when_due(home, monkeypatch):
    monkeypatch.setattr(update_check, "fetch_latest", lambda: "9.9.9")
    assert update_check.refresh(home, force=True) == "9.9.9"
    assert json.loads((home / ".doberman" / "update-check.json").read_text())["latest"] == "9.9.9"


def test_refresh_uses_fresh_cache_without_fetching(home, monkeypatch):
    _write_cache(home, "1.2.3")  # far-future timestamp -> fresh
    monkeypatch.setattr(
        update_check, "fetch_latest", lambda: pytest.fail("fresh cache must not fetch")
    )
    assert update_check.refresh(home) == "1.2.3"


def test_refresh_returns_stale_cache_when_fetch_fails(home, monkeypatch):
    _write_cache(home, "1.0.0", checked_at="2000-01-01T00:00:00Z")  # stale
    monkeypatch.setattr(update_check, "fetch_latest", lambda: None)  # PyPI unreachable
    assert update_check.refresh(home, force=True) == "1.0.0"


def test_fetch_latest_is_fail_open(monkeypatch):
    def _boom(*a, **k):
        raise OSError("no network")

    monkeypatch.setattr(update_check.urllib.request, "urlopen", _boom)
    assert update_check.fetch_latest() is None  # never raises


# --------------------------------------------------------------------------- #
# refresh_async — daemon, guarded                                               #
# --------------------------------------------------------------------------- #
def test_refresh_async_runs_when_due(home, monkeypatch):
    ran = {"v": False}

    class _SyncThread:
        def __init__(self, target, daemon=None):
            self._target = target

        def start(self):
            self._target()

    monkeypatch.setattr(update_check.threading, "Thread", _SyncThread)
    monkeypatch.setattr(update_check, "fetch_latest", lambda: ran.__setitem__("v", True) or "5.5.5")
    update_check.refresh_async(home)
    assert ran["v"] is True
    assert update_check._read_cache(home).get("latest") == "5.5.5"


def test_refresh_async_skips_when_cache_fresh(home, monkeypatch):
    _write_cache(home, "1.2.3")  # fresh
    monkeypatch.setattr(
        update_check.threading, "Thread", lambda *a, **k: pytest.fail("should not spawn a thread")
    )
    update_check.refresh_async(home)  # no thread, no error


def test_refresh_async_thread_is_joined_at_exit(home, monkeypatch):
    # Isolate from any thread objects other tests left in the module list.
    monkeypatch.setattr(update_check, "_REFRESH_THREADS", [])
    event = threading.Event()

    def _slow_refresh(home=None, *, force=False):
        time.sleep(0.05)
        event.set()

    monkeypatch.setattr(update_check, "refresh", _slow_refresh)
    update_check.refresh_async(home)  # real daemon thread, not the interpreter-exit path
    update_check._join_refresh_threads()
    assert event.is_set()


# --------------------------------------------------------------------------- #
# kill switches                                                                 #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "var,val",
    [("DO_NOT_TRACK", "1"), ("CI", "true"), ("DOBERMAN_UPDATE_CHECK", "off")],
)
def test_disabled_switches_block_everything(home, monkeypatch, var, val):
    monkeypatch.setenv(var, val)
    _write_cache(home, "999.0.0")
    assert update_check.disabled_reason() is not None
    assert update_check.pending_notice(home) is None
    monkeypatch.setattr(
        update_check, "fetch_latest", lambda: pytest.fail("disabled check must not fetch")
    )
    assert update_check.refresh(home, force=True) is None
    update_check.refresh_async(home)  # no-op, no thread


# --------------------------------------------------------------------------- #
# CLI — doberman update                                                          #
# --------------------------------------------------------------------------- #
def _runner():
    from typer.testing import CliRunner

    from doberman.cli.main import app

    return CliRunner(), app


def test_cli_update_reports_newer(home, monkeypatch):
    monkeypatch.setenv("DOBERMAN_HOME", str(home))
    monkeypatch.setattr(update_check, "fetch_latest", lambda: "999.0.0")
    # Pin the CLI's comparison version -- this box's real __version__ is
    # "0.0.0+unknown" (no dist metadata), which is_newer now always treats as
    # unknown/silent, so the test must supply a real one to see the notice.
    monkeypatch.setattr("doberman.cli.main.__version__", "1.0.0")
    runner, app = _runner()
    res = runner.invoke(app, ["update"])
    assert res.exit_code == 0
    assert "new version is available: 999.0.0" in res.output
    assert update_check.UPGRADE_HINT in res.output


def test_cli_update_reports_current(home, monkeypatch):
    monkeypatch.setenv("DOBERMAN_HOME", str(home))
    monkeypatch.setattr(update_check, "fetch_latest", lambda: __version__)
    runner, app = _runner()
    res = runner.invoke(app, ["update"])
    assert res.exit_code == 0
    assert "latest version" in res.output


def test_cli_update_handles_unreachable_pypi(home, monkeypatch):
    monkeypatch.setenv("DOBERMAN_HOME", str(home))
    monkeypatch.setattr(update_check, "fetch_latest", lambda: None)
    runner, app = _runner()
    res = runner.invoke(app, ["update"])
    assert res.exit_code == 0
    assert "Could not reach PyPI" in res.output


def test_cli_update_respects_kill_switch(home, monkeypatch):
    monkeypatch.setenv("DOBERMAN_HOME", str(home))
    monkeypatch.setenv("DOBERMAN_UPDATE_CHECK", "off")
    monkeypatch.setattr(
        update_check, "fetch_latest", lambda: pytest.fail("kill switch must not fetch")
    )
    runner, app = _runner()
    res = runner.invoke(app, ["update"])
    assert res.exit_code == 0
    assert "Update check is off" in res.output


# --------------------------------------------------------------------------- #
# CLI — doberman status (passive nudge)                                         #
# --------------------------------------------------------------------------- #
def test_status_shows_pending_update_notice(tmp_path, monkeypatch, isolated_device_metrics_home):
    monkeypatch.delenv("DOBERMAN_UPDATE_CHECK", raising=False)
    monkeypatch.setattr(update_check, "refresh_async", lambda *a, **k: None)
    monkeypatch.setattr(update_check, "__version__", "1.0.0")
    _write_cache(isolated_device_metrics_home, "999.0.0")
    runner, app = _runner()
    res = runner.invoke(app, ["status", "--path", str(tmp_path)])
    assert res.exit_code == 0
    assert "A new Doberman is available: 999.0.0" in res.output


def test_status_has_no_notice_without_a_cache(tmp_path, monkeypatch, isolated_device_metrics_home):
    monkeypatch.delenv("DOBERMAN_UPDATE_CHECK", raising=False)
    monkeypatch.setattr(update_check, "refresh_async", lambda *a, **k: None)
    monkeypatch.setattr(update_check, "__version__", "1.0.0")
    runner, app = _runner()
    res = runner.invoke(app, ["status", "--path", str(tmp_path)])
    assert res.exit_code == 0
    assert "A new Doberman is available" not in res.output
