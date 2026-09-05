"""Shared test fixtures.

Feature 3 introduces keyed HMAC fingerprinting, which reads/creates a local key
file. Tests must NEVER touch the real per-user key (deterministic, isolated
runs only), so we point ``DOBERMAN_KEY_FILE`` at a throwaway path inside a
session-scoped temp dir for the whole suite. Individual fingerprint tests that
need to exercise key generation/rotation override this with their own
``tmp_path`` injection.
"""

import json as _json
import logging
import os
from pathlib import Path
from typing import Any

import pytest
from typer.testing import Result

from doberman import config as _config_module
from doberman.auth.password import PASSWORD_FILE_ENV
from doberman.auth.totp import TOTP_FILE_ENV
from doberman.egress import artifact as _artifact_module
from doberman.hosthooks.integrity import MANIFEST_ENV
from doberman.roles.roles import load_builtin_roles as _load_builtin_roles
from doberman.storage import fingerprint as _fingerprint_module
from doberman.storage.device_metrics import HOME_ENV
from doberman.storage.fingerprint import KEY_FILE_ENV

# Captured at import time, before any fixture runs, so real_user_settings_untouched
# below has a pre-test baseline to compare against.
_REAL_USER_SETTINGS = Path.home() / ".claude" / "settings.json"
_REAL_USER_SETTINGS_BEFORE = (
    _REAL_USER_SETTINGS.read_bytes() if _REAL_USER_SETTINGS.exists() else None
)


@pytest.fixture(autouse=True)
def isolated_user_home(tmp_path, monkeypatch):
    """Point ``Path.home()``/``expanduser`` at a throwaway dir for every test.

    A prior suite run reached the real ``~/.claude/settings.json`` through a CLI
    path (install-hooks/uninstall/doctor) and overwrote it, wiping live hooks.
    Nothing here isolated the user home, so this fixture now does.
    """
    user_home = tmp_path / "user-home"
    monkeypatch.setenv("HOME", str(user_home))
    monkeypatch.setenv("USERPROFILE", str(user_home))
    monkeypatch.delenv("HOMEDRIVE", raising=False)
    monkeypatch.delenv("HOMEPATH", raising=False)
    return user_home


@pytest.fixture(scope="session", autouse=True)
def real_user_settings_untouched():
    """Fail the run if any test wrote to the real user-level Claude settings file.

    ``isolated_user_home`` above should make this unreachable; this is the backstop
    that proves it — a per-test fixture can't itself assert after every other test's
    teardown has already run.
    """
    yield
    after = _REAL_USER_SETTINGS.read_bytes() if _REAL_USER_SETTINGS.exists() else None
    assert after == _REAL_USER_SETTINGS_BEFORE, (
        "the test suite modified the real user-level Claude settings file — a test reached Path.home()"
    )


@pytest.fixture(autouse=True)
def isolated_fingerprint_key(tmp_path, monkeypatch):
    """Point the HMAC key at a per-test temp file so tests never use the real
    user key and never share key state across tests.

    Returns the key path so tests that exercise key generation/rotation can use
    it directly (there is exactly ONE setter of the env var — this fixture — so
    the key path is deterministic and free of fixture-ordering races).

    ``_load_or_create_key`` is process-cached (``lru_cache(maxsize=1)``, keyed
    by nothing — one process, one key) for hot-path speed; without clearing it
    here, every test after the first would silently reuse the FIRST test's
    key/path instead of its own fresh ``tmp_path``, breaking isolation across
    the whole suite (not just within one test). A test that rotates the key
    file mid-test (a second ``monkeypatch.setenv(KEY_FILE_ENV, ...)`` of its
    own) must clear the cache again itself after that second ``setenv``.
    """
    key_path = tmp_path / "doberman-fingerprint.key"
    monkeypatch.setenv(KEY_FILE_ENV, str(key_path))
    _fingerprint_module._load_or_create_key.cache_clear()
    return key_path


@pytest.fixture(autouse=True)
def isolated_role_and_pin_caches():
    """Clear the #552 content-keyed role/pin parse caches (and the #547-style
    ``load_builtin_roles`` cache) between tests, same shape as
    ``isolated_fingerprint_key`` above: each is an ``lru_cache`` that is
    process-wide unless cleared here, and one test's cached content (or a
    ``tmp_path`` role/pins file that happens to share bytes with another
    test's) must never leak into the next.
    """
    _load_builtin_roles.cache_clear()
    _config_module._parse_role_yaml_data.cache_clear()
    _artifact_module._parse_pins_yaml_data.cache_clear()


@pytest.fixture(autouse=True)
def isolated_install_manifest(tmp_path, monkeypatch):
    """Point the hook install manifest (#239) at a per-test temp file so CLI
    tests that run install-hooks never write to the real per-user manifest."""
    manifest_path = tmp_path / "doberman-install-manifest.json"
    monkeypatch.setenv(MANIFEST_ENV, str(manifest_path))
    return manifest_path


@pytest.fixture(autouse=True)
def isolated_totp_secret(tmp_path, monkeypatch):
    """Point the TOTP secret at a per-test temp file (Feature 7).

    Tests must never touch the real per-user 2FA secret, and the
    consecutive-failure rate-limit state is keyed by this path, so a fresh path
    per test isolates rate-limit state too. Returns the path for tests that
    enroll/verify directly.
    """
    secret_path = tmp_path / "doberman-totp.secret"
    monkeypatch.setenv(TOTP_FILE_ENV, str(secret_path))
    return secret_path


@pytest.fixture(autouse=True)
def isolated_password_hash(tmp_path, monkeypatch):
    """Point the local password hash at a per-test temp file (C1 slice 2).

    Tests must never touch a real per-user possession factor. The failure
    counter is keyed by this path, so a fresh path also isolates lockout state.
    """
    hash_path = tmp_path / "doberman-password.hash"
    monkeypatch.setenv(PASSWORD_FILE_ENV, str(hash_path))
    return hash_path


@pytest.fixture(autouse=True)
def isolated_device_metrics_home(tmp_path, monkeypatch):
    """Point the device-global metrics rollup (dashboard) at a per-test temp dir.

    ``storage.device_metrics`` writes a lifetime rollup to
    ``~/.doberman/metrics.db`` on every decision (:mod:`doberman.storage.log`);
    tests must never touch the real per-user rollup, so point ``DOBERMAN_HOME``
    at a throwaway dir for the whole suite. Returns the isolated home dir for
    tests that read/seed the rollup directly.
    """
    home = tmp_path / "device-home"
    home.mkdir()
    monkeypatch.setenv(HOME_ENV, str(home))
    return home


@pytest.fixture(autouse=True)
def isolated_executor_repo_root(tmp_path, monkeypatch):
    """Point the proxy's repo root (config + elevation DB) at a temp dir.

    Feature 7 persists elevations to ``<repo_root>/.doberman/doberman.db``; this
    keeps every test's DB/config inside its own tmp dir so nothing is ever
    written into the working tree, and elevation state never leaks across tests.
    Returns the isolated repo root for tests that grant/read elevations.
    """
    from doberman.proxy import executor

    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    monkeypatch.setattr(executor, "REPO_ROOT", str(repo_root))
    return repo_root


@pytest.fixture
def enable_plugins(tmp_path, monkeypatch):
    """Factory: ``enable_plugins("name1", "name2")`` opts those names into the
    process-snapshotted plugins allowlist (:mod:`doberman.engine.plugin_config`).

    Points ``DOBERMAN_PLUGINS_FILE`` at a per-test temp file, writes the given
    names, and calls ``reset_snapshot()`` so the new allowlist is picked up
    immediately (production takes the snapshot once per process; tests need to
    force a fresh read every time). Resets the snapshot again on teardown so a
    later test that doesn't request this fixture never inherits an enabled
    plugin from an earlier one.
    """
    from doberman.engine import plugin_config

    plugins_path = tmp_path / "doberman-plugins.json"
    monkeypatch.setenv(plugin_config.PLUGINS_FILE_ENV, str(plugins_path))

    def _enable(*names: str) -> list[str]:
        for name in names:
            plugin_config.enable(name)
        plugin_config.reset_snapshot()
        return list(names)

    yield _enable
    plugin_config.reset_snapshot()


@pytest.fixture(autouse=True)
def _neutralize_hosthook_auth_prompter(monkeypatch):
    """Issues #65/#67: the PreToolUse hook now runs Doberman's own auth challenge on an
    AUTH verdict. Force the injected prompter to an unavailable channel so no test ever
    pops a real GUI dialog or blocks on a terminal — an AUTH then fails closed to deny
    unless a test injects its own approving/declining fake.

    Every hosthook module with its own ``AUTH_PROMPTER`` injection seam must be patched
    here — ``claude_code`` and ``codex`` today (see each module's ``AUTH_PROMPTER``
    docstring; ``codex.py``'s explicitly says it "mirrors" ``claude_code``'s). Missing one
    isn't just a coverage gap: any of that module's tests that reach an AUTH-tier decision
    without injecting their own fake prompter falls through to
    ``hookio._default_auth_prompter()``, which opens a REAL GUI dialog (blocking up to
    ``DEFAULT_CHALLENGE_TIMEOUT_S`` = 10 minutes) on any machine with an active desktop
    session — this previously happened to ``codex.AUTH_PROMPTER`` before it was added below.
    """
    from doberman.auth.gui_prompter import PrompterUnavailableError
    from doberman.hosthooks import claude_code, codex

    class _NoChannel:
        def confirm(self, message):
            raise PrompterUnavailableError("headless test: no auth channel")

        def read_code(self, message):
            raise PrompterUnavailableError("headless test: no auth channel")

    monkeypatch.setattr(claude_code, "AUTH_PROMPTER", _NoChannel())
    monkeypatch.setattr(codex, "AUTH_PROMPTER", _NoChannel())


# ── JSON output assertion helper (Issue #192) ─────────────────────────────────


def assert_json_stdout(result: Result, *, jsonl: bool = False) -> Any:
    """Assert that *result.stdout* contains valid JSON and nothing else.

    Parameters
    ----------
    result:
        The ``CliRunner`` result whose ``stdout`` attribute is inspected.
    jsonl:
        ``False`` (default) — assert stdout is exactly **one** valid JSON
        value (object or array) and return it.  This is the ``--json`` contract
        shared by ``scan``, ``doctor``, and ``policy-history``.

        ``True`` — assert stdout is zero or more **newline-separated** JSON
        objects, one per non-empty line, and return them as a list.  This is
        the ``--jsonl`` contract used by ``log``.  An empty result set must
        produce empty stdout, not ``[]``; this helper returns ``[]`` in that
        case.

    Returns
    -------
    Any
        The parsed Python value(s):
        - ``jsonl=False``: the single parsed document (dict, list, …).
        - ``jsonl=True``: a list of parsed dicts (may be empty).

    Raises
    ------
    AssertionError
        If stdout is not valid JSON, if it mixes JSON with non-JSON text,
        or (for ``jsonl=True``) if any non-empty line is not a JSON object.

    Safety contract
    ---------------
    This helper asserts *shape only* — valid JSON, nothing extraneous on stdout.
    It deliberately does **not** assert redaction, field presence, or content
    values.  Each command's own test keeps its redaction assertions so they
    cannot be accidentally weakened by sharing this helper.
    """
    stdout = result.stdout

    if not jsonl:
        # ── Single-document mode (--json) ────────────────────────────────────
        # stdout must be exactly one JSON value — nothing before, nothing after
        # (allow a single trailing newline as typer.echo adds one).
        text = stdout.strip()
        assert text, (  # noqa: S101
            "Expected one JSON document on stdout but stdout was empty.\n"
            f"stderr: {getattr(result, 'stderr', '(unavailable)')}"
        )
        try:
            doc = _json.loads(text)
        except _json.JSONDecodeError as exc:
            raise AssertionError(f"stdout is not valid JSON: {exc}\nstdout was: {text!r}") from exc
        # Guard against mixed output: extra bytes surrounding the JSON value
        # (e.g. a Rich heading on the same stream) are caught here.
        extra = stdout.replace(text, "", 1).strip()
        assert not extra, (  # noqa: S101
            f"Non-JSON text found on stdout alongside the JSON document: {extra!r}"
        )
        return doc

    else:
        # ── JSON Lines mode (--jsonl) ─────────────────────────────────────────
        # Empty stdout is valid (no rows → no output).
        lines = [line for line in stdout.splitlines() if line.strip()]
        records: list[Any] = []
        for i, line in enumerate(lines):
            try:
                obj = _json.loads(line)
            except _json.JSONDecodeError as exc:
                raise AssertionError(
                    f"Line {i + 1} of --jsonl output is not valid JSON: {exc}\nLine was: {line!r}"
                ) from exc
            assert isinstance(obj, dict), (  # noqa: S101
                f"Line {i + 1} of --jsonl output is not a JSON object "
                f"(got {type(obj).__name__})\nLine was: {line!r}"
            )
            records.append(obj)
        return records


@pytest.fixture(autouse=True)
def _telemetry_forced_off(monkeypatch):
    """Telemetry is on by default, so every test runs with the kill switch set; the telemetry
    tests that exercise sending clear it explicitly and stub the transport."""
    monkeypatch.setenv("DOBERMAN_TELEMETRY", "0")


@pytest.fixture(autouse=True)
def _update_check_forced_off(monkeypatch):
    """The update check is on by default, so every test runs with the kill switch set; the
    update-check tests that exercise it explicitly clear it."""
    monkeypatch.setenv("DOBERMAN_UPDATE_CHECK", "off")


@pytest.fixture(autouse=True)
def _isolated_doberman_logger_state(monkeypatch):
    """Restore the shared ``doberman``/root loggers after every test.

    ``cli.main._configure_stderr_logging`` (run by the ``hook pre/post/openclaw/
    codex-pre`` and ``serve`` commands) permanently flips
    ``logging.getLogger("doberman").propagate`` to ``False`` and replaces its
    handlers — correct for a real one-shot hook/serve subprocess, but Typer's
    ``CliRunner`` invokes the command function in-process, so without this fixture
    the mutation leaks into every later test in the same pytest worker. Concretely:
    once ``propagate`` is ``False``, records from a ``doberman.*`` child logger
    (e.g. ``doberman.storage.sinks``) never reach ``caplog``'s handler on the root
    logger, so an unrelated later test's ``caplog.records`` assertion goes empty.
    """
    root = logging.getLogger()
    doberman_logger = logging.getLogger("doberman")
    monkeypatch.setattr(root, "handlers", root.handlers[:])
    monkeypatch.setattr(doberman_logger, "handlers", doberman_logger.handlers[:])
    monkeypatch.setattr(doberman_logger, "propagate", doberman_logger.propagate)


# --- half-space trees: fast by default, production-size on request -------------
#
# Production builds HST_TREES x 2**(HST_HEIGHT+1) nodes (25 x 65k = 1.6M) on the
# first observation per entity, per process - the single largest cost in the
# suite (seconds per test on every leg, ~15 s on a loaded Windows box), paid by
# every test that reaches ``baseline.observe``. Tests use river's defaults instead
# (10 x height 8: ~30 ms). Where the model's shape is the thing under test - the
# benchmark and gate modules - ``pytestmark = pytest.mark.real_hst`` keeps the
# production size; the nightly deep workflow sets ``DOBERMAN_TEST_REAL_HST=1`` to
# run the whole suite at production size and guard this shortcut, and the Windows
# PR leg sets ``DOBERMAN_TEST_FAST_HST_GATES=1`` to run even the gates fast.
#
# Done as a setup HOOK, not a fixture: module-scoped fixtures (the poisoning
# eval, the subjective benchmark) are built before any function-scoped fixture
# runs, so a fixture could not reach them. ``tryfirst`` puts this before the
# runner's own setup, i.e. before ANY fixture of the item.
#
# The per-entity model cache is process-global; clearing it around each test
# keeps learned state from leaking between tests that reuse an entity id (an
# xdist-ordering flake source otherwise).

_HST_PRODUCTION = (25, 15)
_HST_FAST = (10, 8)


def _apply_hst_size(trees: int, height: int) -> None:
    from doberman.subjective import baseline

    baseline.reset_hst()
    baseline.HST_TREES = trees
    baseline.HST_HEIGHT = height


@pytest.hookimpl(tryfirst=True)
def pytest_runtest_setup(item: pytest.Item) -> None:
    if os.environ.get("DOBERMAN_TEST_REAL_HST"):
        real = True  # the nightly: the whole suite at production size
    elif os.environ.get("DOBERMAN_TEST_FAST_HST_GATES"):
        # The Windows PR leg: even the gate modules run fast. Their production-size
        # eval is DB-heavy (minutes on Windows, ~100x faster on Linux) and, under
        # its 20-minute marker, a slow Windows runner let it stall the leg to the
        # job cap four times on 2026-09-01/02. Production size still runs on every
        # Linux PR leg and on every nightly leg (Windows included, 60-minute caps).
        real = False
    else:
        real = item.get_closest_marker("real_hst") is not None
    _apply_hst_size(*(_HST_PRODUCTION if real else _HST_FAST))


@pytest.hookimpl(trylast=True)
def pytest_runtest_teardown(item: pytest.Item) -> None:
    _apply_hst_size(*_HST_PRODUCTION)


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Auto-mark every test that uses the GUI prompter tests' ``real_root``
    fixture ``real_display`` (item 12 of the round-4 GUI dialog critique) and
    ``xdist_group("tk")`` (issue #551).

    A fixture can't add its own marker in time for ``-m``/``-k`` selection --
    by the time a fixture runs, mark-based deselection has already happened at
    collection. Fixture NAMES, though, are already known at collection time
    (``item.fixturenames``), so this hook adds the marker from there instead
    of hand-maintaining a list of test names. Lets a local coverage run
    approximate the headless Linux CI runner (which skips every real-Tk test)
    via ``-m "not real_display"`` without a real display test actually
    needing one to be deselected.

    # ponytail: every real-Tk window this file opens can steal OS/WM focus
    # from every other one -- confirmed as the cause of both the local
    # `pytest -n 4` flake and the windows-latest CI flake in #551 (a real,
    # asynchronous focus change racing a test's own focus assertion). CI runs
    # `--dist loadgroup`, so one shared xdist group serializes every real-Tk
    # test onto the same worker instead of pinning each test individually;
    # upgrade path is a real per-OS focus arbiter if serializing ever stops
    # being enough.
    """
    for item in items:
        if "real_root" in getattr(item, "fixturenames", ()):
            item.add_marker(pytest.mark.real_display)
            item.add_marker(pytest.mark.xdist_group("tk"))


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    """Arm a shutdown watchdog on every process (xdist workers included).

    An interpreter that cannot exit -- a non-daemon thread left behind by a
    test, an event loop that never woke -- otherwise stalls the whole job in
    silence at 99 % until the runner's timeout kills it (45 minutes on the
    Windows leg, three times on 2026-09-02, never with a traceback: the
    per-test ``--timeout`` cannot fire once the last test has finished).
    faulthandler's watchdog is a C thread that needs no GIL: after 120 s it
    dumps every thread's stack to stderr and exits hard, so the log names the
    culprit and the job ends. A normal exit cancels it.
    """
    import faulthandler

    faulthandler.dump_traceback_later(timeout=120, exit=True)
