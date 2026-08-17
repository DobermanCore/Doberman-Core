"""Shared test fixtures.
Feature 3 introduces keyed HMAC fingerprinting, which reads/creates a local key
file. Tests must NEVER touch the real per-user key (deterministic, isolated
runs only), so we point ``DOBERMAN_KEY_FILE`` at a throwaway path inside a
session-scoped temp dir for the whole suite. Individual fingerprint tests that
need to exercise key generation/rotation override this with their own
``tmp_path`` injection.
"""

import json as _json
from typing import Any

import pytest
from typer.testing import Result

from doberman.auth.password import PASSWORD_FILE_ENV
from doberman.auth.totp import TOTP_FILE_ENV
from doberman.storage.device_metrics import HOME_ENV
from doberman.storage.fingerprint import KEY_FILE_ENV


@pytest.fixture(autouse=True)
def isolated_fingerprint_key(tmp_path, monkeypatch):
    """Point the HMAC key at a per-test temp file so tests never use the real
    user key and never share key state across tests.
    Returns the key path so tests that exercise key generation/rotation can use
    it directly (there is exactly ONE setter of the env var — this fixture — so
    the key path is deterministic and free of fixture-ordering races).
    """
    key_path = tmp_path / "doberman-fingerprint.key"
    monkeypatch.setenv(KEY_FILE_ENV, str(key_path))
    return key_path


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


@pytest.fixture(autouse=True)
def _neutralize_hosthook_auth_prompter(monkeypatch):
    """Issues #65/#67: the PreToolUse hook now runs Doberman's own auth challenge on an
    AUTH verdict. Force the injected prompter to an unavailable channel so no test ever
    pops a real GUI dialog or blocks on a terminal — an AUTH then fails closed to deny
    unless a test injects its own approving/declining fake.
    """
    from doberman.auth.gui_prompter import PrompterUnavailableError
    from doberman.hosthooks import claude_code

    class _NoChannel:
        def confirm(self, message):
            raise PrompterUnavailableError("headless test: no auth channel")

        def read_code(self, message):
            raise PrompterUnavailableError("headless test: no auth channel")

    monkeypatch.setattr(claude_code, "AUTH_PROMPTER", _NoChannel())


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
