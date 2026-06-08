"""Shared test fixtures.

Feature 3 introduces keyed HMAC fingerprinting, which reads/creates a local key
file. Tests must NEVER touch the real per-user key (deterministic, isolated
runs only), so we point ``DOBERMAN_KEY_FILE`` at a throwaway path inside a
session-scoped temp dir for the whole suite. Individual fingerprint tests that
need to exercise key generation/rotation override this with their own
``tmp_path`` injection.
"""

import pytest

from doberman.auth.totp import TOTP_FILE_ENV
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
