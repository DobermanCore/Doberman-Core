"""Shared test fixtures.

Feature 3 introduces keyed HMAC fingerprinting, which reads/creates a local key
file. Tests must NEVER touch the real per-user key (deterministic, isolated
runs only), so we point ``DOBERMAN_KEY_FILE`` at a throwaway path inside a
session-scoped temp dir for the whole suite. Individual fingerprint tests that
need to exercise key generation/rotation override this with their own
``tmp_path`` injection.
"""

import pytest

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
