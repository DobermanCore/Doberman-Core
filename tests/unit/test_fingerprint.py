"""Slice 3.1 — HMAC secret-fingerprint helper.

Covers: determinism for a (value, key) pair; key-dependence (a new key changes
every fingerprint); the plaintext is never returned/recoverable; key-file
permissions; oversized/empty/unicode inputs; and fail-closed key handling. All
key state is injected via a temp path — no real global state, fully
deterministic.
"""

import os
import sys

import pytest

from doberman.storage import fingerprint as fp_mod
from doberman.storage.fingerprint import KEY_FILE_ENV, fingerprint

# A clearly-FAKE secret so the gitleaks CI job and redaction tests stay clean.
FAKE_SECRET = "AKIAIOSFODNN7EXAMPLE"  # noqa: S105 — synthetic AWS example key


@pytest.fixture
def key_path(isolated_fingerprint_key):
    """The per-test key path (set by the autouse conftest fixture — the single
    authoritative setter of the env var, so there is no fixture-ordering race)."""
    return isolated_fingerprint_key


def test_fingerprint_is_deterministic_for_same_value_and_key(key_path):
    assert fingerprint(FAKE_SECRET) == fingerprint(FAKE_SECRET)


def test_fingerprint_has_hmac_prefix_and_hex_digest(key_path):
    value = fingerprint(FAKE_SECRET)
    assert value.startswith("hmac:")
    digest = value.removeprefix("hmac:")
    assert len(digest) == 64  # sha256 hex
    int(digest, 16)  # parses as hex (raises if not)


def test_fingerprint_never_contains_plaintext(key_path):
    value = fingerprint(FAKE_SECRET)
    assert FAKE_SECRET not in value
    assert "AKIA" not in value


def test_different_keys_produce_different_fingerprints(tmp_path, monkeypatch):
    monkeypatch.setenv(KEY_FILE_ENV, str(tmp_path / "k1.key"))
    first = fingerprint(FAKE_SECRET)
    # Rotate to a brand-new key file → the same secret fingerprints differently.
    monkeypatch.setenv(KEY_FILE_ENV, str(tmp_path / "k2.key"))
    second = fingerprint(FAKE_SECRET)
    assert first != second


def test_distinct_values_have_distinct_fingerprints(key_path):
    assert fingerprint("value-one") != fingerprint("value-two")


def test_key_file_is_created_on_first_use(key_path):
    assert not key_path.exists()
    fingerprint(FAKE_SECRET)
    assert key_path.exists()
    assert len(key_path.read_bytes()) >= 32


@pytest.mark.skipif(os.name == "nt", reason="POSIX file-mode bits not applicable on Windows")
def test_key_file_is_created_0600(key_path):
    fingerprint(FAKE_SECRET)
    mode = key_path.stat().st_mode & 0o777
    assert mode == 0o600


def test_empty_string_is_handled(key_path):
    value = fingerprint("")
    assert value.startswith("hmac:")


def test_oversized_input_is_capped_not_crashed(key_path):
    # A pathologically large input must not blow up; it is truncated internally.
    huge = "A" * (fp_mod._MAX_INPUT_CHARS + 10_000)
    value = fingerprint(huge)
    assert value.startswith("hmac:")


def test_unicode_normalization_collapses_equivalent_forms(key_path):
    # NFC vs NFD of "é" must fingerprint identically (same logical secret).
    nfc = "café-token"  # é as one code point
    nfd = "café-token"  # e + combining acute
    assert fingerprint(nfc) == fingerprint(nfd)


def test_corrupt_short_key_fails_closed(key_path):
    # A truncated key file is unusable — we must raise, never hash with weak
    # material and never silently regenerate (could mask tampering).
    key_path.write_bytes(b"too-short")
    with pytest.raises(RuntimeError):
        fingerprint(FAKE_SECRET)


def test_key_is_reused_across_calls(key_path):
    fingerprint(FAKE_SECRET)
    key_after_first = key_path.read_bytes()
    fingerprint("something-else")
    assert key_path.read_bytes() == key_after_first  # not regenerated


def test_default_key_path_is_outside_any_repo(monkeypatch):
    # With no override, the key lives under a per-user config dir, never in cwd.
    monkeypatch.delenv(KEY_FILE_ENV, raising=False)
    path = fp_mod._default_key_path()
    assert "doberman" in str(path).lower()
    # It must not resolve inside the current working directory (the repo).
    assert os.path.commonpath([str(path.resolve()), os.getcwd()]) != os.getcwd()


def test_fingerprint_module_exposes_no_plaintext_key(key_path):
    # The key bytes are never returned by the public API.
    fingerprint(FAKE_SECRET)
    assert not hasattr(fp_mod, "fingerprint_key")
    assert "key" not in fingerprint(FAKE_SECRET)  # the string never says "key"


def test_runs_in_fresh_interpreter_without_real_key(tmp_path):
    # Belt-and-suspenders: a clean process with an injected key path works and
    # never writes outside that path.
    key = tmp_path / "fresh.key"
    code = (
        "from doberman.storage.fingerprint import fingerprint;"
        "v = fingerprint('AKIAIOSFODNN7EXAMPLE');"
        "assert v.startswith('hmac:');"
        "assert 'AKIA' not in v"
    )
    env = dict(os.environ, **{KEY_FILE_ENV: str(key)})
    import subprocess

    subprocess.run([sys.executable, "-c", code], check=True, timeout=60, env=env)  # noqa: S603
    assert key.exists()
