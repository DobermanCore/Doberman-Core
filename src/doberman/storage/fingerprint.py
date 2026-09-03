"""Keyed (HMAC) one-way fingerprints for recognizing secrets without storing them.

Doberman must be able to say "I have seen this secret before / this secret is
being sent to an unknown host" **without ever persisting the secret itself**.
A plain hash would not be enough: most credentials are low-entropy enough that
an attacker with the fingerprint store could brute-force them offline. We
therefore key the hash — ``HMAC-SHA256(local_key, normalized_value)`` — so the
fingerprints are useless to anyone who does not also hold the local key.

Key handling (SECURITY):

* The key lives in a local file, **never** in the repo, logs, or any returned
  value. Its location is ``$DOBERMAN_KEY_FILE`` if set, else a per-user config
  directory (``%LOCALAPPDATA%`` / ``$XDG_CONFIG_HOME`` / ``~/.config``).
* It is generated on first use with :func:`secrets.token_bytes` (32 bytes) and
  written best-effort ``0600``. The directory is created ``0700``.
* If the key cannot be created or read, we **fail closed**: the caller gets an
  exception, never a silent unkeyed/plaintext fallback. (Callers in the rule
  layer turn that into a conservative AUTH via the engine's per-rule isolation
  — a missing key must never downgrade a decision to PASS.)

Fingerprints are returned as the opaque string ``"hmac:<hexdigest>"``; the
plaintext is unicode-normalized (NFC) and length-capped before hashing so that
trivially-different encodings of the same secret collide and a pathological
input cannot exhaust memory.
"""

import hashlib
import hmac
import os
import secrets
import unicodedata
from functools import lru_cache
from pathlib import Path

#: Environment variable that overrides the key-file location (used by tests to
#: inject a temp path — production never needs to set it).
KEY_FILE_ENV = "DOBERMAN_KEY_FILE"

#: HMAC key length. 32 bytes (256 bits) matches the SHA-256 block security.
_KEY_BYTES = 32

#: Inputs longer than this are truncated before hashing. A secret far larger
#: than any real credential is almost certainly a payload, not a secret; the
#: cap bounds work and memory. Truncation only affects the fingerprint value,
#: never correctness of "is this a secret" (that is the rule's job).
_MAX_INPUT_CHARS = 8192

#: ``"hmac:"`` prefix makes the value self-describing and impossible to mistake
#: for a raw secret in a log scan.
_PREFIX = "hmac:"


def _default_key_path() -> Path:
    """Per-user key path OUTSIDE any repository (never committed)."""
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.path.join(
            os.path.expanduser("~"), "AppData", "Local"
        )
    else:
        base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return Path(base) / "doberman" / "fingerprint.key"


def _key_path() -> Path:
    override = os.environ.get(KEY_FILE_ENV)
    return Path(override) if override else _default_key_path()


def resolve_path() -> Path:
    """Resolve the active fingerprint key file, including env overrides."""
    return _key_path()


@lru_cache(maxsize=1)
def _load_or_create_key() -> bytes:
    """Return the local HMAC key, generating it on first use.

    Fails closed: any inability to create/read a usable key raises. We never
    fall back to an unkeyed hash (that would defeat the offline-attack defense)
    and never return the key to the caller.

    Cached for the life of the process (``lru_cache(maxsize=1)``): the key
    never changes within a process, so re-reading it from disk on every
    ``fingerprint()`` call is pure overhead — measured ~20s of disk I/O for
    60k calls on a padded-args hook path (see ``engine/taint_floor.py``'s
    aggregate fingerprint cap). A raised exception is never cached (lru_cache
    only memoizes successful returns), so a transient failure still retries on
    the next call. Tests that rotate ``$DOBERMAN_KEY_FILE`` mid-process (key
    generation/rotation tests) must call ``_load_or_create_key.cache_clear()``
    after changing the env var — the isolated_fingerprint_key autouse fixture
    (tests/conftest.py) already does this between tests.
    """
    path = _key_path()
    try:
        if path.exists():
            data = path.read_bytes()
            if len(data) >= _KEY_BYTES:
                return data
            # A truncated/corrupt key is unusable — refuse rather than hash with
            # weak key material. (Do not auto-overwrite: that could mask an
            # attacker tampering with the key file.)
            raise RuntimeError("fingerprint key file is present but too short to be valid")

        # First-use generation. Create the parent 0700, write the key 0600.
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        key = secrets.token_bytes(_KEY_BYTES)
        # Write with restrictive perms from the start where the OS supports it.
        # O_BINARY (a no-op flag on POSIX) is REQUIRED on Windows: without it
        # os.write translates 0x0A bytes in the key to 0x0D 0x0A (CRLF), which
        # silently corrupts ~12% of randomly-generated keys and makes
        # fingerprints non-deterministic. The key is binary, not text.
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        fd = os.open(str(path), flags, 0o600)
        try:
            os.write(fd, key)
        finally:
            os.close(fd)
        # Best-effort tighten (no-op on Windows ACLs; harmless if already 0600).
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return key
    except FileExistsError:
        # Lost a race to create the file — read what the winner wrote.
        data = path.read_bytes()
        if len(data) >= _KEY_BYTES:
            return data
        raise RuntimeError("fingerprint key file is present but too short to be valid") from None


def _normalize(value: str) -> bytes:
    """Unicode-normalize (NFC) and length-cap, then encode for hashing."""
    normalized = unicodedata.normalize("NFC", value)
    if len(normalized) > _MAX_INPUT_CHARS:
        normalized = normalized[:_MAX_INPUT_CHARS]
    return normalized.encode("utf-8", errors="replace")


def fingerprint(value: str) -> str:
    """Return ``"hmac:<hex>"`` — a keyed, one-way fingerprint of ``value``.

    Deterministic for a given (value, key): the same secret always yields the
    same fingerprint, and regenerating the key changes every fingerprint. The
    plaintext is never embedded in or recoverable from the result.

    Raises if the local key cannot be obtained (fail closed) — callers in the
    rule layer must let that surface as a conservative escalation, not a PASS.
    """
    key = _load_or_create_key()
    digest = hmac.new(key, _normalize(value), hashlib.sha256).hexdigest()
    return f"{_PREFIX}{digest}"
