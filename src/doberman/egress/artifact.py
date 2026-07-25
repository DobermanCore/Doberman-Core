"""Post-fetch artifact digest verification (Feature RB, slice RB.7).

**Post-fetch only.** A PASS decision is granted BEFORE the fetch happens, and
the RB.2b broker is an HTTP ``CONNECT`` proxy that relays TLS opaquely — it
never sees plaintext response bytes. Verifying content pre-decision would
require TLS MITM interception, which this feature deliberately excludes.
Instead, this module verifies content on the path where Doberman already
sees returned tool-result bytes: the proxy's post-fetch output handling in
:mod:`doberman.proxy.executor`, alongside the existing output secret-scan.

Pins are loaded from ``.doberman/artifact_pins.yaml`` following the same
loading convention as :mod:`doberman.egress.allowlist` (optional, fail-closed
to empty — a missing or malformed pins file means every artifact is
UNPINNED, i.e. today's unchanged pass-through behavior, not an error).
Expected shape::

    pins:
      https://example.com/tool.tar.gz: "sha256:<hex>"

Never logs or stores raw content, and never logs the computed/expected digest
of an UNPINNED artifact — only the identity string and the verdict.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
from enum import StrEnum
from pathlib import Path

import yaml

from doberman.config import CONFIG_DIR

logger = logging.getLogger("doberman.egress.artifact")

#: Optional pinned-digest file, following the same `.doberman/` config
#: convention as `doberman.egress.allowlist`.
PINS_FILE = "artifact_pins.yaml"


class ArtifactVerdict(StrEnum):
    """Outcome of comparing fetched content against a pinned digest."""

    match = "match"
    #: A pin exists and the content's digest differs — the dangerous case.
    mismatch = "mismatch"
    #: No pin for this identity. The common case; not an error.
    unpinned = "unpinned"


def _pins_file_path(repo_root: str) -> Path:
    return Path(repo_root) / CONFIG_DIR / PINS_FILE


def load_pins(repo_root: str = ".") -> dict[str, str]:
    """Read pinned artifact digests from ``.doberman/artifact_pins.yaml``.

    Optional and fail-closed-to-empty like every other ``.doberman/`` loader
    in :mod:`doberman.config`: a missing or malformed file yields no pins
    (everything UNPINNED, the safe no-op default) rather than raising.
    """
    path = _pins_file_path(repo_root)
    if not path.exists():
        return {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        logger.warning("could not read %s; no artifact pins loaded", path)
        return {}
    if not isinstance(data, dict):
        logger.warning("%s is not a mapping; no artifact pins loaded", path)
        return {}
    pins = data.get("pins")
    if not isinstance(pins, dict):
        return {}
    return {
        str(identity): str(digest)
        for identity, digest in pins.items()
        if isinstance(identity, str) and isinstance(digest, str) and digest.strip()
    }


class ArtifactPinStore:
    """A small pinned-digest store: artifact identity -> expected digest.

    Identity is a caller-supplied string (a URL, or a canonical host + path)
    — this store does no canonicalization of its own, matching by exact key
    the same way the pins file is authored.
    """

    def __init__(self, pins: dict[str, str] | None = None) -> None:
        self._pins: dict[str, str] = dict(pins or {})

    @classmethod
    def from_repo(cls, repo_root: str = ".") -> "ArtifactPinStore":
        """Load pins from ``.doberman/artifact_pins.yaml`` under ``repo_root``."""
        return cls(load_pins(repo_root))

    def verify(self, identity: str, content: bytes) -> ArtifactVerdict:
        """Compare ``content``'s sha256 digest against any pin for ``identity``.

        Digest comparison is constant-time (``hmac.compare_digest``), not
        ``==``. Never logs or returns the raw content, the computed digest,
        or (for an UNPINNED identity) any digest at all — callers must only
        surface ``identity`` and the returned verdict.
        """
        expected = self._pins.get(identity)
        if expected is None:
            return ArtifactVerdict.unpinned
        actual = f"sha256:{hashlib.sha256(content).hexdigest()}"
        if hmac.compare_digest(actual, expected):
            return ArtifactVerdict.match
        return ArtifactVerdict.mismatch
