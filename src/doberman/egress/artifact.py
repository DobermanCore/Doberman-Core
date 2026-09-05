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
from functools import lru_cache
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


@lru_cache(maxsize=8)
def _parse_pins_yaml_data(raw: bytes) -> dict:
    """Parse+validate ``artifact_pins.yaml``, cached on its raw content (#552).

    Same mechanism as :func:`doberman.config._parse_role_yaml_data`: keyed on
    the file's ``bytes`` rather than ``(path, mtime_ns)``, because a
    same-mtime-tick rewrite (coarse filesystem clock resolution, or two fast
    writes) could hash to the same mtime key and serve a stale pin set --
    for a *newly added* pin that means an artifact verifies UNPINNED instead
    of MISMATCH, the loosening direction prime directive 2 forbids. The read
    itself stays outside this helper (see ``load_pins``) so this function is
    pure parse+validate; ``maxsize=8`` bounds memory across a handful of
    repo roots/edits without unbounded growth. Raises straight through on
    parse failure -- never cached.
    """
    return yaml.safe_load(raw.decode("utf-8")) or {}


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
        # ponytail: one small read per decision; the parse+validate work below
        # is cached on the bytes themselves, so no staleness ceiling remains.
        raw = path.read_bytes()
        data = _parse_pins_yaml_data(raw)
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
