"""Default-deny egress allowlist (Feature RB, slice RB.2a).

Seeds from the existing ``TRUSTED_HOSTS`` static-classification list
(:mod:`doberman.engine.rules.destinations`) and reuses that module's host
canonicalization / registered-domain matching (``_parse_host``,
``_registered_match``) rather than re-implementing a second host parser. A
divergent parser between the static classifier and the runtime broker would
itself be a security bug — the two could then disagree about what "trusted"
means for the same destination string.

Default-deny: any destination whose host does not match an allowlist entry is
denied, including unparseable destinations and raw IP literals (an IP is
never on the list by name, so it never matches).
"""

import logging
from collections.abc import Iterable
from pathlib import Path

import yaml

from doberman.config import CONFIG_DIR
from doberman.engine.rules.destinations import TRUSTED_HOSTS, _parse_host, _registered_match

logger = logging.getLogger("doberman.egress.allowlist")

#: Optional extra-hosts file, following the same `.doberman/` config
#: convention as `doberman.config` (role.yaml / policies.yaml).
ALLOWLIST_FILE = "egress_allowlist.yaml"


def _allowlist_file_path(repo_root: str) -> Path:
    return Path(repo_root) / CONFIG_DIR / ALLOWLIST_FILE


def load_extra_allowed_hosts(repo_root: str = ".") -> tuple[str, ...]:
    """Read extra allowlisted hosts from ``.doberman/egress_allowlist.yaml``.

    Optional, additive-only, and fail-closed like every other ``.doberman/``
    loader in :mod:`doberman.config`: a missing file returns no extra hosts,
    and a malformed one is logged and ignored — it never raises, and it never
    silently grants trust it can't validate. Expected shape::

        allowed_hosts:
          - internal.example.corp
    """
    path = _allowlist_file_path(repo_root)
    if not path.exists():
        return ()
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        logger.warning("could not read %s; ignoring extra egress allowlist entries", path)
        return ()
    if not isinstance(data, dict):
        logger.warning("%s is not a mapping; ignoring extra egress allowlist entries", path)
        return ()
    hosts = data.get("allowed_hosts")
    if not isinstance(hosts, list):
        return ()
    return tuple(h.strip() for h in hosts if isinstance(h, str) and h.strip())


class EgressAllowlist:
    """Default-deny allowlist of egress destinations the broker will permit.

    Matching reuses ``destinations.py``'s ``_parse_host``/``_registered_match``
    canonicalization (IDNA-decoding, credential stripping, registered-domain
    suffix match) so the broker and the static classifier can never disagree
    about what counts as a trusted host.
    """

    def __init__(self, extra_hosts: Iterable[str] = ()) -> None:
        self._hosts: tuple[str, ...] = tuple(
            dict.fromkeys(h.lower() for h in (*TRUSTED_HOSTS, *extra_hosts) if h)
        )

    @classmethod
    def from_repo(cls, repo_root: str = ".") -> "EgressAllowlist":
        """Built-in trusted hosts plus any ``.doberman/egress_allowlist.yaml`` extras."""
        return cls(extra_hosts=load_extra_allowed_hosts(repo_root))

    def is_allowed(self, destination: str) -> bool:
        """True only if ``destination`` parses to a host matching the allowlist.

        Default-deny: an unparseable destination or a host absent from the
        list (including any raw IP literal, which is never trusted by name)
        is denied.
        """
        host, _had_credentials = _parse_host(destination)
        if not host:
            return False
        return _registered_match(host, self._hosts)
