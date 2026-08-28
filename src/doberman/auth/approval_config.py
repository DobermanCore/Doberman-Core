"""Opt-in configuration for approval methods (which are enabled, in what order).

Mirrors :mod:`doberman.auth.totp`'s storage discipline: a per-user JSON file
OUTSIDE any repository, written ``0600``. The file holds an ordered list of
enabled method names (preference order — the first available one runs). With no
file, or an empty list, nothing is enabled and a 2FA challenge uses TOTP exactly
as before: enabling an approval method is always an explicit act.

Reads never raise: a missing, unreadable, or malformed file yields ``[]`` (no
methods) so a corrupt config can only fall back to TOTP, never bypass the second
factor. ``$DOBERMAN_APPROVAL_FILE`` overrides the path (tests inject a temp file).
"""

from __future__ import annotations

import json
import logging
import os
import re
import stat
from pathlib import Path

logger = logging.getLogger("doberman.auth.approval_config")

#: Env var overriding the config-file location (tests inject a temp path).
APPROVAL_FILE_ENV = "DOBERMAN_APPROVAL_FILE"

#: A method name is a short lowercase identifier — matches the registry/CLI name.
_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")


def _default_path() -> Path:
    """Per-user config path OUTSIDE any repository (never committed)."""
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.path.join(
            os.path.expanduser("~"), "AppData", "Local"
        )
    else:
        base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return Path(base) / "doberman" / "approval.json"


def _path() -> Path:
    override = os.environ.get(APPROVAL_FILE_ENV)
    return Path(override) if override else _default_path()


def enabled_methods() -> list[str]:
    """Enabled method names in preference order (``[]`` if none / on any error)."""
    path = _path()
    try:
        raw = path.read_text(encoding="utf-8")
    except (FileNotFoundError, OSError):
        return []
    try:
        data = json.loads(raw)
        names = data.get("enabled", []) if isinstance(data, dict) else []
        # Keep only well-formed names, order-preserving and de-duplicated.
        seen: set[str] = set()
        out: list[str] = []
        for name in names:
            if isinstance(name, str) and _NAME_RE.match(name) and name not in seen:
                seen.add(name)
                out.append(name)
        return out
    except (ValueError, TypeError):
        logger.warning(
            "approval config at %s is malformed; treating as empty (TOTP fallback)", path
        )
        return []


def is_enabled(name: str) -> bool:
    return name in enabled_methods()


def _write(names: list[str]) -> None:
    """Persist ``names`` (preference order) to a ``0600`` file in a ``0700`` dir."""
    path = _path()
    path.parent.mkdir(parents=True, exist_ok=True)
    try:  # best-effort dir hardening, mirroring totp.py
        path.parent.chmod(stat.S_IRWXU)
    except OSError:  # pragma: no cover — non-POSIX perms
        pass
    payload = json.dumps({"enabled": names}, indent=2)
    # Write then tighten perms (0600), same as the TOTP secret.
    path.write_text(payload, encoding="utf-8")
    try:
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except OSError:  # pragma: no cover — non-POSIX perms
        pass


def enable(name: str) -> list[str]:
    """Enable ``name`` (appended at lowest preference if new). Returns the new list.

    Raises ``ValueError`` for a malformed name so the CLI can reject typos rather
    than silently persisting an unusable entry.
    """
    if not _NAME_RE.match(name):
        raise ValueError(f"invalid approval method name: {name!r}")
    names = enabled_methods()
    if name not in names:
        names.append(name)
        _write(names)
    return names


def disable(name: str) -> list[str]:
    """Disable ``name`` if present. Returns the new list."""
    names = [n for n in enabled_methods() if n != name]
    _write(names)
    return names


def set_order(names: list[str]) -> list[str]:
    """Replace the enabled list with ``names`` (preference order). Validates each."""
    for name in names:
        if not _NAME_RE.match(name):
            raise ValueError(f"invalid approval method name: {name!r}")
    # De-duplicate, order-preserving.
    seen: set[str] = set()
    ordered = [n for n in names if not (n in seen or seen.add(n))]
    _write(ordered)
    return ordered
