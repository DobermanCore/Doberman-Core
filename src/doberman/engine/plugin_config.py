"""Opt-in allowlist for every entry-point plugin seam (the enterprise seam).

Mirrors :mod:`doberman.auth.approval_config`'s storage discipline: a per-user
JSON file OUTSIDE any repository, written ``0600``. The file holds a list of
enabled entry-point names, across ALL registry groups (rules, detectors,
policy sources, auth providers, approval methods, audit sinks, algebra
adapters, adjudicators, egress brokers, drift observers, cost observers). With
no file, or an empty list, nothing is imported: enabling a plugin is always an
explicit act, by name — a package merely being installed is never enough.

Reads never raise: a missing, unreadable, or malformed file yields ``[]`` (no
plugins) so a corrupt config can only fall back to core-only behavior, never
widen what gets imported. ``$DOBERMAN_PLUGINS_FILE`` overrides the path (tests
inject a temp file).

**Why a snapshot, not a live read.** :func:`allowed_plugin_names` reads
:func:`enabled_plugins` exactly ONCE per process and caches the result — the
snapshot is taken before discovery ever runs, so nothing loaded LATER in the
process (an already-enabled plugin importing more code, an env var or file
mutation made after startup) can widen the allowlist mid-run. A malicious rule
plugin that flips an env var or rewrites the plugins file at import time gains
nothing: the registry already took its snapshot. This does not cover
``.pth``/``sitecustomize`` code, which runs before Doberman does at all — out
of scope for a process-level snapshot.
"""

from __future__ import annotations

import json
import logging
import os
import re
import stat
from pathlib import Path

logger = logging.getLogger("doberman.engine.plugin_config")

#: Env var overriding the config-file location (tests inject a temp path).
PLUGINS_FILE_ENV = "DOBERMAN_PLUGINS_FILE"

#: An entry-point name shape (mirrors typical Python entry-point names).
_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")

#: Process-wide snapshot cache — see the module docstring. ``None`` means "not
#: yet snapshotted"; a snapshot of zero plugins is a non-``None`` empty tuple.
_snapshot: tuple[str, ...] | None = None


def _default_path() -> Path:
    """Per-user config path OUTSIDE any repository (never committed)."""
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.path.join(
            os.path.expanduser("~"), "AppData", "Local"
        )
    else:
        base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return Path(base) / "doberman" / "plugins.json"


def _path() -> Path:
    override = os.environ.get(PLUGINS_FILE_ENV)
    return Path(override) if override else _default_path()


def enabled_plugins() -> list[str]:
    """Enabled entry-point names, de-duplicated and order-preserving (``[]`` on any error).

    A LIVE read of the config file — use :func:`allowed_plugin_names` for the
    process-snapshotted view discovery actually consults.
    """
    path = _path()
    try:
        raw = path.read_text(encoding="utf-8")
    except (FileNotFoundError, OSError):
        return []
    try:
        data = json.loads(raw)
        names = data.get("enabled", []) if isinstance(data, dict) else []
        seen: set[str] = set()
        out: list[str] = []
        for name in names:
            if isinstance(name, str) and _NAME_RE.match(name) and name not in seen:
                seen.add(name)
                out.append(name)
        return out
    except (ValueError, TypeError):
        logger.warning("plugins config at %s is malformed; treating as empty (core-only)", path)
        return []


def allowed_plugin_names() -> tuple[str, ...]:
    """The snapshotted allowlist discovery consults — read once per process.

    See the module docstring for why this is a snapshot rather than a live
    read. Call :func:`reset_snapshot` (tests only) to force a re-read.
    """
    global _snapshot
    if _snapshot is None:
        _snapshot = tuple(enabled_plugins())
    return _snapshot


def reset_snapshot() -> None:
    """Clear the process snapshot so the next :func:`allowed_plugin_names` re-reads.

    Test-only: production discovery runs once per process and never needs
    this. Never call this to "pick up" a plugin enabled mid-run — that is
    exactly the widening the snapshot exists to prevent.
    """
    global _snapshot
    _snapshot = None


def _write(names: list[str]) -> None:
    """Persist ``names`` to a ``0600`` file in a ``0700`` dir."""
    path = _path()
    path.parent.mkdir(parents=True, exist_ok=True)
    try:  # best-effort dir hardening, mirroring approval_config.py
        path.parent.chmod(stat.S_IRWXU)
    except OSError:  # pragma: no cover — non-POSIX perms
        pass
    payload = json.dumps({"enabled": names}, indent=2)
    path.write_text(payload, encoding="utf-8")
    try:
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except OSError:  # pragma: no cover — non-POSIX perms
        pass


def enable(name: str) -> list[str]:
    """Enable ``name`` (appended if new). Returns the new list.

    Raises ``ValueError`` for a malformed name so the CLI can reject typos
    rather than silently persisting an unusable entry. Does NOT affect the
    current process's snapshot — see :func:`allowed_plugin_names`.
    """
    if not _NAME_RE.match(name):
        raise ValueError(f"invalid plugin name: {name!r}")
    names = enabled_plugins()
    if name not in names:
        names.append(name)
        _write(names)
    return names


def disable(name: str) -> list[str]:
    """Disable ``name`` if present. Returns the new list."""
    names = [n for n in enabled_plugins() if n != name]
    _write(names)
    return names
