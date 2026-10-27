"""Opt-in allowlist for every entry-point plugin seam (the enterprise seam).

Mirrors :mod:`doberman.auth.approval_config`'s storage discipline: a per-user
JSON file OUTSIDE any repository, written ``0600``. The file holds a list of
enabled entries, each ``<group>:<name>`` (``doberman.rules:my_rule``): the
entry-point group a plugin registers under (rules, detectors, policy sources,
auth providers, approval methods, audit sinks, algebra adapters, adjudicators,
egress brokers, drift observers, cost observers, ...) plus its entry-point
name. Enabling ``my_rule`` as a rule never trusts a same-named detector or
audit sink (#638). With no file, or an empty list, nothing is imported:
enabling a plugin is always an explicit act, by name — a package merely being
installed is never enough.

**Legacy bare names.** A file written before #638 lists bare names
(``my_rule``), which matched that name under every group. They keep working
exactly as before, so an upgrade never silently disables a plugin, and
:func:`legacy_entries` reports them so ``doberman plugins list`` and
``doberman doctor`` can ask for a group. Enabling the name again for a group
replaces the bare entry with the narrower one.

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
#: An entry-point group shape: every group Doberman discovers is ``doberman.<seam>``.
_GROUP_RE = re.compile(r"^doberman\.[a-z_]{1,48}$")

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


def entry(group: str, name: str) -> str:
    """The allowlist entry for ``name`` registered under ``group``."""
    return f"{group}:{name}"


def _valid_entry(value: str) -> bool:
    group, sep, name = value.rpartition(":")
    if not sep:
        return bool(_NAME_RE.match(value))  # legacy bare name
    return bool(_GROUP_RE.match(group) and _NAME_RE.match(name))


def is_allowed(group: str, name: str, allowed: tuple[str, ...] | list[str]) -> bool:
    """Whether ``name`` under ``group`` is opted in: by its group-qualified entry,
    or by a legacy bare entry (which, as before #638, matches every group)."""
    return entry(group, name) in allowed or name in allowed


def names_for_group(group: str, allowed: tuple[str, ...] | list[str]) -> list[str]:
    """The names ``allowed`` opts in under ``group``, in allowlist order."""
    prefix = f"{group}:"
    out: list[str] = []
    for value in allowed:
        if value.startswith(prefix):
            name = value[len(prefix) :]
        elif ":" not in value:
            name = value
        else:
            continue
        if name not in out:
            out.append(name)
    return out


def legacy_entries(allowed: tuple[str, ...] | list[str]) -> list[str]:
    """Bare names from a pre-#638 file: trusted under every group until re-enabled."""
    return [value for value in allowed if ":" not in value]


def enabled_plugins() -> list[str]:
    """Enabled allowlist entries, de-duplicated and order-preserving (``[]`` on any error).

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
            if isinstance(name, str) and _valid_entry(name) and name not in seen:
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


def enable(name: str, group: str | None = None) -> list[str]:
    """Enable ``name`` under ``group`` (appended if new). Returns the new list.

    With a ``group`` the entry is ``<group>:<name>``, and a legacy bare entry
    for the same name is dropped: it trusted every group, so replacing it can
    only narrow what loads. Without a ``group`` a bare (any-group) entry is
    written, as before #638; ``doberman plugins enable`` always passes one.

    Raises ``ValueError`` for a malformed name or group so the CLI can reject
    typos rather than silently persisting an unusable entry. Does NOT affect
    the current process's snapshot — see :func:`allowed_plugin_names`.
    """
    if not _NAME_RE.match(name):
        raise ValueError(f"invalid plugin name: {name!r}")
    if group is not None and not _GROUP_RE.match(group):
        raise ValueError(f"invalid plugin group: {group!r}")
    value = name if group is None else entry(group, name)
    names = enabled_plugins()
    updated = [n for n in names if group is None or n != name]
    if value not in updated:
        updated.append(value)
    if updated != names:
        _write(updated)
    return updated


def disable(name: str, group: str | None = None) -> list[str]:
    """Disable ``name``: under ``group`` only, or (no group) under every group,
    including a legacy bare entry. Returns the new list."""
    if group is None:
        names = [n for n in enabled_plugins() if n != name and n.rpartition(":")[2] != name]
    else:
        names = [n for n in enabled_plugins() if n != entry(group, name)]
    _write(names)
    return names
