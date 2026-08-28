"""Device-wide, human-gated list of projects excluded from global hooks.

A global (``--global``) Claude Code hook, or a Codex ``user``-scope hook, fires
for every project on the machine — there is no way to make the hook *file*
itself skip one project (Claude Code's hook ``matcher`` keys off tool name, not
cwd). ``doberman uninstall`` closes that gap: when it detects a global/user-scope
hook is still installed, it adds the project to this list so the (unchanged)
global hook abstains for it, the same as if it were never installed there.

Storage: a small JSON file at ``~/.doberman/excluded_projects.json``, resolved
via the same ``DOBERMAN_HOME`` env-var override :mod:`doberman.storage.device_metrics`
already uses (tests get isolation for free via the existing autouse fixture).
Deliberately sync, no ``aiosqlite``/asyncio — :func:`is_excluded` sits on the hot
hook path (:func:`doberman.hosthooks.spine.is_excluded`), so it stays as light as
:mod:`doberman.storage.device_metrics`.

Security model: this list is a real bypass surface — whoever can write to it can
silently disable Doberman for any project. :func:`add_exclusion` is therefore only
ever called from the already possession-factor-gated ``doberman uninstall`` CLI
path, never from the hot hook path. :func:`is_excluded` is a **pure read**: it
never creates ``.doberman/`` or this file, and any failure (missing file,
malformed JSON, bad permissions) is swallowed and treated as "not excluded" —
protection stays ON, since an exclusion-list failure must never grant a bypass.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from doberman.storage.device_metrics import HOME_ENV

_EXCLUSIONS_FILE = "excluded_projects.json"


def excluded_projects_path(home: Path | None = None) -> Path:
    """Resolve the exclusion-list file path, respecting ``DOBERMAN_HOME``."""
    base = home if home is not None else Path(os.environ.get(HOME_ENV) or Path.home())
    return base / ".doberman" / _EXCLUSIONS_FILE


def load_excluded_projects(*, home: Path | None = None) -> list[str]:
    """The raw stored (already-canonical) excluded paths, or ``[]``.

    Read-only: never raises, never creates the file or its parent directory. A
    missing, unreadable, or malformed file is treated as an empty list.
    """
    path = excluded_projects_path(home)
    try:
        if not path.exists():
            return []
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return []
        entries = data.get("excluded")
        if not isinstance(entries, list):
            return []
        return [entry for entry in entries if isinstance(entry, str) and entry]
    except Exception:  # noqa: BLE001 — fail closed: unreadable list = nothing excluded
        return []


def is_excluded(repo_root: str, *, home: Path | None = None) -> bool:
    """True if *repo_root* equals, or is nested under, an excluded project.

    Pure read — never creates ``.doberman/`` or the exclusion file, so this is
    safe to call on every hook invocation. Any resolution failure fails closed
    (returns ``False`` = protection stays ON).
    """
    try:
        target = Path(repo_root).resolve()
    except (OSError, ValueError):
        return False
    for entry in load_excluded_projects(home=home):
        try:
            excluded_root = Path(entry).resolve()
        except (OSError, ValueError):
            continue
        if target == excluded_root or target.is_relative_to(excluded_root):
            return True
    return False


def _write(path: Path, entries: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps({"excluded": entries}, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)
    try:
        os.chmod(path.parent, 0o700)
        os.chmod(path, 0o600)
    except OSError:
        pass


def add_exclusion(repo_root: str, *, home: Path | None = None) -> None:
    """Add *repo_root* (canonicalized) to the device-wide exclusion list.

    Idempotent (de-duped by resolved path). Only ever called from the
    possession-factor-gated ``doberman uninstall`` CLI path.
    """
    target = str(Path(repo_root).resolve())
    entries = load_excluded_projects(home=home)
    existing = set()
    for entry in entries:
        try:
            existing.add(str(Path(entry).resolve()))
        except (OSError, ValueError):
            continue
    if target in existing:
        return
    _write(excluded_projects_path(home), [*entries, target])


def remove_exclusion(repo_root: str, *, home: Path | None = None) -> bool:
    """Remove *repo_root* from the exclusion list, if present.

    Returns whether anything changed. No gate: re-running ``install-hooks``
    against a project is an unambiguous "protect this project again" signal —
    a strengthen, same as turning the enforcement dial back up.
    """
    try:
        target = Path(repo_root).resolve()
    except (OSError, ValueError):
        return False
    entries = load_excluded_projects(home=home)
    kept: list[str] = []
    changed = False
    for entry in entries:
        try:
            same = Path(entry).resolve() == target
        except (OSError, ValueError):
            same = False
        if same:
            changed = True
        else:
            kept.append(entry)
    if changed:
        _write(excluded_projects_path(home), kept)
    return changed
