"""Idempotent install/uninstall of Doberman's Codex CLI hook into a hooks.json.

Codex's hooks.json is Claude-Code-shaped (a live capture confirmed the schema —
see ``tests/fixtures/codex/README.md``): ``{"hooks": {"<Event>": [{"matcher":
"<regex>", "hooks": [{"type": "command", "command": "..."}]}]}}``. Doberman
registers a single ``PreToolUse`` group matching every tool (``matcher": ".*"``)
that runs ``doberman hook codex-pre``.

This mirrors :mod:`doberman.hosthooks.install` (Claude Code) and reuses its
format-agnostic JSON I/O (:func:`~doberman.hosthooks.install.load_settings` /
:func:`~doberman.hosthooks.install.write_settings`) and its Doberman-group
sentinel (``doberman hook `` — matches ``codex-pre`` too). Pure merge/remove
functions never mutate their inputs, so they are trivially unit-testable.

Scopes: ``user`` -> ``~/.codex/hooks.json`` (auto-loaded by Codex; confirmed live),
``repo`` -> ``<project_root>/.codex/hooks.json``. There is no Codex equivalent of
Claude Code's ``settings.local.json`` "local" scope. A third **plugin** scope
(a plugin-bundled hooks.json) is install/uninstalled by adding/removing the Codex
plugin itself, not by this command — it is reported by
:func:`codex_hook_install_states` but never written here.
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

from doberman.hosthooks.install import _is_doberman_group, load_settings

#: Codex PreToolUse group Doberman registers — matches every tool. The
#: ``doberman hook `` marker (shared with the Claude Code installer) identifies it
#: for idempotent replace + removal. Shape confirmed against a live codex CLI
#: (see tests/fixtures/codex/README.md for version + date).
CODEX_PRE_ENTRY: dict[str, Any] = {
    "matcher": ".*",
    "hooks": [{"type": "command", "command": "doberman hook codex-pre"}],
}

#: Where a Codex plugin's bundled hooks live once installed (cache probed
#: read-only for the *reporting* path only; this module never writes here). Codex
#: unpacks plugins under ``~/.codex/.tmp/plugins/plugins/<name>/`` (observed
#: 2026-08-08); a Doberman plugin would ship its own ``hooks.json`` there.
_PLUGIN_ROOT = Path.home() / ".codex" / ".tmp" / "plugins" / "plugins"


def merge_codex_hooks(settings: dict[str, Any]) -> dict[str, Any]:
    """Return a *new* hooks.json dict with Doberman's PreToolUse group added.

    Existing non-Doberman groups and every other key are preserved. **Idempotent:**
    a pre-existing Doberman group is replaced in place, never duplicated.
    """
    result: dict[str, Any] = copy.deepcopy(settings)
    hooks: dict[str, Any] = copy.deepcopy(result.get("hooks") or {})

    existing: list[dict[str, Any]] = list(hooks.get("PreToolUse") or [])
    non_doberman = [g for g in existing if not _is_doberman_group(g)]
    hooks["PreToolUse"] = [*non_doberman, copy.deepcopy(CODEX_PRE_ENTRY)]

    result["hooks"] = hooks
    return result


def remove_codex_hooks(settings: dict[str, Any]) -> dict[str, Any]:
    """Return a *new* hooks.json dict with Doberman's hook groups removed.

    Non-Doberman groups and every other key are preserved. Empty event lists are
    dropped; if ``hooks`` becomes empty it is removed too. A no-op when absent.
    """
    result: dict[str, Any] = copy.deepcopy(settings)
    if "hooks" not in result:
        return result

    hooks: dict[str, Any] = copy.deepcopy(result["hooks"])
    cleaned: dict[str, Any] = {}
    for event_key, groups in hooks.items():
        if not isinstance(groups, list):
            cleaned[event_key] = groups
            continue
        kept = [g for g in groups if not _is_doberman_group(g)]
        if kept:
            cleaned[event_key] = kept

    if cleaned:
        result["hooks"] = cleaned
    else:
        del result["hooks"]
    return result


def resolve_codex_hooks_path(scope: str, project_root: str) -> Path:
    """Resolve the target ``hooks.json`` path for *scope*.

    ``user`` -> ``~/.codex/hooks.json`` · ``repo`` -> ``<project_root>/.codex/hooks.json``.

    Raises:
        ValueError: if *scope* is not ``"user"`` or ``"repo"`` (``"plugin"`` is not
            writable here — the plugin owns its bundled hooks.json).
    """
    match scope:
        case "user":
            return Path.home() / ".codex" / "hooks.json"
        case "repo":
            return Path(project_root) / ".codex" / "hooks.json"
        case _:
            raise ValueError(f"Unknown Codex scope {scope!r}; expected 'user' or 'repo'.")


def codex_hook_install_states(project_root: str) -> list[tuple[str, str, bool]]:
    """Report, per Codex scope, whether Doberman's hook is wired in.

    Returns ``(scope, path, installed)`` for ``user`` / ``repo`` / ``plugin``.
    **Never raises:** an unreadable or unparseable hooks.json is reported as
    *not installed* rather than crashing ``status`` / ``doctor``.
    """
    states: list[tuple[str, str, bool]] = []
    for scope in ("user", "repo"):
        path = resolve_codex_hooks_path(scope, project_root)
        installed = False
        try:
            settings = load_settings(path)
            hooks_section = settings.get("hooks") or {}
            installed = any(
                _is_doberman_group(group)
                for groups in hooks_section.values()
                if isinstance(groups, list)
                for group in groups
            )
        except Exception:  # noqa: BLE001,S110 — a bad hooks.json must not crash the caller
            pass
        states.append((scope, str(path), installed))
    states.append(("plugin", str(_PLUGIN_ROOT), _plugin_installed()))
    return states


def _plugin_installed() -> bool:
    """Best-effort read-only probe: is a Doberman plugin's bundled hooks.json
    present in Codex's plugin cache? False (never a guess) when the cache is
    absent or unreadable — the plugin is added/removed via ``codex plugin``, not
    this command."""
    try:
        if not _PLUGIN_ROOT.is_dir():
            return False
        for plugin_dir in _PLUGIN_ROOT.iterdir():
            if "doberman" not in plugin_dir.name.lower():
                continue
            hooks_json = plugin_dir / "hooks.json"
            if not hooks_json.is_file():
                continue
            settings = load_settings(hooks_json)
            hooks_section = settings.get("hooks") or {}
            if any(
                _is_doberman_group(group)
                for groups in hooks_section.values()
                if isinstance(groups, list)
                for group in groups
            ):
                return True
    except Exception:  # noqa: BLE001,S110 — probing the cache must never crash the caller
        pass
    return False
