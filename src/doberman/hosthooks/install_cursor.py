"""Idempotent install/uninstall of Doberman's Cursor hook into a hooks.json.

Cursor's ``hooks.json`` is FLAT (from the adapter README, ``docs/CONNECTOR_MEMO_CURSOR.md``):
``{"version": 1, "hooks": {"<event>": [{"command": "...", "timeout": <seconds>,
"failClosed": <bool>}]}}`` — one entry per list, no nested ``hooks`` list, no
``matcher``. That shape means the Claude/Codex ``_is_doberman_group`` sentinel
(which looks for a ``hooks`` sub-list) never matches a Cursor entry, so this
module carries its own entry predicate (:func:`_is_doberman_entry`) rather than
reusing :mod:`doberman.hosthooks.install`'s.

Doberman registers ONE command, ``doberman hook cursor``, for every gating event
(:data:`GATE_EVENTS`) plus ``sessionStart`` (a liveness heartbeat, not a gate —
see :mod:`doberman.hosthooks.cursor`). Every gating entry carries
``"failClosed": true``: Cursor's own default is fail-OPEN on a hook crash or
timeout, and this flag is what turns that into a deny. The gate timeout is set
comfortably above Doberman's own approval dialog (:data:`GATE_TIMEOUT_S`) so an
unanswered AUTH is denied by the human, not by Cursor's clock.

This mirrors :mod:`doberman.hosthooks.install_codex` in shape (pure merge/remove
functions never mutate their inputs, so they are trivially unit-testable) and
reuses its format-agnostic JSON I/O (:func:`~doberman.hosthooks.install.load_settings`).

Scopes: ``user`` -> ``~/.cursor/hooks.json`` (every project), ``project`` ->
``<project_root>/.cursor/hooks.json``. There is no Cursor equivalent of Claude
Code's ``settings.local.json`` "local" scope.
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

from doberman.auth.approval import DEFAULT_APPROVAL_TIMEOUT_S
from doberman.hosthooks.install import load_settings

# Event names and the marker filename are LITERALS, not imports from
# doberman.hosthooks.cursor: that module pulls the whole adapter stack (config,
# policy, egress - ~400 ms), and this one is imported on EVERY host's hook hot
# path by the install-integrity check once a manifest exists.
# tests/unit/test_install_hooks_cursor.py pins them to the adapter's constants.
EVENT_PRE_TOOL = "preToolUse"
EVENT_SHELL = "beforeShellExecution"
EVENT_MCP = "beforeMCPExecution"
EVENT_READ = "beforeReadFile"
EVENT_SESSION_START = "sessionStart"
SESSION_MARKER = "cursor_session"

#: The command every Cursor hook entry runs.
HOOK_COMMAND = "doberman hook cursor"

#: The four gating events, in registration order (matches the adapter README).
GATE_EVENTS: tuple[str, ...] = (EVENT_PRE_TOOL, EVENT_SHELL, EVENT_MCP, EVENT_READ)

#: Cursor's per-hook timeout (seconds) must outlast Doberman's in-hook approval dialog, or an
#: unanswered AUTH is denied by the timeout instead of the human.
GATE_TIMEOUT_S = int(DEFAULT_APPROVAL_TIMEOUT_S) + 30  # 120

#: sessionStart is a cosmetic heartbeat, not a gate — a short timeout is fine, and
#: `failClosed: false` (see session_start_entry) means it can never abort a session.
SESSION_START_TIMEOUT_S = 10

#: Sentinel substring used to detect Doberman-owned entries (same marker family as
#: doberman.hosthooks.install / install_codex's "doberman hook " sentinel).
_DOBERMAN_MARKER = "doberman hook "


def gate_entry() -> dict[str, Any]:
    """One Doberman entry for a gating event."""
    return {"command": HOOK_COMMAND, "timeout": GATE_TIMEOUT_S, "failClosed": True}


def session_start_entry() -> dict[str, Any]:
    """Doberman's sessionStart entry.

    ``failClosed`` is False ON PURPOSE: a failed heartbeat must never abort a
    session; it is a liveness record, not a gate.
    """
    return {"command": HOOK_COMMAND, "timeout": SESSION_START_TIMEOUT_S, "failClosed": False}


def _is_doberman_entry(entry: Any) -> bool:
    """True if *entry* is a dict whose ``command`` names a Doberman hook."""
    if not isinstance(entry, dict):
        return False
    cmd = entry.get("command")
    return isinstance(cmd, str) and _DOBERMAN_MARKER in cmd


def merge_cursor_hooks(settings: dict[str, Any]) -> dict[str, Any]:
    """Return a *new* hooks.json dict with Doberman's entries added/replaced.

    Existing non-Doberman entries, foreign events, and every other top-level key
    are preserved. ``version`` defaults to ``1`` when absent; an existing value
    is kept. **Idempotent:** a pre-existing Doberman entry for an event is
    replaced (never duplicated) — calling this twice yields the same result as
    calling it once. Never mutates *settings*.
    """
    result: dict[str, Any] = copy.deepcopy(settings)
    result.setdefault("version", 1)
    hooks: dict[str, Any] = copy.deepcopy(result.get("hooks") or {})

    for event in (*GATE_EVENTS, EVENT_SESSION_START):
        existing: list[Any] = list(hooks.get(event) or [])
        non_doberman = [e for e in existing if not _is_doberman_entry(e)]
        entry = gate_entry() if event in GATE_EVENTS else session_start_entry()
        hooks[event] = [*non_doberman, entry]

    result["hooks"] = hooks
    return result


def remove_cursor_hooks(settings: dict[str, Any]) -> dict[str, Any]:
    """Return a *new* hooks.json dict with Doberman's entries removed.

    Non-Doberman entries and every other key (including ``version``) are
    preserved. Empty event lists are dropped; if ``hooks`` becomes empty it is
    removed too. A no-op when ``hooks`` is absent.
    """
    result: dict[str, Any] = copy.deepcopy(settings)
    if "hooks" not in result:
        return result

    hooks: dict[str, Any] = copy.deepcopy(result["hooks"])
    cleaned: dict[str, Any] = {}
    for event, entries in hooks.items():
        if not isinstance(entries, list):
            cleaned[event] = entries
            continue
        kept = [e for e in entries if not _is_doberman_entry(e)]
        if kept:
            cleaned[event] = kept

    if cleaned:
        result["hooks"] = cleaned
    else:
        del result["hooks"]
    return result


def cursor_doberman_groups(settings: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Doberman-owned entries per event, for the install manifest.

    Only list-valued events are considered, and the fingerprint input is the
    WHOLE entry (command, timeout, failClosed), so weakening ``failClosed`` or
    lowering ``timeout`` counts as a divergence.
    """
    hooks_section = settings.get("hooks") or {}
    out: dict[str, list[dict[str, Any]]] = {}
    for event, entries in hooks_section.items():
        if not isinstance(entries, list):
            continue
        ours = [e for e in entries if isinstance(e, dict) and _is_doberman_entry(e)]
        if ours:
            out[event] = ours
    return out


def resolve_cursor_hooks_path(scope: str, project_root: str) -> Path:
    """Resolve the target ``hooks.json`` path for *scope*.

    ``user`` -> ``~/.cursor/hooks.json`` · ``project`` -> ``<project_root>/.cursor/hooks.json``.

    Raises:
        ValueError: if *scope* is not ``"user"`` or ``"project"``.
    """
    match scope:
        case "user":
            return Path.home() / ".cursor" / "hooks.json"
        case "project":
            return Path(project_root) / ".cursor" / "hooks.json"
        case _:
            raise ValueError(f"Unknown Cursor scope {scope!r}; expected 'user' or 'project'.")


def cursor_hook_install_states(project_root: str) -> list[tuple[str, str, bool]]:
    """Report, per Cursor scope, whether Doberman's hooks are wired in.

    Returns ``(scope, path, installed)`` for ``user`` then ``project``.
    **Never raises:** an unreadable or unparseable hooks.json is reported as
    *not installed* rather than crashing ``status`` / ``doctor``.
    """
    states: list[tuple[str, str, bool]] = []
    for scope in ("user", "project"):
        path = resolve_cursor_hooks_path(scope, project_root)
        installed = False
        try:
            settings = load_settings(path)
            hooks_section = settings.get("hooks") or {}
            installed = any(
                _is_doberman_entry(entry)
                for entries in hooks_section.values()
                if isinstance(entries, list)
                for entry in entries
            )
        except Exception:  # noqa: BLE001,S110 — a bad hooks.json must not crash the caller
            pass
        states.append((scope, str(path), installed))
    return states


def registration_issues(settings: dict[str, Any]) -> list[tuple[str, bool]]:
    """Weaknesses in the live registration, as ``(message, critical)`` pairs.

    Checked in this order, per gate event (:data:`GATE_EVENTS`): not registered
    at all (critical) · registered but ``failClosed`` is not ``True`` (critical,
    since Cursor fails OPEN otherwise) · a timeout below the approval window
    (non-critical: late, not silently open). Then, once: ``sessionStart`` not
    registered (non-critical — cosmetic, but doctor loses its liveness signal).
    """
    hooks_section = settings.get("hooks") or {}

    def _doberman_entries(event: str) -> list[dict[str, Any]]:
        entries = hooks_section.get(event)
        if not isinstance(entries, list):
            return []
        return [e for e in entries if isinstance(e, dict) and _is_doberman_entry(e)]

    issues: list[tuple[str, bool]] = []
    for event in GATE_EVENTS:
        entries = _doberman_entries(event)
        if not entries:
            issues.append((f"{event}: not registered", True))
            continue
        entry = entries[-1]
        if entry.get("failClosed") is not True:
            issues.append(
                (
                    f"{event}: failClosed is not true (Cursor fails OPEN on a hook crash or timeout)",
                    True,
                )
            )
        timeout = entry.get("timeout")
        is_number = isinstance(timeout, (int, float)) and not isinstance(timeout, bool)
        if not is_number or timeout < DEFAULT_APPROVAL_TIMEOUT_S:
            issues.append(
                (
                    f"{event}: timeout {f'{timeout}s' if is_number else 'missing'} is below the "
                    f"{int(DEFAULT_APPROVAL_TIMEOUT_S)}s approval window "
                    "(an unanswered approval is denied early)",
                    False,
                )
            )

    if not _doberman_entries(EVENT_SESSION_START):
        issues.append(
            (
                "sessionStart: not registered (no session heartbeat; doctor cannot tell "
                "whether hooks fire)",
                False,
            )
        )
    return issues


def session_marker_path(project_root: str) -> Path:
    """Where :func:`doberman.hosthooks.cursor.record_session_start` writes its heartbeat."""
    from doberman.storage.db import CONFIG_DIR

    return Path(project_root) / CONFIG_DIR / SESSION_MARKER


def last_session_start(project_root: str) -> str | None:
    """The marker's ISO timestamp text, or ``None`` if absent/unreadable/unparseable.

    Never raises: a missing or corrupt marker just means "no session seen yet",
    not a doctor crash.
    """
    from datetime import datetime

    try:
        text = session_marker_path(project_root).read_text(encoding="utf-8").strip()
        datetime.fromisoformat(text)
    except Exception:  # noqa: BLE001 — an unreadable/unparseable marker is "no session yet"
        return None
    return text
