"""Install-integrity manifest for Doberman's own hook registration (issue #239).

A host hook is registered by editing the agent's settings file. Nothing used to
record what was installed, so an agent (or anything else) that strips those
entries silently removed Doberman from its own execution path. This module keeps
a per-user manifest of keyed fingerprints of the installed Doberman hook groups
and lets every surviving hook invocation, and ``doberman doctor``, notice when a
recorded registration changed.

Design rules:

* The manifest lives in the per-user config dir next to the fingerprint key,
  never inside a repository. A repo-local manifest could be deleted by the same
  actor that strips the hooks, turning "absent means intentional" into a bypass.
* Warning-only. :func:`verify_install` and :func:`note_divergence` never raise;
  callers on the hook path degrade to "no warning". The check never changes a
  hook's verdict, envelope, or exit code.
* Redaction: the manifest holds host, scope, a keyed fingerprint of the settings
  path, keyed fingerprints of the Doberman groups per event, timestamps, and a
  divergence record. Never a raw path or command.
* Speed: stdlib only at module scope; the fingerprint helper is imported lazily.
"""

from __future__ import annotations

import hmac
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

#: Env override for the manifest file (tests, unusual layouts).
MANIFEST_ENV = "DOBERMAN_INSTALL_MANIFEST"
MANIFEST_VERSION = 1
#: Events whose Doberman group is the gate itself. Losing one means Doberman is
#: no longer gating calls on that host; anything else (SessionStart) is cosmetic.
CRITICAL_EVENTS = frozenset({"PreToolUse", "PostToolUse"})


@dataclass(frozen=True)
class IntegrityStatus:
    """The verdict for one recorded (host, scope) registration."""

    host: str
    scope: str
    #: ``"intact"`` | ``"diverged"`` | ``"absent"`` (no manifest entry, or unreadable).
    state: str
    diverged_events: tuple[str, ...] = ()
    critical: bool = False
    #: ISO timestamp of the last divergence noted for this entry, if any.
    divergence_seen: str | None = None


def manifest_path() -> Path:
    override = os.environ.get(MANIFEST_ENV)
    if override:
        return Path(override)
    from doberman.storage.fingerprint import user_config_dir

    return user_config_dir() / "install-manifest.json"


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _fp(value: str) -> str:
    from doberman.storage.fingerprint import fingerprint

    return fingerprint(value)


def _path_fp(settings_path: Path) -> str:
    return _fp(str(Path(settings_path).expanduser().resolve(strict=False)))


def _group_fps(groups_by_event: dict[str, list[dict[str, Any]]]) -> dict[str, str]:
    """One keyed fingerprint per event that has at least one Doberman group.

    Canonical JSON (sorted keys, no whitespace) so formatting never counts as a
    change. Events with no Doberman group are omitted rather than fingerprinted
    as ``[]`` so a foreign addition elsewhere in the file is not a divergence.
    """
    out: dict[str, str] = {}
    for event, groups in groups_by_event.items():
        if groups:
            out[event] = _fp(json.dumps(groups, sort_keys=True, separators=(",", ":")))
    return out


def _load() -> dict[str, Any]:
    path = manifest_path()
    if not path.exists():
        return {"version": MANIFEST_VERSION, "entries": []}
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("entries"), list):
        raise ValueError("install manifest is not a manifest object")
    return data


def _save(data: dict[str, Any]) -> None:
    path = manifest_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def _matches(entry: Any, host: str, scope: str, path_fp: str) -> bool:
    return (
        isinstance(entry, dict)
        and entry.get("host") == host
        and entry.get("scope") == scope
        and entry.get("path_fp") == path_fp
    )


def _find(data: dict[str, Any], host: str, scope: str, path_fp: str) -> dict[str, Any] | None:
    return next((e for e in data["entries"] if _matches(e, host, scope, path_fp)), None)


def record_install(
    host: str,
    scope: str,
    settings_path: Path,
    groups_by_event: dict[str, list[dict[str, Any]]],
) -> None:
    """Record (or replace) the fingerprints for one installed registration.

    Replaces any previous entry for the same (host, scope, path) and clears a
    prior divergence record: a re-install is the human saying "this is the
    intended state". Raises on I/O or key failure; the CLI reports it.
    """
    data = _load()
    path_fp = _path_fp(settings_path)
    entry = {
        "host": host,
        "scope": scope,
        "path_fp": path_fp,
        "groups": _group_fps(groups_by_event),
        "recorded_at": _now(),
    }
    data["entries"] = [e for e in data["entries"] if not _matches(e, host, scope, path_fp)]
    data["entries"].append(entry)
    _save(data)


def clear_install(host: str, scope: str, settings_path: Path) -> None:
    """Forget one registration. Absent manifest or entry is a no-op.

    Called BEFORE the hooks are removed so a legitimate uninstall never trips
    the guard. Raises on I/O failure; the CLI reports it.
    """
    path = manifest_path()
    if not path.exists():
        return
    data = _load()
    path_fp = _path_fp(settings_path)
    before = len(data["entries"])
    data["entries"] = [e for e in data["entries"] if not _matches(e, host, scope, path_fp)]
    if len(data["entries"]) != before:
        _save(data)


def verify_install(
    host: str,
    scope: str,
    settings_path: Path,
    groups_by_event: dict[str, list[dict[str, Any]]],
) -> IntegrityStatus:
    """Compare the live Doberman groups against the recorded entry. Never raises.

    ``absent`` when there is no entry or anything cannot be read/fingerprinted
    (no alarm: the guard must never crash or block a hook). ``diverged`` names
    every recorded event whose group is missing or changed; events recorded
    with no Doberman group are not tracked, so additions never diverge.
    """
    try:
        data = _load()
        entry = _find(data, host, scope, _path_fp(settings_path))
        if entry is None or not isinstance(entry.get("groups"), dict):
            return IntegrityStatus(host, scope, "absent")
        live = _group_fps(groups_by_event)
        diverged: list[str] = []
        for event, recorded_fp in entry["groups"].items():
            current = live.get(event)
            if current is None or not hmac.compare_digest(str(recorded_fp), current):
                diverged.append(event)
        seen = None
        div = entry.get("diverged")
        if isinstance(div, dict) and isinstance(div.get("last_seen"), str):
            seen = div["last_seen"]
        if diverged:
            return IntegrityStatus(
                host,
                scope,
                "diverged",
                tuple(sorted(diverged)),
                critical=any(e in CRITICAL_EVENTS for e in diverged),
                divergence_seen=seen,
            )
        return IntegrityStatus(host, scope, "intact", divergence_seen=seen)
    except Exception:  # noqa: BLE001 - the guard degrades to "no alarm", never crashes a hook
        return IntegrityStatus(host, scope, "absent")


def note_divergence(host: str, scope: str, settings_path: Path, events: tuple[str, ...]) -> None:
    """Best-effort tamper record on the entry (first/last seen, count). Never raises."""
    try:
        data = _load()
        entry = _find(data, host, scope, _path_fp(settings_path))
        if entry is None:
            return
        now = _now()
        div = entry.get("diverged")
        if not isinstance(div, dict):
            div = {"events": [], "first_seen": now, "last_seen": now, "count": 0}
        div["events"] = sorted(set(div.get("events") or []) | set(events))
        div["last_seen"] = now
        div["count"] = int(div.get("count") or 0) + 1
        entry["diverged"] = div
        _save(data)
    except Exception:  # noqa: BLE001,S110 - a record-keeping failure must never reach a hook
        pass


#: Every tracked (host, scope) registration. Codex's scopes are "repo" (the
#: project-settings analog) and "user" (the global-settings analog) -- see
#: doberman.hosthooks.install_codex.resolve_codex_hooks_path.
_SCOPES: tuple[tuple[str, str], ...] = (
    ("claude", "project"),
    ("claude", "global"),
    ("claude", "local"),
    ("codex", "repo"),
    ("codex", "user"),
)


def _live_groups(
    host: str, scope: str, project_root: str
) -> tuple[Path, dict[str, list[dict[str, Any]]]]:
    """Resolve a scope's settings file and its live Doberman groups. May raise."""
    from doberman.hosthooks.install import load_settings

    if host == "claude":
        from doberman.hosthooks.install import doberman_groups, resolve_settings_path

        path = resolve_settings_path(scope, project_root)
        return path, doberman_groups(load_settings(path))
    from doberman.hosthooks.install_codex import codex_doberman_groups, resolve_codex_hooks_path

    path = resolve_codex_hooks_path(scope, project_root)
    return path, codex_doberman_groups(load_settings(path))


def check_all(project_root: str) -> list[IntegrityStatus]:
    """Verify every tracked scope for *project_root*. Never raises.

    One status per ``(host, scope)`` in :data:`_SCOPES`; a scope whose settings
    file is unreadable yields ``absent`` rather than raising.
    """
    out: list[IntegrityStatus] = []
    for host, scope in _SCOPES:
        try:
            path, groups = _live_groups(host, scope, project_root)
            out.append(verify_install(host, scope, path, groups))
        except Exception:  # noqa: BLE001 - an unreadable settings file is "absent", never a crash
            out.append(IntegrityStatus(host, scope, "absent"))
    return out


def hook_warning(project_root: str) -> str | None:
    """The one-line warning a hook attaches when a recorded registration diverged.

    Cheap when there is nothing to check (no manifest file: return without
    reading any settings file). Never raises; any failure is "no warning".
    """
    try:
        if not manifest_path().exists():
            return None
        diverged = [s for s in check_all(project_root) if s.state == "diverged"]
        if not diverged:
            return None
        for s in diverged:
            try:
                path, _ = _live_groups(s.host, s.scope, project_root)
                note_divergence(s.host, s.scope, path, s.diverged_events)
            except Exception:  # noqa: BLE001,S110
                pass
        from doberman.branding import DOG

        where = ", ".join(f"{s.host} {s.scope}: {'/'.join(s.diverged_events)}" for s in diverged)
        return (
            f"{DOG} Doberman: hook registration changed since install ({where}). "
            "Doberman may not be gating every call here. Run `doberman doctor`, "
            "then `doberman install-hooks` to restore."
        )
    except Exception:  # noqa: BLE001 - warning-only; never reaches the hook's decision
        return None
