"""Best-effort "a newer Doberman is on PyPI" notice — CLI-only and fail-open.

This module is never imported by the hook or proxy hot paths, and every public
operation is best-effort: any error (network, parse, disk) is swallowed and the
CLI proceeds silently. It never blocks a tool call and never raises.

PyPI is queried at most once per :data:`DEFAULT_INTERVAL`; the result is cached
under the user's ``.doberman`` dir. Between checks the cached latest version
drives the notice with no network at all, so the common path is a cheap file
read. The passive notice (``doberman status``) refreshes in the background and
shows on the *next* run — it never waits on the network; the explicit
``doberman update`` command does one synchronous, timeout-bounded check.

Respecting ``DO_NOT_TRACK`` / ``CI`` is politeness, not privacy-critical: the
check sends nothing but a normal PyPI GET (the same request ``pip`` makes). It is
on by default; ``DOBERMAN_UPDATE_CHECK=off`` turns it off.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

from doberman import __version__
from doberman.storage.device_metrics import HOME_ENV

logger = logging.getLogger("doberman.update_check")

#: PyPI's JSON metadata endpoint for the distribution.
PYPI_JSON_URL = "https://pypi.org/pypi/doberman-core/json"
#: One-line upgrade instruction shown to the user (we never run pip for them).
UPGRADE_HINT = "pip install -U doberman-core"

_CACHE_NAME = "update-check.json"
#: How stale the cached "latest" may get before we hit PyPI again.
DEFAULT_INTERVAL = timedelta(hours=24)
_TIMEOUT_S = 2.0


def _now() -> datetime:
    return datetime.now(timezone.utc)


def disabled_reason() -> str | None:
    """Why the update check is off right now, or ``None`` if it may run."""
    do_not_track = os.environ.get("DO_NOT_TRACK", "")
    if do_not_track and do_not_track != "0":
        return "DO_NOT_TRACK is set"
    if os.environ.get("DOBERMAN_UPDATE_CHECK", "").lower() in {"0", "false", "off", "no"}:
        return "DOBERMAN_UPDATE_CHECK disables the update check"
    if os.environ.get("CI", ""):
        return "CI is set"
    return None


def _cache_path(home: Path | None = None) -> Path:
    base = home if home is not None else Path(os.environ.get(HOME_ENV) or Path.home())
    return base / ".doberman" / _CACHE_NAME


def _read_cache(home: Path | None = None) -> dict:
    try:
        return json.loads(_cache_path(home).read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001 — a missing/corrupt cache is just "unknown"
        return {}


def _write_cache(latest: str, home: Path | None = None) -> None:
    try:
        path = _cache_path(home)
        path.parent.mkdir(parents=True, exist_ok=True)
        stamp = _now().isoformat().replace("+00:00", "Z")
        path.write_text(json.dumps({"checked_at": stamp, "latest": latest}), encoding="utf-8")
    except Exception:  # noqa: BLE001 — caching is best-effort; never break the CLI
        logger.debug("could not write update-check cache", exc_info=True)


def _parse(version: object) -> tuple[int, ...]:
    """Leading numeric ``X.Y.Z`` parts as a tuple; ``()`` on anything unparseable.

    ponytail: compares only the numeric release prefix — a pre-release/dev suffix
    (``1.2.0rc1``) is treated as ``(1, 2, 0)``, so we never nag toward a
    pre-release. Swap in ``packaging.version`` if suffix-aware ordering matters.
    """
    out: list[int] = []
    for part in str(version).split("."):
        digits = ""
        for ch in part:
            if ch.isdigit():
                digits += ch
            else:
                break
        if not digits:
            break
        out.append(int(digits))
    return tuple(out)


def is_newer(latest: object, current: object) -> bool:
    """True only if ``latest`` parses to a strictly higher release than ``current``."""
    latest_parts = _parse(latest)
    return bool(latest_parts) and latest_parts > _parse(current)


def fetch_latest() -> str | None:
    """GET the latest version string from PyPI, or ``None`` on any failure."""
    try:
        with urllib.request.urlopen(  # noqa: S310 — constant https URL, not user input
            PYPI_JSON_URL, timeout=_TIMEOUT_S
        ) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        latest = data.get("info", {}).get("version")
        return latest if isinstance(latest, str) and latest else None
    except Exception:  # noqa: BLE001 — fail open: an unreachable PyPI is not an error
        logger.debug("PyPI update check failed", exc_info=True)
        return None


def _cache_fresh(cache: dict, now: datetime) -> bool:
    stamp = cache.get("checked_at")
    try:
        checked_at = datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return False
    if checked_at.tzinfo is None:
        checked_at = checked_at.replace(tzinfo=timezone.utc)
    return now - checked_at < DEFAULT_INTERVAL


def refresh(home: Path | None = None, *, force: bool = False) -> str | None:
    """Return the latest version, hitting PyPI only if due (or ``force``). Synchronous.

    Returns the cached value when the cache is still fresh, the fetched value when
    a fetch succeeds (and caches it), or the stale cached value if the fetch fails.
    Returns ``None`` when the check is disabled or nothing is known.
    """
    if disabled_reason():
        return None
    cache = _read_cache(home)
    if not force and _cache_fresh(cache, _now()):
        return cache.get("latest")
    latest = fetch_latest()
    if latest:
        _write_cache(latest, home)
        return latest
    return cache.get("latest")


def refresh_async(home: Path | None = None) -> None:
    """Kick a background refresh in a daemon thread. Never blocks or raises.

    A no-op when disabled or when the cache is still fresh (so the common case
    starts no thread and touches no network)."""
    if disabled_reason():
        return
    if _cache_fresh(_read_cache(home), _now()):
        return
    threading.Thread(target=lambda: refresh(home), daemon=True).start()


def pending_notice(home: Path | None = None) -> str | None:
    """A one-line upgrade notice if the cached latest beats the installed version.

    Reads only the cache — no network — so it is safe to call on any human CLI
    command. ``None`` when disabled, unknown, or already current.
    """
    if disabled_reason():
        return None
    latest = _read_cache(home).get("latest")
    if isinstance(latest, str) and is_newer(latest, __version__):
        return (
            f"A new Doberman is available: {latest} (you have {__version__}). "
            f"Upgrade with: {UPGRADE_HINT}"
        )
    return None
