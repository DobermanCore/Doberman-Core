"""Opt-in, anonymous CLI usage telemetry.

This module is deliberately stdlib-only and CLI-only. It is never imported by
the hook or proxy hot paths, and every public operation is best-effort.
"""

from __future__ import annotations

import atexit
import json
import os
import platform
import re
import sys
import threading
import time
import urllib.request
import uuid
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from doberman import __version__
from doberman.storage.device_metrics import HOME_ENV, read_metrics

POSTHOG_HOST = "https://us.i.posthog.com"
POSTHOG_PROJECT_KEY = "phc_znQ8ksFQhXYhQKTvA3Qr8QpqH5NfbE9cQropAxefUDWs"
ENV_KEY = "DOBERMAN_POSTHOG_KEY"
_PLACEHOLDER_PREFIX = "phc_REPLACE"

#: Printed once, to stderr, by the first CLI command that runs under the default-on state.
FIRST_RUN_NOTICE = (
    "Doberman sends anonymous usage counts (command names and daily totals; never paths, "
    "prompts, or secrets). Turn it off with `doberman telemetry off` or DO_NOT_TRACK=1. "
    "Details: docs/TELEMETRY.md"
)

_STATE_NAME = "telemetry.json"
_VALUE_PATTERN = re.compile(r"^[A-Za-z0-9_.+-]*$")
_EVENT_PROPERTIES = {
    "telemetry_enabled": frozenset(),
    "telemetry_disabled": frozenset(),
    "setup_completed": frozenset({"mode", "host", "hooks_installed", "global_install", "source"}),
    "cli_command": frozenset({"command"}),
    "usage_summary": frozenset({"total", "pass", "auth", "block", "days_since_first_seen"}),
}
_SENDER_THREADS: list[threading.Thread] = []
_THREADS_LOCK = threading.Lock()
_SUMMARY_LOCK = threading.Lock()


@dataclass(frozen=True)
class TelemetryState:
    """Local consent state; ``forced_off_reasons`` is computed, never persisted.

    Default-on: with no state file telemetry is enabled, ``consent_at`` stays ``None`` until
    the person makes an explicit choice, and ``notice_shown`` records the one-time notice.
    """

    enabled: bool = True
    distinct_id: str = ""
    consent_at: datetime | None = None
    last_summary_at: datetime | None = None
    notice_shown: bool = False
    forced_off_reasons: tuple[str, ...] = ()


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return _as_utc(value).isoformat().replace("+00:00", "Z")


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _state_path(home: Path | None = None) -> Path:
    base = home if home is not None else Path(os.environ.get(HOME_ENV) or Path.home())
    return base / ".doberman" / _STATE_NAME


def _read_state(home: Path | None = None) -> TelemetryState:
    try:
        raw = json.loads(_state_path(home).read_text(encoding="utf-8"))
        return TelemetryState(
            enabled=raw.get("enabled") is not False,
            distinct_id=raw.get("distinct_id") if isinstance(raw.get("distinct_id"), str) else "",
            consent_at=_parse_time(raw.get("consent_at")),
            last_summary_at=_parse_time(raw.get("last_summary_at")),
            notice_shown=raw.get("notice_shown") is True,
        )
    except Exception:  # noqa: BLE001 — telemetry state must never affect the CLI
        return TelemetryState()


def _write_state(state: TelemetryState, home: Path | None = None) -> None:
    try:
        path = _state_path(home)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_text(
            json.dumps(
                {
                    "enabled": state.enabled,
                    "distinct_id": state.distinct_id,
                    "consent_at": _iso(state.consent_at),
                    "last_summary_at": _iso(state.last_summary_at),
                    "notice_shown": state.notice_shown,
                },
                separators=(",", ":"),
            ),
            encoding="utf-8",
        )
        try:
            os.chmod(path.parent, 0o700)
            os.chmod(path, 0o600)
        except OSError:
            pass
    except Exception:  # noqa: BLE001 — telemetry state must never affect the CLI
        return


def _project_key() -> str:
    return os.environ.get(ENV_KEY) or POSTHOG_PROJECT_KEY


def _forced_off_reasons() -> tuple[str, ...]:
    reasons = []
    do_not_track = os.environ.get("DO_NOT_TRACK", "")
    if do_not_track and do_not_track != "0":
        reasons.append("DO_NOT_TRACK is set")
    if os.environ.get("DOBERMAN_TELEMETRY", "").lower() in {"0", "false", "off"}:
        reasons.append("DOBERMAN_TELEMETRY disables telemetry")
    if os.environ.get("CI", ""):
        reasons.append("CI is set")
    if _project_key().startswith(_PLACEHOLDER_PREFIX):
        reasons.append("PostHog project key is still the placeholder")
    return tuple(reasons)


def status(home: Path | None = None) -> TelemetryState:
    """Return local consent state and any active forced-off reasons."""
    try:
        return replace(_read_state(home), forced_off_reasons=_forced_off_reasons())
    except Exception:  # noqa: BLE001 — telemetry status must never affect the CLI
        return TelemetryState(forced_off_reasons=("telemetry state unavailable",))


def is_enabled(home: Path | None = None) -> bool:
    """Return whether consent, environment, and project key permit a send."""
    try:
        state = status(home)
        return state.enabled and not state.forced_off_reasons
    except Exception:  # noqa: BLE001 — telemetry must default off
        return False


def _ensure_id(home: Path | None = None) -> TelemetryState:
    """Return the state with a persisted anonymous id, creating one on the first send."""
    current = _read_state(home)
    if current.distinct_id:
        return current
    state = replace(current, distinct_id=str(uuid.uuid4()))
    _write_state(state, home)
    return state


def first_run_notice(home: Path | None = None) -> str | None:
    """Return the one-time notice the first time the default-on state can actually send."""
    try:
        state = _read_state(home)
        if state.notice_shown or not is_enabled(home):
            return None
        _write_state(replace(state, notice_shown=True), home)
        return FIRST_RUN_NOTICE
    except Exception:  # noqa: BLE001 — a notice must never affect the CLI
        return None


def enable(home: Path | None = None) -> TelemetryState:
    """Persist opt-in consent and best-effort emit ``telemetry_enabled``."""
    try:
        current = _read_state(home)
        state = replace(
            current,
            enabled=True,
            distinct_id=current.distinct_id or str(uuid.uuid4()),
            consent_at=current.consent_at or _utc_now(),
            notice_shown=True,
            forced_off_reasons=(),
        )
        _write_state(state, home)
        capture("telemetry_enabled", home=home)
        return status(home)
    except Exception:  # noqa: BLE001 — telemetry controls must never affect the CLI
        return status(home)


def disable(home: Path | None = None) -> TelemetryState:
    """Emit one final event, then persist disabled state without rotating the id."""
    try:
        current = _read_state(home)
        if current.enabled:
            capture("telemetry_disabled", home=home)
        _write_state(
            replace(
                current,
                enabled=False,
                consent_at=current.consent_at or _utc_now(),
                notice_shown=True,
            ),
            home,
        )
        return status(home)
    except Exception:  # noqa: BLE001 — telemetry controls must never affect the CLI
        return status(home)


def base_properties() -> dict:
    """Return the complete fixed property set shared by every event."""
    return {
        "$process_person_profile": False,
        "$geoip_disable": True,
        "$lib": "doberman-cli",
        "version": __version__,
        "os": platform.system().lower(),
        "python": f"{sys.version_info.major}.{sys.version_info.minor}",
    }


def _valid_value(value: object) -> bool:
    if not isinstance(value, str | int | float | bool | None):
        return False
    return not isinstance(value, str) or (
        len(value) <= 64 and _VALUE_PATTERN.fullmatch(value) is not None
    )


def _join_sender_threads(
    threads: list[threading.Thread] | None = None, *, timeout: float = 1.0
) -> None:
    """Join sender threads within one shared wall-clock budget."""
    try:
        if threads is None:
            with _THREADS_LOCK:
                threads = list(_SENDER_THREADS)
        deadline = time.monotonic() + timeout
        for thread in threads:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            thread.join(remaining)
    except Exception:  # noqa: BLE001 — shutdown must never delay or break CLI exit
        return


atexit.register(_join_sender_threads)


def capture(
    event: str,
    properties: dict | None = None,
    *,
    home: Path | None = None,
    now: datetime | None = None,
) -> None:
    """Queue one allowlisted event in a daemon thread; never raise or do network inline."""
    try:
        allowed = _EVENT_PROPERTIES.get(event)
        if allowed is None or not _valid_value(event) or not is_enabled(home):
            return
        extras = {key: value for key, value in (properties or {}).items() if key in allowed}
        event_properties = base_properties() | extras
        if not all(_valid_value(value) for value in event_properties.values()):
            return
        state = _ensure_id(home)
        uuid.UUID(state.distinct_id, version=4)
        payload = json.dumps(
            {
                "api_key": _project_key(),
                "event": event,
                "distinct_id": state.distinct_id,
                "properties": event_properties,
                "timestamp": _iso(_as_utc(now or _utc_now())),
            },
            separators=(",", ":"),
        ).encode("utf-8")
        request = urllib.request.Request(  # noqa: S310 — fixed HTTPS host
            f"{POSTHOG_HOST}/i/v0/e/",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        def send() -> None:
            try:
                with urllib.request.urlopen(request, timeout=3):  # noqa: S310 — fixed HTTPS host
                    pass
            except Exception:  # noqa: BLE001 — telemetry transport is best-effort
                return
            finally:
                with _THREADS_LOCK:
                    if thread in _SENDER_THREADS:
                        _SENDER_THREADS.remove(thread)

        thread = threading.Thread(target=send, name="doberman-telemetry", daemon=True)
        with _THREADS_LOCK:
            _SENDER_THREADS.append(thread)
        try:
            thread.start()
        except Exception:  # noqa: BLE001 — thread startup must never affect the CLI
            with _THREADS_LOCK:
                if thread in _SENDER_THREADS:
                    _SENDER_THREADS.remove(thread)
    except Exception:  # noqa: BLE001 — telemetry must never affect the CLI
        return


def maybe_send_usage_summary(home: Path | None = None, now: datetime | None = None) -> bool:
    """Queue the local aggregate at most once per 24 hours."""
    try:
        current_time = _as_utc(now or _utc_now())
        with _SUMMARY_LOCK:
            state = _read_state(home)
            if not is_enabled(home) or (
                state.last_summary_at is not None
                and current_time - state.last_summary_at < timedelta(hours=24)
            ):
                return False
            metrics = read_metrics(home=home)
            first_seen = metrics.get("first_seen")
            days = 0
            if isinstance(first_seen, str):
                days = max(
                    0, (current_time.date() - datetime.fromisoformat(first_seen).date()).days
                )
            capture(
                "usage_summary",
                {
                    "total": int(metrics["total"]),
                    "pass": int(metrics["pass"]),
                    "auth": int(metrics["auth"]),
                    "block": int(metrics["block"]),
                    "days_since_first_seen": days,
                },
                home=home,
                now=current_time,
            )
            _write_state(replace(state, last_summary_at=current_time), home)
            return True
    except Exception:  # noqa: BLE001 — telemetry summaries must never affect the CLI
        return False
