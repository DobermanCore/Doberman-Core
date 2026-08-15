"""
doberman.storage.otel_sink
~~~~~~~~~~~~~~~~~~~~~~~~~~
OpenTelemetry AuditSink — ships the redacted decision record to any OTLP collector.

This is the second **built-in** concrete sink (after :class:`WebhookAuditSink`).
It is config-gated via ``.doberman/audit_otel.yaml`` and active only when that
file is present and valid.  :func:`doberman.storage.sinks.emit_to_sinks` calls
it alongside the webhook sink on the same fan-out path.

Design contract (mirrors :class:`WebhookAuditSink` in ``storage/sinks.py``):
  - ``emit()`` enqueues the record and returns before any network I/O.
  - Active-state check and enqueue are atomic under ``_state_lock`` so a
    concurrent ``close()`` cannot strand a record with no consumer.
  - ``close()`` flips ``_active`` to ``False`` atomically, sets the stop event,
    then joins the worker with a bounded timeout.  Idempotent; never raises.
  - Queue overflow drops the *oldest* record and increments a counter.
  - Config lives in ``.doberman/audit_otel.yaml``.  Absent or malformed config
    → the sink is inert (zero network I/O, zero side-effects).
  - The sink exports *only* the allowlisted fields; it adds none of its own.
  - Auth token comes from a named env-var only; never stored, never logged.

Allowlisted record fields (same set the webhook sink may see upstream):
    timestamp, verdict, tool, reason_codes, explanation, session_id

OTLP/HTTP endpoint:
    POST <endpoint>/v1/logs  (JSON, application/json)
    Each record becomes one LogRecord in a ResourceLogs payload.

Dependencies: stdlib only (``urllib.request``, ``json``, ``queue``,
``threading``, ``os``, ``logging``, ``pathlib``). No opentelemetry-sdk
import required — we speak the wire protocol directly so any OTLP-capable
collector works without extra dependencies.
"""

from __future__ import annotations

import json
import logging
import os
import queue
import threading
import time
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

logger = logging.getLogger(__name__)

# ── constants ────────────────────────────────────────────────────────────────

_CONFIG_FILENAME = "audit_otel.yaml"
_DEFAULT_TIMEOUT_S = 5.0
_DEFAULT_QUEUE_MAX = 1_000
_OTLP_LOG_PATH = "/v1/logs"
_DRAIN_POLL_S = 0.05

# The *only* fields that leave the process.  Already redacted upstream; we
# re-filter here as defence-in-depth so upstream contract drift never leaks.
_ALLOWED_FIELDS: frozenset[str] = frozenset(
    {"timestamp", "verdict", "tool", "reason_codes", "explanation", "session_id"}
)


# ── endpoint validation (mirrors _is_loopback / _load_webhook_config) ────────


def _is_loopback(host: str) -> bool:
    """Mirror of sinks.py _is_loopback — covers IPv4 127.x, ::1, localhost."""
    h = host.strip("[]").lower()
    if h in ("localhost", "::1"):
        return True
    parts = h.split(".")
    if len(parts) == 4 and parts[0] == "127":
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False
    return False


def _validate_endpoint(endpoint: str) -> str | None:
    """Accept only http/https schemes; reject loopback hosts.

    Returns the normalised endpoint string (trailing slash stripped), or
    ``None`` on rejection with a warning already logged.
    """
    try:
        parsed = urlparse(endpoint)
    except Exception:  # noqa: BLE001
        return None

    if parsed.scheme not in ("http", "https"):
        logger.warning(
            "audit_otel: endpoint scheme %r is not http/https — sink disabled",
            parsed.scheme,
        )
        return None

    if _is_loopback(parsed.hostname or ""):
        logger.warning(
            "audit_otel: endpoint %r is a loopback address — sink disabled",
            endpoint,
        )
        return None

    return endpoint.rstrip("/")


# ── config loading ────────────────────────────────────────────────────────────


def _load_config(policy_dir: Path) -> dict | None:
    """Parse ``.doberman/audit_otel.yaml``.

    Returns a config dict on success, or ``None`` when the file is absent,
    unreadable, missing ``endpoint``, or the endpoint fails validation.
    Never raises.
    """
    cfg_path = policy_dir / _CONFIG_FILENAME
    if not cfg_path.exists():
        return None
    try:
        raw = yaml.safe_load(cfg_path.read_text()) or {}
    except Exception as exc:  # noqa: BLE001
        logger.warning("audit_otel: could not read config (%s) — sink disabled", exc)
        return None

    if not isinstance(raw, dict):
        logger.warning("audit_otel: config is not a mapping — sink disabled")
        return None

    raw_endpoint = raw.get("endpoint", "").strip()
    if not raw_endpoint:
        logger.warning("audit_otel: 'endpoint' missing or empty — sink disabled")
        return None

    endpoint = _validate_endpoint(raw_endpoint)
    if endpoint is None:
        return None  # warning already logged

    timeout_raw = raw.get("timeout_s", _DEFAULT_TIMEOUT_S)
    try:
        timeout_s = float(timeout_raw)
        if timeout_s <= 0:
            raise ValueError("timeout must be positive")
    except (TypeError, ValueError):
        logger.warning("audit_otel: invalid 'timeout_s' %r; using default", timeout_raw)
        timeout_s = _DEFAULT_TIMEOUT_S

    queue_max_raw = raw.get("queue_max", _DEFAULT_QUEUE_MAX)
    try:
        queue_max = int(queue_max_raw)
        if queue_max <= 0:
            raise ValueError("queue_max must be positive")
    except (TypeError, ValueError):
        logger.warning("audit_otel: invalid 'queue_max' %r; using default", queue_max_raw)
        queue_max = _DEFAULT_QUEUE_MAX

    return {
        "endpoint": endpoint,
        "auth_env": raw.get("auth_env") or None,
        "timeout_s": timeout_s,
        "queue_max": queue_max,
    }


# ── OTLP payload builder ─────────────────────────────────────────────────────


def _build_otlp_payload(record: dict[str, Any]) -> bytes:
    """Wrap a redacted record in a minimal OTLP/HTTP LogRecord payload (JSON)."""
    safe = {k: v for k, v in record.items() if k in _ALLOWED_FIELDS}
    ts_ns = _timestamp_to_ns(safe.get("timestamp"))
    attributes = [
        {"key": k, "value": {"stringValue": str(v)}} for k, v in safe.items() if k != "timestamp"
    ]
    log_record = {
        "timeUnixNano": str(ts_ns),
        "observedTimeUnixNano": str(int(time.time() * 1e9)),
        "body": {"stringValue": json.dumps(safe)},
        "attributes": attributes,
    }
    payload = {
        "resourceLogs": [
            {
                "resource": {
                    "attributes": [{"key": "service.name", "value": {"stringValue": "doberman"}}]
                },
                "scopeLogs": [
                    {
                        "scope": {"name": "doberman.audit"},
                        "logRecords": [log_record],
                    }
                ],
            }
        ]
    }
    return json.dumps(payload).encode()


def _timestamp_to_ns(ts: Any) -> int:
    if ts is None:
        return int(time.time() * 1e9)
    if isinstance(ts, (int, float)):
        return int(ts * 1e9)
    try:
        import datetime

        if isinstance(ts, str):
            dt = datetime.datetime.fromisoformat(ts)
            return int(dt.timestamp() * 1e9)
    except Exception:  # noqa: BLE001
        logger.debug("audit_otel: could not parse timestamp %r — using current time", ts)
    return int(time.time() * 1e9)


# ── public sink ───────────────────────────────────────────────────────────────


class OtelAuditSink:
    """Built-in OTLP/HTTP forwarder for the ``AuditSink`` seam.

    Mirrors :class:`WebhookAuditSink` exactly: same ``_state_lock`` /
    ``_active`` pattern, same ``close()`` contract, same ``from_repo()``
    classmethod, same queue-overflow semantics, same secret hygiene.

    Activated by ``.doberman/audit_webhook.yaml`` → this one by
    ``.doberman/audit_otel.yaml``.  With no file (or a malformed one) the
    sink is **inert**: :meth:`emit` returns immediately with no I/O.
    """

    def __init__(self, config: dict | None) -> None:
        self._active = False
        self._endpoint: str = ""
        self._auth_env: str | None = None
        self._timeout_s: float = _DEFAULT_TIMEOUT_S
        self._queue: queue.Queue[dict] = queue.Queue(maxsize=0)
        self._drops = 0
        self._drops_lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._worker_thread: threading.Thread | None = None

        if not config:
            return

        self._endpoint = config["endpoint"]
        self._auth_env = config.get("auth_env")
        self._timeout_s = float(config.get("timeout_s", _DEFAULT_TIMEOUT_S))
        queue_max = int(config.get("queue_max", _DEFAULT_QUEUE_MAX))
        self._queue = queue.Queue(maxsize=queue_max)

        worker = threading.Thread(target=self._worker, daemon=True, name="doberman-otel-sink")
        try:
            worker.start()
        except Exception:  # noqa: BLE001 — cache failure as inert; no retry storm
            logger.warning("audit_otel: failed to start worker thread; sink is inert")
            return

        self._worker_thread = worker
        self._active = True

    @classmethod
    def from_repo(cls, repo_root: str) -> OtelAuditSink:
        """Construct from the repo's ``.doberman/audit_otel.yaml``.

        Returns an inert sink when the config file is absent or malformed.
        """
        policy_dir = Path(repo_root) / ".doberman"
        return cls(_load_config(policy_dir))

    # ── AuditSink interface ──────────────────────────────────────────────────

    def emit(self, record: dict) -> None:
        """Enqueue *record* for async delivery; returns immediately (no I/O).

        Active-state check and enqueue are atomic under ``_state_lock`` —
        mirrors the WebhookAuditSink contract exactly.  After ``close()``
        records are silently discarded.  Never raises.
        """
        with self._state_lock:
            if not self._active:
                return
            # Filter to allowlist inside the lock (defence-in-depth)
            safe = {k: v for k, v in record.items() if k in _ALLOWED_FIELDS}
            if not safe:
                return
            try:
                try:
                    self._queue.put_nowait(safe)
                except queue.Full:
                    try:
                        self._queue.get_nowait()  # drop oldest
                    except queue.Empty:
                        pass
                    with self._drops_lock:
                        self._drops += 1
                    try:
                        self._queue.put_nowait(safe)
                    except queue.Full:
                        with self._drops_lock:
                            self._drops += 1
            except Exception:  # noqa: BLE001 — emit must never raise
                logger.warning("audit_otel: emit() internal error; record dropped")

    def close(self, drain_timeout_s: float = 5.0) -> None:
        """Stop the worker and drain remaining queued records.

        Mirrors :meth:`WebhookAuditSink.close` exactly: acquires
        ``_state_lock`` to flip ``_active`` atomically, then joins the worker
        with a bounded timeout.  Idempotent; never raises.
        """
        with self._state_lock:
            if not self._active:
                return
            self._active = False
        self._stop_event.set()
        if self._worker_thread is not None:
            self._worker_thread.join(timeout=drain_timeout_s)

    # ── observability ────────────────────────────────────────────────────────

    @property
    def drops(self) -> int:
        """Total records dropped due to queue overflow."""
        with self._drops_lock:
            return self._drops

    @property
    def is_active(self) -> bool:
        """``True`` when the sink is configured and exporting."""
        return self._active

    # ── internal ─────────────────────────────────────────────────────────────

    def _worker(self) -> None:
        """Daemon thread: dequeue and POST records until stopped."""
        while not self._stop_event.is_set():
            try:
                record = self._queue.get(block=True, timeout=1.0)
            except queue.Empty:
                continue
            try:
                self._post(record)
            except Exception:  # noqa: BLE001 — worker must never crash
                logger.warning("audit_otel: POST failed; record dropped")
            finally:
                self._queue.task_done()
        # Drain records that arrived before the stop signal was noticed.
        while True:
            try:
                record = self._queue.get_nowait()
            except queue.Empty:
                break
            try:
                self._post(record)
            except Exception:  # noqa: BLE001
                logger.warning("audit_otel: POST failed during drain; record dropped")
            finally:
                self._queue.task_done()

    def _post(self, record: dict[str, Any]) -> None:
        payload = _build_otlp_payload(record)
        url = self._endpoint + _OTLP_LOG_PATH
        headers: dict[str, str] = {"Content-Type": "application/json"}

        if self._auth_env:
            token = os.environ.get(self._auth_env, "")
            if token:
                headers["Authorization"] = token

        req = urllib.request.Request(url, data=payload, headers=headers, method="POST")  # noqa: S310
        with urllib.request.urlopen(req, timeout=self._timeout_s) as resp:  # noqa: S310
            _ = resp.read()


# ── module-level cache (mirrors _webhook_sinks in sinks.py) ──────────────────

_otel_sinks: dict[str, OtelAuditSink] = {}
_otel_sink_lock = threading.Lock()


def _get_builtin_otel_sink(repo_root: str = ".") -> OtelAuditSink:
    """Return (or lazily create) the process-level OTel sink for *repo_root*.

    Mirrors :func:`_get_builtin_webhook_sink` in ``sinks.py`` exactly.
    """
    key = str(Path(repo_root).resolve())
    with _otel_sink_lock:
        sink = _otel_sinks.get(key)
        if sink is None:
            sink = _otel_sinks[key] = OtelAuditSink.from_repo(repo_root)
    return sink
