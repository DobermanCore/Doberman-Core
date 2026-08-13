"""
doberman.storage.otel_sink
~~~~~~~~~~~~~~~~~~~~~~~~~~
OpenTelemetry AuditSink — ships the redacted decision record to any OTLP collector.

Design contract (mirrors the webhook sink in storage/sinks.py):
  - ``emit()`` is called on the decision path and MUST return in O(1) —
    no network I/O, no blocking.  It appends the record to a bounded
    in-memory queue; a daemon worker thread drains it via OTLP/HTTP.
  - Queue overflow drops the *oldest* record and increments a counter
    (best-effort semantics — this is a bridge, not a delivery guarantee).
  - Config lives in ``.doberman/audit_otel.yaml``.  Absent or malformed
    config → the sink is inert (zero network I/O, zero side-effects).
  - The sink exports *only* the allowlisted fields it receives; it adds
    no fields of its own and reads nothing else from process state.
  - Auth token comes from a named env-var only; it is never stored in
    YAML, never logged.

Allowlisted record fields (same set the webhook sink may see upstream):
    timestamp, verdict, tool, reason_codes, explanation, session_id

OTLP/HTTP endpoint:
    POST <endpoint>/v1/logs  (JSON, application/json)
    Each record becomes one LogRecord in a ResourceLogs payload.

Dependencies: stdlib only (``urllib.request``, ``json``, ``queue``,
``threading``, ``os``, ``logging``, ``pathlib``). No opentelemetry-sdk
import required at the *sink* level — we speak the wire protocol directly
so users don't have to install the OTel Python SDK.  This keeps the
dependency footprint of doberman-core minimal and lets any OTLP-capable
collector (Grafana Alloy, Otel Collector, Honeycomb, …) receive records
without any glue code.
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

import yaml

logger = logging.getLogger(__name__)

# ── constants ────────────────────────────────────────────────────────────────

_CONFIG_FILENAME = "audit_otel.yaml"
_DEFAULT_TIMEOUT_S = 5.0
_DEFAULT_QUEUE_MAX = 1_000
_OTLP_LOG_PATH = "/v1/logs"

# The *only* fields that leave the process.  The record is already redacted
# upstream; we re-filter here as a defence-in-depth measure so that even if
# the upstream contract drifts, this sink never forwards unexpected fields.
_ALLOWED_FIELDS: frozenset[str] = frozenset(
    {"timestamp", "verdict", "tool", "reason_codes", "explanation", "session_id"}
)


# ── config model (plain dataclass to avoid pydantic import here) ─────────────

class _OtelSinkConfig:
    __slots__ = ("auth_env", "endpoint", "queue_max", "timeout_s")

    def __init__(
        self,
        endpoint: str,
        auth_env: str | None,
        timeout_s: float,
        queue_max: int,
    ) -> None:
        self.endpoint = endpoint.rstrip("/")
        self.auth_env = auth_env
        self.timeout_s = timeout_s
        self.queue_max = queue_max


def _load_config(policy_dir: Path) -> _OtelSinkConfig | None:
    """
    Parse ``.doberman/audit_otel.yaml``.  Returns ``None`` if the file is
    absent, unreadable, or missing the required ``endpoint`` key — in all
    cases the sink is inert.
    """
    cfg_path = policy_dir / _CONFIG_FILENAME
    if not cfg_path.exists():
        return None
    try:
        raw = yaml.safe_load(cfg_path.read_text())
    except Exception as exc:  # noqa: BLE001
        logger.warning("audit_otel: could not read config (%s) — sink disabled", exc)
        return None

    if not isinstance(raw, dict):
        logger.warning("audit_otel: config is not a mapping — sink disabled")
        return None

    endpoint = raw.get("endpoint", "").strip()
    if not endpoint:
        logger.warning("audit_otel: 'endpoint' missing or empty — sink disabled")
        return None

    return _OtelSinkConfig(
        endpoint=endpoint,
        auth_env=raw.get("auth_env") or None,
        timeout_s=float(raw.get("timeout_s", _DEFAULT_TIMEOUT_S)),
        queue_max=int(raw.get("queue_max", _DEFAULT_QUEUE_MAX)),
    )


# ── OTLP payload builder ─────────────────────────────────────────────────────

def _build_otlp_payload(record: dict[str, Any]) -> bytes:
    """
    Wrap a single redacted decision record in a minimal OTLP/HTTP LogRecord
    payload (JSON encoding).

    Schema reference:
        https://opentelemetry.io/docs/specs/otlp/#otlphttp
        https://opentelemetry.io/docs/specs/otel/logs/data-model/

    We use timeUnixNano from ``record["timestamp"]`` when available;
    fall back to the current time.
    """
    # Filter to the allowlist
    safe = {k: v for k, v in record.items() if k in _ALLOWED_FIELDS}

    ts_ns = _timestamp_to_ns(safe.get("timestamp"))

    # Attributes: every field except timestamp goes in as a string attribute
    attributes = [
        {"key": k, "value": {"stringValue": str(v)}}
        for k, v in safe.items()
        if k != "timestamp"
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
                    "attributes": [
                        {"key": "service.name", "value": {"stringValue": "doberman"}}
                    ]
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
    """Convert a timestamp value to integer nanoseconds since Unix epoch."""
    if ts is None:
        return int(time.time() * 1e9)
    if isinstance(ts, (int, float)):
        # Assume seconds if the value looks like a Unix timestamp
        return int(ts * 1e9)
    try:
        import datetime  # local import to keep module top-level clean
        if isinstance(ts, str):
            dt = datetime.datetime.fromisoformat(ts)
            return int(dt.timestamp() * 1e9)
    except Exception:  # noqa: BLE001
        logger.debug("audit_otel: could not parse timestamp %r — using current time", ts)
    return int(time.time() * 1e9)


# ── worker thread ─────────────────────────────────────────────────────────────

class _OtlpWorker(threading.Thread):
    """
    Background daemon that pops records from the queue and POSTs them to the
    OTLP endpoint.  Errors are logged; they never propagate to the caller.
    """

    def __init__(self, cfg: _OtelSinkConfig, q: queue.Queue) -> None:  # type: ignore[type-arg]
        super().__init__(daemon=True, name="doberman-otel-worker")
        self._cfg = cfg
        self._q = q

    def run(self) -> None:
        while True:
            try:
                record = self._q.get(block=True, timeout=1.0)
            except queue.Empty:
                continue
            try:
                self._post(record)
            except Exception as exc:  # noqa: BLE001
                logger.debug("audit_otel: export failed: %s", exc)
            finally:
                self._q.task_done()

    def _post(self, record: dict[str, Any]) -> None:
        payload = _build_otlp_payload(record)
        url = self._cfg.endpoint + _OTLP_LOG_PATH
        headers: dict[str, str] = {"Content-Type": "application/json"}

        # Auth token: resolved from env-var at send time, never cached
        if self._cfg.auth_env:
            token = os.environ.get(self._cfg.auth_env, "")
            if token:
                headers["Authorization"] = token
            # If the var is absent we proceed without the header rather than
            # crash; the collector will reject if auth is mandatory.

        req = urllib.request.Request(url, data=payload, headers=headers, method="POST")  # noqa: S310
        with urllib.request.urlopen(req, timeout=self._cfg.timeout_s) as resp:  # noqa: S310
            _ = resp.read()  # drain


# ── public sink ───────────────────────────────────────────────────────────────

class OtelAuditSink:
    """
    AuditSink implementation that exports each redacted decision record to an
    OTLP/HTTP collector endpoint.

    Usage — in ``.doberman/audit_otel.yaml``::

        endpoint: https://otel-collector.example.com:4318
        auth_env: OTEL_AUTH_TOKEN          # optional
        timeout_s: 5                       # optional, default 5
        queue_max: 1000                    # optional, default 1000

    The sink is inert when the config file is absent.

    Thread-safety: ``emit()`` is safe to call from any thread; the internal
    queue and the worker thread handle all concurrency.
    """

    def __init__(self, policy_dir: Path | str | None = None) -> None:
        if policy_dir is None:
            policy_dir = Path(".doberman")
        self._policy_dir = Path(policy_dir)
        self._cfg = _load_config(self._policy_dir)
        self._q: queue.Queue[dict[str, Any]] | None = None
        self._worker: _OtlpWorker | None = None
        self._drops = 0
        self._lock = threading.Lock()

        if self._cfg is not None:
            self._q = queue.Queue(maxsize=0)  # unbounded — we enforce the cap ourselves
            self._worker = _OtlpWorker(self._cfg, self._q)
            self._worker.start()

    # ── AuditSink interface ──────────────────────────────────────────────────

    def emit(self, record: dict[str, Any]) -> None:
        """
        Enqueue the record for export.  Returns immediately — no I/O, no
        blocking, no exception propagation.  Queue overflow drops the *oldest*
        record and counts the drop.
        """
        if self._cfg is None or self._q is None:
            return  # inert

        # Filter to the allowlist before touching the queue
        safe = {k: v for k, v in record.items() if k in _ALLOWED_FIELDS}
        if not safe:
            return

        with self._lock:
            if self._q.qsize() >= self._cfg.queue_max:
                # Drop oldest to make room
                try:
                    self._q.get_nowait()
                    self._q.task_done()
                    self._drops += 1
                    logger.debug(
                        "audit_otel: queue overflow — dropped oldest record "
                        "(total drops: %d)",
                        self._drops,
                    )
                except queue.Empty:
                    pass
            try:
                self._q.put_nowait(safe)
            except queue.Full:
                # Extremely unlikely race; drop-and-count
                self._drops += 1

    # ── observability ────────────────────────────────────────────────────────

    @property
    def drop_count(self) -> int:
        """Total number of records dropped due to queue overflow."""
        return self._drops

    @property
    def is_active(self) -> bool:
        """``True`` when the sink is configured and will attempt exports."""
        return self._cfg is not None

    # ── lifecycle ────────────────────────────────────────────────────────────

    def close(self, timeout: float = 5.0) -> None:
        """
        Signal the worker to finish in-flight exports, then return.
        Best-effort — in-queue records that haven't been POSTed yet may be
        lost (same honest-scope caveat as the webhook sink).
        """
        if self._q is not None:
            self._q.join()  # wait for queue to drain
