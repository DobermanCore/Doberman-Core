"""
tests/unit/test_otel_sink.py
────────────────────────────
Tests for OtelAuditSink (Issue #245).

Invariants covered:

1.  ``emit()`` never blocks or raises into the decision path.
2.  Queue overflow drops-and-counts rather than growing unbounded.
3.  The sink exports ONLY the allowlisted record fields and adds none of its own.
4.  Absent config → zero network I/O, sink is inert.
5.  Lifecycle — close() drains, stops the worker, makes emit() a no-op.
6.  Endpoint validation rejects non-http(s) schemes and loopback addresses.
7.  emit_to_sinks() reaches the OTel sink through the real fan-out path.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import yaml

from doberman.storage.otel_sink import (
    _ALLOWED_FIELDS,
    OtelAuditSink,
    _build_otlp_payload,
    _validate_endpoint,
)

# ── helpers / fixtures ────────────────────────────────────────────────────────


def _make_config(tmp_path: Path, extra: dict | None = None) -> Path:
    """Write a minimal valid audit_otel.yaml and return the policy dir."""
    policy_dir = tmp_path / ".doberman"
    policy_dir.mkdir()
    cfg: dict[str, Any] = {"endpoint": "https://otel-collector.example.com:4318"}
    if extra:
        cfg.update(extra)
    (policy_dir / "audit_otel.yaml").write_text(yaml.dump(cfg))
    return policy_dir


def _record(**kwargs: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "timestamp": "2026-08-14T10:00:00Z",
        "verdict": "BLOCK",
        "tool": "run_terminal_cmd",
        "reason_codes": ["destructive_command"],
        "explanation": "Recursive force-delete of a home/root target.",
        "session_id": "sess-abc123",
    }
    base.update(kwargs)
    return base


# ── 1. emit() never blocks or raises ─────────────────────────────────────────


class TestEmitNonBlocking:
    def test_emit_returns_immediately_without_posting(self, tmp_path: Path) -> None:
        _make_config(tmp_path)
        sink = OtelAuditSink.from_repo(str(tmp_path))

        post_unblocked = threading.Event()
        original_post = sink._post

        def slow_post(record: dict) -> None:
            post_unblocked.wait(timeout=5)
            original_post(record)

        assert sink._worker_thread is not None
        sink._post = slow_post  # type: ignore[method-assign]

        t0 = time.monotonic()
        sink.emit(_record())
        elapsed = time.monotonic() - t0

        assert elapsed < 0.5, f"emit() took {elapsed:.3f}s — it is blocking"
        post_unblocked.set()
        sink.close()

    def test_emit_does_not_raise_on_wedged_endpoint(self, tmp_path: Path) -> None:
        _make_config(tmp_path)
        sink = OtelAuditSink.from_repo(str(tmp_path))
        assert sink._worker_thread is not None

        def always_raise(_: dict) -> None:
            raise OSError("connection refused")

        sink._post = always_raise  # type: ignore[method-assign]
        for _ in range(5):
            sink.emit(_record())  # must not raise
        sink.close()

    def test_emit_never_raises_on_exception_in_worker(self, tmp_path: Path) -> None:
        _make_config(tmp_path)
        sink = OtelAuditSink.from_repo(str(tmp_path))
        assert sink._worker_thread is not None
        sink._post = MagicMock(side_effect=RuntimeError("boom"))  # type: ignore[method-assign]
        try:
            sink.emit(_record())
        except Exception as exc:  # noqa: BLE001
            pytest.fail(f"emit() raised: {exc}")
        sink.close()


# ── 2. Queue overflow drops-and-counts ────────────────────────────────────────


class TestQueueOverflow:
    def test_overflow_drops_oldest_and_counts(self, tmp_path: Path) -> None:
        _make_config(tmp_path, extra={"queue_max": 3})
        sink = OtelAuditSink.from_repo(str(tmp_path))

        pause = threading.Event()
        original_post = sink._post

        def blocking_post(record: dict) -> None:
            pause.wait(timeout=10)
            original_post(record)

        assert sink._worker_thread is not None
        sink._post = blocking_post  # type: ignore[method-assign]

        for i in range(3):
            sink.emit(_record(session_id=f"sess-{i}"))
        sink.emit(_record(session_id="sess-overflow"))

        assert sink.drops >= 1, "Expected at least one drop"
        pause.set()
        sink.close()

    def test_queue_never_grows_beyond_max(self, tmp_path: Path) -> None:
        max_q = 10
        _make_config(tmp_path, extra={"queue_max": max_q})
        sink = OtelAuditSink.from_repo(str(tmp_path))

        pause = threading.Event()
        original_post = sink._post

        def blocking_post(r: dict) -> None:
            pause.wait(timeout=10)
            original_post(r)

        assert sink._worker_thread is not None
        sink._post = blocking_post  # type: ignore[method-assign]

        for i in range(max_q * 3):
            sink.emit(_record(session_id=f"s-{i}"))

        assert sink._queue.qsize() <= max_q
        pause.set()
        sink.close()


# ── 3. Only allowlisted fields leave the process ─────────────────────────────


class TestFieldAllowlist:
    def test_non_allowlisted_fields_are_stripped(self, tmp_path: Path) -> None:
        _make_config(tmp_path)
        sink = OtelAuditSink.from_repo(str(tmp_path))
        captured: list[dict] = []
        sink._post = lambda r: captured.append(r)  # type: ignore[method-assign]

        sink.emit(
            _record(
                secret="sk-THIS-MUST-NOT-APPEAR",  # noqa: S106
                internal_trace="raw-prompt-contents",
            )
        )
        time.sleep(0.1)

        assert len(captured) == 1
        for bad_key in ("secret", "internal_trace"):
            assert bad_key not in captured[0], f"Forbidden field '{bad_key}' leaked"
        sink.close()

    def test_all_allowlisted_fields_pass_through(self, tmp_path: Path) -> None:
        _make_config(tmp_path)
        sink = OtelAuditSink.from_repo(str(tmp_path))
        captured: list[dict] = []
        sink._post = lambda r: captured.append(r)  # type: ignore[method-assign]

        record = _record()
        sink.emit(record)
        time.sleep(0.1)

        assert captured
        for field in _ALLOWED_FIELDS:
            if field in record:
                assert field in captured[0], f"Allowed field '{field}' missing"
        sink.close()

    def test_sink_adds_no_extra_fields(self, tmp_path: Path) -> None:
        _make_config(tmp_path)
        sink = OtelAuditSink.from_repo(str(tmp_path))
        captured: list[dict] = []
        sink._post = lambda r: captured.append(r)  # type: ignore[method-assign]

        sink.emit(_record())
        time.sleep(0.1)

        for key in captured[0]:
            assert key in _ALLOWED_FIELDS, f"Sink injected unexpected field '{key}'"
        sink.close()


# ── 4. Absent config → inert ──────────────────────────────────────────────────


class TestAbsentConfig:
    def test_no_config_means_inert(self, tmp_path: Path) -> None:
        (tmp_path / ".doberman").mkdir()
        sink = OtelAuditSink.from_repo(str(tmp_path))
        assert not sink.is_active
        assert sink._worker_thread is None

    def test_emit_on_inert_sink_is_noop(self, tmp_path: Path) -> None:
        (tmp_path / ".doberman").mkdir()
        sink = OtelAuditSink.from_repo(str(tmp_path))
        with patch("urllib.request.urlopen") as mock_open:
            sink.emit(_record())
            mock_open.assert_not_called()

    def test_malformed_config_means_inert(self, tmp_path: Path) -> None:
        policy_dir = tmp_path / ".doberman"
        policy_dir.mkdir()
        (policy_dir / "audit_otel.yaml").write_text("not: a: valid: structure: [")
        sink = OtelAuditSink.from_repo(str(tmp_path))
        assert not sink.is_active

    def test_missing_endpoint_key_means_inert(self, tmp_path: Path) -> None:
        policy_dir = tmp_path / ".doberman"
        policy_dir.mkdir()
        (policy_dir / "audit_otel.yaml").write_text(yaml.dump({"auth_env": "TOKEN"}))
        sink = OtelAuditSink.from_repo(str(tmp_path))
        assert not sink.is_active

    def test_nonexistent_policy_dir_means_inert(self, tmp_path: Path) -> None:
        sink = OtelAuditSink.from_repo(str(tmp_path / "does_not_exist"))
        assert not sink.is_active


# ── 5. OTLP payload shape ────────────────────────────────────────────────────


class TestOtlpPayload:
    def test_payload_is_valid_json(self) -> None:
        assert "resourceLogs" in json.loads(_build_otlp_payload(_record()))

    def test_payload_contains_service_name(self) -> None:
        payload = json.loads(_build_otlp_payload(_record()))
        attrs = payload["resourceLogs"][0]["resource"]["attributes"]
        svc = next((a for a in attrs if a["key"] == "service.name"), None)
        assert svc is not None
        assert svc["value"]["stringValue"] == "doberman"

    def test_payload_excludes_non_allowlisted_fields(self) -> None:
        record = _record(secret="must-not-appear")  # noqa: S106
        payload = json.loads(_build_otlp_payload(record))
        body = json.loads(
            payload["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]["body"]["stringValue"]
        )
        assert "secret" not in body

    def test_payload_scope_name(self) -> None:
        payload = json.loads(_build_otlp_payload(_record()))
        assert payload["resourceLogs"][0]["scopeLogs"][0]["scope"]["name"] == "doberman.audit"


# ── 6. Auth token ─────────────────────────────────────────────────────────────


class TestAuthToken:
    def test_auth_header_set_from_env_var(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("MY_OTEL_TOKEN", "Bearer secret-token-xyz")
        _make_config(tmp_path, extra={"auth_env": "MY_OTEL_TOKEN"})
        sink = OtelAuditSink.from_repo(str(tmp_path))

        captured_headers: list[dict] = []

        def fake_urlopen(req: Any, timeout: float) -> Any:
            captured_headers.append(dict(req.headers))
            m = MagicMock()
            m.__enter__ = lambda s: s
            m.__exit__ = MagicMock(return_value=False)
            m.read.return_value = b""
            return m

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            assert sink._worker_thread is not None
            sink._post(_record())

        assert any(
            "authorization" in {k.lower(): v for k, v in h.items()} for h in captured_headers
        )
        sink.close()

    def test_token_never_logged(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        secret_val = "super-secret-bearer-token-must-not-appear-in-logs"  # noqa: S105
        monkeypatch.setenv("OTEL_SECRET_TOKEN", f"Bearer {secret_val}")
        _make_config(tmp_path, extra={"auth_env": "OTEL_SECRET_TOKEN"})
        sink = OtelAuditSink.from_repo(str(tmp_path))

        with patch("urllib.request.urlopen", side_effect=OSError("forced error")):
            try:
                sink._post(_record())
            except OSError:
                pass

        for rec in caplog.records:
            assert secret_val not in rec.getMessage()
        sink.close()


# ── 7. Lifecycle ──────────────────────────────────────────────────────────────


class TestLifecycle:
    def test_close_makes_emit_noop(self, tmp_path: Path) -> None:
        _make_config(tmp_path)
        sink = OtelAuditSink.from_repo(str(tmp_path))
        captured: list[dict] = []
        sink._post = lambda r: captured.append(r)  # type: ignore[method-assign]

        sink.close()
        sink.emit(_record())
        time.sleep(0.1)

        assert captured == [], "emit() enqueued a record after close()"

    def test_close_stops_worker(self, tmp_path: Path) -> None:
        _make_config(tmp_path)
        sink = OtelAuditSink.from_repo(str(tmp_path))
        assert sink._worker_thread is not None
        sink.close()
        sink._worker_thread.join(timeout=2.0)
        assert not sink._worker_thread.is_alive()

    def test_close_drains_pending_records(self, tmp_path: Path) -> None:
        _make_config(tmp_path)
        sink = OtelAuditSink.from_repo(str(tmp_path))
        delivered: list[dict] = []
        gate = threading.Event()

        def gated_post(record: dict) -> None:
            gate.wait(timeout=5)
            delivered.append(record)

        sink._post = gated_post  # type: ignore[method-assign]

        sink.emit(_record(session_id="drain-me"))
        gate.set()
        sink.close(drain_timeout_s=3.0)

        assert len(delivered) >= 1

    def test_close_is_idempotent(self, tmp_path: Path) -> None:
        _make_config(tmp_path)
        sink = OtelAuditSink.from_repo(str(tmp_path))
        sink.close()
        sink.close()  # must not raise or deadlock

    def test_close_respects_timeout(self, tmp_path: Path) -> None:
        _make_config(tmp_path)
        sink = OtelAuditSink.from_repo(str(tmp_path))
        stuck = threading.Event()
        sink._post = lambda _r: stuck.wait(timeout=60)  # type: ignore[method-assign]

        sink.emit(_record())
        t0 = time.monotonic()
        sink.close(drain_timeout_s=0.3)
        elapsed = time.monotonic() - t0

        assert elapsed < 2.0, f"close() hung for {elapsed:.2f}s"
        stuck.set()

    def test_emit_close_race_no_stranded_record(self, tmp_path: Path) -> None:
        """Atomic _state_lock: record emitted just before close() must be delivered."""
        _make_config(tmp_path)
        sink = OtelAuditSink.from_repo(str(tmp_path))
        captured: list[dict] = []

        # Block inside put_nowait so close() runs while emit() holds the lock
        emit_inside_lock = threading.Event()
        close_called = threading.Event()
        original_put = sink._queue.put_nowait

        def blocking_put(item: dict) -> None:
            emit_inside_lock.set()
            close_called.wait(timeout=2)
            original_put(item)

        sink._queue.put_nowait = blocking_put  # type: ignore[method-assign]
        sink._post = lambda r: captured.append(r)  # type: ignore[method-assign]

        def do_emit() -> None:
            sink.emit(_record(session_id="race-record"))

        t = threading.Thread(target=do_emit)
        t.start()
        emit_inside_lock.wait(timeout=2)
        close_called.set()
        sink.close(drain_timeout_s=3.0)
        t.join(timeout=2)

        assert len(captured) == 1, (
            f"Record stranded: captured={len(captured)} — emit/close race broke atomicity"
        )


# ── 8. Endpoint validation ────────────────────────────────────────────────────


class TestEndpointValidation:
    def test_https_accepted(self) -> None:
        assert _validate_endpoint("https://collector.example.com:4318") is not None

    def test_http_accepted(self) -> None:
        assert _validate_endpoint("http://collector.internal:4318") is not None

    def test_file_scheme_rejected(self) -> None:
        assert _validate_endpoint("file:///etc/passwd") is None

    def test_ftp_scheme_rejected(self) -> None:
        assert _validate_endpoint("ftp://collector.example.com") is None

    def test_localhost_rejected(self) -> None:
        assert _validate_endpoint("https://localhost:4318") is None

    def test_127_0_0_1_rejected(self) -> None:
        assert _validate_endpoint("https://127.0.0.1:4318") is None

    def test_ipv6_loopback_rejected(self) -> None:
        assert _validate_endpoint("https://[::1]:4318") is None

    def test_loopback_config_makes_sink_inert(self, tmp_path: Path) -> None:
        policy_dir = tmp_path / ".doberman"
        policy_dir.mkdir()
        (policy_dir / "audit_otel.yaml").write_text(
            yaml.dump({"endpoint": "https://localhost:4318"})
        )
        sink = OtelAuditSink.from_repo(str(tmp_path))
        assert not sink.is_active


# ── 9. Secret never exported ──────────────────────────────────────────────────


class TestSecretNeverExported:
    SYNTHETIC_SECRET = "AKIAIOSFODNN7SYNTHETIC"  # noqa: S105

    def test_not_in_otlp_body(self) -> None:
        payload = _build_otlp_payload(_record(raw_credentials=self.SYNTHETIC_SECRET))
        assert self.SYNTHETIC_SECRET not in payload.decode()

    def test_not_in_emitted_record(self, tmp_path: Path) -> None:
        _make_config(tmp_path)
        sink = OtelAuditSink.from_repo(str(tmp_path))
        captured_payloads: list[bytes] = []
        sink._post = lambda r: captured_payloads.append(json.dumps(r).encode())  # type: ignore[method-assign]

        sink.emit(_record(raw_credentials=self.SYNTHETIC_SECRET))
        time.sleep(0.1)

        for payload in captured_payloads:
            assert self.SYNTHETIC_SECRET not in payload.decode()
        sink.close()


# ── 10. Wiring — emit_to_sinks() reaches OTel sink ───────────────────────────


class TestWiring:
    """Proves a record reaches OtelAuditSink through the real emit_to_sinks path."""

    def test_emit_to_sinks_reaches_otel_sink(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from doberman.storage import otel_sink as otel_module
        from doberman.storage.sinks import emit_to_sinks

        # Wire a fresh sink into the module-level cache for this tmp_path
        _make_config(tmp_path)
        sink = OtelAuditSink.from_repo(str(tmp_path))
        delivered: list[dict] = []
        sink._post = lambda r: delivered.append(r)  # type: ignore[method-assign]

        key = str(tmp_path.resolve())
        original_sinks = dict(otel_module._otel_sinks)
        otel_module._otel_sinks[key] = sink

        # Patch discover_audit_sinks to return nothing (isolate our sink)
        monkeypatch.setattr("doberman.engine.registry.discover_audit_sinks", list)
        # Patch _get_builtin_webhook_sink to return an inert sink
        from doberman.storage import sinks as sinks_module
        from doberman.storage.sinks import WebhookAuditSink

        monkeypatch.setattr(
            sinks_module,
            "_get_builtin_webhook_sink",
            lambda repo_root=".": WebhookAuditSink(None),
        )
        # Patch _get_builtin_otel_sink to return our prepared sink
        monkeypatch.setattr(
            sinks_module,
            "_get_builtin_otel_sink",
            lambda repo_root=".": sink,
        )

        record = _record()
        emit_to_sinks(record, repo_root=str(tmp_path))
        time.sleep(0.15)

        assert len(delivered) == 1, "OTel sink did not receive the record via emit_to_sinks()"
        for bad_key in set(record) - _ALLOWED_FIELDS:
            assert bad_key not in delivered[0], f"Non-allowlisted field '{bad_key}' leaked"

        otel_module._otel_sinks.clear()
        otel_module._otel_sinks.update(original_sinks)
        sink.close()
