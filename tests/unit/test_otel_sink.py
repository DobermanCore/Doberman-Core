"""
tests/unit/test_otel_sink.py
────────────────────────────
Tests for OtelAuditSink (Issue #245).

Every invariant the issue demands is covered:

1.  ``emit()`` never blocks or raises into the decision path.
2.  Queue overflow drops-and-counts rather than growing unbounded.
3.  The sink exports ONLY the allowlisted record fields and adds none of its own.
4.  Absent config → zero network I/O, sink is inert.
5.  ``emit()`` is synchronous from the caller's perspective (returns before I/O).
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
    _load_config,
)

# ── helpers / fixtures ────────────────────────────────────────────────────────


def _make_config(tmp_path: Path, extra: dict | None = None) -> Path:
    """Write a minimal valid audit_otel.yaml and return the policy dir."""
    policy_dir = tmp_path / ".doberman"
    policy_dir.mkdir()
    cfg: dict[str, Any] = {"endpoint": "http://localhost:4318"}
    if extra:
        cfg.update(extra)
    (policy_dir / "audit_otel.yaml").write_text(yaml.dump(cfg))
    return policy_dir


def _record(**kwargs: Any) -> dict[str, Any]:
    """Build a minimal record dict."""
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
    """emit() must return before any network I/O occurs."""

    def test_emit_returns_immediately_without_posting(self, tmp_path: Path) -> None:
        policy_dir = _make_config(tmp_path)
        sink = OtelAuditSink(policy_dir)

        post_started = threading.Event()
        post_unblocked = threading.Event()

        original_post = sink._worker._post  # type: ignore[union-attr]

        def slow_post(record: dict) -> None:
            post_started.set()
            post_unblocked.wait(timeout=5)
            original_post(record)

        assert sink._worker is not None
        sink._worker._post = slow_post  # type: ignore[method-assign]

        record = _record()
        t0 = time.monotonic()
        sink.emit(record)
        elapsed = time.monotonic() - t0

        # emit() must return well before any POST has finished
        assert elapsed < 0.5, f"emit() took {elapsed:.3f}s — it is blocking"
        post_unblocked.set()

    def test_emit_does_not_raise_on_wedged_endpoint(self, tmp_path: Path) -> None:
        policy_dir = _make_config(tmp_path)
        sink = OtelAuditSink(policy_dir)

        def always_raise(_: dict) -> None:
            raise OSError("connection refused")

        assert sink._worker is not None
        sink._worker._post = always_raise  # type: ignore[method-assign]

        # emit must never propagate the network error
        for _ in range(5):
            sink.emit(_record())  # must not raise

    def test_emit_never_raises_on_exception_in_worker(self, tmp_path: Path) -> None:
        policy_dir = _make_config(tmp_path)
        sink = OtelAuditSink(policy_dir)

        assert sink._worker is not None
        sink._worker._post = MagicMock(side_effect=RuntimeError("boom"))

        try:
            sink.emit(_record())
        except Exception as exc:  # noqa: BLE001
            pytest.fail(f"emit() raised: {exc}")


# ── 2. Queue overflow drops-and-counts ────────────────────────────────────────


class TestQueueOverflow:
    """On overflow the sink drops the oldest and increments drop_count."""

    def test_overflow_drops_oldest_and_counts(self, tmp_path: Path) -> None:
        policy_dir = _make_config(tmp_path, extra={"queue_max": 3})
        sink = OtelAuditSink(policy_dir)

        # Pause the worker so the queue fills up
        pause = threading.Event()
        original_post = sink._worker._post  # type: ignore[union-attr]

        def blocking_post(record: dict) -> None:
            pause.wait(timeout=10)
            original_post(record)

        assert sink._worker is not None
        sink._worker._post = blocking_post  # type: ignore[method-assign]

        # Fill to cap
        for i in range(3):
            sink.emit(_record(session_id=f"sess-{i}"))

        # One more — should trigger a drop
        sink.emit(_record(session_id="sess-overflow"))

        assert sink.drop_count >= 1, "Expected at least one drop"
        pause.set()

    def test_queue_never_grows_beyond_max(self, tmp_path: Path) -> None:
        max_q = 10
        policy_dir = _make_config(tmp_path, extra={"queue_max": max_q})
        sink = OtelAuditSink(policy_dir)

        # Halt worker so queue fills deterministically
        pause = threading.Event()
        original_post = sink._worker._post  # type: ignore[union-attr]

        def blocking_post(r: dict) -> None:
            pause.wait(timeout=10)
            original_post(r)

        assert sink._worker is not None
        sink._worker._post = blocking_post  # type: ignore[method-assign]

        for i in range(max_q * 3):
            sink.emit(_record(session_id=f"s-{i}"))

        assert sink._q is not None  # type: ignore[union-attr]
        assert sink._q.qsize() <= max_q

        pause.set()


# ── 3. Only allowlisted fields leave the process ─────────────────────────────


class TestFieldAllowlist:
    """The sink must export only the allowlisted fields and add none of its own."""

    def test_non_allowlisted_fields_are_stripped(self, tmp_path: Path) -> None:
        policy_dir = _make_config(tmp_path)
        sink = OtelAuditSink(policy_dir)

        captured: list[dict] = []

        def capturing_post(record: dict) -> None:
            captured.append(record)

        assert sink._worker is not None
        sink._worker._post = capturing_post  # type: ignore[method-assign]

        # Include extra fields that should NOT appear
        dirty_record = _record(
            secret="sk-THIS-MUST-NOT-APPEAR",  # noqa: S106
            internal_trace="raw-prompt-contents",
            raw_payload="very sensitive data",
        )
        sink.emit(dirty_record)

        # Give the worker time to process
        time.sleep(0.1)

        assert len(captured) == 1
        exported = captured[0]
        for bad_key in ("secret", "internal_trace", "raw_payload"):
            assert bad_key not in exported, f"Forbidden field '{bad_key}' leaked into export"

    def test_all_allowlisted_fields_pass_through(self, tmp_path: Path) -> None:
        policy_dir = _make_config(tmp_path)
        sink = OtelAuditSink(policy_dir)

        captured: list[dict] = []

        assert sink._worker is not None
        sink._worker._post = lambda r: captured.append(r)  # type: ignore[method-assign]

        record = _record()
        sink.emit(record)
        time.sleep(0.1)

        assert captured, "Worker never processed the record"
        exported = captured[0]
        for field in _ALLOWED_FIELDS:
            if field in record:
                assert field in exported, f"Allowed field '{field}' missing from export"

    def test_sink_adds_no_extra_fields(self, tmp_path: Path) -> None:
        policy_dir = _make_config(tmp_path)
        sink = OtelAuditSink(policy_dir)

        captured: list[dict] = []

        assert sink._worker is not None
        sink._worker._post = lambda r: captured.append(r)  # type: ignore[method-assign]

        sink.emit(_record())
        time.sleep(0.1)

        exported = captured[0]
        for key in exported:
            assert key in _ALLOWED_FIELDS, f"Sink injected unexpected field '{key}'"


# ── 4. Absent config → inert (zero network I/O) ───────────────────────────────


class TestAbsentConfig:
    """Without a config file the sink must be completely inert."""

    def test_no_config_means_inert(self, tmp_path: Path) -> None:
        policy_dir = tmp_path / ".doberman"
        policy_dir.mkdir()
        # No audit_otel.yaml
        sink = OtelAuditSink(policy_dir)

        assert not sink.is_active
        assert sink._q is None
        assert sink._worker is None

    def test_emit_on_inert_sink_is_noop(self, tmp_path: Path) -> None:
        policy_dir = tmp_path / ".doberman"
        policy_dir.mkdir()
        sink = OtelAuditSink(policy_dir)

        with patch("urllib.request.urlopen") as mock_open:
            sink.emit(_record())
            mock_open.assert_not_called()

    def test_malformed_config_means_inert(self, tmp_path: Path) -> None:
        policy_dir = tmp_path / ".doberman"
        policy_dir.mkdir()
        (policy_dir / "audit_otel.yaml").write_text("not: a: valid: structure: [")
        sink = OtelAuditSink(policy_dir)
        assert not sink.is_active

    def test_missing_endpoint_key_means_inert(self, tmp_path: Path) -> None:
        policy_dir = tmp_path / ".doberman"
        policy_dir.mkdir()
        (policy_dir / "audit_otel.yaml").write_text(yaml.dump({"auth_env": "TOKEN"}))
        sink = OtelAuditSink(policy_dir)
        assert not sink.is_active

    def test_nonexistent_policy_dir_means_inert(self, tmp_path: Path) -> None:
        policy_dir = tmp_path / ".doberman_nonexistent"
        sink = OtelAuditSink(policy_dir)
        assert not sink.is_active


# ── 5. OTLP payload shape ────────────────────────────────────────────────────


class TestOtlpPayload:
    """Verify the OTLP/HTTP payload structure."""

    def test_payload_is_valid_json(self) -> None:
        payload = _build_otlp_payload(_record())
        parsed = json.loads(payload)
        assert "resourceLogs" in parsed

    def test_payload_contains_service_name(self) -> None:
        payload = json.loads(_build_otlp_payload(_record()))
        resource_attrs = payload["resourceLogs"][0]["resource"]["attributes"]
        service_attr = next((a for a in resource_attrs if a["key"] == "service.name"), None)
        assert service_attr is not None
        assert service_attr["value"]["stringValue"] == "doberman"

    def test_payload_excludes_non_allowlisted_fields(self) -> None:
        record = _record(secret="must-not-appear")  # noqa: S106
        payload_str = json.loads(_build_otlp_payload(record))
        body_str = payload_str["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]["body"][
            "stringValue"
        ]
        body = json.loads(body_str)
        assert "secret" not in body

    def test_payload_body_matches_filtered_record(self) -> None:
        record = _record()
        payload = json.loads(_build_otlp_payload(record))
        body_str = payload["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]["body"][
            "stringValue"
        ]
        body = json.loads(body_str)
        for field in _ALLOWED_FIELDS:
            if field in record and field != "timestamp":
                assert field in body

    def test_payload_scope_name(self) -> None:
        payload = json.loads(_build_otlp_payload(_record()))
        scope = payload["resourceLogs"][0]["scopeLogs"][0]["scope"]
        assert scope["name"] == "doberman.audit"


# ── 6. Auth token handling ────────────────────────────────────────────────────


class TestAuthToken:
    """Auth token must come only from the env-var and must never be logged."""

    def test_auth_header_set_from_env_var(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("MY_OTEL_TOKEN", "Bearer secret-token-xyz")
        policy_dir = _make_config(tmp_path, extra={"auth_env": "MY_OTEL_TOKEN"})

        captured_headers: list[dict] = []

        def fake_urlopen(req: Any, timeout: float) -> Any:
            captured_headers.append(dict(req.headers))
            m = MagicMock()
            m.__enter__ = lambda s: s
            m.__exit__ = MagicMock(return_value=False)
            m.read.return_value = b""
            return m

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            sink = OtelAuditSink(policy_dir)
            assert sink._worker is not None
            # Call _post directly to avoid threading timing issues in this test
            sink._worker._post(_record())

        assert any(
            "authorization" in {k.lower(): v for k, v in h.items()} for h in captured_headers
        ), "Authorization header was not sent"

    def test_auth_token_absent_env_var_sends_no_header(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("MISSING_TOKEN_ENV", raising=False)
        policy_dir = _make_config(tmp_path, extra={"auth_env": "MISSING_TOKEN_ENV"})

        captured_headers: list[dict] = []

        def fake_urlopen(req: Any, timeout: float) -> Any:
            captured_headers.append(dict(req.headers))
            m = MagicMock()
            m.__enter__ = lambda s: s
            m.__exit__ = MagicMock(return_value=False)
            m.read.return_value = b""
            return m

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            sink = OtelAuditSink(policy_dir)
            assert sink._worker is not None
            sink._worker._post(_record())

        for h in captured_headers:
            for k in h:
                assert k.lower() != "authorization", "Auth header sent without a token value"

    def test_token_never_logged(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        secret_val = "super-secret-bearer-token-must-not-appear-in-logs"  # noqa: S105
        monkeypatch.setenv("OTEL_SECRET_TOKEN", f"Bearer {secret_val}")
        policy_dir = _make_config(tmp_path, extra={"auth_env": "OTEL_SECRET_TOKEN"})

        with patch("urllib.request.urlopen", side_effect=OSError("forced error")):
            sink = OtelAuditSink(policy_dir)
            assert sink._worker is not None
            # Trigger an error path which might log
            try:
                sink._worker._post(_record())
            except OSError:
                pass  # expected — we patched urlopen to raise

        for record in caplog.records:
            assert secret_val not in record.getMessage(), "Token value appeared in a log record"


# ── 7. Config loading edge cases ──────────────────────────────────────────────


class TestConfigLoading:
    def test_load_config_returns_none_for_missing_file(self, tmp_path: Path) -> None:
        result = _load_config(tmp_path)
        assert result is None

    def test_load_config_trims_trailing_slash_from_endpoint(self, tmp_path: Path) -> None:
        (tmp_path / "audit_otel.yaml").write_text(
            yaml.dump({"endpoint": "https://collector.example.com:4318/"})
        )
        cfg = _load_config(tmp_path)
        assert cfg is not None
        assert not cfg.endpoint.endswith("/")

    def test_load_config_respects_custom_timeout(self, tmp_path: Path) -> None:
        (tmp_path / "audit_otel.yaml").write_text(
            yaml.dump({"endpoint": "https://collector.example.com", "timeout_s": 15.0})
        )
        cfg = _load_config(tmp_path)
        assert cfg is not None
        assert cfg.timeout_s == 15.0

    def test_load_config_respects_custom_queue_max(self, tmp_path: Path) -> None:
        (tmp_path / "audit_otel.yaml").write_text(
            yaml.dump({"endpoint": "https://collector.example.com", "queue_max": 500})
        )
        cfg = _load_config(tmp_path)
        assert cfg is not None
        assert cfg.queue_max == 500


# ── 8. Synthetic secret never appears in exported body ────────────────────────


class TestSecretNeverExported:
    """
    A synthetic secret placed in a non-allowlisted record field must never
    appear in the serialised OTLP payload body.
    """

    SYNTHETIC_SECRET = "AKIAIOSFODNN7SYNTHETIC"  # noqa: S105

    def test_synthetic_secret_not_in_otlp_body(self) -> None:
        record = _record(raw_credentials=self.SYNTHETIC_SECRET)
        payload = _build_otlp_payload(record)
        assert self.SYNTHETIC_SECRET not in payload.decode()

    def test_synthetic_secret_not_in_emitted_record(self, tmp_path: Path) -> None:
        policy_dir = _make_config(tmp_path)
        sink = OtelAuditSink(policy_dir)

        captured_payloads: list[bytes] = []

        def capturing_post(record: dict) -> None:
            captured_payloads.append(json.dumps(record).encode())

        assert sink._worker is not None
        sink._worker._post = capturing_post  # type: ignore[method-assign]

        sink.emit(_record(raw_credentials=self.SYNTHETIC_SECRET))
        time.sleep(0.1)

        for payload in captured_payloads:
            assert self.SYNTHETIC_SECRET not in payload.decode(), (
                "Synthetic secret leaked into an emitted record"
            )
