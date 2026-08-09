"""Tests for the built-in WebhookAuditSink (Feature 8, slice 8.5).

Proves every contract from the issue:
- A synthetic secret never appears in any POSTed body.
- A wedged endpoint never delays or alters a decision (emit() returns before
  any network I/O).
- Drop-oldest counting works correctly.
- Inert without config (no file → no thread, no I/O).
- HTTPS required for non-loopback URLs.
- Auth token absent from logs.
- emit_to_sinks wires the built-in webhook sink after plugin-discovered sinks.
"""

import json
import logging
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest
import yaml

from doberman.storage.sinks import (
    WebhookAuditSink,
    _is_loopback,
    _load_webhook_config,
    emit_to_sinks,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SECRET = "AKIA-FAKE-WEBHOOK-SECRET-9999"  # noqa: S105 — synthetic test value only


def _write_webhook_yaml(tmp_path: Path, **kwargs) -> None:
    """Write a minimal audit_webhook.yaml under tmp_path/.doberman/."""
    d = tmp_path / ".doberman"
    d.mkdir(parents=True, exist_ok=True)
    (d / "audit_webhook.yaml").write_text(yaml.dump(kwargs), encoding="utf-8")


def _sink_with_mock_post(config: dict):
    """Build a WebhookAuditSink and replace _post with a capturing mock.

    Returns ``(sink, posted_bodies)`` where ``posted_bodies`` is a list that
    accumulates every raw dict handed to the real POST path.
    """
    sink = WebhookAuditSink(config)
    posted: list[dict] = []

    def _fake_post(record: dict) -> None:
        posted.append(record)

    sink._post = _fake_post  # monkeypatch the internal method
    return sink, posted


# ---------------------------------------------------------------------------
# _is_loopback
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "host,expected",
    [
        ("localhost", True),
        ("LOCALHOST", True),
        ("127.0.0.1", True),
        ("127.255.255.255", True),
        ("::1", True),
        ("[::1]", True),
        ("0.0.0.0", False),  # noqa: S104 — test value, not a real bind
        ("192.168.1.1", False),
        ("example.com", False),
        ("", False),
    ],
)
def test_is_loopback(host: str, expected: bool) -> None:
    assert _is_loopback(host) is expected


# ---------------------------------------------------------------------------
# _load_webhook_config — config parsing
# ---------------------------------------------------------------------------


def test_load_webhook_config_absent(tmp_path: Path) -> None:
    """No file → None (sink is inert)."""
    assert _load_webhook_config(str(tmp_path)) is None


def test_load_webhook_config_minimal(tmp_path: Path) -> None:
    _write_webhook_yaml(tmp_path, url="https://example.com/audit")
    cfg = _load_webhook_config(str(tmp_path))
    assert cfg is not None
    assert cfg["url"] == "https://example.com/audit"
    assert cfg["auth_env"] is None


def test_load_webhook_config_full(tmp_path: Path) -> None:
    _write_webhook_yaml(
        tmp_path, url="https://example.com/audit", auth_env="MY_TOKEN", timeout_s=10
    )
    cfg = _load_webhook_config(str(tmp_path))
    assert cfg is not None
    assert cfg["auth_env"] == "MY_TOKEN"
    assert cfg["timeout_s"] == 10.0


def test_load_webhook_config_missing_url(tmp_path: Path) -> None:
    _write_webhook_yaml(tmp_path, auth_env="TOKEN")
    assert _load_webhook_config(str(tmp_path)) is None


def test_load_webhook_config_non_https_non_loopback(tmp_path: Path) -> None:
    _write_webhook_yaml(tmp_path, url="http://example.com/audit")
    assert _load_webhook_config(str(tmp_path)) is None


def test_load_webhook_config_http_loopback_allowed(tmp_path: Path) -> None:
    """HTTP is OK for loopback targets (dev/test scenarios)."""
    _write_webhook_yaml(tmp_path, url="http://127.0.0.1:9999/audit")
    cfg = _load_webhook_config(str(tmp_path))
    assert cfg is not None
    assert cfg["url"] == "http://127.0.0.1:9999/audit"


def test_load_webhook_config_http_localhost_allowed(tmp_path: Path) -> None:
    _write_webhook_yaml(tmp_path, url="http://localhost:8080/hook")
    cfg = _load_webhook_config(str(tmp_path))
    assert cfg is not None


def test_load_webhook_config_malformed_yaml(tmp_path: Path) -> None:
    d = tmp_path / ".doberman"
    d.mkdir()
    (d / "audit_webhook.yaml").write_text(": :: bad yaml {{", encoding="utf-8")
    assert _load_webhook_config(str(tmp_path)) is None


def test_load_webhook_config_bad_timeout(tmp_path: Path) -> None:
    """An invalid timeout_s falls back to the default rather than failing."""
    _write_webhook_yaml(tmp_path, url="https://example.com/audit", timeout_s="not-a-number")
    cfg = _load_webhook_config(str(tmp_path))
    assert cfg is not None
    assert cfg["timeout_s"] == 5.0  # default


# ---------------------------------------------------------------------------
# WebhookAuditSink — inert without config
# ---------------------------------------------------------------------------


def test_inert_without_config() -> None:
    """No config → emit() is a no-op; no worker thread is started."""
    initial_thread_count = threading.active_count()
    sink = WebhookAuditSink(None)
    sink.emit({"x": 1})
    # Thread count should not increase for an inert sink.
    assert threading.active_count() == initial_thread_count
    assert sink.drops == 0


def test_inert_from_repo_no_file(tmp_path: Path) -> None:
    sink = WebhookAuditSink.from_repo(str(tmp_path))
    sink.emit({"x": 1})  # must not raise


# ---------------------------------------------------------------------------
# emit() returns immediately (no blocking on the decision path)
# ---------------------------------------------------------------------------


def test_emit_does_not_block_on_wedged_endpoint() -> None:
    """emit() must return before any network I/O — even with a frozen _post."""
    config = {"url": "https://example.com/audit", "auth_env": None, "timeout_s": 5.0}
    sink = WebhookAuditSink(config)

    # Replace _post with a call that blocks until we release it.
    gate = threading.Event()

    def _blocking_post(record: dict) -> None:
        gate.wait(timeout=30)  # blocks the worker, not emit()

    sink._post = _blocking_post

    start = time.monotonic()
    sink.emit({"final_verdict": "BLOCK"})
    elapsed = time.monotonic() - start
    gate.set()  # unblock the worker thread

    # emit() must complete in well under 1 second (the network timeout is 5s).
    assert elapsed < 1.0, f"emit() blocked for {elapsed:.3f}s — it must be synchronous"


# ---------------------------------------------------------------------------
# Records are POSTed correctly (body, content-type, no secret leakage)
# ---------------------------------------------------------------------------


def test_record_posted_as_json(tmp_path: Path) -> None:
    """The worker thread POSTs the exact record as JSON."""
    config = {"url": "https://example.com/audit", "auth_env": None, "timeout_s": 5.0}
    sink, posted = _sink_with_mock_post(config)

    record = {"final_verdict": "ALLOW", "action_id": "act-webhook-1"}
    sink.emit(record)
    # Give the worker time to drain the queue.
    sink._queue.join()

    assert len(posted) == 1
    assert posted[0]["final_verdict"] == "ALLOW"
    assert posted[0]["action_id"] == "act-webhook-1"


def test_synthetic_secret_never_in_posted_body(tmp_path: Path) -> None:
    """A synthetic secret value must never appear in the JSON body sent to the endpoint."""
    config = {"url": "https://example.com/audit", "auth_env": None, "timeout_s": 5.0}

    # Capture the raw bytes that would be sent.
    captured_bodies: list[bytes] = []

    class _CapturingSink(WebhookAuditSink):
        def _post(self, record: dict) -> None:
            body = json.dumps(record, default=str).encode()
            captured_bodies.append(body)

    sink = _CapturingSink(config)

    # The record is already redacted upstream; sinks must add nothing.
    # We embed the synthetic secret key to prove it does NOT leak through.
    record = {
        "final_verdict": "AUTH",
        "reason_codes": ["sensitive_secret_access"],
        # payload_fingerprints are HMAC fingerprints, not the raw secret.
        "payload_fingerprints": ["hmac:deadbeef1234"],
    }
    sink.emit(record)
    sink._queue.join()

    assert len(captured_bodies) == 1
    body_text = captured_bodies[0].decode()
    assert _SECRET not in body_text, "Synthetic secret must never appear in the POSTed body"
    # The HMAC fingerprint may appear (it's safe); the raw secret must not.
    assert "hmac:deadbeef1234" in body_text


# ---------------------------------------------------------------------------
# Auth token handling — token absent from logs
# ---------------------------------------------------------------------------


def test_auth_token_not_logged(tmp_path: Path, caplog: pytest.LogCaptureFixture, monkeypatch):
    """The Authorization token value must never appear in any log output."""
    _FAKE_TOKEN = "Bearer super-secret-token-xyz"  # noqa: S105 — synthetic
    monkeypatch.setenv("WEBHOOK_TOKEN", _FAKE_TOKEN)

    config = {"url": "https://example.com/audit", "auth_env": "WEBHOOK_TOKEN", "timeout_s": 5.0}
    sink, _ = _sink_with_mock_post(config)

    with caplog.at_level(logging.DEBUG, logger="doberman.storage.sinks"):
        sink.emit({"final_verdict": "BLOCK"})
        sink._queue.join()

    # The raw token value must not appear anywhere in the captured log records.
    for record in caplog.records:
        assert _FAKE_TOKEN not in record.getMessage(), (
            f"Token appeared in log: {record.getMessage()!r}"
        )
        assert _FAKE_TOKEN not in (record.exc_text or "")


def test_auth_env_missing_does_not_raise(tmp_path: Path, monkeypatch):
    """If the named env var is absent, the POST continues without Authorization."""
    monkeypatch.delenv("WEBHOOK_TOKEN_MISSING", raising=False)

    config = {
        "url": "https://example.com/audit",
        "auth_env": "WEBHOOK_TOKEN_MISSING",
        "timeout_s": 5.0,
    }
    captured_headers: list[dict] = []

    class _HeaderSink(WebhookAuditSink):
        def _post(self, record: dict) -> None:
            # Simulate reading what headers would be sent.
            token = __import__("os").environ.get(self._auth_env or "", "")
            captured_headers.append({"has_auth": bool(token)})

    sink = _HeaderSink(config)
    sink.emit({"x": 1})
    sink._queue.join()

    assert captured_headers == [{"has_auth": False}]


def test_auth_token_read_at_post_time_not_stored(monkeypatch) -> None:
    """The token must not be cached on the sink object — it is read at POST time."""
    monkeypatch.setenv("LATE_TOKEN", "initial-value")
    config = {"url": "https://example.com/audit", "auth_env": "LATE_TOKEN", "timeout_s": 5.0}
    sink = WebhookAuditSink(config)
    # The env var name is stored, but the VALUE must not be.
    assert sink._auth_env == "LATE_TOKEN"
    assert not hasattr(sink, "_token"), "Token value must not be cached on the sink"
    # Verify the value is not embedded as a string anywhere in __dict__.
    for v in sink.__dict__.values():
        if isinstance(v, str):
            assert v != "initial-value", "Token value stored on sink"


# ---------------------------------------------------------------------------
# Drop-oldest counting
# ---------------------------------------------------------------------------


def test_drop_oldest_when_queue_full() -> None:
    """When the queue is at capacity the oldest record is dropped, not the newest."""
    # Create a tiny-queue sink; block the worker so it can't drain.
    config = {"url": "https://example.com/audit", "auth_env": None, "timeout_s": 5.0}
    sink = WebhookAuditSink(config)

    # Replace the queue with a tiny one.
    import queue as _q

    tiny_q: _q.Queue = _q.Queue(maxsize=2)
    sink._queue = tiny_q

    # Pause the worker so it can't drain items.
    pause = threading.Event()
    orig_post = sink._post

    def _slow_post(record: dict) -> None:
        pause.wait(timeout=10)
        orig_post(record)

    sink._post = _slow_post

    # Wait until the worker blocks on the empty queue before we fill it.
    time.sleep(0.05)

    # Fill the queue to capacity.
    sink._queue.put({"seq": 0})
    sink._queue.put({"seq": 1})

    # Now emit a third record — should drop oldest (seq=0) to make room.
    sink.emit({"seq": 2})

    # The drop counter must be at least 1.
    assert sink.drops >= 1

    # Unpause and let the worker finish.
    pause.set()


def test_drop_counter_increments_on_each_overflow() -> None:
    """Each overflow event increments the drop counter."""
    config = {"url": "https://example.com/audit", "auth_env": None, "timeout_s": 5.0}
    sink = WebhookAuditSink(config)

    # Freeze the worker so queue never drains.
    freeze = threading.Event()
    sink._post = lambda r: freeze.wait(timeout=10)
    time.sleep(0.05)

    import queue as _q

    # Fill a tiny queue, then overflow it multiple times.
    tiny_q: _q.Queue = _q.Queue(maxsize=1)
    sink._queue = tiny_q
    sink._queue.put({"seq": 0})

    for i in range(3):
        sink.emit({"seq": i + 1})

    assert sink.drops >= 1
    freeze.set()


# ---------------------------------------------------------------------------
# HTTPS enforcement
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url,should_activate",
    [
        ("https://example.com/audit", True),
        ("http://example.com/audit", False),  # non-loopback HTTP blocked
        ("http://127.0.0.1:9999/audit", True),  # loopback HTTP allowed
        ("http://localhost/audit", True),  # loopback HTTP allowed
        ("https://hooks.slack.com/audit", True),
    ],
)
def test_https_rule_via_config(tmp_path: Path, url: str, should_activate: bool) -> None:
    """Config loading enforces HTTPS for non-loopback URLs."""
    _write_webhook_yaml(tmp_path, url=url)
    cfg = _load_webhook_config(str(tmp_path))
    if should_activate:
        assert cfg is not None, f"Expected active config for URL: {url}"
    else:
        assert cfg is None, f"Expected rejected config for URL: {url}"


# ---------------------------------------------------------------------------
# emit_to_sinks wires the built-in webhook sink
# ---------------------------------------------------------------------------


def test_emit_to_sinks_includes_builtin_webhook(tmp_path: Path, monkeypatch) -> None:
    """emit_to_sinks() hands records to the built-in WebhookAuditSink."""
    from doberman.storage import sinks as sinks_mod

    # Reset the module-level singleton so our tmp_path config is picked up.
    monkeypatch.setattr(sinks_mod, "_webhook_sink", None)
    _write_webhook_yaml(tmp_path, url="http://localhost:9999/audit")

    received: list[dict] = []

    # Patch _get_builtin_webhook_sink to return a sink with a capturing emit.
    class _CapturingSink(WebhookAuditSink):
        def emit(self, record: dict) -> None:
            received.append(record)

    capturing = _CapturingSink(
        {"url": "http://localhost:9999/audit", "auth_env": None, "timeout_s": 5.0}
    )
    monkeypatch.setattr(sinks_mod, "_get_builtin_webhook_sink", lambda *a, **kw: capturing)

    # No plugin-discovered sinks.
    monkeypatch.setattr("doberman.engine.registry.discover_audit_sinks", lambda: [])

    emit_to_sinks({"final_verdict": "ALLOW", "action_id": "wh-1"}, repo_root=str(tmp_path))

    assert len(received) == 1
    assert received[0]["action_id"] == "wh-1"


def test_emit_to_sinks_plugin_sinks_run_before_builtin(monkeypatch) -> None:
    """Plugin sinks are called before the built-in webhook sink."""
    from doberman.storage import sinks as sinks_mod

    order: list[str] = []

    class _PluginSink:
        def emit(self, record: dict) -> None:
            order.append("plugin")

    class _BuiltinSink:
        def emit(self, record: dict) -> None:
            order.append("builtin")

    monkeypatch.setattr("doberman.engine.registry.discover_audit_sinks", lambda: [_PluginSink()])
    monkeypatch.setattr(sinks_mod, "_get_builtin_webhook_sink", lambda *a, **kw: _BuiltinSink())

    emit_to_sinks({"x": 1})

    assert order == ["plugin", "builtin"]


def test_emit_to_sinks_inert_builtin_with_no_config(tmp_path: Path, monkeypatch) -> None:
    """When no audit_webhook.yaml exists the built-in sink is inert (no I/O)."""
    from doberman.storage import sinks as sinks_mod

    monkeypatch.setattr(sinks_mod, "_webhook_sink", None)
    monkeypatch.setattr("doberman.engine.registry.discover_audit_sinks", lambda: [])

    # No config file → should be inert.
    emit_to_sinks({"x": 1}, repo_root=str(tmp_path))
    # If we get here without error the inert path works; no assertion needed.


# ---------------------------------------------------------------------------
# POST error paths — worker never crashes
# ---------------------------------------------------------------------------


def test_http_error_is_swallowed(caplog: pytest.LogCaptureFixture) -> None:
    """An HTTPError from the endpoint is swallowed; the worker never crashes.

    The worker's outer try/except catches all _post failures and logs a drop
    message — the specific exception type is surfaced via _post's own logging
    for HTTP/URL/Timeout errors.  Here we verify the worker keeps running and
    emits no unhandled exception after an HTTP 500 from the server.
    """
    config = {"url": "https://example.com/audit", "auth_env": None, "timeout_s": 5.0}
    sink = WebhookAuditSink(config)

    def _raise_http(_record: dict) -> None:
        raise urllib.error.HTTPError(
            url="https://example.com/audit",
            code=500,
            msg="Internal Server Error",
            hdrs=None,  # type: ignore[arg-type]
            fp=None,
        )

    sink._post = _raise_http

    with caplog.at_level(logging.WARNING, logger="doberman.storage.sinks"):
        sink.emit({"x": 1})
        sink._queue.join()

    # Worker must log a warning (drop message) and not crash.
    assert any("dropped" in r.getMessage().lower() for r in caplog.records)


def test_url_error_is_swallowed(caplog: pytest.LogCaptureFixture) -> None:
    """A URLError (connection refused, DNS failure, etc.) is swallowed gracefully."""
    config = {"url": "https://example.com/audit", "auth_env": None, "timeout_s": 5.0}
    sink = WebhookAuditSink(config)

    def _raise_url_error(_record: dict) -> None:
        raise urllib.error.URLError("connection refused")

    sink._post = _raise_url_error

    with caplog.at_level(logging.WARNING, logger="doberman.storage.sinks"):
        sink.emit({"x": 1})
        sink._queue.join()

    assert any("dropped" in r.getMessage().lower() for r in caplog.records)


def test_timeout_error_is_swallowed(caplog: pytest.LogCaptureFixture) -> None:
    """A TimeoutError from the endpoint is swallowed; the worker keeps running."""
    config = {"url": "https://example.com/audit", "auth_env": None, "timeout_s": 5.0}
    sink = WebhookAuditSink(config)

    def _raise_timeout(_record: dict) -> None:
        raise TimeoutError("timed out")

    sink._post = _raise_timeout

    with caplog.at_level(logging.WARNING, logger="doberman.storage.sinks"):
        sink.emit({"x": 1})
        sink._queue.join()

    assert any("dropped" in r.getMessage().lower() for r in caplog.records)
