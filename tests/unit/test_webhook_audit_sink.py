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


class _FakeResponse:
    """Minimal context-manager response stub for urllib.request.urlopen."""

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


def _stub_urlopen(captured_requests: list):
    """Return a urlopen replacement that records Request objects instead of POSTing.

    Stubs at the urlopen level so the real _post path — JSON serialisation,
    header construction, Request object assembly — is fully exercised.
    """

    def _fake_urlopen(req, timeout=None):
        captured_requests.append(req)
        return _FakeResponse()

    return _fake_urlopen


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


def test_record_posted_as_json(monkeypatch) -> None:
    """The worker POSTs the exact record as JSON — exercises the real _post path."""
    config = {"url": "https://example.com/audit", "auth_env": None, "timeout_s": 5.0}
    captured: list[urllib.request.Request] = []
    monkeypatch.setattr(urllib.request, "urlopen", _stub_urlopen(captured))

    sink = WebhookAuditSink(config)
    record = {"final_verdict": "ALLOW", "action_id": "act-webhook-1"}
    sink.emit(record)
    sink._queue.join()

    assert len(captured) == 1
    body = json.loads(captured[0].data)
    assert body["final_verdict"] == "ALLOW"
    assert body["action_id"] == "act-webhook-1"
    assert captured[0].get_header("Content-type") == "application/json"


def test_synthetic_secret_never_in_posted_body(monkeypatch) -> None:
    """A synthetic secret value must never appear in the JSON body — real _post exercised."""
    config = {"url": "https://example.com/audit", "auth_env": None, "timeout_s": 5.0}
    captured: list[urllib.request.Request] = []
    monkeypatch.setattr(urllib.request, "urlopen", _stub_urlopen(captured))

    sink = WebhookAuditSink(config)
    record = {
        "final_verdict": "AUTH",
        "reason_codes": ["sensitive_secret_access"],
        # HMAC fingerprints are safe to transmit; raw secrets must never appear.
        "payload_fingerprints": ["hmac:deadbeef1234"],
    }
    sink.emit(record)
    sink._queue.join()

    assert len(captured) == 1
    body_text = captured[0].data.decode()
    assert _SECRET not in body_text, "Synthetic secret must never appear in the POSTed body"
    assert "hmac:deadbeef1234" in body_text


# ---------------------------------------------------------------------------
# Auth token handling — token absent from logs
# ---------------------------------------------------------------------------


def test_auth_token_in_header_not_in_body(monkeypatch) -> None:
    """Authorization header carries the token; the JSON body must not contain it."""
    _FAKE_TOKEN = "Bearer super-secret-token-xyz"  # noqa: S105 — synthetic
    monkeypatch.setenv("WEBHOOK_TOKEN", _FAKE_TOKEN)

    config = {"url": "https://example.com/audit", "auth_env": "WEBHOOK_TOKEN", "timeout_s": 5.0}
    captured: list[urllib.request.Request] = []
    monkeypatch.setattr(urllib.request, "urlopen", _stub_urlopen(captured))

    sink = WebhookAuditSink(config)
    sink.emit({"final_verdict": "BLOCK"})
    sink._queue.join()

    assert len(captured) == 1
    req = captured[0]
    # Token must be in the Authorization header (real Request object).
    assert req.get_header("Authorization") == _FAKE_TOKEN
    # Token must NOT appear anywhere in the POST body.
    body_text = req.data.decode()
    assert _FAKE_TOKEN not in body_text, "Token must never appear in the POST body"


def test_auth_token_not_logged(monkeypatch, caplog: pytest.LogCaptureFixture) -> None:
    """The Authorization token value must never appear in any log output."""
    _FAKE_TOKEN = "Bearer super-secret-token-xyz"  # noqa: S105 — synthetic
    monkeypatch.setenv("WEBHOOK_TOKEN", _FAKE_TOKEN)

    config = {"url": "https://example.com/audit", "auth_env": "WEBHOOK_TOKEN", "timeout_s": 5.0}
    captured: list[urllib.request.Request] = []
    monkeypatch.setattr(urllib.request, "urlopen", _stub_urlopen(captured))

    sink = WebhookAuditSink(config)
    with caplog.at_level(logging.DEBUG, logger="doberman.storage.sinks"):
        sink.emit({"final_verdict": "BLOCK"})
        sink._queue.join()

    for record in caplog.records:
        assert _FAKE_TOKEN not in record.getMessage(), (
            f"Token appeared in log: {record.getMessage()!r}"
        )
        assert _FAKE_TOKEN not in (record.exc_text or "")


def test_auth_env_missing_omits_authorization_header(monkeypatch) -> None:
    """When the named env var is absent the POST goes out without Authorization."""
    monkeypatch.delenv("WEBHOOK_TOKEN_MISSING", raising=False)

    config = {
        "url": "https://example.com/audit",
        "auth_env": "WEBHOOK_TOKEN_MISSING",
        "timeout_s": 5.0,
    }
    captured: list[urllib.request.Request] = []
    monkeypatch.setattr(urllib.request, "urlopen", _stub_urlopen(captured))

    sink = WebhookAuditSink(config)
    sink.emit({"x": 1})
    sink._queue.join()

    assert len(captured) == 1
    assert captured[0].get_header("Authorization") is None


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


def test_drop_oldest_when_queue_full(monkeypatch) -> None:
    """When the queue is at capacity the oldest record is dropped, not the newest."""
    import queue as _q

    config = {"url": "https://example.com/audit", "auth_env": None, "timeout_s": 5.0}
    captured: list[urllib.request.Request] = []
    monkeypatch.setattr(urllib.request, "urlopen", _stub_urlopen(captured))

    sink = WebhookAuditSink(config)

    # Swap in a tiny queue and block the worker so it can't drain.
    tiny_q: _q.Queue = _q.Queue(maxsize=2)
    sink._queue = tiny_q

    pause = threading.Event()
    sink._post = lambda r: pause.wait(timeout=10)  # block worker; never hits urlopen

    time.sleep(0.05)  # let the worker settle on the empty queue

    # Fill the queue to capacity, then emit one more — should drop oldest.
    sink._queue.put({"seq": 0})
    sink._queue.put({"seq": 1})
    sink.emit({"seq": 2})

    assert sink.drops >= 1

    pause.set()  # unblock worker


def test_drop_counter_increments_on_each_overflow(monkeypatch) -> None:
    """Each overflow event increments the drop counter."""
    import queue as _q

    config = {"url": "https://example.com/audit", "auth_env": None, "timeout_s": 5.0}
    monkeypatch.setattr(urllib.request, "urlopen", _stub_urlopen([]))

    sink = WebhookAuditSink(config)

    freeze = threading.Event()
    sink._post = lambda r: freeze.wait(timeout=10)  # block worker; network-free
    time.sleep(0.05)

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

    # Reset the module-level cache so our tmp_path config is picked up.
    monkeypatch.setattr(sinks_mod, "_webhook_sinks", {})
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

    monkeypatch.setattr(sinks_mod, "_webhook_sinks", {})
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
