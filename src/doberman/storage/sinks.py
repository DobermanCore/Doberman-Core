"""The ``AuditSink`` seam (Feature 8, slice 8.4) — the enterprise audit fan-out.

Core's default audit destination is the local SQLite decision log
(:mod:`doberman.storage.log`). Additional destinations — centralized audit,
hosted monitoring, SIEM export — live in separately-installed packages that
register an :class:`AuditSink` through the ``doberman.audit_sinks`` entry-point
group, so core never imports them by name (the repo-boundary rule).

SECURITY: a sink receives **only the already-redacted record** the local log
persists — a path *class*, reason codes, a verdict, ids, timestamps. It can
never request raw data, and it can never block, alter, or fail a decision: every
sink is isolated (a raising/slow sink is logged and skipped), and fan-out is
best-effort and happens *after* the decision is already made and the local row
written. With nothing installed, only the local log runs.

This module also ships the first **built-in** concrete sink (Feature 8, slice
8.5): :class:`WebhookAuditSink`. It is config-gated via
``.doberman/audit_webhook.yaml`` and active only when that file is present and
valid. See the class docstring for the full contract.
"""

import json
import logging
import os
import queue
import threading
import urllib.error
import urllib.request
from pathlib import Path
from typing import Protocol, runtime_checkable
from urllib.parse import urlparse

import yaml

logger = logging.getLogger("doberman.storage.sinks")

#: Config file that activates the built-in webhook sink.
_WEBHOOK_CONFIG_FILE = "audit_webhook.yaml"
#: Maximum records held in the in-process queue before drop-oldest kicks in.
_QUEUE_MAX = 512
#: Default POST timeout (seconds).
_DEFAULT_TIMEOUT_S = 5.0


@runtime_checkable
class AuditSink(Protocol):
    """A destination for already-redacted decision records.

    ``emit`` must not raise into the caller and must treat the record as
    read-only; it receives exactly the redacted dict the local log stores.
    """

    def emit(self, record: dict) -> None: ...


def _looks_like_audit_sink(obj: object) -> bool:
    """Structural check (the Protocol's isinstance is method-name only)."""
    return callable(getattr(obj, "emit", None))


def _is_loopback(host: str) -> bool:
    """Return True when ``host`` resolves to a loopback address or name.

    Covers IPv4 127.0.0.0/8, the IPv6 loopback ``::1``, and the canonical
    hostname ``localhost``. Bracket-notation IPv6 (``[::1]``) is handled by
    stripping the brackets first.
    """
    h = host.strip("[]").lower()
    if h == "localhost" or h == "::1":
        return True
    # IPv4: any address starting with "127."
    parts = h.split(".")
    if len(parts) == 4 and parts[0] == "127":
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False
    return False


def _load_webhook_config(repo_root: str) -> dict | None:
    """Parse ``.doberman/audit_webhook.yaml`` and return the config dict.

    Returns ``None`` when the file is absent (inert), and ``None`` after
    logging a warning when the file is present but malformed or missing the
    required ``url`` key. Never raises.

    SECURITY: the function only reads ``url``, ``auth_env``, and
    ``timeout_s`` — any other key is silently ignored. The token value is
    **never** read here; :class:`WebhookAuditSink` reads it from the named
    env var at POST time so it is never stored on the object.
    """
    path = Path(repo_root) / ".doberman" / _WEBHOOK_CONFIG_FILE
    if not path.exists():
        return None
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        logger.warning("audit_webhook: could not read %s; webhook sink disabled", path)
        return None
    if not isinstance(raw, dict):
        logger.warning("audit_webhook: %s is not a mapping; webhook sink disabled", path)
        return None
    url = raw.get("url")
    if not isinstance(url, str) or not url.strip():
        logger.warning("audit_webhook: missing or empty 'url' in %s; webhook sink disabled", path)
        return None
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        logger.warning(
            "audit_webhook: unsupported URL scheme %r in %s; webhook sink disabled",
            parsed.scheme,
            path,
        )
        return None
    if not _is_loopback(parsed.hostname or "") and parsed.scheme != "https":
        logger.warning(
            "audit_webhook: non-loopback URL must use HTTPS (got %r); webhook sink disabled",
            parsed.scheme,
        )
        return None
    auth_env = raw.get("auth_env")
    if auth_env is not None and not isinstance(auth_env, str):
        logger.warning(
            "audit_webhook: 'auth_env' must be a string in %s; webhook sink disabled", path
        )
        return None
    timeout_raw = raw.get("timeout_s", _DEFAULT_TIMEOUT_S)
    try:
        timeout_s = float(timeout_raw)
        if timeout_s <= 0:
            raise ValueError("timeout must be positive")
    except (TypeError, ValueError):
        logger.warning(
            "audit_webhook: invalid 'timeout_s' %r in %s; using default", timeout_raw, path
        )
        timeout_s = _DEFAULT_TIMEOUT_S
    return {"url": url.strip(), "auth_env": auth_env, "timeout_s": timeout_s}


class WebhookAuditSink:
    """Built-in webhook forwarder for the ``AuditSink`` seam (F8.5).

    Activated by ``.doberman/audit_webhook.yaml``.  With no file (or a
    malformed one) the sink is **inert**: :meth:`emit` returns immediately
    without any I/O.

    **Decision-path contract:** :meth:`emit` enqueues the record and returns
    before any network I/O. A daemon worker thread does the actual POST so a
    wedged or slow endpoint *cannot* delay a decision.

    **Queue overflow:** when the queue is full the *oldest* record is dropped
    (not the incoming one) and the drop count is incremented.  Records lost on
    overflow or process exit are lost — this sink is a bridge to your own log
    pipeline, not a delivery guarantee.

    **Secret hygiene:** the ``Authorization`` token comes *only* from the env
    var named by ``auth_env``. The token value is never stored on this object,
    never logged, and never read from YAML.  The POST body is exactly the
    already-redacted record dict — the sink adds nothing and reads nothing else.
    """

    def __init__(self, config: dict | None) -> None:
        """Construct the sink.

        ``config`` is the parsed dict from :func:`_load_webhook_config`; pass
        ``None`` (or an empty/invalid dict) to create an inert sink.
        """
        self._active = False
        self._url: str = ""
        self._auth_env: str | None = None
        self._timeout_s: float = _DEFAULT_TIMEOUT_S
        self._queue: queue.Queue[dict] = queue.Queue(maxsize=0)  # replaced below if active
        self._drops = 0
        self._drops_lock = threading.Lock()

        if not config:
            return

        self._url = config["url"]
        self._auth_env = config.get("auth_env")
        self._timeout_s = float(config.get("timeout_s", _DEFAULT_TIMEOUT_S))
        self._queue = queue.Queue(maxsize=_QUEUE_MAX)
        self._active = True

        worker = threading.Thread(target=self._worker, daemon=True, name="doberman-webhook-sink")
        worker.start()

    @classmethod
    def from_repo(cls, repo_root: str) -> "WebhookAuditSink":
        """Construct from the repo's ``.doberman/audit_webhook.yaml``.

        Returns an inert sink when the config file is absent or malformed.
        """
        return cls(_load_webhook_config(repo_root))

    # ------------------------------------------------------------------
    # AuditSink interface
    # ------------------------------------------------------------------

    def emit(self, record: dict) -> None:
        """Enqueue *record* for async delivery; returns immediately (no I/O).

        If the queue is full the oldest record is dropped to make room, the
        drop counter is incremented, and the new record is enqueued. Never
        raises: any internal error is logged and swallowed.
        """
        if not self._active:
            return
        try:
            try:
                self._queue.put_nowait(record)
            except queue.Full:
                try:
                    self._queue.get_nowait()  # drop oldest
                except queue.Empty:
                    pass
                with self._drops_lock:
                    self._drops += 1
                # Best-effort: try again; if still full another thread won the
                # race — just drop the incoming record rather than blocking.
                try:
                    self._queue.put_nowait(record)
                except queue.Full:
                    with self._drops_lock:
                        self._drops += 1
        except Exception:  # noqa: BLE001 — emit must never raise
            logger.warning("audit_webhook: emit() internal error; record dropped")

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @property
    def drops(self) -> int:
        """Total records dropped due to queue overflow."""
        with self._drops_lock:
            return self._drops

    def _worker(self) -> None:
        """Daemon thread: dequeue records and POST them until the process exits."""
        while True:
            try:
                record = self._queue.get(block=True, timeout=1.0)
            except queue.Empty:
                continue
            try:
                self._post(record)
            except Exception:  # noqa: BLE001 — worker must never crash
                logger.warning("audit_webhook: POST failed; record dropped")
            finally:
                self._queue.task_done()

    def _post(self, record: dict) -> None:
        """POST *record* as JSON to the configured URL.

        The ``Authorization`` token is read from the env var named by
        ``auth_env`` at call time — never from this object's fields — so it
        is never stored in memory longer than the single request.  The token
        value is **never** written to any log.
        """
        body = json.dumps(record, default=str).encode()
        headers = {"Content-Type": "application/json"}

        if self._auth_env:
            token = os.environ.get(self._auth_env, "")
            if token:
                # The header value itself must not be logged anywhere.
                headers["Authorization"] = token

        req = urllib.request.Request(self._url, data=body, headers=headers, method="POST")  # noqa: S310
        try:
            with urllib.request.urlopen(req, timeout=self._timeout_s) as _resp:  # noqa: S310
                pass  # success; response body is ignored
        except urllib.error.HTTPError as exc:
            logger.warning("audit_webhook: HTTP %s from %s; record dropped", exc.code, self._url)
        except urllib.error.URLError as exc:
            logger.warning(
                "audit_webhook: URLError posting to %s: %s; record dropped",
                self._url,
                type(exc.reason).__name__,
            )
        except TimeoutError:
            logger.warning("audit_webhook: timeout posting to %s; record dropped", self._url)
        except OSError:
            logger.warning("audit_webhook: network error posting to %s; record dropped", self._url)


# Module-level cache — one sink per repo root, created once per process and
# keyed by the *resolved* root path so "." and its absolute spelling share one
# instance (one worker thread per configured repo, not per spelling). Tests
# that need a custom root should construct WebhookAuditSink directly via
# WebhookAuditSink.from_repo(root) or WebhookAuditSink(config).
_webhook_sinks: dict[str, WebhookAuditSink] = {}
_webhook_sink_lock = threading.Lock()


def _get_builtin_webhook_sink(repo_root: str = ".") -> WebhookAuditSink:
    """Return (or lazily create) the process-level webhook sink for *repo_root*.

    Only the first call for a given ``repo_root`` constructs a sink; subsequent
    calls return the cached instance.  This avoids spinning up multiple worker
    threads for the same config — while a second, different repo root in the
    same process still gets its own sink instead of silently reusing the
    first repo's config.
    """
    key = str(Path(repo_root).resolve())
    with _webhook_sink_lock:
        sink = _webhook_sinks.get(key)
        if sink is None:
            sink = _webhook_sinks[key] = WebhookAuditSink.from_repo(repo_root)
    return sink


def emit_to_sinks(record: dict, *, repo_root: str = ".") -> None:
    """Fan a redacted record out to every registered sink, isolating failures.

    Consults plugin-registered sinks first (entry-point group
    ``doberman.audit_sinks``) and then the built-in
    :class:`WebhookAuditSink`.  Never raises: a sink that is not sink-shaped,
    or whose ``emit`` raises, is logged and skipped.  With no sinks installed
    and no webhook config this is a no-op.  The local SQLite log is written by
    the caller (:mod:`doberman.storage.log`), not here — this fan-out is for
    *extra* destinations only.
    """
    # Lazy import: the registry lives in the engine layer.
    from doberman.engine.registry import discover_audit_sinks

    all_sinks: list[object] = list(discover_audit_sinks())
    # Built-in webhook sink comes after plugin-discovered sinks (same isolation).
    all_sinks.append(_get_builtin_webhook_sink(repo_root))

    for sink in all_sinks:
        if not _looks_like_audit_sink(sink):
            logger.warning("skipping audit sink %r: not sink-shaped", sink)
            continue
        try:
            sink.emit(dict(record))  # hand each sink its own copy (read-only intent)
        except Exception:  # noqa: BLE001 — a sink failure must never affect a decision
            logger.warning("audit sink %r raised; skipping", type(sink).__name__)
