"""Phone approvals via the ntfy push service — a tap replaces the desk.

Doberman's challenge normally needs a human at the desk: a GUI dialog, a
terminal prompt, or the dashboard. This module adds a **phone** channel
through ntfy (public ``ntfy.sh`` or self-hosted): :class:`NtfyChannel`
publishes a push notification with Approve/Deny buttons whose taps POST a
one-time reply to a second, secret topic; it then streams that topic and
waits for the exact reply. Two thin adapters sit on top of the channel:

* :class:`NtfyApprovalMethod` — the :class:`~doberman.auth.approval.ApprovalMethod`
  (the possession factor) for the ``two_factor``/``role_elevation`` tiers, the
  same seam :mod:`doberman.auth.methods.windows_hello` uses.
* :class:`NtfyPrompter` — a :class:`~doberman.auth.challenge.Prompter` for the
  ``FallbackPrompter`` chain, covering the confirm-only tiers (``soft_confirm``/
  ``local_auth``). It steps aside (raises
  :class:`~doberman.auth.gui_prompter.PrompterUnavailableError`) on a 2FA tier —
  the method above already owns the phone there, so the human is never
  notified twice for one challenge.

Config lives beside ``approval.json`` (:func:`doberman.auth.approval_config.config_dir`),
as ``ntfy.json``, written ``0600`` in a ``0700`` dir. Opt-in is two-layered, same
discipline as every other approval method: the config file must exist AND
``doberman 2fa methods enable ntfy`` (:func:`doberman.auth.approval_config.is_enabled`)
must have run — either alone leaves the channel inert.

SECURITY CONTRACT:

* **Fail closed.** Any exception while publishing → ``"unavailable"``; any
  exception while streaming the reply → ``"timeout"``. Neither ever becomes an
  approval. A reply is honoured only on an EXACT ``"approve <nonce>"`` /
  ``"deny <nonce>"`` line for THIS request's nonce; a deny is final even if a
  (spoofed or delayed) approve follows it.
* **Never logged.** The topics, the nonce, and the bearer token never appear in
  a log line — only the server host and the outcome, at DEBUG.
* **Prompt-only.** This module never derives the notification text itself; it
  publishes exactly the (already-masked, see :mod:`doberman.proxy.normalize`)
  prompt string the caller hands it.

Stdlib only (``urllib.request``, ``secrets``, ``json``, ``time``) — no new
dependency.
"""

from __future__ import annotations

import json
import logging
import os
import re
import secrets
import stat
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from doberman.auth import approval_config
from doberman.auth.approval import ApprovalOutcome
from doberman.auth.challenge import AuthTier, current_challenge
from doberman.auth.gui_prompter import PrompterUnavailableError

logger = logging.getLogger("doberman.auth.ntfy")

#: Env var overriding the ntfy config-file location (tests inject a temp path).
NTFY_FILE_ENV = "DOBERMAN_NTFY_FILE"

DEFAULT_SERVER = "https://ntfy.sh"

#: Stable identifier — matches the approval_config/CLI name (``doberman phone ...``).
METHOD_NAME = "ntfy"

_WAIT_MIN_S = 10
_WAIT_MAX_S = 300
_MESSAGE_MAX_BYTES = 3500
_PUBLISH_TIMEOUT_S = 10.0
_STREAM_TIMEOUT_S = 30.0
_TITLE = "Doberman: approve this action?"
#: The 2FA tiers already run the phone through NtfyApprovalMethod — never
#: double-notify by also engaging the prompter for them.
_TWO_FACTOR_TIERS = frozenset({AuthTier.two_factor, AuthTier.role_elevation})
#: The message always ends with this exact shape (see :func:`NtfyChannel.ask`);
#: truncation preserves it instead of cutting it off.
_ID_LINE_RE = re.compile(r"\n\nid [^\n]*$")


@dataclass(frozen=True)
class NtfyConfig:
    """One phone's config: where to publish and the two secret topics.

    ``topic`` is where the notification is published; ``reply_topic`` is a
    SEPARATE topic the Approve/Deny buttons POST to — "the topic name is your
    password" on ntfy.sh, so keeping them apart (and secret) matters.
    """

    server: str
    topic: str
    reply_topic: str
    token: str = ""
    wait_s: int = 60


def config_path() -> Path:
    """Where the ntfy config lives: :data:`NTFY_FILE_ENV` override, else
    ``ntfy.json`` beside ``approval.json`` (:func:`approval_config.config_dir`)."""
    override = os.environ.get(NTFY_FILE_ENV)
    return Path(override) if override else approval_config.config_dir() / "ntfy.json"


def load_config() -> NtfyConfig | None:
    """The saved config, or ``None`` when absent/unreadable/malformed. Never raises."""
    path = config_path()
    try:
        raw = path.read_text(encoding="utf-8")
    except (FileNotFoundError, OSError):
        return None
    try:
        data = json.loads(raw)
        if not isinstance(data, dict):
            return None
        return NtfyConfig(
            server=str(data["server"]),
            topic=str(data["topic"]),
            reply_topic=str(data["reply_topic"]),
            token=str(data.get("token", "")),
            wait_s=int(data.get("wait_s", 60)),
        )
    except (KeyError, ValueError, TypeError):
        logger.warning("ntfy config at %s is malformed; treating as absent", path)
        return None


def save_config(cfg: NtfyConfig) -> Path:
    """Persist ``cfg`` to a ``0600`` file in a ``0700`` dir (best-effort on Windows)."""
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.parent.chmod(stat.S_IRWXU)
    except OSError:  # pragma: no cover — non-POSIX perms
        pass
    payload = json.dumps(
        {
            "server": cfg.server,
            "topic": cfg.topic,
            "reply_topic": cfg.reply_topic,
            "token": cfg.token,
            "wait_s": cfg.wait_s,
        },
        indent=2,
    )
    path.write_text(payload, encoding="utf-8")
    try:
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except OSError:  # pragma: no cover — non-POSIX perms
        pass
    return path


def delete_config() -> bool:
    """Remove the config file. ``True`` if a file was actually removed."""
    try:
        config_path().unlink()
        return True
    except OSError:
        return False


def new_config(*, server: str = DEFAULT_SERVER, token: str = "", wait_s: int = 60) -> NtfyConfig:
    """A fresh config: two random topics, ``wait_s`` clamped to ``[10, 300]``."""
    clamped = max(_WAIT_MIN_S, min(_WAIT_MAX_S, wait_s))
    return NtfyConfig(
        server=server.rstrip("/"),
        topic=secrets.token_urlsafe(18),
        reply_topic=secrets.token_urlsafe(18),
        token=token,
        wait_s=clamped,
    )


def is_enabled() -> bool:
    """Configured AND opted in — both gates must hold (mirrors every approval method)."""
    return load_config() is not None and approval_config.is_enabled(METHOD_NAME)


class NtfyUnavailable(RuntimeError):
    """Raised by :meth:`NtfyChannel.publish` when the notification could not be sent."""


def _host(server: str) -> str:
    """The bare hostname for a DEBUG log line — never the full server URL/topics."""
    try:
        return urlparse(server).hostname or "?"
    except ValueError:
        return "?"


def _truncate_message(message: str) -> str:
    """Cap ``message`` at :data:`_MESSAGE_MAX_BYTES` on a UTF-8 char boundary.

    The message always ends with a ``"\\n\\nid <action_id>"`` line (see
    :meth:`NtfyChannel.ask`); truncation shortens the BODY before that line and
    keeps the id line intact, so a truncated notification still names the action.
    """
    encoded = message.encode("utf-8")
    if len(encoded) <= _MESSAGE_MAX_BYTES:
        return message
    match = _ID_LINE_RE.search(message)
    head, tail = (message[: match.start()], message[match.start() :]) if match else (message, "")
    ellipsis = "…"
    budget = max(_MESSAGE_MAX_BYTES - len(tail.encode("utf-8")) - len(ellipsis.encode("utf-8")), 0)
    head_bytes = head.encode("utf-8")[:budget]
    while head_bytes:
        try:
            head_text = head_bytes.decode("utf-8")
            break
        except UnicodeDecodeError:
            head_bytes = head_bytes[:-1]
    else:
        head_text = ""
    return head_text + ellipsis + tail


def _http_action(label: str, url: str, body: str, token: str) -> dict[str, Any]:
    action: dict[str, Any] = {
        "action": "http",
        "label": label,
        "url": url,
        "method": "POST",
        "body": body,
        "clear": True,
    }
    if token:
        action["headers"] = {"Authorization": f"Bearer {token}"}
    return action


class NtfyChannel:
    """Publish an Approve/Deny push notification, then wait for the exact reply."""

    def __init__(self, cfg: NtfyConfig, *, urlopen=urllib.request.urlopen, clock=time.time) -> None:
        self._cfg = cfg
        self._urlopen = urlopen
        self._clock = clock

    def publish(self, *, title: str, message: str, nonce: str) -> float:
        """POST the notification. Returns the publish time; raises
        :class:`NtfyUnavailable` on any HTTP or transport failure — never lets
        a broken backend become a silent approval."""
        cfg = self._cfg
        reply_url = f"{cfg.server}/{cfg.reply_topic}"
        headers = {"Content-Type": "application/json"}
        if cfg.token:
            headers["Authorization"] = f"Bearer {cfg.token}"
        payload = {
            "topic": cfg.topic,
            "title": title,
            "message": _truncate_message(message),
            "priority": 4,
            "tags": ["dog"],
            "actions": [
                _http_action("Approve", reply_url, f"approve {nonce}", cfg.token),
                _http_action("Deny", reply_url, f"deny {nonce}", cfg.token),
            ],
        }
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(  # noqa: S310 — server is user-configured http(s), never file:
            cfg.server, data=body, headers=headers, method="POST"
        )
        try:
            with self._urlopen(req, timeout=_PUBLISH_TIMEOUT_S) as resp:
                status = getattr(resp, "status", 200) or 200
                if status >= 400:
                    raise NtfyUnavailable(f"ntfy publish failed: HTTP {status}")
        except NtfyUnavailable:
            raise
        except Exception as exc:  # noqa: BLE001 — any transport failure -> unavailable
            raise NtfyUnavailable("ntfy publish failed") from exc
        return self._clock()

    def wait(self, nonce: str, *, since: float, deadline_s: float) -> str:
        """Stream the reply topic for an exact ``"approve <nonce>"``/``"deny
        <nonce>"`` line. ``"denied"``/``"approved"`` on the first exact match
        (deny wins if it comes first — a later approve can never undo it),
        ``"timeout"`` when the stream ends, the deadline passes, or anything
        raises (fail closed: a streaming error is never treated as silence
        meaning approval)."""
        cfg = self._cfg
        url = f"{cfg.server}/{cfg.reply_topic}/json?since={int(since) - 1}"
        headers = {"Authorization": f"Bearer {cfg.token}"} if cfg.token else {}
        req = urllib.request.Request(url, headers=headers, method="GET")  # noqa: S310 — same host as publish
        approve_line, deny_line = f"approve {nonce}", f"deny {nonce}"
        deadline_at = since + deadline_s
        # ponytail: one connection for the whole wait, timeout = min(30s,
        # remaining) at open time; a real per-line-recomputed timeout would
        # need direct socket manipulation urllib doesn't expose. Upgrade path
        # only if a slow/idle stream is observed to overrun in practice.
        timeout = min(_STREAM_TIMEOUT_S, max(deadline_at - self._clock(), 0.0)) or _STREAM_TIMEOUT_S
        try:
            with self._urlopen(req, timeout=timeout) as resp:
                while self._clock() < deadline_at:
                    line = resp.readline()
                    if not line:
                        return "timeout"
                    try:
                        event = json.loads(line)
                    except (ValueError, TypeError):
                        continue
                    message = str(event.get("message", "")).strip()
                    if message == deny_line:
                        return "denied"
                    if message == approve_line:
                        return "approved"
                return "timeout"
        except Exception:  # noqa: BLE001 — fail closed: a stream error is a timeout, never approved
            return "timeout"

    def ask(self, prompt: str, *, action_id: str, deadline_s: float) -> str:
        """Publish + wait in one call. ``"unavailable"`` when publish fails —
        the stream is never opened in that case."""
        nonce = secrets.token_urlsafe(16)
        message = f"{prompt}\n\nid {action_id[:8]}"
        try:
            since = self.publish(title=_TITLE, message=message, nonce=nonce)
        except NtfyUnavailable:
            logger.debug("ntfy publish to %s: unavailable", _host(self._cfg.server))
            return "unavailable"
        outcome = self.wait(nonce, since=since, deadline_s=deadline_s)
        logger.debug("ntfy ask via %s: %s", _host(self._cfg.server), outcome)
        return outcome


_OUTCOME_MAP: dict[str, ApprovalOutcome] = {
    "approved": ApprovalOutcome.approved,
    "denied": ApprovalOutcome.denied,
}


class NtfyApprovalMethod:
    """Approve an action with a tap on the ntfy push notification (2FA tiers)."""

    name = METHOD_NAME

    def is_available(self) -> bool:
        """Conservative, never raises: configured AND opted in."""
        return is_enabled()

    def request(self, prompt: str, *, action_id: str, timeout_s: float) -> ApprovalOutcome:
        """``approved``/``denied`` only on an explicit exact reply; every
        other case (``timeout``, publish failure, not configured) is
        ``unavailable`` so the caller falls back to TOTP — never a bypass.
        The deadline is ``min(timeout_s, wait_s)``: never wait longer than
        either the tier's own budget or what the user configured.
        """
        cfg = load_config()
        if cfg is None:
            return ApprovalOutcome.unavailable
        channel = NtfyChannel(cfg)
        outcome = channel.ask(prompt, action_id=action_id, deadline_s=min(timeout_s, cfg.wait_s))
        return _OUTCOME_MAP.get(outcome, ApprovalOutcome.unavailable)


class NtfyPrompter:
    """The confirm-only channel (``soft_confirm``/``local_auth``) in the
    ``FallbackPrompter`` chain — steps aside on a 2FA tier so the phone is
    never notified twice for one challenge (see module docstring).
    """

    def __init__(self) -> None:
        self.last_reason: str | None = None

    def confirm(self, message: str) -> bool:
        self.last_reason = None
        cfg = load_config()
        if cfg is None or not approval_config.is_enabled(METHOD_NAME):
            raise PrompterUnavailableError("ntfy phone approvals are not configured")
        challenge = current_challenge()
        if challenge is not None and challenge[2] in _TWO_FACTOR_TIERS:
            raise PrompterUnavailableError(
                "this tier's phone approval already runs via NtfyApprovalMethod"
            )
        action_id = challenge[1].id if challenge is not None else ""
        channel = NtfyChannel(cfg)
        outcome = channel.ask(message, action_id=action_id, deadline_s=cfg.wait_s)
        if outcome == "approved":
            return True
        if outcome == "denied":
            self.last_reason = "denied on phone"
            return False
        # "timeout" / "unavailable" — this channel could not answer; let the
        # chain try the next one rather than manufacture a denial.
        raise PrompterUnavailableError(f"ntfy phone approval {outcome}")

    def read_code(self, message: str) -> str:  # noqa: ARG002 - no code entry on a notification
        raise PrompterUnavailableError("ntfy has no code entry; the tap alone approves")
