"""Cross-channel single-flight for Codex hooks (W1.2).

Doberman's Codex hooks can be installed two ways at once — a config-layer
``~/.codex/hooks.json`` (``doberman install-hooks --host codex``) and a
plugin-bundled ``hooks.json`` (the awesome-codex-plugins package). With both
wired, Codex fires the PreToolUse hook **twice per tool call**: two AUTH
prompts, two history rows, and doubled taint counters (``storage/taint.py``
increments unconditionally). The first invocation records its final answer
under a per-call marker; the second replays it byte-for-byte instead of
re-evaluating.

The dedupe key is the tool call's ``tool_use_id`` (a live capture confirmed each
Codex tool call carries a stable ``"tool_use_id": "exec-<uuid>"`` that is
identical across both hook channels for the same call — see
``tests/fixtures/codex/README.md``).

SECURITY MODEL: dedupe is a UX / observability concern, **never a gate**. Two
layers, both keyed by :func:`doberman.storage.fingerprint.fingerprint` (a ``0600``
HMAC key, itself glob-blocked ``**/*.key``):

* The marker **name** is a keyed HMAC of the ``tool_use_id`` — an agent cannot
  precompute a marker path and pre-seed an answer without the key.
* The marker **content** carries a keyed MAC verified on read — so even a blind
  overwrite of every ``doberman-sf-*`` file in the shared tempdir (an attacker
  who can't derive the name but can enumerate the prefix) cannot spoof a replayed
  verdict: a MAC mismatch is treated as no marker and the call is re-evaluated.

Any marker read/write error, MAC mismatch, or expired marker falls through to a
full duplicate evaluation (same verdict — safe), NEVER to a skipped one. The TTL
is tight (older than 30s is dead) so a stale marker can never suppress a later
genuine call.
"""

from __future__ import annotations

import os
import tempfile
import time

#: The payload key carrying Codex's per-tool-call identifier (live-captured:
#: ``"tool_use_id": "exec-<uuid>"``). If a payload carries none, dedupe is off
#: and a doubled install double-fires (documented in adapters/codex/README).
EVENT_ID_KEY = "tool_use_id"

_TTL_SECONDS = 30.0
_ABSTAIN = "__DOBERMAN_ABSTAIN__"  # noqa: S105 — a sentinel string, not a credential


def event_key(payload: dict) -> str | None:
    """A keyed, non-derivable marker key for this tool call — or ``None`` (no dedupe).

    ``None`` whenever the payload carries no ``tool_use_id`` or the HMAC key is
    unavailable: dedupe simply does not engage, and each channel evaluates
    independently (safe — same verdict, just not de-duplicated).
    """
    raw = payload.get(EVENT_ID_KEY)
    if not isinstance(raw, str) or not raw:
        return None
    try:
        from doberman.storage.fingerprint import fingerprint  # keyed HMAC, lazy

        sid = payload.get("session_id") or ""
        return fingerprint(f"codex-event:{sid}:{raw}")[:32]
    except Exception:  # noqa: BLE001 — no key material -> no dedupe (safe)
        return None


def _marker_path(key: str) -> str:
    return os.path.join(tempfile.gettempdir(), f"doberman-sf-{key}")


def _content_mac(content: str) -> str | None:
    """Keyed MAC over a marker's content, or ``None`` if the key is unavailable."""
    try:
        from doberman.storage.fingerprint import fingerprint  # keyed HMAC, lazy

        return fingerprint(f"codex-sf-content:{content}")[:32]
    except Exception:  # noqa: BLE001 — no key -> cannot verify -> caller re-evaluates
        return None


def replay(key: str | None) -> str | None:
    """The first invocation's recorded answer, or ``None`` to evaluate normally.

    Returns ``""`` when the first invocation abstained (the caller maps that back
    to "print nothing"), the recorded JSON string when it produced output, or
    ``None`` when there is no *trustworthy* live marker — missing, expired, a read
    error, or a **content-MAC mismatch** (a tampered / forged marker). In every
    ``None`` case the caller evaluates from scratch (fail-safe).
    """
    if not key:
        return None
    path = _marker_path(key)
    try:
        if time.time() - os.path.getmtime(path) > _TTL_SECONDS:
            return None
        with open(path, encoding="utf-8") as f:
            raw = f.read()
    except OSError:
        return None
    stored_mac, sep, content = raw.partition("\n")
    if not sep:
        return None  # malformed marker (no MAC line) -> re-evaluate
    expected = _content_mac(content)
    if expected is None or stored_mac != expected:
        return None  # tampered / unverifiable -> re-evaluate (never trust it)
    return "" if content == _ABSTAIN else (content or None)


def record(key: str | None, answer: str | None) -> None:
    """Persist this call's final answer (``None`` -> the abstain sentinel) with a
    keyed content MAC.

    Best-effort and atomic (write-temp-then-rename); any failure (including an
    unavailable MAC key) just means the other channel re-evaluates instead of
    replaying — never a wrong verdict.
    """
    if not key:
        return
    content = _ABSTAIN if answer is None else answer
    mac = _content_mac(content)
    if mac is None:
        return  # no key -> don't write an unverifiable marker (the peer re-evaluates)
    try:
        fd, tmp = tempfile.mkstemp(dir=tempfile.gettempdir(), prefix="doberman-sf-")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(f"{mac}\n{content}")
        os.replace(tmp, _marker_path(key))
    except OSError:
        pass
