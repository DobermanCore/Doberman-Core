"""Cross-channel single-flight for Codex hooks (W1.2).

When both install channels are wired, Codex fires the PreToolUse hook twice per
tool call; the second invocation must replay the first's answer instead of
re-evaluating (no doubled AUTH prompt / history row / taint bump). Keyed on the
captured ``tool_use_id``, with a keyed-MAC over the marker content so a tampered
marker is re-evaluated rather than trusted.

The marker name AND content MAC both use the keyed fingerprint, so every test
that exercises ``event_key`` / ``record`` / ``replay`` requests the
``isolated_fingerprint_key`` fixture (conftest) for a deterministic, xdist-safe
key. The no-key / no-id fail-safe path is covered without it.
"""

import json
import os
import time
import uuid

from doberman.hosthooks import codex, singleflight


def _payload(tmp_path, tool_use_id=None):
    # Unique tool_use_id + session per test so a leftover marker from a prior run
    # (TTL 30s) can't pre-satisfy replay.
    return {
        "tool_name": "Bash",
        "tool_input": {"command": "rm -rf /"},
        "cwd": str(tmp_path),
        "session_id": "sess-" + uuid.uuid4().hex,
        singleflight.EVENT_ID_KEY: tool_use_id or ("exec-" + uuid.uuid4().hex),
    }


def test_event_id_key_matches_capture():
    # The dedupe key is the captured per-call id, not the plan's placeholder.
    assert singleflight.EVENT_ID_KEY == "tool_use_id"


def test_second_invocation_replays_first_answer(tmp_path, monkeypatch, isolated_fingerprint_key):
    calls = {"n": 0}
    real = codex.evaluate_pre

    def counting(payload):
        calls["n"] += 1
        return real(payload)

    monkeypatch.setattr(codex, "evaluate_pre", counting)
    # Pin a deterministic marker key so this end-to-end replay test doesn't depend
    # on event_key's fingerprint call being stable across xdist workers (that path
    # is covered by test_event_key_is_keyed_not_raw). record/replay + the content
    # MAC still run for real (isolated_fingerprint_key provides the MAC key).
    fixed_key = "sf-e2e-" + uuid.uuid4().hex
    monkeypatch.setattr(singleflight, "event_key", lambda _payload: fixed_key)
    text = json.dumps(_payload(tmp_path))

    first = codex.run_codex_pre(text)
    second = codex.run_codex_pre(text)

    assert calls["n"] == 1, "one evaluation per tool call, even with both channels installed"
    assert first == second, "the second channel replays the first's answer byte-for-byte"
    # rm -rf / is a hard BLOCK -> both channels deny.
    assert json.loads(first)["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_no_event_id_means_no_dedupe_and_full_evaluation(tmp_path, monkeypatch):
    calls = {"n": 0}
    real = codex.evaluate_pre

    def counting(payload):
        calls["n"] += 1
        return real(payload)

    monkeypatch.setattr(codex, "evaluate_pre", counting)
    p = _payload(tmp_path)
    del p[singleflight.EVENT_ID_KEY]
    text = json.dumps(p)

    first = codex.run_codex_pre(text)
    second = codex.run_codex_pre(text)

    assert calls["n"] == 2, "no tool_use_id -> no dedupe -> each channel evaluates"
    assert first is not None and second is not None  # still denied, never skipped


def test_event_key_is_none_without_id(tmp_path):
    p = _payload(tmp_path)
    del p[singleflight.EVENT_ID_KEY]
    assert singleflight.event_key(p) is None


def test_event_key_is_keyed_not_raw(tmp_path, isolated_fingerprint_key):
    tuid = "exec-marker-visible-123"
    key = singleflight.event_key(_payload(tmp_path, tool_use_id=tuid))
    assert key is not None
    assert tuid not in key  # keyed HMAC digest, never the raw id


def test_replay_none_without_key():
    assert singleflight.replay(None) is None


def test_record_then_replay_roundtrip(isolated_fingerprint_key):
    key = "unit-sf-" + uuid.uuid4().hex
    assert singleflight.replay(key) is None  # nothing recorded yet
    singleflight.record(key, '{"x": 1}')
    assert singleflight.replay(key) == '{"x": 1}'
    # An abstain (None) round-trips to "" (the caller maps that to "print nothing").
    key2 = "unit-sf-" + uuid.uuid4().hex
    singleflight.record(key2, None)
    assert singleflight.replay(key2) == ""


def test_expired_marker_is_ignored(isolated_fingerprint_key):
    key = "unit-sf-" + uuid.uuid4().hex
    singleflight.record(key, '{"x": 1}')
    path = singleflight._marker_path(key)
    old = time.time() - (singleflight._TTL_SECONDS + 5)
    os.utime(path, (old, old))  # backdate past the TTL
    assert singleflight.replay(key) is None  # stale marker -> re-evaluate


def test_tampered_marker_content_is_rejected(isolated_fingerprint_key):
    # A blind overwrite of the marker (attacker who can't forge the keyed MAC)
    # must not be trusted — replay returns None so the call is re-evaluated.
    key = "unit-sf-" + uuid.uuid4().hex
    singleflight.record(key, '{"hookSpecificOutput": {"permissionDecision": "deny"}}')
    path = singleflight._marker_path(key)
    with open(path, "w", encoding="utf-8") as f:
        f.write('deadbeef\n{"hookSpecificOutput": {"permissionDecision": "allow"}}')
    assert singleflight.replay(key) is None  # forged content rejected, never replayed


def test_missing_key_writes_no_marker(monkeypatch):
    # With no MAC key available, record must not write an unverifiable marker.
    monkeypatch.setattr(singleflight, "_content_mac", lambda _c: None)
    key = "unit-sf-" + uuid.uuid4().hex
    singleflight.record(key, '{"x": 1}')
    assert not os.path.exists(singleflight._marker_path(key))
