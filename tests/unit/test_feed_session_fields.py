"""Session fields on the dash feed and ``doberman log --jsonl``.

A companion UI groups decisions by the host session that made them, so the
live feed carries ``session_id``, ``agent_role``, ``auth_path`` and
``human_confirmed`` (all existing ``decisions`` columns), and ``log --jsonl``
adds ``session_id`` to the three it already exported. These are allow-list
additions: the session id is the host's opaque session UUID, the role is a
configured name, and the other two are a closed enum and a 1/0/NULL flag.
A row that never recorded one of them serializes it as ``null``.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone

import pytest
from starlette.testclient import TestClient
from typer.testing import CliRunner

from doberman.cli.main import app
from doberman.dash.app import _feed_row, create_app
from doberman.models import (
    ActionType,
    AuthPath,
    Decision,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    SourceContext,
    Verdict,
)
from doberman.storage.log import exportable_session_id, record_decision

_TOKEN = "test-dash-token-session-fields-01"  # noqa: S105 - fixture value, not a real secret
_SECRET = "SYNTHETIC-SECRET-AKIA0000SESS"  # noqa: S105 - synthetic test fixture, not a real key
_SESSION = "3f2b9c1e-7a4d-4e5f-9b8a-0c1d2e3f4a5b"
_NOW = datetime(2026, 10, 17, tzinfo=timezone.utc)

# Every key the feed may serialize. Pinned so a new field is always a
# deliberate edit here, never a silent widening of what the dash sends.
_FEED_KEYS = {
    "id",
    "ts",
    "verdict",
    "action_type",
    "target_path_class",
    "risk",
    "source_context",
    "reason_codes",
    "headline",
    "explanation",
    "session_id",
    "agent_role",
    "auth_path",
    "human_confirmed",
}

# Every key one `log --jsonl` line may carry, pinned the same way.
_JSONL_KEYS = {
    "ts",
    "final_verdict",
    "action_type",
    "target_path_class",
    "reason_codes",
    "auth_result",
    "id",
    "agent_role",
    "risk",
    "auth_path",
    "human_confirmed",
    "source_context",
    "session_id",
    "policy_version",
}


def _record(root: str, **kwargs) -> None:
    objective = GuardrailResult(
        verdict=Verdict.AUTH,
        risk=Risk.high,
        reason_codes=[ReasonCode.sensitive_secret_access],
        explanation="seeded for test",
    )
    decision = Decision(
        action_id="act-s1",
        final_verdict=Verdict.AUTH,
        final_risk=Risk.high,
        objective=objective,
        reason_codes=[ReasonCode.sensitive_secret_access],
        explanation="seeded for test",
        decided_at=_NOW,
    )
    action = SecurityObject(
        id="act-s1",
        ts=_NOW,
        agent_role="backend",
        action_type=ActionType.file_read,
        tool_name="fs_read",
        target=f"backend/secrets/{_SECRET}.env",
        source_context=SourceContext.user,
    )
    asyncio.run(record_decision(decision, action, repo_root=root, auth_result="approved", **kwargs))


def _feed_events(root: str) -> list[dict]:
    client = TestClient(create_app(_TOKEN, root, feed_poll_interval=0.01, feed_max_polls=0))
    resp = client.get("/api/feed", headers={"Authorization": f"Bearer {_TOKEN}"})
    assert resp.status_code == 200
    events = []
    for line in resp.text.splitlines():
        if line.startswith("data: "):
            events.append(json.loads(line[len("data: ") :]))
    assert _SECRET not in resp.text
    return events


def _jsonl(root: str) -> list[dict]:
    result = CliRunner().invoke(app, ["log", "--path", root, "--jsonl"])
    assert result.exit_code == 0, result.output
    assert _SECRET not in result.stdout
    return [json.loads(ln) for ln in result.stdout.splitlines() if ln.strip()]


# --- dash feed -------------------------------------------------------------


def test_feed_row_carries_the_session_fields(tmp_path):
    root = str(tmp_path)
    _record(
        root,
        session_id=_SESSION,
        auth_path=AuthPath.host_hook_challenge,
        human_confirmed=True,
    )

    [event] = _feed_events(root)
    assert event["session_id"] == _SESSION
    assert event["agent_role"] == "backend"
    assert event["auth_path"] == "host_hook_challenge"
    assert event["human_confirmed"] == 1
    # True == 1 in Python, so the value check alone would pass a JSON bool.
    assert type(event["human_confirmed"]) is int
    assert set(event) == _FEED_KEYS


def test_feed_row_with_no_recorded_session_fields_serializes_null(tmp_path):
    root = str(tmp_path)
    _record(root)

    [event] = _feed_events(root)
    assert event["session_id"] is None
    assert event["auth_path"] is None
    assert event["human_confirmed"] is None
    assert event["agent_role"] == "backend"
    assert set(event) == _FEED_KEYS


def test_feed_row_keeps_human_confirmed_zero_distinct_from_null(tmp_path):
    # 0 means "a challenge ran and no person answered"; it must never read as
    # null ("not recorded") or be dropped as falsy.
    root = str(tmp_path)
    _record(root, auth_path=AuthPath.host_hook_monitor, human_confirmed=False)

    [event] = _feed_events(root)
    assert event["human_confirmed"] == 0
    assert event["human_confirmed"] is not None
    assert type(event["human_confirmed"]) is int


def test_feed_row_of_a_legacy_row_without_the_columns_is_null():
    row = _feed_row({"id": 1, "ts": "2026-10-17T00:00:00Z", "final_verdict": "PASS"})
    assert set(row) == _FEED_KEYS
    for key in ("session_id", "agent_role", "auth_path", "human_confirmed"):
        assert row[key] is None


def test_feed_row_still_drops_auth_result_and_raw_columns():
    row = _feed_row(
        {
            "final_verdict": "PASS",
            "auth_result": "approved",
            "action_id": "act-raw",
            "entity_id": "hmac:entity",
            "elevation_id": "elev-1",
        }
    )
    for key in ("auth_result", "action_id", "entity_id", "elevation_id"):
        assert key not in row


# --- log --jsonl -----------------------------------------------------------


def test_log_jsonl_exports_session_id(tmp_path):
    root = str(tmp_path)
    _record(
        root,
        session_id=_SESSION,
        auth_path=AuthPath.host_hook_challenge,
        human_confirmed=True,
        entity_id="hmac:entity-populated",
        elevation_id="elev-populated",
    )

    [obj] = _jsonl(root)
    assert obj["session_id"] == _SESSION
    assert obj["agent_role"] == "backend"
    assert obj["auth_path"] == "host_hook_challenge"
    assert obj["human_confirmed"] == 1
    assert type(obj["human_confirmed"]) is int
    # Every column of a fully populated row went through the allow-list, so
    # anything beyond these keys (action_id, entity_id, ...) is a leak.
    assert obj["policy_version"] is None  # seed has no evaluation snapshot
    assert set(obj) == _JSONL_KEYS


def test_log_jsonl_keeps_human_confirmed_zero_an_int(tmp_path):
    root = str(tmp_path)
    _record(root, auth_path=AuthPath.host_hook_monitor, human_confirmed=False)

    [obj] = _jsonl(root)
    assert obj["human_confirmed"] == 0
    assert type(obj["human_confirmed"]) is int


def test_log_jsonl_session_id_is_null_when_not_recorded(tmp_path):
    root = str(tmp_path)
    _record(root)

    [obj] = _jsonl(root)
    assert "session_id" in obj
    assert obj["session_id"] is None
    assert obj["auth_path"] is None
    assert obj["human_confirmed"] is None
    assert obj["policy_version"] is None  # seed has no evaluation snapshot
    assert set(obj) == _JSONL_KEYS


# --- session id shape at export ---------------------------------------------
#
# The hook path stores any non-empty string the host sends as session_id, so
# a crafted payload can plant a path or a credential there. Both exports send
# it on only when it has an id's shape, and null otherwise. That covers rows
# written before the check existed too, because it runs at read time.

_CRAFTED_SESSION_IDS = [
    "/home/alice/.ssh/id_ed25519",
    "C:\\Users\\alice\\secrets\\prod.env",
    "../../.doberman/doberman.db",
    "aws_secret_access_key=SYNTHETICSESSIONCANARY0001",
    "Authorization: Bearer SYNTHETICSESSIONCANARY0002",
    "https://hooks.example.test/T000/SYNTHETICSESSIONCANARY0003",
    "sess-ok\nSYNTHETICSESSIONCANARY0004",
    "-leading-dash",
    "a" * 129,
]

_REAL_SESSION_IDS = [
    _SESSION,  # Claude Code / Codex / Cursor: a UUID
    "conv-00000000-0000-0000-0000-000000000001",  # Cursor conversation_id fixture
    "hmac:" + "0123456789abcdef" * 4,  # ambient monitor session fingerprint
    "agent:main:main",  # colon-separated host session key
    "sess_abc.123",
    "a" * 128,
]


@pytest.mark.parametrize("crafted", _CRAFTED_SESSION_IDS)
def test_crafted_session_id_exports_as_null_in_both_surfaces(tmp_path, crafted):
    root = str(tmp_path)
    _record(root, session_id=crafted)

    [event] = _feed_events(root)
    [obj] = _jsonl(root)
    assert event["session_id"] is None
    assert obj["session_id"] is None

    feed_text = json.dumps(event)
    jsonl_text = json.dumps(obj)
    for fragment in ("alice", "SYNTHETICSESSIONCANARY", "doberman.db", "leading-dash", "a" * 129):
        if fragment in crafted:
            assert fragment not in feed_text
            assert fragment not in jsonl_text


@pytest.mark.parametrize("value", _REAL_SESSION_IDS)
def test_real_session_id_shapes_export_unchanged(value):
    assert exportable_session_id(value) == value
    assert _feed_row({"final_verdict": "PASS", "session_id": value})["session_id"] == value


@pytest.mark.parametrize("value", [None, "", 42, b"sess-bytes"])
def test_non_string_or_empty_session_id_exports_as_null(value):
    assert exportable_session_id(value) is None
