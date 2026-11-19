"""Pins the local companion contract v1 (docs/COMPANION-CONTRACT.md).

A local tool on the same machine may read these surfaces. Each test here turns an
accidental change to one of them into a red build: a rename, a removal or a meaning
change must bump the contract major in ``/api/health`` and the doc, never land quietly.
"""

import re
import sys
from datetime import datetime, timezone

from starlette.testclient import TestClient
from typer.testing import CliRunner

import doberman
from doberman.dash.app import create_app
from doberman.storage import approvals
from doberman.storage.db import SCHEMA_VERSION, open_db

_TOKEN = "test-dash-token-0123456789"  # noqa: S105 - fixture value, not a real secret
_AUTH = {"Authorization": f"Bearer {_TOKEN}"}

DASH_LINE = re.compile(r"^Dashboard: http://127\.0\.0\.1:(\d+)/\?token=([A-Za-z0-9_-]+)$")
MISSING_EXTRA_MARKER = 'requires the optional "dash" extra'
FEATURES_V1 = {"pending", "resolve", "session_id", "needs_totp"}
PENDING_FIELDS = {
    "id",
    "created_at",
    "expires_at",
    "tier",
    "action_type",
    "risk",
    "reason_codes",
    "explanation",
    "target_path_class",
    "needs_totp",
    "session_id",
}
DECISION_COLUMNS = {
    "id",
    "ts",
    "action_id",
    "final_verdict",
    "action_type",
    "target_path_class",
    "risk",
    "reason_codes_json",
    "session_id",
    "auth_result",
    "human_confirmed",
}
RECORD_KEYS = {
    "ts",
    "action_id",
    "final_verdict",
    "reason_codes",
    "action_type",
    "target_path_class",
    "risk",
    "session_id",
    "auth_result",
    "human_confirmed",
}


# --- /api/health: the version field --------------------------------------------------


def test_health_reports_contract_1_version_and_features(tmp_path):
    body = TestClient(create_app(_TOKEN, str(tmp_path))).get("/api/health", headers=_AUTH).json()

    assert body["status"] == "ok"
    assert body["contract"] == 1
    assert body["doberman"] == doberman.__version__
    assert FEATURES_V1 <= set(body["features"])


def test_health_still_needs_the_bearer_token(tmp_path):
    resp = TestClient(create_app(_TOKEN, str(tmp_path))).get("/api/health")

    assert resp.status_code == 401
    assert resp.json() == {"error": "unauthorized"}


# --- S3: the dash process's stdout line and missing-extra marker ---------------------


def _free_port() -> int:
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def test_dash_prints_the_pinned_url_line(monkeypatch, tmp_path):
    import uvicorn

    from doberman.cli.main import app as cli_app

    monkeypatch.setattr(uvicorn, "run", lambda *args, **kwargs: None)
    monkeypatch.setattr("doberman.storage.heartbeat.touch_heartbeat", lambda _path: None)
    port = _free_port()

    result = CliRunner().invoke(cli_app, ["dash", "--port", str(port), "--path", str(tmp_path)])

    assert result.exit_code == 0
    matches = [DASH_LINE.match(line) for line in result.stdout.splitlines()]
    found = [m for m in matches if m]
    assert len(found) == 1
    assert found[0].group(1) == str(port)


def test_dash_missing_extra_prints_the_pinned_marker_on_stderr(monkeypatch):
    from doberman.cli.main import app as cli_app

    monkeypatch.setitem(sys.modules, "doberman.dash", None)

    result = CliRunner().invoke(cli_app, ["dash"])

    assert result.exit_code == 1
    assert MISSING_EXTRA_MARKER in result.stderr
    assert MISSING_EXTRA_MARKER not in result.stdout


# --- S4: pending rows and resolve ----------------------------------------------------


def _queue(root: str) -> str:
    import asyncio

    return asyncio.run(
        approvals.create_pending(
            "action-1",
            tier="two_factor",
            action_type="shell_exec",
            risk="high",
            reason_codes=["destructive_command"],
            explanation="test",
            target_path_class=None,
            repo_root=root,
        )
    )


def test_pending_rows_carry_exactly_the_pinned_fields(tmp_path):
    _queue(str(tmp_path))

    rows = TestClient(create_app(_TOKEN, str(tmp_path))).get("/api/pending", headers=_AUTH).json()

    assert len(rows) == 1
    assert set(rows[0]) == PENDING_FIELDS
    assert rows[0]["needs_totp"] is True


def test_resolve_status_codes_and_exact_strings(tmp_path):
    approval_id = _queue(str(tmp_path))
    client = TestClient(create_app(_TOKEN, str(tmp_path)))
    url = f"/api/resolve/{approval_id}"

    unauthorized = client.post(url, json={"decision": "approved"})
    assert (unauthorized.status_code, unauthorized.json()) == (401, {"error": "unauthorized"})

    bad = client.post(url, json={"decision": "maybe"}, headers=_AUTH)
    assert (bad.status_code, bad.json()) == (
        400,
        {"error": "decision must be 'approved' or 'denied'"},
    )

    won = client.post(url, json={"decision": "denied", "totp_code": "123456"}, headers=_AUTH)
    assert (won.status_code, won.json()) == (200, {"status": "resolved"})
    assert "123456" not in won.text

    again = client.post(url, json={"decision": "approved"}, headers=_AUTH)
    assert (again.status_code, again.json()) == (409, {"error": "already resolved or expired"})


# --- S2: the decision history columns a reader may rely on ---------------------------


async def test_decisions_table_keeps_the_pinned_columns_and_schema_version(tmp_path):
    async with open_db(str(tmp_path)) as conn:
        cursor = await conn.execute("PRAGMA table_info(decisions)")
        columns = {row[1] for row in await cursor.fetchall()}
        cursor = await conn.execute("SELECT version FROM schema_version")
        versions = [row[0] for row in await cursor.fetchall()]

    assert DECISION_COLUMNS <= columns
    assert versions == [SCHEMA_VERSION]
    assert isinstance(SCHEMA_VERSION, int)


# --- S1: the audit webhook body ------------------------------------------------------


def test_audit_record_always_carries_the_pinned_keys():
    from doberman.models import (
        ActionType,
        Decision,
        GuardrailResult,
        ReasonCode,
        Risk,
        SecurityObject,
        Verdict,
    )
    from doberman.storage.log import build_record

    now = datetime(2026, 11, 19, tzinfo=timezone.utc)
    action = SecurityObject(
        id="action-1",
        ts=now,
        agent_role="tester",
        action_type=ActionType.shell_exec,
        tool_name="shell",
        target="ls",
        risk=Risk.low,
    )
    objective = GuardrailResult(
        verdict=Verdict.PASS, risk=Risk.low, reason_codes=[], explanation="ok"
    )
    decision = Decision(
        action_id="action-1",
        final_verdict=Verdict.PASS,
        final_risk=Risk.low,
        objective=objective,
        reason_codes=[ReasonCode.destructive_command],
        explanation="ok",
        decided_at=now,
    )

    record = build_record(decision, action, auth_result=None, elevation_id=None, now=now)

    assert RECORD_KEYS <= set(record)
    assert record["reason_codes"] == ["destructive_command"]
