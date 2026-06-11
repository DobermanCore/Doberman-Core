"""Slice 8.4 — the AuditSink seam: redacted-only, isolated, never blocking."""

import json
from datetime import datetime, timezone

from doberman.models import (
    ActionType,
    Decision,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    Verdict,
)
from doberman.storage.log import record_decision
from doberman.storage.sinks import _looks_like_audit_sink, emit_to_sinks

_NOW = datetime(2026, 6, 8, tzinfo=timezone.utc)
_SECRET = "AKIA-FAKE-SINK-SECRET-0001"  # noqa: S105 — synthetic test value


class RecordingSink:
    def __init__(self):
        self.records: list[dict] = []

    def emit(self, record):
        self.records.append(record)


class ExplodingSink:
    def emit(self, record):
        raise RuntimeError("sink boom")


def test_sink_receives_the_record(monkeypatch):
    sink = RecordingSink()
    monkeypatch.setattr("doberman.engine.registry.discover_audit_sinks", lambda: [sink])
    emit_to_sinks({"final_verdict": "PASS", "action_id": "a1"})
    assert sink.records == [{"final_verdict": "PASS", "action_id": "a1"}]


def test_failing_sink_is_isolated(monkeypatch):
    good = RecordingSink()
    monkeypatch.setattr(
        "doberman.engine.registry.discover_audit_sinks", lambda: [ExplodingSink(), good]
    )
    emit_to_sinks({"x": 1})  # must not raise despite the exploding sink
    assert good.records == [{"x": 1}]


def test_non_sink_shaped_registration_is_skipped(monkeypatch):
    monkeypatch.setattr("doberman.engine.registry.discover_audit_sinks", lambda: [object()])
    emit_to_sinks({"x": 1})  # must not raise
    assert _looks_like_audit_sink(object()) is False


async def test_record_decision_fans_out_only_redacted_records(tmp_path, monkeypatch):
    sink = RecordingSink()
    monkeypatch.setattr("doberman.engine.registry.discover_audit_sinks", lambda: [sink])

    objective = GuardrailResult(
        verdict=Verdict.AUTH,
        risk=Risk.high,
        reason_codes=[ReasonCode.sensitive_secret_access],
        explanation="local secret access",
    )
    decision = Decision(
        action_id="act-9",
        final_verdict=Verdict.AUTH,
        final_risk=Risk.high,
        objective=objective,
        reason_codes=[ReasonCode.sensitive_secret_access],
        explanation="local secret access",
        decided_at=_NOW,
    )
    action = SecurityObject(
        id="act-9",
        ts=_NOW,
        agent_role="backend",
        action_type=ActionType.file_read,
        tool_name="fs_read",
        target="backend/secrets/local.env",
        payload_fingerprints=["hmac:deadbeef"],  # secrets only ever appear as fingerprints
    )

    await record_decision(decision, action, repo_root=str(tmp_path), auth_result="denied")

    assert len(sink.records) == 1
    record = sink.records[0]
    # The raw target key is never present; only a path class is.
    assert "target" not in record
    assert record["target_path_class"] == "backend/secrets/*.env"
    # No raw secret anywhere in the emitted record.
    assert _SECRET not in json.dumps(record)
    assert record["final_verdict"] == "AUTH"
    assert "sensitive_secret_access" in record["reason_codes"]
