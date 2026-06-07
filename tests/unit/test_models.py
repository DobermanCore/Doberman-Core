"""Slice 1.1 — tests for the SecurityObject schema and core enums."""

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from doberman.models import (
    ActionType,
    GuardrailResult,
    ReasonCode,
    Reversibility,
    Risk,
    SecurityObject,
    SourceContext,
    Verdict,
)

# The thesis example: a frontend agent deleting a backend auth file based on
# an instruction that arrived via a GitHub issue.
THESIS_EXAMPLE = {
    "id": "act-0001",
    "ts": datetime(2026, 6, 7, 12, 0, 0, tzinfo=timezone.utc),
    "agent_role": "frontend_agent",
    "action_type": ActionType.file_delete,
    "tool_name": "fs_delete",
    "target": "backend/auth/session.ts",
    "target_path_class": "auth_code",
    "risk": Risk.high,
    "source_context": SourceContext.github_issue,
    "reversibility": Reversibility.low,
    "sensitive_asset": True,
}


def test_valid_construction_thesis_example():
    obj = SecurityObject(**THESIS_EXAMPLE)
    assert obj.action_type is ActionType.file_delete
    assert obj.source_context is SourceContext.github_issue
    assert obj.risk is Risk.high
    assert obj.target == "backend/auth/session.ts"


def test_defaults_applied():
    obj = SecurityObject(
        id="act-0002",
        ts=datetime(2026, 6, 7, 12, 0, 0, tzinfo=timezone.utc),
        agent_role="unknown",
        action_type=ActionType.final_output,
        tool_name="final_output",
    )
    assert obj.target is None  # missing target is allowed (pure final_output)
    assert obj.risk is Risk.low
    assert obj.source_context is SourceContext.unknown
    assert obj.reversibility is Reversibility.medium
    assert obj.sensitive_asset is False
    assert obj.external_destination is None
    assert obj.payload_fingerprints == []
    assert obj.raw_args_redacted == {}
    assert obj.metadata == {}


def test_bad_enum_rejected():
    with pytest.raises(ValidationError):
        SecurityObject(**{**THESIS_EXAMPLE, "action_type": "format_disk"})
    with pytest.raises(ValidationError):
        SecurityObject(**{**THESIS_EXAMPLE, "risk": "extreme"})
    with pytest.raises(ValidationError):
        GuardrailResult(verdict="MAYBE", risk=Risk.low)


def test_frozen_blocks_assignment():
    obj = SecurityObject(**THESIS_EXAMPLE)
    with pytest.raises(ValidationError):
        obj.risk = Risk.low  # no layer may mutate risk downward
    result = GuardrailResult(verdict=Verdict.BLOCK, risk=Risk.critical)
    with pytest.raises(ValidationError):
        result.verdict = Verdict.PASS


def test_guardrail_result_defaults_and_fields():
    result = GuardrailResult(
        verdict=Verdict.BLOCK,
        risk=Risk.critical,
        reason_codes=[ReasonCode.unknown_tool],
        explanation="Tool is not in the downstream tool list.",
    )
    assert result.reason_codes == ["unknown_tool"]
    assert GuardrailResult(verdict=Verdict.PASS, risk=Risk.low).reason_codes == []


def test_enums_have_expected_members():
    assert ActionType.other in ActionType  # unknown tools normalize to `other`
    assert {v.value for v in Verdict} == {"PASS", "AUTH", "BLOCK"}
    assert Risk.critical in Risk
    # Reason codes serialize as stable strings.
    assert ReasonCode.normalization_failed == "normalization_failed"


def test_distinct_instances_do_not_share_default_containers():
    kwargs = dict(
        ts=datetime(2026, 6, 7, tzinfo=timezone.utc),
        agent_role="unknown",
        action_type=ActionType.other,
        tool_name="x",
    )
    a = SecurityObject(id="a", **kwargs)
    b = SecurityObject(id="b", **kwargs)
    assert a.metadata is not b.metadata
    assert a.payload_fingerprints is not b.payload_fingerprints
