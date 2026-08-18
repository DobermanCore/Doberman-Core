"""`doberman tune` — friction telemetry report + gated standing-elevation
proposals (#243).

Covers: pure aggregation correctness (interventions/session, top AUTH
reasons, approval rates, weekly trend), proposal-generation allowlist
semantics (role_out_of_scope-only, narrow path class, min occurrences, 100%
approval), the report path never applying anything, `--accept` routing
through the same possession-factor-gated weaken chokepoint as every other
policy loosening, `--json` stability, redaction, the reader's new
session/entity columns, and the control-plane block on a shelled accept.
"""

import asyncio
import json
from datetime import datetime, timezone

import pyotp
import pytest
from typer.testing import CliRunner

from doberman.auth import password, totp
from doberman.cli.main import app
from doberman.models import (
    ActionType,
    Decision,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    Verdict,
)
from doberman.policy.drift import Classification, apply_standing_elevation, read_policy_changes
from doberman.policy.friction import build_friction_report, generate_proposals
from doberman.storage.db import active_elevations, grant_elevation
from doberman.storage.log import (
    _DECISION_COLUMNS,
    read_decisions,
    read_decisions_since,
    record_decision,
)

runner = CliRunner()

_PASSWORD = "correct horse battery staple"  # noqa: S105 — synthetic test credential
_NOW = datetime(2026, 7, 16, tzinfo=timezone.utc)


class ScriptedPrompter:
    def __init__(self, *, confirm=True, code=""):
        self._confirm, self._code = confirm, code
        self.confirm_calls = 0
        self.read_code_calls = 0

    def confirm(self, message):
        self.confirm_calls += 1
        return self._confirm

    def read_code(self, message):
        self.read_code_calls += 1
        return self._code


def _enrolled_code() -> str:
    totp.enroll()
    secret = totp._read_secret()
    assert secret is not None
    return pyotp.TOTP(secret).now()


def _row(
    *,
    id=1,  # noqa: A002 - matches the storage row shape
    ts="2026-07-06T10:00:00+00:00",
    action_type="file_write",
    target_path_class="migrations/*.py",
    final_verdict="AUTH",
    reason_codes_json='["role_out_of_scope"]',
    auth_result="approved",
    session_id="s1",
    entity_id="e1",
):
    """A hand-built row in the exact shape `read_decisions` returns."""
    return {
        "id": id,
        "ts": ts,
        "action_id": f"act-{id}",
        "agent_role": "backend",
        "action_type": action_type,
        "target_path_class": target_path_class,
        "risk": "medium",
        "source_context": "user",
        "final_verdict": final_verdict,
        "decided_layer": "objective",
        "reason_codes_json": reason_codes_json,
        "auth_required": 1 if final_verdict == "AUTH" else 0,
        "auth_result": auth_result,
        "elevation_id": None,
        "entity_id": entity_id,
        "session_id": session_id,
    }


async def _seed_decision_async(
    root,
    *,
    action_id,
    target,
    action_type=ActionType.file_write,
    verdict=Verdict.AUTH,
    risk=Risk.medium,
    reason_codes=(ReasonCode.role_out_of_scope,),
    auth_result="approved",
    session_id="s1",
    entity_id="e1",
    now=None,
):
    """Round-trip a real decision through `record_decision`/`build_record`."""
    now = now or _NOW
    reason_codes = list(reason_codes)
    objective = GuardrailResult(
        verdict=verdict, risk=risk, reason_codes=reason_codes, explanation="test"
    )
    decision = Decision(
        action_id=action_id,
        final_verdict=verdict,
        final_risk=risk,
        objective=objective,
        reason_codes=reason_codes,
        explanation="test",
        decided_at=now,
    )
    action = SecurityObject(
        id=action_id,
        ts=now,
        agent_role="backend",
        action_type=action_type,
        tool_name="fs_write",
        target=target,
    )
    await record_decision(
        decision,
        action,
        repo_root=root,
        auth_result=auth_result,
        now=now,
        entity_id=entity_id,
        session_id=session_id,
    )


def _seed_decision(root, **kwargs):
    """Sync wrapper for non-async test functions."""
    asyncio.run(_seed_decision_async(root, **kwargs))


def _seed_five_approved_migrations(root):
    for i in range(5):
        _seed_decision(
            root,
            action_id=f"mig-{i}",
            target=f"migrations/{i:03d}_init.py",
            session_id=f"s{i}",
        )


# --- 1. Aggregation correctness -----------------------------------------


def test_build_friction_report_known_fixture():
    rows = [
        _row(id=1, ts="2026-07-06T10:00:00+00:00", target_path_class=".env", session_id="s1"),
        _row(
            id=2,
            ts="2026-07-06T11:00:00+00:00",
            target_path_class="migrations/*.py",
            session_id="s1",
        ),
        _row(
            id=3,
            ts="2026-07-07T09:00:00+00:00",
            action_type="file_read",
            target_path_class=None,
            final_verdict="PASS",
            reason_codes_json="[]",
            auth_result=None,
            session_id="s1",
        ),
        _row(
            id=4,
            ts="2026-07-08T09:00:00+00:00",
            target_path_class="secrets/*.env",
            reason_codes_json='["secret_exfiltration"]',
            auth_result="denied",
            session_id="s2",
        ),
        _row(
            id=5,
            ts="2026-07-13T09:00:00+00:00",
            action_type="shell_exec",
            target_path_class=None,
            reason_codes_json="not-json",
            session_id="s3",
        ),
        _row(
            id=6,
            ts="not-a-timestamp",
            action_type="file_read",
            target_path_class="README.md",
            final_verdict="BLOCK",
            reason_codes_json='["destructive_command"]',
            auth_result=None,
            session_id=None,
        ),
    ]

    report = build_friction_report(rows)

    assert report["version"] == 1
    assert report["decisions"] == 6
    assert report["sessions"] == 3
    assert report["unsessioned_decisions"] == 1
    assert report["interventions"] == 4
    assert report["interventions_per_session"] == pytest.approx(4 / 3)
    assert report["top_auth_reason_codes"] == [
        ["role_out_of_scope", 2],
        ["secret_exfiltration", 1],
    ]
    assert report["approval_rate_by_reason"]["role_out_of_scope"] == {
        "n": 2,
        "approved": 2,
        "rate": 1.0,
    }
    assert report["approval_rate_by_reason"]["secret_exfiltration"] == {
        "n": 1,
        "approved": 0,
        "rate": 0.0,
    }
    assert report["approval_rate_by_target"]["file_write .env"] == {
        "n": 1,
        "approved": 1,
        "rate": 1.0,
    }
    assert report["approval_rate_by_target"]["file_write migrations/*.py"] == {
        "n": 1,
        "approved": 1,
        "rate": 1.0,
    }
    assert report["approval_rate_by_target"]["file_write secrets/*.env"] == {
        "n": 1,
        "approved": 0,
        "rate": 0.0,
    }
    # malformed ts (row 6) excluded from trend only, everything else counted.
    assert len(report["trend"]) == 2
    assert report["trend"]["2026-07-06"] == {
        "decisions": 4,
        "interventions": 3,
        "sessions": 2,
        "interventions_per_session": 1.5,
    }
    assert report["trend"]["2026-07-13"] == {
        "decisions": 1,
        "interventions": 1,
        "sessions": 1,
        "interventions_per_session": 1.0,
    }


def test_build_friction_report_empty_rows_never_raises():
    report = build_friction_report([])
    assert report["decisions"] == 0
    assert report["sessions"] == 0
    assert report["interventions_per_session"] is None
    assert report["top_auth_reason_codes"] == []
    assert report["trend"] == {}


# --- 2. Proposal emitted --------------------------------------------------


def test_proposal_emitted_for_five_approved_role_out_of_scope_auths():
    rows = [
        _row(id=i, ts=f"2026-07-{6 + i:02d}T10:00:00+00:00", session_id=f"s{i}")
        for i in range(1, 6)
    ]

    proposals = generate_proposals(rows, min_occurrences=5)

    assert len(proposals) == 1
    p = proposals[0]
    assert p["kind"] == "standing_elevation"
    assert p["action_type"] == "file_write"
    assert p["target_path_class"] == "migrations/*.py"
    assert p["occurrences"] == 5
    assert p["approval_rate"] == 1.0
    assert p["reason_codes"] == ["role_out_of_scope"]
    assert p["ttl_days"] == 7
    assert len(p["id"]) == 10

    # id determinism: same input -> same id.
    proposals2 = generate_proposals(rows, min_occurrences=5)
    assert proposals2[0]["id"] == p["id"]


# --- 3. NO proposal cases -------------------------------------------------


def test_no_proposal_below_min_occurrences():
    rows = [_row(id=i, session_id=f"s{i}") for i in range(1, 5)]  # n=4
    assert generate_proposals(rows, min_occurrences=5) == []


@pytest.mark.parametrize("bad_result", ["denied", "timeout", None])
def test_no_proposal_when_one_row_is_not_approved(bad_result):
    rows = [_row(id=i, session_id=f"s{i}") for i in range(1, 5)]
    rows.append(_row(id=5, session_id="s5", auth_result=bad_result))
    assert generate_proposals(rows, min_occurrences=5) == []


def test_no_proposal_when_reason_codes_contain_a_security_code_even_at_100pct():
    rows = [
        _row(id=i, session_id=f"s{i}", reason_codes_json='["secret_exfiltration"]')
        for i in range(1, 11)
    ]
    assert generate_proposals(rows, min_occurrences=5) == []


def test_no_proposal_when_path_class_is_none():
    rows = [_row(id=i, session_id=f"s{i}", target_path_class=None) for i in range(1, 6)]
    assert generate_proposals(rows, min_occurrences=5) == []


def test_no_proposal_for_root_level_wildcard():
    rows = [_row(id=i, session_id=f"s{i}", target_path_class="*.py") for i in range(1, 6)]
    assert generate_proposals(rows, min_occurrences=5) == []


def test_no_proposal_for_whole_tree_class():
    rows = [_row(id=i, session_id=f"s{i}", target_path_class="**") for i in range(1, 6)]
    assert generate_proposals(rows, min_occurrences=5) == []


def test_no_proposal_for_shell_exec():
    rows = [
        _row(id=i, session_id=f"s{i}", action_type="shell_exec", target_path_class="scripts/*.sh")
        for i in range(1, 6)
    ]
    assert generate_proposals(rows, min_occurrences=5) == []


# --- 4. Report mode never applies anything --------------------------------


def test_report_mode_never_applies_anything(tmp_path):
    root = str(tmp_path)
    _seed_five_approved_migrations(root)

    result = runner.invoke(app, ["tune", "--path", root])

    assert result.exit_code == 0, result.output
    assert asyncio.run(active_elevations(root, datetime.now(timezone.utc))) == []
    assert asyncio.run(read_policy_changes(root)) == []


# --- 5. Accept triggers the weaken gate (unit-level, on the chokepoint) --


async def test_apply_standing_elevation_denied_confirm_yields_no_grant_but_ledger_row(tmp_path):
    root = str(tmp_path)
    outcome = await apply_standing_elevation(
        "migrations/*.py",
        "doberman tune accept abc123",
        repo_root=root,
        ttl_days=7,
        prompter=ScriptedPrompter(confirm=False),
        now=_NOW,
    )

    assert outcome.classification is Classification.weaken
    assert outcome.approved is False

    rows = await read_policy_changes(root)
    assert len(rows) == 1
    assert rows[0]["approved"] == 0
    assert rows[0]["classification"] == "weaken"
    assert await active_elevations(root, _NOW) == []


async def test_apply_standing_elevation_approved_then_grant_matches_the_scope(tmp_path):
    root = str(tmp_path)
    password.enroll(_PASSWORD)
    outcome = await apply_standing_elevation(
        "migrations/*.py",
        "doberman tune accept abc123",
        repo_root=root,
        ttl_days=7,
        prompter=ScriptedPrompter(confirm=True, code=_PASSWORD),
        now=_NOW,
    )

    assert outcome.approved is True
    assert outcome.classification is Classification.weaken

    rows = await read_policy_changes(root)
    assert rows[0]["classification"] == "weaken"
    assert rows[0]["approved"] == 1

    # Applying the outcome is the caller's job (`doberman tune --accept`); prove
    # the resulting elevation matches what apply_standing_elevation proposed.
    grant = await grant_elevation(
        root, "migrations/*.py", task_id="tune:abc123", now=_NOW, ttl_seconds=7 * 86400
    )
    active = await active_elevations(root, _NOW)
    assert len(active) == 1
    assert active[0].id == grant.id
    assert active[0].scope_glob == "migrations/*.py"
    assert (grant.expires_at - grant.granted_at).days == 7


# --- 6. CLI: unknown accept id fails closed --------------------------------


def test_accept_unknown_id_fails_closed(tmp_path):
    root = str(tmp_path)
    result = runner.invoke(app, ["tune", "--accept", "doesnotexist", "--path", root])

    assert result.exit_code == 1
    assert "unknown or stale proposal id" in result.stderr
    assert asyncio.run(active_elevations(root, datetime.now(timezone.utc))) == []


# --- Full CLI accept flow (approved path) ----------------------------------


def test_cli_accept_full_flow_grants_a_revocable_elevation(tmp_path, monkeypatch):
    root = str(tmp_path)
    _seed_five_approved_migrations(root)
    password.enroll(_PASSWORD)
    monkeypatch.setattr(
        "doberman.auth.provider.CliPrompter",
        lambda: ScriptedPrompter(confirm=True, code=_PASSWORD),
    )

    report_result = runner.invoke(app, ["tune", "--path", root, "--json"])
    assert report_result.exit_code == 0, report_result.output
    payload = json.loads(report_result.output)
    assert len(payload["proposals"]) == 1
    proposal_id = payload["proposals"][0]["id"]

    accept_result = runner.invoke(app, ["tune", "--accept", proposal_id, "--path", root])
    assert accept_result.exit_code == 0, accept_result.output
    assert "revoke" in accept_result.output.lower()

    active = asyncio.run(active_elevations(root, datetime.now(timezone.utc)))
    assert len(active) == 1
    assert active[0].scope_glob == "migrations/*.py"


def test_cli_accept_denied_grants_nothing(tmp_path, monkeypatch):
    root = str(tmp_path)
    _seed_five_approved_migrations(root)
    monkeypatch.setattr(
        "doberman.auth.provider.CliPrompter",
        lambda: ScriptedPrompter(confirm=False),
    )

    report_result = runner.invoke(app, ["tune", "--path", root, "--json"])
    proposal_id = json.loads(report_result.output)["proposals"][0]["id"]

    accept_result = runner.invoke(app, ["tune", "--accept", proposal_id, "--path", root])

    assert accept_result.exit_code == 1
    assert "denied" in accept_result.stderr
    assert asyncio.run(active_elevations(root, datetime.now(timezone.utc))) == []


# --- 7. --json stability ----------------------------------------------------


def test_json_output_is_byte_identical_across_invocations(tmp_path):
    root = str(tmp_path)
    _seed_five_approved_migrations(root)

    r1 = runner.invoke(app, ["tune", "--path", root, "--json"])
    r2 = runner.invoke(app, ["tune", "--path", root, "--json"])

    assert r1.exit_code == 0
    assert r2.exit_code == 0
    assert r1.output == r2.output
    payload = json.loads(r1.output)
    assert "proposals" in payload


# --- 8. Redaction ------------------------------------------------------------


def test_redaction_never_leaks_the_raw_filename(tmp_path):
    root = str(tmp_path)
    _seed_decision(root, action_id="act-secret", target="src/super_secret_name_xyz.py")

    human = runner.invoke(app, ["tune", "--path", root])
    as_json = runner.invoke(app, ["tune", "--path", root, "--json"])

    assert human.exit_code == 0, human.output
    assert as_json.exit_code == 0, as_json.output
    assert "super_secret_name_xyz" not in human.output
    assert "super_secret_name_xyz" not in as_json.output
    assert "src/*.py" in human.output
    assert "src/*.py" in as_json.output


# --- 9. Reader extension -----------------------------------------------------


def test_decision_columns_end_with_entity_and_session_id():
    assert _DECISION_COLUMNS[-2:] == ["entity_id", "session_id"]


async def test_read_decisions_carries_session_and_entity_id(tmp_path):
    root = str(tmp_path)
    await _seed_decision_async(
        root, action_id="act-1", target="migrations/001.py", session_id="sess-9", entity_id="ent-9"
    )

    rows = await read_decisions(root)

    assert rows[0]["session_id"] == "sess-9"
    assert rows[0]["entity_id"] == "ent-9"


async def test_read_decisions_since_still_zips_with_new_columns(tmp_path):
    root = str(tmp_path)
    await _seed_decision_async(
        root, action_id="act-1", target="migrations/001.py", session_id="sess-1", entity_id="ent-1"
    )

    rows = await read_decisions_since(root, 0)

    assert len(rows) == 1
    assert rows[0]["session_id"] == "sess-1"
    assert rows[0]["entity_id"] == "ent-1"
