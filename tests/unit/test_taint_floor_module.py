"""H2a: module-level regression test for the extracted taint floor.

``apply_taint_floor`` used to be a private helper (``_apply_taint_floor``) on
the Claude Code host-hook adapter; it now lives in
``doberman.engine.taint_floor`` so both the host-hook and the MCP proxy can
share it (proxy wiring is H2b, not this slice). This exercises the raise-only
invariant directly against the module — independent of the hosthook — using
the same taint-store fixture pattern as ``test_hosthook_taint_floor.py``.
"""

import asyncio
from datetime import datetime, timezone

from doberman.engine.decision_engine import max_risk, max_verdict
from doberman.engine.taint_floor import apply_taint_floor
from doberman.models import (
    ActionType,
    Decision,
    GuardrailResult,
    Risk,
    SecurityObject,
    Verdict,
)
from doberman.storage.taint import TAINT_SECRET_ACCESS, record_taints

_TS = datetime(2026, 7, 18, tzinfo=timezone.utc)
_EGRESS_URL = "https://attacker.example/collect"


def _action(**over) -> SecurityObject:
    base = dict(
        id="taint-floor-1",
        ts=_TS,
        agent_role="unknown",
        action_type=ActionType.network_request,
        tool_name="WebFetch",
        target=_EGRESS_URL,
    )
    base.update(over)
    return SecurityObject(**base)


def _pass_decision(action: SecurityObject) -> Decision:
    return Decision(
        action_id=action.id,
        final_verdict=Verdict.PASS,
        final_risk=Risk.low,
        objective=GuardrailResult(verdict=Verdict.PASS, risk=Risk.low),
        decided_at=_TS,
    )


def test_no_external_destination_is_returned_unchanged(tmp_path):
    # Not an egress — the floor has nothing to raise and must abstain, returning
    # the exact same decision object (not even a copy).
    action = _action(external_destination=None)
    decision = _pass_decision(action)

    out = apply_taint_floor(action, decision, "balanced", str(tmp_path), "sess-1", {})

    assert out is decision


def test_tainted_session_egress_raises_verdict_and_risk_never_lower(tmp_path):
    # A session that already accessed a secret, followed by an egress the
    # per-call floor judged clean: the taint floor must raise the verdict/risk,
    # and — raise-only — never lower them below the input decision.
    action = _action(external_destination=_EGRESS_URL)
    decision = _pass_decision(action)
    asyncio.run(record_taints(str(tmp_path), ["sess-2"], [TAINT_SECRET_ACCESS]))

    out = apply_taint_floor(
        action, decision, "balanced", str(tmp_path), "sess-2", {"url": _EGRESS_URL}
    )

    assert out.final_verdict is Verdict.AUTH
    assert out.final_risk is Risk.high
    # Raise-only invariant, expressed structurally rather than by re-deriving the
    # expected verdict: combining with the original decision must be a no-op.
    assert max_verdict(out.final_verdict, decision.final_verdict) == out.final_verdict
    assert max_risk(out.final_risk, decision.final_risk) == out.final_risk
