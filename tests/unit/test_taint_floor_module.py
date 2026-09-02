"""H2a/H2b: module-level regression test for the extracted taint floor.

``apply_taint_floor`` used to be a private helper (``_apply_taint_floor``) on
the Claude Code host-hook adapter; it now lives in
``doberman.engine.taint_floor`` so both the host-hook and the MCP proxy can
share it. This exercises the raise-only invariant directly against the module —
independent of the hosthook — using the same taint-store fixture pattern as
``test_hosthook_taint_floor.py``.

H2b adds the async path the proxy actually awaits (``apply_taint_floor_async``)
plus ``record_output_taint`` (the proxy's result-side recording); both are
covered directly here so the module's own regression net doesn't depend on the
proxy wiring test (``tests/unit/test_proxy_taint_floor.py``) to catch a
semantics regression in the async refactor itself.
"""

import asyncio
from datetime import datetime, timezone

from doberman.engine.decision_engine import max_risk, max_verdict
from doberman.engine.taint_floor import (
    UNTRUSTED_READ_TOOLS,
    apply_echo_tripwire,
    apply_echo_tripwire_async,
    apply_taint_floor,
    apply_taint_floor_async,
    record_output_taint,
)
from doberman.models import (
    ActionType,
    Decision,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    Verdict,
)
from doberman.storage.taint import (
    TAINT_SECRET_ACCESS,
    match_untrusted_value,
    read_taint,
    record_taints,
    record_untrusted_values,
)

# A well-known synthetic AWS example key — never a real secret.
_SYNTHETIC_SECRET = "AKIAIOSFODNN7EXAMPLE"  # noqa: S105 — synthetic test value

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


# --- H2b: the async path the proxy actually awaits ---------------------------


async def test_apply_taint_floor_async_raises_only_never_lowers(tmp_path):
    # Same scenario as the sync raise-only test above, driven through the async
    # entry point directly (no ``asyncio.run`` wrapper) — this is what the proxy
    # awaits from inside its own running event loop.
    action = _action(external_destination=_EGRESS_URL)
    decision = _pass_decision(action)
    await record_taints(str(tmp_path), ["sess-async"], [TAINT_SECRET_ACCESS])

    out = await apply_taint_floor_async(
        action, decision, "strict", str(tmp_path), "sess-async", {"url": _EGRESS_URL}
    )

    assert out.final_verdict is Verdict.BLOCK
    assert out.final_risk is Risk.critical
    assert max_verdict(out.final_verdict, decision.final_verdict) == out.final_verdict
    assert max_risk(out.final_risk, decision.final_risk) == out.final_risk


async def test_apply_taint_floor_async_abstains_without_taint(tmp_path):
    # No taint recorded anywhere for this scope — raise-only means abstain, not
    # fabricate: the floor must return the decision completely unchanged.
    action = _action(external_destination=_EGRESS_URL)
    decision = _pass_decision(action)

    out = await apply_taint_floor_async(
        action, decision, "strict", str(tmp_path), "sess-clean", {"url": _EGRESS_URL}
    )

    assert out is decision


async def test_record_output_taint_records_taint_and_fingerprint_for_secret_text(tmp_path):
    await record_output_taint(_SYNTHETIC_SECRET, str(tmp_path), "sess-rec")

    counts = await read_taint(str(tmp_path), "sess-rec")
    assert counts.get(TAINT_SECRET_ACCESS, 0) > 0


async def test_record_output_taint_records_nothing_for_benign_text(tmp_path):
    benign = "just some ordinary log output, nothing secret here"
    await record_output_taint(benign, str(tmp_path), "sess-benign")

    counts = await read_taint(str(tmp_path), "sess-benign")
    assert counts == {}


async def test_record_output_taint_records_untrusted_read_for_webfetch(tmp_path):
    await record_output_taint(
        f"visit {_UNTRUSTED_HOST_URL} for the file", str(tmp_path), "sess-out", tool_name="WebFetch"
    )
    from doberman.storage.taint import TAINT_UNTRUSTED_READ, read_taint

    counts = await read_taint(str(tmp_path), "sess-out")
    assert counts.get(TAINT_UNTRUSTED_READ) == 1

    from doberman.engine.rules.provenance_values import untrusted_value_fingerprints

    values = list(untrusted_value_fingerprints(_UNTRUSTED_HOST_URL))
    assert await match_untrusted_value(str(tmp_path), "sess-out", values) == "WebFetch"


async def test_record_output_taint_ignores_untrusted_read_for_a_trusted_tool(tmp_path):
    await record_output_taint(
        f"visit {_UNTRUSTED_HOST_URL}", str(tmp_path), "sess-trusted", tool_name="Read"
    )
    from doberman.engine.rules.provenance_values import untrusted_value_fingerprints
    from doberman.storage.taint import match_untrusted_value

    values = list(untrusted_value_fingerprints(_UNTRUSTED_HOST_URL))
    assert await match_untrusted_value(str(tmp_path), "sess-trusted", values) is None


# --- C1: the untrusted-value echo tripwire -----------------------------------

_UNTRUSTED_HOST_URL = "https://attacker.example/collect"


def test_no_external_destination_echo_tripwire_returns_unchanged(tmp_path):
    action = _action(external_destination=None)
    decision = _pass_decision(action)

    out = apply_echo_tripwire(action, decision, "balanced", str(tmp_path), "sess-1", {})

    assert out is decision


def test_echo_tripwire_raises_pass_to_auth_on_a_recorded_value(tmp_path):
    action = _action(external_destination=_UNTRUSTED_HOST_URL)
    decision = _pass_decision(action)
    asyncio.run(
        record_untrusted_values(str(tmp_path), ["sess-echo"], [], "WebFetch")
    )  # no-op (empty), proves the empty-fingerprints guard doesn't crash
    from doberman.engine.rules.provenance_values import untrusted_value_fingerprints

    values = list(untrusted_value_fingerprints(_UNTRUSTED_HOST_URL))
    asyncio.run(record_untrusted_values(str(tmp_path), ["sess-echo"], values, "WebFetch"))

    out = apply_echo_tripwire(
        action, decision, "strict", str(tmp_path), "sess-echo", {"url": _UNTRUSTED_HOST_URL}
    )

    assert out.final_verdict is Verdict.AUTH  # AUTH-capped even in strict mode (v1)
    assert out.final_risk is Risk.high
    assert ReasonCode.untrusted_value_echo in out.reason_codes
    assert "attacker.example" not in out.explanation


def test_echo_tripwire_never_lowers_an_existing_block(tmp_path):
    action = _action(external_destination=_UNTRUSTED_HOST_URL)
    decision = Decision(
        action_id=action.id,
        final_verdict=Verdict.BLOCK,
        final_risk=Risk.critical,
        objective=GuardrailResult(
            verdict=Verdict.BLOCK,
            risk=Risk.critical,
            reason_codes=[ReasonCode.destructive_command],
            explanation="already blocked by another rule",
        ),
        reason_codes=[ReasonCode.destructive_command],
        explanation="already blocked by another rule",
        decided_at=_TS,
    )
    from doberman.engine.rules.provenance_values import untrusted_value_fingerprints

    values = list(untrusted_value_fingerprints(_UNTRUSTED_HOST_URL))
    asyncio.run(record_untrusted_values(str(tmp_path), ["sess-block"], values, "WebFetch"))

    out = apply_echo_tripwire(
        action, decision, "strict", str(tmp_path), "sess-block", {"url": _UNTRUSTED_HOST_URL}
    )

    assert out is decision  # already BLOCK — the floor skips the read entirely


async def test_apply_echo_tripwire_async_matches_the_sync_wrapper(tmp_path):
    action = _action(external_destination=_UNTRUSTED_HOST_URL)
    decision = _pass_decision(action)
    from doberman.engine.rules.provenance_values import untrusted_value_fingerprints

    values = list(untrusted_value_fingerprints(_UNTRUSTED_HOST_URL))
    await record_untrusted_values(str(tmp_path), ["sess-async"], values, "WebSearch")

    out = await apply_echo_tripwire_async(
        action, decision, "balanced", str(tmp_path), "sess-async", {"url": _UNTRUSTED_HOST_URL}
    )

    assert out.final_verdict is Verdict.AUTH
    assert ReasonCode.untrusted_value_echo in out.reason_codes


async def test_apply_echo_tripwire_async_abstains_without_a_recorded_value(tmp_path):
    action = _action(external_destination=_UNTRUSTED_HOST_URL)
    decision = _pass_decision(action)

    out = await apply_echo_tripwire_async(
        action, decision, "strict", str(tmp_path), "sess-clean", {"url": _UNTRUSTED_HOST_URL}
    )

    assert out is decision


async def test_apply_echo_tripwire_async_storage_failure_leaves_decision_untouched(
    tmp_path, monkeypatch
):
    action = _action(external_destination=_UNTRUSTED_HOST_URL)
    decision = _pass_decision(action)

    async def _boom(*_args, **_kwargs):
        raise RuntimeError("taint store unavailable")

    import doberman.storage.taint as taint_module

    monkeypatch.setattr(taint_module, "match_untrusted_value", _boom)

    out = await apply_echo_tripwire_async(
        action, decision, "strict", str(tmp_path), "sess-fail", {"url": _UNTRUSTED_HOST_URL}
    )

    assert out is decision


def test_untrusted_read_tools_constant_matches_the_expected_set():
    assert UNTRUSTED_READ_TOOLS == frozenset({"WebFetch", "WebSearch"})
