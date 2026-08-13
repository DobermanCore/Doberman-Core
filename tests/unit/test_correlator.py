"""C3.1 — the session correlator (`doberman.engine.correlator`).

Pure-function tests: no DB, no executor wiring — just `correlate()` over
hand-built `DecisionRow` history plus a live `SecurityObject`/`Decision` for
the current action. Mirrors `test_taint_floor_module.py`'s scope (the floor
module, not its executor wiring) for the correlator's own pure core.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from doberman.engine.correlator import DecisionRow, correlate
from doberman.models import (
    ActionType,
    Decision,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    SourceContext,
    Verdict,
)

_NOW = datetime(2026, 8, 13, tzinfo=timezone.utc)


def _row(
    *,
    action_type: ActionType = ActionType.file_read,
    target_path_class: str | None = None,
    source_context: SourceContext = SourceContext.user,
    risk: Risk = Risk.low,
    reason_codes: tuple[ReasonCode, ...] = (),
    final_verdict: Verdict = Verdict.PASS,
) -> DecisionRow:
    return DecisionRow(
        action_type=action_type,
        target_path_class=target_path_class,
        source_context=source_context,
        risk=risk,
        reason_codes=reason_codes,
        final_verdict=final_verdict,
    )


def _action(
    *,
    action_type: ActionType = ActionType.network_request,
    external_destination: str | None = "https://attacker.example/collect",
) -> SecurityObject:
    return SecurityObject(
        id="a1",
        ts=_NOW,
        agent_role="backend",
        action_type=action_type,
        tool_name="net_send",
        target=external_destination,
        external_destination=external_destination,
    )


def _pass_decision(action: SecurityObject) -> Decision:
    return Decision(
        action_id=action.id,
        final_verdict=Verdict.PASS,
        final_risk=Risk.low,
        objective=GuardrailResult(verdict=Verdict.PASS, risk=Risk.low),
        decided_at=_NOW,
    )


# ---------------------------------------------------------------------------
# correlated_trifecta
# ---------------------------------------------------------------------------


def test_trifecta_blocks_in_strict_and_auths_in_balanced():
    # Session shows all three legs across 3 decisions: an untrusted-provenance
    # ingress, a sensitive/secret read (a different row), and the CURRENT
    # action is an external egress.
    recent = [
        _row(action_type=ActionType.file_read, source_context=SourceContext.tool_output),
        _row(
            action_type=ActionType.file_read,
            source_context=SourceContext.user,
            reason_codes=(ReasonCode.sensitive_secret_access,),
        ),
    ]
    action = _action()
    decision = _pass_decision(action)

    strict_result = correlate(recent, decision, action, "strict")
    assert strict_result is not None
    assert strict_result.verdict is Verdict.BLOCK
    assert strict_result.risk is Risk.critical
    assert ReasonCode.correlated_trifecta in strict_result.reason_codes

    balanced_result = correlate(recent, decision, action, "balanced")
    assert balanced_result is not None
    assert balanced_result.verdict is Verdict.AUTH
    assert ReasonCode.correlated_trifecta in balanced_result.reason_codes


def test_single_egress_with_no_prior_sensitive_read_does_not_fire():
    # An untrusted ingress alone, with NO sensitive/secret read anywhere in
    # history, must not produce a false trifecta.
    recent = [_row(action_type=ActionType.file_read, source_context=SourceContext.webpage)]
    action = _action()
    decision = _pass_decision(action)

    assert correlate(recent, decision, action, "balanced") is None
    assert correlate([], decision, action, "strict") is None


def test_benign_reads_and_write_sequence_does_not_fire():
    # Reads + a write, all trusted provenance, no egress at all: no untrusted
    # ingress, no shell command, no egress leg — nothing should fire.
    recent = [
        _row(action_type=ActionType.file_read, source_context=SourceContext.user),
        _row(action_type=ActionType.file_write, source_context=SourceContext.user),
    ]
    action = _action(action_type=ActionType.file_write, external_destination=None)
    decision = _pass_decision(action)

    assert correlate(recent, decision, action, "strict") is None


# ---------------------------------------------------------------------------
# correlated_destructive_flow
# ---------------------------------------------------------------------------


def test_destructive_flow_fires_on_read_then_command_then_egress():
    recent = [
        _row(action_type=ActionType.file_read, source_context=SourceContext.user),
        _row(action_type=ActionType.shell_exec, source_context=SourceContext.user),
    ]
    action = _action()
    decision = _pass_decision(action)

    result = correlate(recent, decision, action, "balanced")
    assert result is not None
    assert result.verdict is Verdict.AUTH
    assert ReasonCode.correlated_destructive_flow in result.reason_codes

    strict_result = correlate(recent, decision, action, "paranoid")
    assert strict_result is not None
    assert strict_result.verdict is Verdict.BLOCK


def test_destructive_flow_requires_both_read_and_command_legs():
    # A shell command with no prior broad read, or a read with no command,
    # must not fire on its own.
    action = _action()
    decision = _pass_decision(action)

    only_command = [_row(action_type=ActionType.shell_exec, source_context=SourceContext.user)]
    assert correlate(only_command, decision, action, "balanced") is None

    only_read = [_row(action_type=ActionType.file_read, source_context=SourceContext.user)]
    assert correlate(only_read, decision, action, "balanced") is None


# ---------------------------------------------------------------------------
# no egress currently in flight -> neither pattern can fire
# ---------------------------------------------------------------------------


def test_no_current_egress_never_fires_either_pattern():
    recent = [
        _row(action_type=ActionType.file_read, source_context=SourceContext.tool_output),
        _row(
            action_type=ActionType.shell_exec,
            source_context=SourceContext.user,
            reason_codes=(ReasonCode.sensitive_secret_access,),
        ),
    ]
    action = _action(action_type=ActionType.file_write, external_destination=None)
    decision = _pass_decision(action)

    assert correlate(recent, decision, action, "paranoid") is None


# ---------------------------------------------------------------------------
# fail-closed: a malformed row must never crash correlate(), and must never
# be mistaken for a fired pattern.
# ---------------------------------------------------------------------------


def test_exception_inside_a_pattern_returns_none_not_raise():
    action = _action()
    decision = _pass_decision(action)

    class _Malformed:
        """Not a DecisionRow — any attribute access raises AttributeError."""

        def __getattr__(self, name):
            raise AttributeError(f"no {name}")

    # Feeding a non-DecisionRow object into the sequence must not escape
    # correlate() as an exception — a broken row degrades to "no match", never
    # a crash of the decision path.
    result = correlate([_Malformed()], decision, action, "strict")
    assert result is None


def test_decision_row_from_storage_returns_none_on_bad_values():
    assert DecisionRow.from_storage({"action_type": "not_a_real_action_type"}) is None
    assert DecisionRow.from_storage({}) is None


def test_decision_row_from_storage_round_trips_a_real_row():
    row = DecisionRow.from_storage(
        {
            "action_type": "file_read",
            "target_path_class": "*.env",
            "source_context": "tool_output",
            "risk": "high",
            "reason_codes": ["sensitive_secret_access"],
            "final_verdict": "AUTH",
        }
    )
    assert row is not None
    assert row.action_type is ActionType.file_read
    assert row.source_context is SourceContext.tool_output
    assert row.reason_codes == (ReasonCode.sensitive_secret_access,)


# ---------------------------------------------------------------------------
# budget clause: weak, combinable-only — never fires (returns non-None) on
# volume alone.
# ---------------------------------------------------------------------------


def test_budget_volume_alone_never_fires():
    # Plenty of egress-attempt-flagged and sensitive-read-flagged rows, but
    # NONE of the structural legs (no untrusted ingress, no shell command) —
    # volume must never be the sole trigger.
    recent = [
        _row(
            action_type=ActionType.network_request,
            source_context=SourceContext.user,
            reason_codes=(ReasonCode.unknown_external_destination,),
        )
        for _ in range(10)
    ]
    action = _action(action_type=ActionType.file_write, external_destination=None)
    decision = _pass_decision(action)

    assert correlate(recent, decision, action, "paranoid") is None


def test_budget_volume_strengthens_an_already_firing_pattern_to_critical():
    # The trifecta legs fire on their own (AUTH/high in balanced). Adding
    # enough sensitive-read/egress-attempt volume on top pushes risk to
    # critical even in balanced — but only because a pattern already fired.
    sparse_recent = [
        _row(action_type=ActionType.file_read, source_context=SourceContext.tool_output),
        _row(
            action_type=ActionType.file_read,
            source_context=SourceContext.user,
            reason_codes=(ReasonCode.sensitive_secret_access,),
        ),
    ]
    action = _action()
    decision = _pass_decision(action)
    sparse_result = correlate(sparse_recent, decision, action, "balanced")
    assert sparse_result is not None
    assert sparse_result.risk is Risk.high  # below the volume threshold

    volume_recent = list(sparse_recent) + [
        _row(
            action_type=ActionType.network_request,
            source_context=SourceContext.user,
            reason_codes=(ReasonCode.unknown_external_destination,),
        )
        for _ in range(5)
    ]
    volume_result = correlate(volume_recent, decision, action, "balanced")
    assert volume_result is not None
    assert volume_result.verdict is Verdict.AUTH  # mode still balanced, not strict
    assert volume_result.risk is Risk.critical  # but volume pushed risk up


@pytest.mark.parametrize("mode", ["light", "balanced"])
def test_soft_modes_never_hard_block(mode):
    recent = [
        _row(action_type=ActionType.file_read, source_context=SourceContext.tool_output),
        _row(
            action_type=ActionType.file_read,
            source_context=SourceContext.user,
            reason_codes=(ReasonCode.sensitive_secret_access,),
        ),
    ]
    action = _action()
    decision = _pass_decision(action)

    result = correlate(recent, decision, action, mode)
    assert result is not None
    assert result.verdict is Verdict.AUTH
