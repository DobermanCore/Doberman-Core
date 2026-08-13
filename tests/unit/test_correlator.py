"""C3.1 — the session correlator (`doberman.engine.correlator`).

Most of this file is pure-function tests: no DB, no executor wiring — just
`correlate()` over hand-built `DecisionRow` history plus a live
`SecurityObject`/`Decision` for the current action. The trailing
`apply_correlator`/`apply_correlator_async` section DOES touch a real
(tmp_path) DB — mirrors `test_taint_floor_module.py`'s own split (pure core +
a module-level regression test for the shared read-correlate-raise wrapper,
independent of either caller's own wiring test).
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import pytest

from doberman.engine.correlator import DecisionRow, apply_correlator, correlate
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
from doberman.storage.log import record_decision

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


def test_sensitive_path_access_only_read_does_not_fire_trifecta():
    # C3.1 FP fix: a PRIOR row carrying ONLY sensitive_path_access (a bare
    # glob-policy hit — e.g. a legitimate read under infra/**/backend/auth/**
    # that happens to hold config an agent legitimately needs) must NOT count
    # as the trifecta's "sensitive read" leg — narrowed to secret-class
    # evidence only (sensitive_secret_access / possible_high_entropy_secret /
    # secret_exfiltration). This is what separates
    # "read untrusted content -> read a policy-sensitive but non-secret
    # config -> call a real external API" (benign) from
    # "read untrusted content -> read an actual secret store -> exfiltrate"
    # (attack) — see the module's _SENSITIVE_READ_REASONS docstring.
    recent = [
        _row(action_type=ActionType.file_read, source_context=SourceContext.webpage),
        _row(
            action_type=ActionType.file_read,
            source_context=SourceContext.user,
            reason_codes=(ReasonCode.sensitive_path_access,),
        ),
    ]
    action = _action()
    decision = _pass_decision(action)

    assert correlate(recent, decision, action, "balanced") is None
    assert correlate(recent, decision, action, "strict") is None


def test_secret_class_read_still_fires_trifecta_alongside_path_access():
    # A row carrying BOTH sensitive_path_access and a secret-class code (a
    # real credential store that also happens to match a sensitive glob)
    # still fires — the narrowing only drops path-access-ALONE evidence, it
    # never weakens a genuine secret-class hit.
    recent = [
        _row(action_type=ActionType.file_read, source_context=SourceContext.webpage),
        _row(
            action_type=ActionType.file_read,
            source_context=SourceContext.user,
            reason_codes=(ReasonCode.sensitive_path_access, ReasonCode.sensitive_secret_access),
        ),
    ]
    action = _action()
    decision = _pass_decision(action)

    result = correlate(recent, decision, action, "balanced")
    assert result is not None
    assert ReasonCode.correlated_trifecta in result.reason_codes


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


# ---------------------------------------------------------------------------
# apply_correlator / apply_correlator_async — the shared read-correlate-raise
# wrapper (C3.1 Part 2), against a real (tmp_path) decision-log DB. Mirrors
# test_taint_floor_module.py's own module-level regression coverage of
# apply_taint_floor/apply_taint_floor_async, independent of either caller's
# own wiring test (test_proxy_correlator.py / test_hosthook_spine.py).
# ---------------------------------------------------------------------------


def _seed_row(repo_root: str, session_id: str, *, reason_codes: tuple[ReasonCode, ...]) -> None:
    row_action = SecurityObject(
        id="hist-1",
        ts=_NOW,
        agent_role="unknown",
        action_type=ActionType.file_read,
        tool_name="file_read",
        target=".npmrc",
    )
    row_decision = Decision(
        action_id=row_action.id,
        final_verdict=Verdict.AUTH,
        final_risk=Risk.high,
        objective=GuardrailResult(
            verdict=Verdict.AUTH,
            risk=Risk.high,
            reason_codes=list(reason_codes),
            explanation="synthetic history row for the apply_correlator test",
        ),
        reason_codes=list(reason_codes),
        explanation="synthetic history row for the apply_correlator test",
        decided_at=_NOW,
    )
    asyncio.run(
        record_decision(
            row_decision,
            row_action,
            repo_root=repo_root,
            auth_result="executed",
            session_id=session_id,
        )
    )


def test_apply_correlator_reads_real_history_and_raises(tmp_path):
    repo_root = str(tmp_path)
    session_id = "sess-apply-1"
    _seed_row(repo_root, session_id, reason_codes=(ReasonCode.sensitive_secret_access,))

    action = _action()
    decision = _pass_decision(action)

    out = apply_correlator(action, decision, "balanced", repo_root, session_id)

    assert out.final_verdict is Verdict.AUTH
    assert ReasonCode.correlated_trifecta in out.reason_codes
    # Raise-only: risk never drops below the input decision's own risk.
    assert out.final_risk is not Risk.low


def test_apply_correlator_no_session_id_reads_empty_history(tmp_path):
    repo_root = str(tmp_path)
    _seed_row(repo_root, "sess-apply-2", reason_codes=(ReasonCode.sensitive_secret_access,))

    action = _action()
    decision = _pass_decision(action)

    # A DIFFERENT (or absent) session id must not see another session's rows.
    out = apply_correlator(action, decision, "balanced", repo_root, None)

    assert out.final_verdict is Verdict.PASS
    assert ReasonCode.correlated_trifecta not in out.reason_codes


def test_apply_correlator_no_db_yet_returns_decision_unchanged(tmp_path):
    # A repo root with no decision-log DB at all (recent_session_decisions'
    # own fail-closed-to-[] path) must leave the decision untouched, never
    # crash or escalate — mirrors _apply_correlator's fail-closed contract.
    action = _action()
    decision = _pass_decision(action)

    out = apply_correlator(action, decision, "balanced", str(tmp_path / "does-not-exist"), "sess-x")
    assert out is decision


# ---------------------------------------------------------------------------
# D2 — the task-match leg: a user-justified egress destination (a token from
# THIS session's trusted, typed-only user prompt) suppresses the trifecta's
# fire condition. Pure-`correlate()` tests first, then the same behavior
# proven end to end against a real DB via apply_correlator.
# ---------------------------------------------------------------------------

_TRIFECTA_RECENT = [
    _row(action_type=ActionType.file_read, source_context=SourceContext.tool_output),
    _row(
        action_type=ActionType.file_read,
        source_context=SourceContext.user,
        reason_codes=(ReasonCode.sensitive_secret_access,),
    ),
]


def test_task_match_suppresses_trifecta_for_user_justified_destination():
    # The legit-API case: the session's trifecta legs are all present, but the
    # CURRENT egress destination matches a task token the user's own prompt
    # named (e.g. "call Stripe at api.stripe.com") — no false positive.
    action = _action(external_destination="https://api.stripe.com/v1/charges")
    decision = _pass_decision(action)

    result = correlate(
        _TRIFECTA_RECENT, decision, action, "balanced", task_hosts=frozenset({"stripe.com"})
    )
    assert result is None

    # Subdomain match too (mirrors ExternalDestinationRule's own registered-
    # domain semantics): a task token of the parent domain covers a subdomain.
    result_subdomain = correlate(
        _TRIFECTA_RECENT, decision, action, "strict", task_hosts=frozenset({"stripe.com"})
    )
    assert result_subdomain is None


def test_task_match_does_not_suppress_an_unrelated_destination():
    # SECURITY: the injection-soundness case. A task token exists for this
    # session (the user asked to call Stripe), but the CURRENT egress is to a
    # DIFFERENT, unrelated destination (e.g. one an indirect prompt injection
    # in fetched content tried to add). Task-match must not blanket-suppress
    # the trifecta for the whole session — only for the destination the user
    # actually named.
    action = _action(external_destination="https://evil.example/collect")
    decision = _pass_decision(action)

    result = correlate(
        _TRIFECTA_RECENT, decision, action, "balanced", task_hosts=frozenset({"stripe.com"})
    )
    assert result is not None
    assert ReasonCode.correlated_trifecta in result.reason_codes


def test_no_task_hosts_leaves_trifecta_unchanged():
    # No task tokens at all (the default) -> byte-for-byte the same behavior
    # as before this feature existed.
    action = _action(external_destination="https://api.stripe.com/v1/charges")
    decision = _pass_decision(action)

    result = correlate(_TRIFECTA_RECENT, decision, action, "balanced")
    assert result is not None
    assert ReasonCode.correlated_trifecta in result.reason_codes


def test_task_match_never_suppresses_the_destructive_flow_leg():
    # D2 is scoped to the trifecta only (a different attack shape from the
    # archive-and-exfiltrate destructive flow) — a task token must not soften
    # correlated_destructive_flow.
    recent = [
        _row(action_type=ActionType.file_read, source_context=SourceContext.user),
        _row(action_type=ActionType.shell_exec, source_context=SourceContext.user),
    ]
    action = _action(external_destination="https://api.stripe.com/v1/charges")
    decision = _pass_decision(action)

    result = correlate(recent, decision, action, "balanced", task_hosts=frozenset({"stripe.com"}))
    assert result is not None
    assert ReasonCode.correlated_destructive_flow in result.reason_codes


def test_apply_correlator_suppresses_with_a_real_task_token(tmp_path):
    from doberman.storage.task_match import record_task_hosts

    repo_root = str(tmp_path)
    session_id = "sess-task-1"
    _seed_row(repo_root, session_id, reason_codes=(ReasonCode.sensitive_secret_access,))
    asyncio.run(record_task_hosts(repo_root, session_id, ["stripe.com"]))

    action = _action(external_destination="https://api.stripe.com/v1/charges")
    decision = _pass_decision(action)

    out = apply_correlator(action, decision, "balanced", repo_root, session_id)

    assert out is decision  # untouched -- the trifecta never fired
    assert ReasonCode.correlated_trifecta not in out.reason_codes


def test_apply_correlator_still_fires_for_a_destination_the_task_token_does_not_cover(tmp_path):
    # SECURITY: same session, same recorded task token ("stripe.com") -- but
    # THIS egress goes somewhere else. Proves the real (DB-backed) path is as
    # injection-sound as the pure correlate() test above: a task token can
    # never blanket-suppress a session, only the destination it actually names.
    from doberman.storage.task_match import record_task_hosts

    repo_root = str(tmp_path)
    session_id = "sess-task-2"
    _seed_row(repo_root, session_id, reason_codes=(ReasonCode.sensitive_secret_access,))
    asyncio.run(record_task_hosts(repo_root, session_id, ["stripe.com"]))

    action = _action(external_destination="https://evil.example/collect")
    decision = _pass_decision(action)

    out = apply_correlator(action, decision, "balanced", repo_root, session_id)

    assert out.final_verdict is Verdict.AUTH
    assert ReasonCode.correlated_trifecta in out.reason_codes


def test_apply_correlator_fails_closed_when_task_host_read_errors(tmp_path, monkeypatch):
    # Fail-closed (D2's own invariant, distinct from the correlator's
    # pre-existing whole-call fail-closed-to-unchanged behavior): a task-host
    # READ failure must degrade to "no task hosts" and let the trifecta fire
    # normally -- never to a silently-unraised decision, and never a crash.
    from doberman.storage.task_match import record_task_hosts

    repo_root = str(tmp_path)
    session_id = "sess-task-3"
    _seed_row(repo_root, session_id, reason_codes=(ReasonCode.sensitive_secret_access,))
    asyncio.run(record_task_hosts(repo_root, session_id, ["stripe.com"]))

    async def _boom(repo_root, scope):  # noqa: ARG001
        raise RuntimeError("task-host store unavailable")

    monkeypatch.setattr("doberman.storage.task_match.task_hosts_for", _boom)

    action = _action(external_destination="https://api.stripe.com/v1/charges")
    decision = _pass_decision(action)

    out = apply_correlator(action, decision, "balanced", repo_root, session_id)

    # Despite a real (matching) task token existing, the read blew up -> the
    # trifecta fires as if D2 did not exist. Fail toward MORE protection.
    assert out.final_verdict is Verdict.AUTH
    assert ReasonCode.correlated_trifecta in out.reason_codes
