"""Unit tests for the benchmark harness: metrics math, profile selection,
isolation, and redaction — all with stubs, no dependence on which rules fire."""

from __future__ import annotations

from doberman.engine.decision_engine import Guardrail
from doberman.models import (
    ActionType,
    Decision,
    EvalContext,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    Verdict,
)
from tests.benchmarks.adapter import BenchmarkCase, CandidateAction
from tests.benchmarks.mapping import BENCHMARK_TS
from tests.benchmarks.metrics import ActionOutcome, build_report
from tests.benchmarks.profiles import (
    BUILTINS_ONLY,
    NO_GUARDRAIL,
    WITH_PLUGINS,
    PassthroughPipeline,
    build_pipeline,
)
from tests.benchmarks.runner import run_suite


# --- helpers ----------------------------------------------------------------
def _decision(action_id: str, verdict: Verdict) -> Decision:
    if verdict is Verdict.PASS:
        objective = GuardrailResult(verdict=Verdict.PASS, risk=Risk.low)
        return Decision(
            action_id=action_id,
            final_verdict=Verdict.PASS,
            final_risk=Risk.low,
            objective=objective,
            decided_at=BENCHMARK_TS,
        )
    objective = GuardrailResult(
        verdict=verdict,
        risk=Risk.medium,
        reason_codes=[ReasonCode.unknown_external_destination],
        explanation="stub",
    )
    return Decision(
        action_id=action_id,
        final_verdict=verdict,
        final_risk=Risk.medium,
        objective=objective,
        reason_codes=[ReasonCode.unknown_external_destination],
        explanation="stub",
        decided_at=BENCHMARK_TS,
    )


class _StubPipeline:
    name = "stub"

    def __init__(self, default: Verdict = Verdict.PASS) -> None:
        self._default = default

    def decide(self, action: SecurityObject, ctx: EvalContext) -> Decision:
        return _decision(action.id, self._default)


def _benign(case_id: str) -> BenchmarkCase:
    return BenchmarkCase(
        case_id=case_id,
        label="benign",
        actions=(CandidateAction(action_type=ActionType.file_read, tool_name="read"),),
    )


# --- metrics math -----------------------------------------------------------
def test_build_report_counts_and_rates():
    outcomes = [
        ActionOutcome("attack", Verdict.PASS),
        ActionOutcome("attack", Verdict.AUTH, (ReasonCode.unknown_external_destination,)),
        ActionOutcome("attack", Verdict.BLOCK, (ReasonCode.protected_path_blocked,)),
        ActionOutcome("attack", Verdict.PASS),
        ActionOutcome("benign", Verdict.PASS),
        ActionOutcome("benign", Verdict.AUTH, (ReasonCode.unknown_external_destination,)),
        ActionOutcome("benign", Verdict.BLOCK, (ReasonCode.protected_path_blocked,)),
    ]
    report = build_report("suite", "profile", outcomes)

    assert report.n_attack == 4
    assert report.n_benign == 3
    assert report.attack_bypassed == 2
    assert report.asr == 2 / 4  # mitigation = AUTH or BLOCK; only PASS bypasses
    assert report.asr_strict == (2 + 1) / 4  # AUTH counts as not-stopped
    assert report.fpr == (1 + 1) / 3
    assert report.hard_fpr == 1 / 3
    assert report.verdict_histogram == {"PASS": 3, "AUTH": 2, "BLOCK": 2}
    assert report.reason_codes["unknown_external_destination"] == 2
    assert report.reason_codes["protected_path_blocked"] == 2


def test_empty_report_has_no_division_by_zero():
    report = build_report("suite", "profile", [])
    assert report.asr == 0.0
    assert report.asr_strict == 0.0
    assert report.fpr == 0.0
    assert report.hard_fpr == 0.0


# --- runner isolation -------------------------------------------------------
def test_run_suite_isolates_a_bad_case():
    bad = BenchmarkCase(
        case_id="bad",
        label="attack",
        # An invalid action_type makes SecurityObject construction raise.
        actions=(CandidateAction(action_type="not-a-real-type", tool_name="x"),),  # type: ignore[arg-type]
    )
    good = _benign("good")

    class _Adapter:
        suite_name = "iso"

        def load(self):
            return [bad, good]

    report = run_suite(_Adapter(), _StubPipeline(Verdict.PASS))
    # The bad case is skipped; the good benign case still measured.
    assert report.n_attack == 0
    assert report.n_benign == 1


# --- profile selector wires plugins -----------------------------------------
def test_with_plugins_profile_picks_up_a_registered_rule(monkeypatch):
    class _AlwaysAuthRule:
        def evaluate(self, action: SecurityObject, ctx: EvalContext) -> GuardrailResult:
            return GuardrailResult(
                verdict=Verdict.AUTH,
                risk=Risk.medium,
                reason_codes=[ReasonCode.rule_error],
                explanation="fake registered rule",
            )

    assert isinstance(_AlwaysAuthRule(), Guardrail)

    # Inject via the exact discovery seam the objective guardrail calls.
    import doberman.engine.objective as objective_module

    monkeypatch.setattr(objective_module, "discover_rules", lambda: [_AlwaysAuthRule()])

    from tests.benchmarks.suites.synthetic import SyntheticAdapter

    adapter = SyntheticAdapter()
    builtins = run_suite(adapter, build_pipeline(load_plugins=False))
    with_plugins = run_suite(adapter, build_pipeline(load_plugins=True))

    assert builtins.profile == BUILTINS_ONLY
    assert with_plugins.profile == WITH_PLUGINS
    # The fake rule escalates otherwise-benign trusted traffic only in with_plugins.
    assert builtins.fpr == 0.0
    assert with_plugins.fpr > builtins.fpr


# --- before/after baseline arm ----------------------------------------------
def test_passthrough_pipeline_is_the_unmediated_baseline():
    from tests.benchmarks.suites.synthetic import SyntheticAdapter

    report = run_suite(SyntheticAdapter(), PassthroughPipeline())
    assert report.profile == NO_GUARDRAIL
    # The passthrough never consults the engine: every action is allowed,
    # independent of which rules would otherwise fire. So on a ground-truth
    # attack corpus every attack bypasses and benign work has zero friction.
    assert report.asr == 1.0
    assert report.asr_strict == 1.0
    assert report.fpr == 0.0
    assert report.hard_fpr == 0.0
    assert report.verdict_histogram == {"PASS": report.n_attack + report.n_benign}
    # A PASS carries no reason codes, so the baseline report attributes nothing.
    assert report.reason_codes == {}
