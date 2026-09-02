"""Integration gate: the synthetic suite run through the REAL decision engine.

Proves the harness wiring end-to-end against core's actual built-in rules:
- attacks (untrusted/raw-IP/credential-bearing egress) are all mitigated → ASR 0
- benign traffic to trusted hosts is never blocked → FPR 0
- the run is deterministic and the report leaks no payload text
- with no plugins installed, builtins_only == with_plugins (standalone equivalence)

These assertions describe the harness's contract. If a future core change alters
a built-in rule's verdict, fix the expectation here deliberately — do not weaken
the harness to hide a regression.
"""

from __future__ import annotations

import json

import pytest

from doberman.models import ReasonCode, Verdict
from tests.benchmarks.mapping import to_eval_context, to_security_object
from tests.benchmarks.profiles import build_pipeline
from tests.benchmarks.runner import run_before_after, run_profiles
from tests.benchmarks.suites.synthetic import PAYLOAD_MARKER, SyntheticAdapter

pytestmark = [
    pytest.mark.real_hst,
    pytest.mark.xdist_group("real_hst_synthetic"),
]  # production-size trees, one worker


@pytest.fixture(scope="module")
def report() -> dict:
    return run_profiles(SyntheticAdapter())


@pytest.fixture(scope="module")
def before_after() -> dict:
    return run_before_after(SyntheticAdapter())


def test_report_structure(report):
    assert report["suite"] == "synthetic"
    for profile in ("builtins_only", "with_plugins"):
        section = report[profile]
        assert section["n_attack"] == 3
        assert section["n_benign"] == 3
        assert set(section) >= {"asr", "asr_strict", "fpr", "hard_fpr"}
    assert set(report["uplift"]) == {"delta_asr", "delta_fpr"}


def test_attacks_are_all_mitigated(report):
    # Every synthetic attack targets a destination the built-in rule distrusts,
    # so none should pass through (ASR == 0 means zero bypass).
    assert report["builtins_only"]["asr"] == 0.0


def test_every_attack_is_caught_by_the_destination_rule():
    """AN-5: pin each attack's mitigation to the destination rule, so a future
    destination-coverage regression flips this red instead of hiding behind an
    aggregate ASR an unrelated rule happens to keep at 0.
    """
    pipeline = build_pipeline(load_plugins=False)
    attacks = [c for c in SyntheticAdapter().load() if c.label == "attack"]
    assert attacks  # guard: the suite still has attack cases
    for case in attacks:
        action = case.actions[0]
        decision = pipeline.decide(
            to_security_object(f"synthetic:{case.case_id}:0", action),
            to_eval_context(action),
        )
        assert ReasonCode.unknown_external_destination in decision.reason_codes, (
            f"{case.case_id} mitigated without the destination rule firing"
        )
        assert decision.final_verdict is not Verdict.PASS


def test_benign_traffic_is_not_blocked(report):
    builtins = report["builtins_only"]
    assert builtins["hard_fpr"] == 0.0  # never hard-block a legitimate action
    assert builtins["fpr"] == 0.0  # trusted hosts pass clean


def test_run_is_deterministic():
    first = run_profiles(SyntheticAdapter())
    second = run_profiles(SyntheticAdapter())
    assert first == second


def test_report_never_leaks_payload(report):
    serialized = json.dumps(report)
    assert PAYLOAD_MARKER not in serialized
    # And no obvious raw destination/argument substrings either.
    assert "attacker-domain" not in serialized
    assert "stolen-data" not in serialized


def test_no_plugins_means_zero_uplift(report):
    # On a standalone core install nothing registers, so the two profiles match.
    assert report["uplift"] == {"delta_asr": 0.0, "delta_fpr": 0.0}
    assert report["builtins_only"] == {**report["with_plugins"], "profile": "builtins_only"}


# --- before/after: the no-guardrail baseline vs. the real engine ------------
def test_before_after_brackets_the_engine_effect(before_after):
    before, after, delta = (
        before_after["before"],
        before_after["after"],
        before_after["delta"],
    )
    assert before["profile"] == "no_guardrail"
    assert after["profile"] == "builtins_only"
    # Before: the unmediated path — every synthetic attack would execute, and
    # benign work runs with zero friction (true by construction of passthrough).
    assert before["asr"] == 1.0
    assert before["fpr"] == 0.0
    assert before["hard_fpr"] == 0.0
    # After: the real engine mitigates every synthetic attack (none bypasses).
    assert after["asr"] == 0.0
    # Delta: Doberman stops 100% of the otherwise-executing attacks and, on this
    # trusted-host benign set, adds no friction.
    assert delta["attacks_stopped"] == 1.0
    assert delta["fpr_added"] == 0.0
    assert delta["hard_fpr_added"] == 0.0
    # The strict delta is rule-dependent (AUTH counts as not-stopped); assert the
    # identity against the sub-reports rather than a brittle absolute number.
    assert delta["attacks_stopped_strict"] == round(before["asr_strict"] - after["asr_strict"], 6)
    assert 0.0 <= delta["attacks_stopped_strict"] <= 1.0


def test_before_after_is_deterministic():
    assert run_before_after(SyntheticAdapter()) == run_before_after(SyntheticAdapter())


def test_before_after_never_leaks_payload(before_after):
    serialized = json.dumps(before_after)
    assert PAYLOAD_MARKER not in serialized
    assert "attacker-domain" not in serialized
    assert "stolen-data" not in serialized
