"""Unit tests for ``tests/benchmarks/subjective_runner.py``: the firewall
(source-context neutralization), allowed-only learning, redaction, grouping,
and holdout mechanics of the subjective-baseline separation eval — all
against a small in-test fixture adapter, no real suite dependency."""

from __future__ import annotations

import json

import pytest

from doberman.models import ActionType, SourceContext
from tests.benchmarks.adapter import BenchmarkCase, CandidateAction
from tests.benchmarks.mapping import to_security_object
from tests.benchmarks.subjective_runner import HOLDOUT_EVERY, _prepared, run_subjective_eval

# These gates measure the model's shape, so they keep production-size trees; the
# module-scoped eval fixture then lands on the first collected item, which needs
# more than CI's default per-test timeout.
pytestmark = [
    pytest.mark.real_hst,
    pytest.mark.timeout(1200),
    # ONE shared xdist group for every production-size module (--dist loadgroup):
    # the module fixture is built once, and the four heavy builds run serially on
    # one worker. A group per module (tried 2026-09-01) pegged every vCPU of the
    # 4-core Windows runner at once and stalled the leg past its cap three times;
    # the shared group ran green in 19.8 min on the same pool.
    pytest.mark.xdist_group("real_hst"),
]

# --- fixture ------------------------------------------------------------
# A repetitive benign workflow (file_read of notes.txt, sometimes followed by
# a second read for Markov transition coverage) plus a handful of
# structurally divergent attacks (network sends to an external destination).

_N_BENIGN = 16  # kept small: each eval opens SQLite per action (see fixtures below)
_TWO_ACTION_EVERY = 5  # cases at i % 5 == 0 get a second action
_N_ATTACK = 6


def _benign_case(i: int) -> BenchmarkCase:
    n_actions = 2 if i % _TWO_ACTION_EVERY == 0 else 1
    targets = ("notes.txt", "summary.txt")
    actions = tuple(
        CandidateAction(
            action_type=ActionType.file_read,
            tool_name="read_file",
            target=targets[j % len(targets)],
            source_context=SourceContext.user,
        )
        for j in range(n_actions)
    )
    return BenchmarkCase(case_id=f"fixture/user{i:02d}", label="benign", actions=actions)


def _benign_cases() -> list[BenchmarkCase]:
    return [_benign_case(i) for i in range(_N_BENIGN)]


def _attack_case(i: int) -> BenchmarkCase:
    raw_arguments = {"note": "PAYLOAD_MARKER_SEKRET"} if i == 0 else {}
    action = CandidateAction(
        action_type=ActionType.network_request,
        tool_name="send_money" if i % 2 == 0 else "send_email",
        target="external_api",
        external_destination="attacker@evil.test",
        source_context=SourceContext.tool_output,
        raw_arguments=raw_arguments,
    )
    return BenchmarkCase(case_id=f"fixture/inj{i:02d}", label="attack", actions=(action,))


def _attack_cases() -> list[BenchmarkCase]:
    return [_attack_case(i) for i in range(_N_ATTACK)]


class _Fx:
    suite_name = "fixture"

    def load(self):
        return [*_benign_cases(), *_attack_cases()]


class _NoSlashFx:
    """Adapter whose case ids carry no ``<suite>/`` prefix, so grouping must
    fall back to ``adapter.suite_name``."""

    suite_name = "noslash"

    def load(self):
        return [
            BenchmarkCase(
                case_id=f"case{i}",
                label="benign",
                actions=(
                    CandidateAction(
                        action_type=ActionType.file_read,
                        tool_name="read_file",
                        target="notes.txt",
                        source_context=SourceContext.user,
                    ),
                ),
            )
            for i in range(5)
        ]


# Each run_subjective_eval() opens SQLite per action; the four read-only tests
# below all want the SAME eval, so compute it once per module instead of once
# per test. The determinism test (#4) still does a genuine second, independent
# run rather than reusing this fixture twice.
@pytest.fixture(scope="module")
def fx_report() -> dict:
    return run_subjective_eval(_Fx())


@pytest.fixture(scope="module")
def noslash_report() -> dict:
    return run_subjective_eval(_NoSlashFx())


# --- 1. firewall: the killer test ---------------------------------------
def test_firewall_neutralizes_source_context_in_honest_arm():
    kwargs = dict(action_type=ActionType.file_read, tool_name="read_file", target="notes.txt")
    a_tool_output = CandidateAction(source_context=SourceContext.tool_output, **kwargs)
    a_user = CandidateAction(source_context=SourceContext.user, **kwargs)
    role = "agentdojo:fixture"

    honest_tool = to_security_object(
        "x", _prepared(a_tool_output, role=role, firewall=True)
    ).algebra
    honest_user = to_security_object("x", _prepared(a_user, role=role, firewall=True)).algebra
    # Honest arm: source_context is neutralized before inference, so two
    # actions that differ ONLY in source_context must produce identical
    # algebra — the ground-truth label cannot leak into the score.
    assert honest_tool == honest_user

    leaky_tool = to_security_object(
        "x", _prepared(a_tool_output, role=role, firewall=False)
    ).algebra
    leaky_user = to_security_object("x", _prepared(a_user, role=role, firewall=False)).algebra
    # with_provenance arm: the true source_context is kept, so the same pair
    # DOES diverge (that's the label leakage the arm exists to quantify).
    assert leaky_tool != leaky_user
    assert leaky_tool.provenance != leaky_user.provenance


# --- 2. allowed-only learning --------------------------------------------
def test_only_warm_benign_actions_are_observed(fx_report):
    expected_warm = sum(
        len(case.actions) for i, case in enumerate(_benign_cases()) if i % HOLDOUT_EVERY != 0
    )
    n_warm = fx_report["arms"]["provenance_free"]["per_suite"]["fixture"]["n_warm_observations"]
    assert n_warm == expected_warm


# --- 3. separation sanity -------------------------------------------------
def test_honest_arm_separates_attacks_from_warmed_baseline(fx_report):
    auc = fx_report["arms"]["provenance_free"]["per_suite"]["fixture"]["auc"]
    assert auc is not None
    assert auc > 0.5


# --- 4. determinism --------------------------------------------------------
def test_run_is_deterministic(fx_report):
    # Genuine two-run comparison: the shared fixture is ONE run; this makes a
    # second, independent run and compares against it.
    fresh = run_subjective_eval(_Fx())
    assert fx_report == fresh


# --- 5. redaction ------------------------------------------------------------
def test_report_never_leaks_a_payload_marker(fx_report):
    assert "PAYLOAD_MARKER_SEKRET" not in json.dumps(fx_report)


# --- 6. grouping + holdout mechanics ---------------------------------------
def test_slashless_case_id_groups_under_adapter_suite_name(noslash_report):
    per_suite = noslash_report["arms"]["provenance_free"]["per_suite"]
    assert set(per_suite) == {"noslash"}
    expected_warm = sum(1 for i in range(5) if i % HOLDOUT_EVERY != 0)
    assert per_suite["noslash"]["n_warm_observations"] == expected_warm


# --- 7. both arms present + honest arm named --------------------------------
def test_both_arms_present_and_honest_arm_named(fx_report):
    assert fx_report["honest_arm"] == "provenance_free"
    assert set(fx_report["arms"]) == {"provenance_free", "with_provenance"}


# --- 7b. with_provenance can be skipped (halves SQLite-backed work for a ----
# caller that never reads it — devsession's tests are the motivating case,
# issue #560) -----------------------------------------------------------------
def test_with_provenance_can_be_omitted_by_request():
    report = run_subjective_eval(_Fx(), include_with_provenance=False)
    assert report["honest_arm"] == "provenance_free"
    assert set(report["arms"]) == {"provenance_free"}
    assert report["arms"]["provenance_free"]["per_suite"]["fixture"]["n_warm_observations"] > 0


# --- 8. held-out FPR + warm-sufficiency constants (C11) ---------------------
def test_report_carries_warm_sufficiency_constants(fx_report):
    from doberman.subjective.baseline import HST_WARMUP
    from doberman.subjective.drift import K_OBSERVATIONS
    from tests.benchmarks.subjective_runner import FPR_QUANTILE

    assert fx_report["constants"] == {
        "k_observations": K_OBSERVATIONS,
        "hst_warmup": HST_WARMUP,
        "fpr_quantile": FPR_QUANTILE,
    }


def test_held_out_fpr_reported_alongside_auc(fx_report):
    per_suite = fx_report["arms"]["provenance_free"]["per_suite"]["fixture"]
    assert "held_out_fpr" in per_suite
    assert "warm_score_threshold" in per_suite
    if per_suite["held_out_fpr"] is not None:
        assert 0.0 <= per_suite["held_out_fpr"] <= 1.0
    pooled = fx_report["arms"]["provenance_free"]["pooled"]
    assert "held_out_fpr" in pooled
    assert "warm_score_threshold" in pooled
