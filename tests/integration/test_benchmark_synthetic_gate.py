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

from tests.benchmarks.runner import run_profiles
from tests.benchmarks.suites.synthetic import PAYLOAD_MARKER, SyntheticAdapter


@pytest.fixture(scope="module")
def report() -> dict:
    return run_profiles(SyntheticAdapter())


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
