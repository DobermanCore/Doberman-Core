"""Slice SL5.1 — the preference weight vector, presets, persistence, and CLI.

Load-bearing properties: the four modes are presets over the vector; invalid
weights are rejected; the vector round-trips through the policy YAML; and the
objective hard-block floor is untouched at all-minimal weights.
"""

from datetime import datetime, timezone

import pytest
from typer.testing import CliRunner

from doberman.cli.main import app
from doberman.config import load_preferences, save_preferences
from doberman.engine.decision_engine import StaticGuardrail, decide
from doberman.models import (
    ActionType,
    EvalContext,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    Verdict,
)
from doberman.policy.checklist import PolicyDoc, recommend_policy
from doberman.policy.modes import SecurityMode
from doberman.policy.preferences import (
    DIMENSIONS,
    PRESETS,
    PreferenceVector,
    preset_name,
    vector_for,
)

runner = CliRunner()
_NOW = datetime(2026, 6, 9, tzinfo=timezone.utc)


# --- the vector ----------------------------------------------------------------


def test_presets_cover_every_mode_and_get_stricter():
    assert set(PRESETS) == set(SecurityMode)
    light, paranoid = PRESETS[SecurityMode.light], PRESETS[SecurityMode.paranoid]
    for name in ("confidentiality", "reversibility", "blast_radius"):
        assert getattr(light, name) < getattr(paranoid, name)


def test_invalid_weights_are_rejected():
    with pytest.raises(ValueError):
        PreferenceVector(confidentiality=1.5)
    with pytest.raises(ValueError):
        PreferenceVector(blast_radius=-0.1)
    with pytest.raises(KeyError):
        PreferenceVector().with_weight("bribability", 0.5)


def test_coherent_mixed_stances_are_expressible():
    mixed = PreferenceVector(confidentiality=0.9, reversibility=0.2)
    assert mixed.confidentiality == 0.9
    assert mixed.reversibility == 0.2
    assert preset_name(mixed) is None  # a custom mix matches no preset


def test_unknown_mode_falls_back_to_the_strictest_preset():
    assert vector_for("garbage") == PRESETS[SecurityMode.paranoid]
    assert vector_for("balanced") == PRESETS[SecurityMode.balanced]


# --- persistence ----------------------------------------------------------------


def test_vector_round_trips_through_the_policy_yaml(tmp_path):
    root = str(tmp_path)
    declared = PreferenceVector(0.8, 0.3, 0.6, 0.9)
    save_preferences(declared, root)
    assert load_preferences(root) == declared


def test_absent_vector_falls_back_to_the_mode_preset(tmp_path):
    root = str(tmp_path)
    assert load_preferences(root) == PRESETS[SecurityMode.balanced]


def test_invalid_stored_vector_is_ignored_not_fatal():
    doc = PolicyDoc.from_mapping(
        {"mode": "balanced", "items": [], "preferences": {"confidentiality": 99.0}}
    )
    assert doc.preferences is None  # bad stored weights → preset applies


# --- the floor ----------------------------------------------------------------


def test_objective_floor_survives_all_minimal_weights():
    # Even with every weight at minimum, an objective BLOCK is still a BLOCK —
    # the vector modulates subjective step-ups only.
    minimal = PreferenceVector(0.0, 0.0, 0.0, 0.0)
    blocking = StaticGuardrail(
        GuardrailResult(
            verdict=Verdict.BLOCK,
            risk=Risk.critical,
            reason_codes=[ReasonCode.secret_exfiltration],
            explanation="hard block",
        )
    )
    passing = StaticGuardrail(GuardrailResult(verdict=Verdict.PASS, risk=Risk.low))
    action = SecurityObject(
        id="pref-1",
        ts=_NOW,
        agent_role="frontend",
        action_type=ActionType.network_request,
        tool_name="net_post",
        target="https://evil.example",
    )
    ctx = EvalContext(metadata={"preferences": minimal})
    decision = decide(action, blocking, passing, ctx)
    assert decision.final_verdict is Verdict.BLOCK


# --- CLI ----------------------------------------------------------------


def test_prefs_shows_the_vector_and_preset(tmp_path):
    result = runner.invoke(app, ["prefs", "--path", str(tmp_path)])
    assert result.exit_code == 0
    for name in DIMENSIONS:
        assert name in result.output
    assert "balanced" in result.output


def test_prefs_sets_a_weight_and_status_reflects_it(tmp_path):
    result = runner.invoke(app, ["prefs", "confidentiality", "0.8", "--path", str(tmp_path)])
    assert result.exit_code == 0
    assert load_preferences(str(tmp_path)).confidentiality == 0.8
    status = runner.invoke(app, ["status", "--path", str(tmp_path)])
    assert status.exit_code == 0
    assert "confidentiality=0.80" in status.output
    assert "custom" in status.output


def test_prefs_rejects_invalid_dimension_and_range(tmp_path):
    bad_dim = runner.invoke(app, ["prefs", "bribability", "0.5", "--path", str(tmp_path)])
    assert bad_dim.exit_code == 2
    bad_value = runner.invoke(app, ["prefs", "confidentiality", "1.5", "--path", str(tmp_path)])
    assert bad_value.exit_code == 2
    # Nothing was persisted by the failed attempts.
    assert load_preferences(str(tmp_path)) == PRESETS[SecurityMode.balanced]


def test_recommended_policy_still_builds_without_a_vector():
    doc = recommend_policy()
    assert doc.preferences is None
    assert doc.to_mapping().get("preferences") is None
