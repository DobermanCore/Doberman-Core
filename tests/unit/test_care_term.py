"""Slice SL5.2 — the care term: preference weights × algebra signals.

Load-bearing properties: each weight raises care only for its matching
concern; conflicting signals take the max (never cancel); care stays in
[0,1]; interruption tolerance scales the threshold within hard bounds; and
care can never lower an objective verdict.
"""

from datetime import datetime, timezone

from doberman.engine.decision_engine import StaticGuardrail, decide
from doberman.models import (
    ActionType,
    Algebra,
    BlastRadius,
    DestinationClass,
    EvalContext,
    GuardrailResult,
    Provenance,
    ReasonCode,
    Reversibility,
    Risk,
    SecurityObject,
    TargetClass,
    Verdict,
)
from doberman.policy.preferences import (
    THRESHOLD_CEIL,
    THRESHOLD_FLOOR,
    PreferenceVector,
    care,
    effective_threshold,
)

_NOW = datetime(2026, 6, 9, tzinfo=timezone.utc)


def _algebra(**kw):
    defaults = dict(
        capability="mutate",
        target_class=TargetClass.internal,
        destination_class=DestinationClass.none,
        blast_radius=BlastRadius.single,
        provenance=Provenance.trusted_instruction,
        classification_confidence=0.8,
    )
    defaults.update(kw)
    return Algebra(**defaults)


def test_confidentiality_weight_raises_care_on_secret_and_external():
    confidential = PreferenceVector(confidentiality=1.0, reversibility=0.0, blast_radius=0.0)
    assert care(confidential, _algebra(target_class=TargetClass.secret), Reversibility.high) == 1.0
    assert (
        care(
            confidential,
            _algebra(destination_class=DestinationClass.unknown_external),
            Reversibility.high,
        )
        == 1.0
    )
    # A benign internal action draws no confidentiality concern.
    assert care(confidential, _algebra(), Reversibility.high) == 0.0


def test_reversibility_weight_raises_care_on_irreversible():
    cautious = PreferenceVector(confidentiality=0.0, reversibility=1.0, blast_radius=0.0)
    assert care(cautious, _algebra(), Reversibility.low) == 1.0
    assert care(cautious, _algebra(), Reversibility.medium) == 0.5
    assert care(cautious, _algebra(), Reversibility.high) == 0.0


def test_blast_weight_raises_care_on_volume():
    volume = PreferenceVector(confidentiality=0.0, reversibility=0.0, blast_radius=1.0)
    assert care(volume, _algebra(blast_radius=BlastRadius.mass), Reversibility.high) == 1.0
    assert care(volume, _algebra(blast_radius=BlastRadius.single), Reversibility.high) == 0.0


def test_conflicting_signals_take_the_max_contribution():
    vector = PreferenceVector(confidentiality=0.3, reversibility=0.9, blast_radius=0.1)
    # Confidentiality fires at 0.3, reversibility at 0.9 → max wins.
    value = care(vector, _algebra(target_class=TargetClass.secret), Reversibility.low)
    assert value == 0.9


def test_care_is_always_in_unit_interval():
    for vector in (
        PreferenceVector(0.0, 0.0, 0.0, 0.0),
        PreferenceVector(1.0, 1.0, 1.0, 1.0),
    ):
        for target in TargetClass:
            for blast in BlastRadius:
                value = care(
                    vector, _algebra(target_class=target, blast_radius=blast), Reversibility.low
                )
                assert 0.0 <= value <= 1.0


def test_interruption_tolerance_scales_the_threshold_within_bounds():
    neutral = PreferenceVector(interruption_tolerance=0.5)
    eager = PreferenceVector(interruption_tolerance=1.0)
    reluctant = PreferenceVector(interruption_tolerance=0.0)
    base = 0.7
    assert effective_threshold(base, neutral) == base
    assert effective_threshold(base, eager) < base  # asks sooner
    assert effective_threshold(base, reluctant) > base  # asks later
    # Hard bounds: tuning can never go below the floor or above the ceiling.
    assert effective_threshold(0.01, eager) == THRESHOLD_FLOOR
    assert effective_threshold(5.0, reluctant) == THRESHOLD_CEIL


def test_care_never_lowers_an_objective_verdict():
    # Whatever care computes, the engine's objective short-circuit stands.
    blocking = StaticGuardrail(
        GuardrailResult(
            verdict=Verdict.BLOCK,
            risk=Risk.critical,
            reason_codes=[ReasonCode.protected_path_blocked],
            explanation="hard block",
        )
    )
    passing = StaticGuardrail(GuardrailResult(verdict=Verdict.PASS, risk=Risk.low))
    action = SecurityObject(
        id="care-1",
        ts=_NOW,
        agent_role="frontend",
        action_type=ActionType.file_write,
        tool_name="fs_write",
        target=".env",
    )
    relaxed = EvalContext(metadata={"preferences": PreferenceVector(0.0, 0.0, 0.0, 0.0)})
    assert decide(action, blocking, passing, relaxed).final_verdict is Verdict.BLOCK
