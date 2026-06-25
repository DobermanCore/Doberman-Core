"""Slice SL7.2 — explainable subjective step-ups: the dominant term is named.

Load-bearing properties: every step-up names its driver (unusual /
confidentiality / irreversible+blast / trifecta / unclassified) with a
one-line explanation that speaks in CLASSES — no raw target, argument, or
secret value ever appears in a reason or explanation.
"""

from datetime import datetime, timezone

from doberman.engine.subjective import SubjectiveGuardrail
from doberman.models import (
    ActionType,
    Algebra,
    BlastRadius,
    Capability,
    DestinationClass,
    EvalContext,
    Provenance,
    ReasonCode,
    Reversibility,
    SecurityObject,
    TargetClass,
    Verdict,
)
from doberman.policy.preferences import PreferenceVector

_NOW = datetime(2026, 6, 9, tzinfo=timezone.utc)

# Clearly-FAKE credential (recognized example pattern; NOT a real secret).
FAKE_AWS = "AKIAIOSFODNN7EXAMPLE"  # noqa: S105
_RAW_TARGET = "secrets/launch-codes.env"


def _action(algebra, reversibility=Reversibility.low):
    return SecurityObject(
        id="sr-1",
        ts=_NOW,
        agent_role="frontend",
        action_type=ActionType.file_write,
        tool_name="fs_write",
        target=_RAW_TARGET,
        reversibility=reversibility,
        raw_args_redacted={"path": _RAW_TARGET},
        algebra=algebra,
    )


def _engine():
    return SubjectiveGuardrail(load_plugins=False)


def _assert_no_raw_values(result):
    blob = result.explanation + " " + " ".join(result.reason_codes)
    assert _RAW_TARGET not in blob
    assert "launch-codes" not in blob
    assert FAKE_AWS not in blob


def test_surprise_dominant_names_the_deployment():
    algebra = Algebra(
        capability=Capability.mutate,
        target_class=TargetClass.secret,
        destination_class=DestinationClass.none,
        provenance=Provenance.trusted_instruction,
        classification_confidence=0.9,
    )
    # Surprise 1.0 >= every care contribution → the unusualness is the driver.
    result = _engine().evaluate(_action(algebra), EvalContext(metadata={"surprise": 1.0}))
    assert result.verdict is Verdict.AUTH
    assert ReasonCode.unusual_for_deployment in result.reason_codes
    assert ReasonCode.unusual_for_workflow in result.reason_codes  # legacy continuity
    assert "unusual for this deployment" in result.explanation.lower()
    assert "secret" in result.explanation  # the CLASS, never the path
    _assert_no_raw_values(result)


def test_confidentiality_dominant_names_the_destination_concern():
    algebra = Algebra(
        capability=Capability.send,
        target_class=TargetClass.secret,
        destination_class=DestinationClass.none,
        provenance=Provenance.trusted_instruction,
        classification_confidence=0.9,
    )
    confidential = PreferenceVector(confidentiality=1.0, reversibility=0.0, blast_radius=0.0)
    result = _engine().evaluate(
        _action(algebra, reversibility=Reversibility.high),
        EvalContext(metadata={"surprise": 0.6, "preferences": confidential}),
    )
    assert result.verdict is Verdict.AUTH
    assert ReasonCode.confidentiality_sensitive_destination in result.reason_codes
    assert "confidentiality" in result.explanation.lower()
    _assert_no_raw_values(result)


def test_reversibility_blast_dominant_names_the_irreversibility():
    algebra = Algebra(
        capability=Capability.delete,
        target_class=TargetClass.internal,
        blast_radius=BlastRadius.mass,
        provenance=Provenance.trusted_instruction,
        classification_confidence=0.9,
    )
    cautious = PreferenceVector(confidentiality=0.0, reversibility=1.0, blast_radius=1.0)
    result = _engine().evaluate(
        _action(algebra, reversibility=Reversibility.low),
        EvalContext(mode="strict", metadata={"surprise": 0.8, "preferences": cautious}),
    )
    assert result.verdict is Verdict.AUTH
    assert ReasonCode.irreversible_high_blast in result.reason_codes
    assert "mass" in result.explanation  # the blast CLASS
    _assert_no_raw_values(result)


def test_unclassified_actions_carry_the_unclassified_code():
    result = _engine().evaluate(
        _action(Algebra()),  # zero-confidence default algebra
        EvalContext(mode="strict", metadata={"surprise": 1.0}),
    )
    assert result.verdict is Verdict.AUTH
    assert ReasonCode.unclassified_action in result.reason_codes
    _assert_no_raw_values(result)


def test_trifecta_explanation_names_the_cooccurrence():
    algebra = Algebra(
        target_class=TargetClass.secret,
        destination_class=DestinationClass.unknown_external,
        provenance=Provenance.untrusted_data,
        classification_confidence=0.9,
    )
    result = _engine().evaluate(_action(algebra), EvalContext(metadata={"surprise": 0.0}))
    assert result.verdict is Verdict.AUTH
    assert ReasonCode.lethal_trifecta in result.reason_codes
    assert "trifecta" in result.explanation.lower()
    _assert_no_raw_values(result)


def test_every_step_up_has_codes_and_a_one_line_explanation():
    # The GuardrailResult validator enforces this, but assert it end-to-end for
    # each driver shape used above.
    shapes = (
        Algebra(target_class=TargetClass.secret, classification_confidence=0.9),
        Algebra(),
        Algebra(
            target_class=TargetClass.sensitive,
            destination_class=DestinationClass.known_external,
            provenance=Provenance.mixed,
            classification_confidence=0.9,
        ),
    )
    for algebra in shapes:
        result = _engine().evaluate(
            _action(algebra), EvalContext(mode="strict", metadata={"surprise": 1.0})
        )
        if result.verdict is not Verdict.PASS:
            assert result.reason_codes
            assert result.explanation.strip()
            assert "\n" not in result.explanation.strip()
