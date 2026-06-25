"""Slice SL1.1 — the universal action-algebra sub-model on SecurityObject.

Load-bearing properties: the algebra is frozen (no downward mutation), its
defaults are the CONSERVATIVE members (unknown / zero confidence — never
benign), unseen enum values are rejected at the schema boundary, and adding it
is purely additive (existing SecurityObject construction is untouched).
"""

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from doberman.models import (
    ALGEBRA_VERSION,
    BLAST_RADIUS_ORDER,
    DESTINATION_CLASS_ORDER,
    PROVENANCE_ORDER,
    TARGET_CLASS_ORDER,
    ActionType,
    Algebra,
    BlastRadius,
    Capability,
    DestinationClass,
    Provenance,
    SecurityObject,
    TargetClass,
)

_NOW = datetime(2026, 6, 9, tzinfo=timezone.utc)


def _action(**kw):
    return SecurityObject(
        id="alg-1",
        ts=_NOW,
        agent_role="frontend",
        action_type=ActionType.file_write,
        tool_name="fs_write",
        target="src/app.py",
        **kw,
    )


def test_valid_explicit_build():
    algebra = Algebra(
        capability=Capability.send,
        target_class=TargetClass.sensitive,
        destination_class=DestinationClass.unknown_external,
        blast_radius=BlastRadius.many,
        provenance=Provenance.untrusted_data,
        classification_confidence=0.9,
    )
    assert algebra.capability is Capability.send
    assert algebra.classification_confidence == 0.9


def test_defaults_are_conservative_never_benign():
    algebra = Algebra()
    assert algebra.capability is Capability.other
    assert algebra.target_class is TargetClass.unknown
    assert algebra.destination_class is DestinationClass.none
    assert algebra.blast_radius is BlastRadius.unknown
    assert algebra.provenance is Provenance.unknown
    assert algebra.classification_confidence == 0.0
    # The conservative members never resolve to the most benign tier.
    assert TARGET_CLASS_ORDER[algebra.target_class] > TARGET_CLASS_ORDER[TargetClass.public]
    assert BLAST_RADIUS_ORDER[algebra.blast_radius] > BLAST_RADIUS_ORDER[BlastRadius.single]
    assert PROVENANCE_ORDER[algebra.provenance] > PROVENANCE_ORDER[Provenance.trusted_instruction]


def test_algebra_is_frozen():
    algebra = Algebra()
    with pytest.raises(ValidationError):
        algebra.target_class = TargetClass.public  # type: ignore[misc]


def test_unknown_enum_value_rejected_at_boundary():
    with pytest.raises(ValidationError):
        Algebra(capability="self_destruct")
    with pytest.raises(ValidationError):
        Algebra(target_class="totally_safe")
    with pytest.raises(ValidationError):
        Algebra(provenance="definitely_trusted")


def test_confidence_must_be_in_unit_interval():
    with pytest.raises(ValidationError):
        Algebra(classification_confidence=1.5)
    with pytest.raises(ValidationError):
        Algebra(classification_confidence=-0.1)


def test_security_object_carries_conservative_default_algebra():
    # Additive change: existing construction sites need no algebra argument.
    action = _action()
    assert action.algebra == Algebra()
    assert action.algebra.classification_confidence == 0.0


def test_algebra_attaches_via_model_copy_not_mutation():
    # The SL9 mechanism: inference produces a NEW object; the original is frozen.
    action = _action()
    refined = action.model_copy(
        update={"algebra": Algebra(capability=Capability.mutate, classification_confidence=0.8)}
    )
    assert refined.algebra.capability is Capability.mutate
    assert action.algebra.capability is Capability.other
    with pytest.raises(ValidationError):
        action.algebra = Algebra()  # type: ignore[misc]


def test_order_maps_cover_every_member_and_version_is_set():
    assert set(TARGET_CLASS_ORDER) == set(TargetClass)
    assert set(DESTINATION_CLASS_ORDER) == set(DestinationClass)
    assert set(BLAST_RADIUS_ORDER) == set(BlastRadius)
    assert set(PROVENANCE_ORDER) == set(Provenance)
    assert ALGEBRA_VERSION == 1
