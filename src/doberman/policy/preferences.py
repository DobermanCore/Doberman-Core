"""The preference vector — the "care" axis of the subjective layer (SL5).

What a deployment cares about is an OPERATOR value, not an application
feature, so it gets its own small, fixed vector of weights that applies
identically across every application type:

* ``confidentiality`` — escalate on sensitive/secret targets + external
  destinations.
* ``reversibility`` — escalate on hard-to-undo actions.
* ``interruption_tolerance`` — how much asking the operator tolerates (the
  approval-fatigue dial; HIGH tolerance = more willing to be asked).
* ``blast_radius`` — escalate on high-volume actions.

The four security strength modes (F6) become NAMED PRESETS over this vector;
operators can also express coherent mixed stances ("strict on
confidentiality, relaxed on reversibility").

SECURITY: weights modulate **subjective step-up propensity only**. The
objective hard-block floor (``FLOOR_HARD_BLOCKS``) lives in the objective
layer and is untouched by any weight — even all-minimal weights keep every
hard block. The SL7 lethal-trifecta floor is likewise independent of this
vector. This module is policy core: it must never import ``doberman.proxy``.
"""

from dataclasses import dataclass, fields, replace
from typing import Any

from doberman.models import (
    Algebra,
    BlastRadius,
    DestinationClass,
    Reversibility,
    TargetClass,
)
from doberman.policy.modes import SecurityMode, resolve_mode

#: The vector's fixed dimensions (a versioned commitment — adding one is a
#: core schema change, never an adapter/plugin change).
DIMENSIONS = ("confidentiality", "reversibility", "interruption_tolerance", "blast_radius")


@dataclass(frozen=True)
class PreferenceVector:
    """Operator-value weights, each in [0, 1] (immutable; edits return copies)."""

    confidentiality: float = 0.5
    reversibility: float = 0.5
    interruption_tolerance: float = 0.5
    blast_radius: float = 0.5

    def __post_init__(self) -> None:
        for field in fields(self):
            value = getattr(self, field.name)
            if not isinstance(value, (int, float)) or not 0.0 <= float(value) <= 1.0:
                raise ValueError(
                    f"preference weight {field.name!r} must be in [0, 1], got {value!r}"
                )

    def with_weight(self, dimension: str, value: float) -> "PreferenceVector":
        """Return a copy with one weight changed (unknown dimension → KeyError)."""
        if dimension not in DIMENSIONS:
            raise KeyError(
                f"unknown preference dimension {dimension!r}; valid: {', '.join(DIMENSIONS)}"
            )
        return replace(self, **{dimension: value})

    def to_mapping(self) -> dict[str, float]:
        return {name: float(getattr(self, name)) for name in DIMENSIONS}

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> "PreferenceVector":
        """Build from a mapping; unknown keys are ignored, bad values raise."""
        kwargs = {name: float(data[name]) for name in DIMENSIONS if name in data}
        return cls(**kwargs)


#: The four strength modes as named presets over the vector. Stricter modes
#: weight every concern higher AND tolerate more interruption.
PRESETS: dict[SecurityMode, PreferenceVector] = {
    SecurityMode.light: PreferenceVector(0.2, 0.2, 0.1, 0.2),
    SecurityMode.balanced: PreferenceVector(0.5, 0.5, 0.5, 0.5),
    SecurityMode.strict: PreferenceVector(0.7, 0.7, 0.7, 0.7),
    SecurityMode.paranoid: PreferenceVector(0.9, 0.9, 0.9, 0.9),
}

if set(PRESETS) != set(SecurityMode):  # pragma: no cover — import-time guard
    raise RuntimeError("PRESETS must cover every SecurityMode member")


def vector_for(mode: str | SecurityMode) -> PreferenceVector:
    """The preset vector for ``mode``; unknown modes fall back to the STRICTEST
    preset (fail toward more authentication, never less)."""
    try:
        return PRESETS[resolve_mode(mode)]
    except ValueError:
        return PRESETS[SecurityMode.paranoid]


def preset_name(vector: PreferenceVector) -> str | None:
    """The mode name this vector exactly matches, or ``None`` for a custom mix."""
    for mode, preset in PRESETS.items():
        if preset == vector:
            return mode.value
    return None


# --- the care term (SL5.2) ------------------------------------------------------

#: Per-dimension signal strengths read off the algebra (each in [0, 1]).
_BLAST_SIGNAL: dict[BlastRadius, float] = {
    BlastRadius.single: 0.0,
    BlastRadius.few: 0.2,
    BlastRadius.unknown: 0.4,
    BlastRadius.many: 0.7,
    BlastRadius.mass: 1.0,
}
_REVERSIBILITY_SIGNAL: dict[Reversibility, float] = {
    Reversibility.high: 0.0,  # trivially undone
    Reversibility.medium: 0.5,
    Reversibility.low: 1.0,  # effectively irreversible
}

_EXTERNAL = frozenset({DestinationClass.known_external, DestinationClass.unknown_external})
_CONFIDENTIAL_TARGETS = frozenset({TargetClass.sensitive, TargetClass.secret})

# Threshold scaling by interruption tolerance: tolerance 0.5 is neutral; high
# tolerance lowers the effective threshold (more asks), low tolerance raises it
# (fewer asks) — bounded so no tolerance setting can disable a strict floor or
# push the threshold below an actionable minimum.
THRESHOLD_FLOOR = 0.2
THRESHOLD_CEIL = 1.1  # above any score in [0,1]: effectively disabled (Light)


def _confidentiality_signal(algebra: Algebra) -> float:
    if algebra.target_class in _CONFIDENTIAL_TARGETS or algebra.destination_class in _EXTERNAL:
        return 1.0
    if algebra.target_class is TargetClass.unknown:
        return 0.5
    return 0.0


def care(vector: PreferenceVector, algebra: Algebra, reversibility: Reversibility) -> float:
    """The care term in [0, 1]: how much THIS deployment wants to be involved.

    Each algebra dimension's signal is weighted by the matching preference
    weight; conflicting signals resolve to the MAX contribution (the strongest
    concern wins, contributions never cancel). ``interruption_tolerance`` is
    deliberately not part of this term — it scales the step-up threshold via
    :func:`effective_threshold` instead.
    """
    contributions = (
        vector.confidentiality * _confidentiality_signal(algebra),
        vector.reversibility * _REVERSIBILITY_SIGNAL[reversibility],
        vector.blast_radius * _BLAST_SIGNAL[algebra.blast_radius],
    )
    return max(0.0, min(1.0, max(contributions)))


def effective_threshold(base: float, vector: PreferenceVector) -> float:
    """Scale a mode's base step-up threshold by the interruption tolerance.

    Tolerance 0.5 leaves the base unchanged; 1.0 multiplies by 0.5 (asks
    sooner); 0.0 multiplies by 1.5 (asks later). Clamped to
    [:data:`THRESHOLD_FLOOR`, :data:`THRESHOLD_CEIL`] so tuning can reduce
    *subjective* asks but can never push the threshold beyond reach of a
    maximal score except where the mode itself disables the step-up (Light's
    base is already above 1).
    """
    scaled = base * (1.5 - vector.interruption_tolerance)
    return max(THRESHOLD_FLOOR, min(THRESHOLD_CEIL, scaled))
