"""Domain-adapter seam (SL3.1): optional, refine-only algebra sharpeners.

An :class:`AlgebraAdapter` understands a specific application type (a CRM, a
mail stack, an IDE…) and can *sharpen* the generic classification for calls it
recognizes. Adapters are discovered via the entry-point group
``doberman.algebra_adapters`` — core never imports one by name — and they run
AFTER the generic inference layer (SL2).

SECURITY — the clamp is the contract: an adapter's output is folded against the
generic result so it can only ever RAISE a class up the severity orders (or
raise confidence). It can never lower ``target_class`` below the generic floor,
never launder ``provenance`` toward ``trusted_instruction``, and an adapter
that raises or returns garbage is ignored (the generic result stands — fail
safe). Removing every adapter changes *precision*, never *coverage*.

This module is policy core: it must never import ``doberman.proxy``.
"""

import logging
from collections.abc import Sequence
from typing import Any, Protocol, runtime_checkable

from doberman.models import (
    BLAST_RADIUS_ORDER,
    DESTINATION_CLASS_ORDER,
    PROVENANCE_ORDER,
    TARGET_CLASS_ORDER,
    Algebra,
)
from doberman.subjective.infer import CAPABILITY_SEVERITY

logger = logging.getLogger("doberman.subjective.adapters")


@runtime_checkable
class AlgebraAdapter(Protocol):
    """A refine-only sharpener for the action algebra.

    ``refine`` receives the current (generic or previously-refined) algebra and
    a copy of the raw call ``{"tool_name": ..., "arguments": ...}`` and returns
    a refined :class:`Algebra`. An adapter that does not recognize the call
    should return its input unchanged. Whatever it returns is CLAMPED against
    the input — refinement can only raise classes/confidence, by construction.
    """

    def refine(self, algebra: Algebra, raw_call: dict[str, Any]) -> Algebra: ...


def _looks_like_algebra_adapter(candidate: object) -> bool:
    """Structural check used by the registry (adapters are not Guardrails)."""
    return callable(getattr(candidate, "refine", None))


def clamp_refinement(generic: Algebra, refined: object) -> Algebra:
    """Fold an adapter's output against the generic floor — raise-only.

    Every ordered dimension takes the MORE severe of the two classes (so a
    hostile or buggy adapter cannot lower ``target_class``, soften the blast
    radius, or move ``provenance`` toward ``trusted_instruction``), and
    confidence takes the max. A non-:class:`Algebra` return leaves the generic
    result untouched.
    """
    if not isinstance(refined, Algebra):
        return generic

    def _max_by(order: dict, a, b):
        return a if order[a] >= order[b] else b

    return Algebra(
        capability=_max_by(CAPABILITY_SEVERITY, generic.capability, refined.capability),
        target_class=_max_by(TARGET_CLASS_ORDER, generic.target_class, refined.target_class),
        destination_class=_max_by(
            DESTINATION_CLASS_ORDER, generic.destination_class, refined.destination_class
        ),
        blast_radius=_max_by(BLAST_RADIUS_ORDER, generic.blast_radius, refined.blast_radius),
        provenance=_max_by(PROVENANCE_ORDER, generic.provenance, refined.provenance),
        classification_confidence=max(
            generic.classification_confidence, refined.classification_confidence
        ),
    )


def apply_adapters(
    algebra: Algebra,
    raw_call: dict[str, Any] | None = None,
    *,
    adapters: Sequence[AlgebraAdapter] | None = None,
) -> Algebra:
    """Run every registered adapter over ``algebra``, clamped raise-only.

    Adapters fold sequentially, each clamped against the running result, so
    when several adapters claim the same call the STRICTEST classification
    wins. An adapter that raises is logged and skipped (the prior result
    stands). With nothing installed this returns ``algebra`` unchanged —
    coverage never depends on an adapter.
    """
    if adapters is None:
        from doberman.engine.registry import discover_algebra_adapters

        adapters = discover_algebra_adapters()

    result = algebra
    for adapter in adapters:
        try:
            refined = adapter.refine(result, dict(raw_call or {}))
        except Exception:  # noqa: BLE001 — a broken adapter must never break inference
            logger.warning(
                "algebra adapter %s raised; keeping the generic result", type(adapter).__name__
            )
            continue
        result = clamp_refinement(result, refined)
    return result
