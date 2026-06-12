"""Built-in subjective detectors (Feature 9 seam).

Each detector is a pure ``Guardrail`` — ``evaluate(action, ctx) -> GuardrailResult``
— that runs in the :class:`~doberman.engine.subjective.SubjectiveGuardrail`. Like
the built-in objective rules, they are isolated and reduced raise-only, so a
detector can only ever *add* risk; the subjective layer also cannot hard-block
(the execution rule clamps a subjective BLOCK to AUTH).

This package contains ONLY basic, universally-safe detectors. Advanced /
behavioral (UEBA-style) detection lives in the enterprise edition and attaches
through the ``doberman.detectors`` entry-point registry — core never imports it.
"""

from doberman.engine.detectors.token_channels import TokenChannelDetector

#: The built-in detector set, in a stable order. ``SubjectiveGuardrail``
#: instantiates these with their defaults; they abstain (PASS) on benign input.
BUILTIN_DETECTOR_TYPES = (TokenChannelDetector,)

__all__ = [
    "BUILTIN_DETECTOR_TYPES",
    "TokenChannelDetector",
]
