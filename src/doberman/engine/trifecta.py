"""The lethal-trifecta predicate — a pure, models-only leaf module.

Extracted verbatim from :mod:`doberman.engine.subjective` so the objective-rules
package (constructed by the host hooks on *every* tool call, in a cold-start CLI
process) can enforce the same deterministic floor without dragging in
subjective's heavy ML import chain (``engine.detectors`` / ``engine.registry`` →
numpy/scipy/river). This module imports ONLY :mod:`doberman.models`;
:mod:`doberman.engine.subjective` re-exports these names so existing callers that
``from doberman.engine.subjective import trifecta_fires`` keep working.
"""

from doberman.models import (
    Algebra,
    DestinationClass,
    Provenance,
    TargetClass,
)

#: The lethal-trifecta members (Willison 2025): private data + untrusted
#: content + external communication. NOT tunable by presets, weights, revealed
#: learning, scope tokens, or the step-up budget.
TRIFECTA_TARGETS = frozenset({TargetClass.sensitive, TargetClass.secret})
TRIFECTA_PROVENANCE = frozenset({Provenance.untrusted_data, Provenance.mixed})
TRIFECTA_DESTINATIONS = frozenset(
    {DestinationClass.known_external, DestinationClass.unknown_external}
)


def trifecta_fires(algebra: Algebra) -> bool:
    """True when the action carries the full lethal-trifecta co-occurrence."""
    return (
        algebra.target_class in TRIFECTA_TARGETS
        and algebra.provenance in TRIFECTA_PROVENANCE
        and algebra.destination_class in TRIFECTA_DESTINATIONS
    )
