"""Turn-context handoff into action scoring (TG3.3) — raise-only by construction.

The turn gate observes things the action stage cannot see (prompt style,
heuristic tells, paste lineage). Sub-threshold observations must not vanish:
each released turn publishes a per-entity :class:`TurnContext` here, and the
action stage consumes it two ways —

* :func:`raised_surprise` adds a **bounded, non-negative** contribution to the
  SL4 surprise term — it can push surprise UP toward a step-up, never down;
* :func:`inherit_turn_provenance` raises the provenance of actions tracing to
  a flagged pasted segment to ``untrusted_data`` (formalizing the SL2.2 source)
  — which is what makes the lethal-trifecta floor reachable for them.

Direction of imports keeps the boundaries clean: this module lives in the
policy core and imports **only models**; the turn gate (an invocation adapter)
imports *it* to publish, and the proxy imports it to consume. The policy core
never references either adapter.

Safety properties:

* **Raise-only, structurally.** The contribution is clamped to ``[0, CAP]``;
  ``raised_surprise`` returns ``min(1, surprise + contribution)`` and can never
  return less than its input. Provenance inheritance only ever moves
  ``trusted_instruction`` → ``untrusted_data``; an already-untrusted/mixed
  class is left alone.
* **Failure = status quo.** Any error reading the store leaves the surprise
  and the action exactly as they were — the handoff is an extra signal, and
  its absence degrades to pre-TG3.3 behavior (it can never crash the path).
* **The store is per-entity and process-lifetime** (like the in-process HST):
  each released turn REPLACES the entity's context — the context describes the
  *current* turn, the one actions now trace to. A blocked turn publishes
  nothing (it never reached the model, so nothing traces to it).
"""

import logging
from dataclasses import dataclass, field

from doberman.models import Provenance, SecurityObject

logger = logging.getLogger("doberman.subjective.score")

#: Flag marking a turn whose untrusted (pasted / tool-fetched) content carried
#: flags — the paste lineage that makes follow-on actions inherit
#: ``provenance: untrusted_data``.
UNTRUSTED_PASTE_FLAG = "untrusted_paste"

#: Per-flag surprise contribution, and the cap on the flags component.
FLAG_WEIGHT = 0.1
FLAGS_CAP = 0.2

#: Style component: p-values BELOW this reference contribute, scaled linearly
#: up to :data:`STYLE_WEIGHT` as p → 0. A typical-or-calmer style (p ≥ 0.5)
#: contributes exactly nothing — a clean turn has no effect.
STYLE_REF = 0.5
STYLE_WEIGHT = 0.15

#: Hard cap on the total turn contribution — turn signals bias the action
#: stage toward a step-up; they never dominate the score on their own.
TURN_CONTRIBUTION_CAP = 0.3


@dataclass(frozen=True)
class TurnContext:
    """The redaction-safe turn signals that ride into action scoring.

    ``style_pvalue`` is the TG3.2 empirical-CDF p-value (``None`` when the
    prompt baseline was immature/unavailable); ``flags`` are the turn
    decision's reason codes plus the paste-lineage marker — classes only,
    never text.
    """

    style_pvalue: float | None = None
    flags: tuple[str, ...] = field(default_factory=tuple)


#: In-process per-entity contexts (process-lifetime, like the HST models).
_TURN_CONTEXTS: dict[str, TurnContext] = {}


def attach_turn_context(entity_id: str, context: TurnContext) -> None:
    """Publish the entity's current turn context (replaces the previous one)."""
    _TURN_CONTEXTS[entity_id] = context


def turn_context_for(entity_id: str) -> TurnContext | None:
    """The entity's current turn context, or ``None``."""
    return _TURN_CONTEXTS.get(entity_id)


def clear_turn_contexts(entity_id: str | None = None) -> None:
    """Drop one entity's context, or all (tests / session teardown)."""
    if entity_id is None:
        _TURN_CONTEXTS.clear()
    else:
        _TURN_CONTEXTS.pop(entity_id, None)


def turn_surprise_contribution(context: TurnContext | None) -> float:
    """The bounded, NON-NEGATIVE surprise contribution of a turn context.

    ``flags`` each add :data:`FLAG_WEIGHT` (capped at :data:`FLAGS_CAP`); a
    sub-typical style p-value adds up to :data:`STYLE_WEIGHT` as it approaches
    zero. The total is clamped to ``[0, TURN_CONTRIBUTION_CAP]`` — there is no
    code path that returns a negative value.
    """
    if context is None:
        return 0.0
    flags_term = min(FLAGS_CAP, FLAG_WEIGHT * len(context.flags))
    style_term = 0.0
    if context.style_pvalue is not None:
        p = max(0.0, min(1.0, float(context.style_pvalue)))
        style_term = max(0.0, (STYLE_REF - p) / STYLE_REF) * STYLE_WEIGHT
    return max(0.0, min(TURN_CONTRIBUTION_CAP, flags_term + style_term))


def raised_surprise(surprise: float, entity_id: str) -> float:
    """Apply the entity's turn contribution to a surprise score — raise-only.

    Returns ``min(1, surprise + contribution)``; never less than the input.
    Any failure returns the input untouched (status quo, never a crash and
    never a decrease).
    """
    try:
        contribution = turn_surprise_contribution(turn_context_for(entity_id))
    except Exception:  # noqa: BLE001 — a handoff failure degrades to the status quo
        logger.warning("turn-context read failed (entity %s); continuing", entity_id[:12])
        return surprise
    return min(1.0, max(surprise, surprise + contribution))


def inherit_turn_provenance(action: SecurityObject, entity_id: str) -> SecurityObject:
    """Raise the action's provenance when its turn carried flagged pasted content.

    ``trusted_instruction`` → ``untrusted_data`` ONLY when the entity's current
    turn context carries :data:`UNTRUSTED_PASTE_FLAG`; any other provenance
    class (already untrusted, mixed) is left untouched — this can tighten the
    classification, never relax it. Any failure returns the action unchanged.
    """
    try:
        context = turn_context_for(entity_id)
        if context is None or UNTRUSTED_PASTE_FLAG not in context.flags:
            return action
        if action.algebra.provenance is not Provenance.trusted_instruction:
            return action
        algebra = action.algebra.model_copy(update={"provenance": Provenance.untrusted_data})
        return action.model_copy(update={"algebra": algebra})
    except Exception:  # noqa: BLE001 — a handoff failure degrades to the status quo
        logger.warning("turn-provenance inherit failed (entity %s); continuing", entity_id[:12])
        return action
