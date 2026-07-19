"""Slice TG3.3 — publish a released turn's signals to the action stage.

The adapter half of the handoff: after :func:`~doberman.turngate.hook.gate_turn`
releases a turn, this module builds the redaction-safe
:class:`~doberman.subjective.score.TurnContext` and attaches it to the entity's
session via the core-side store (``doberman.subjective.score``). The import
direction respects the architecture: this adapter imports the policy core; the
core never imports any invocation adapter.

What rides along:

* the TG3.2 stylometric **p-value** (``None`` when the prompt baseline was
  immature/unavailable);
* the turn decision's **reason codes** as flags — including TG3.2's
  tag-and-pass code on a PASS decision (the sub-threshold observation) and
  the Tier 1 reasons of a human-approved AUTH;
* the **paste-lineage marker** (:data:`~doberman.subjective.score.UNTRUSTED_PASTE_FLAG`)
  when an untrusted (pasted / tool-fetched) segment carried flags, or the turn
  was heuristic-flagged and contained untrusted content — formalizing the
  SL2.2 ``untrusted_data`` source for follow-on actions.

A turn that was NOT released publishes nothing: it never reached the model, so
no actions trace to it (and a prior suspicious context is deliberately not
cleared by a blocked attempt). Publishing is best-effort and never raises into
the gate path.
"""

import logging

from doberman.models import Decision, TurnObject
from doberman.subjective.score import (
    UNTRUSTED_PASTE_FLAG,
    TurnContext,
    attach_turn_context,
)

logger = logging.getLogger("doberman.turngate.handoff")


def _flags(turn: TurnObject, decision: Decision) -> tuple[str, ...]:
    """The turn's signal flags: decision reason codes + the paste-lineage marker."""
    flags = list(dict.fromkeys(code.value for code in decision.reason_codes))
    flagged_paste = any(segment.origin.is_untrusted and segment.flags for segment in turn.segments)
    if flagged_paste or (flags and turn.has_untrusted_segment):
        flags.append(UNTRUSTED_PASTE_FLAG)
    return tuple(flags)


def publish_turn_context(
    turn: TurnObject,
    decision: Decision,
    *,
    style_pvalue: float | None,
    released: bool,
) -> None:
    """Attach a released turn's signals to its entity (best-effort, never raises)."""
    if not released:
        return
    try:
        attach_turn_context(
            turn.entity_id,
            TurnContext(style_pvalue=style_pvalue, flags=_flags(turn, decision)),
        )
    except Exception:  # noqa: BLE001 — the handoff must never break the gate path
        logger.warning("turn-context publish failed (turn %s); continuing", turn.id[:12])
