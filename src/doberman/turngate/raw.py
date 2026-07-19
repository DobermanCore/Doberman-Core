"""In-memory raw-turn carrier for the turn guardrails.

The :class:`~doberman.models.TurnObject` is redaction-safe and stores **no raw
prompt text**. But the Tier 0 signature scan and the Tier 1 heuristics need the
actual text to match against. Following the same pattern the action layer uses
for un-redacted arguments (``EvalContext.metadata['raw_arguments']``), the turn
gate passes the raw, origin-tagged text **in memory only** via
``ctx.metadata[RAW_TURN_KEY]`` — it is never logged or persisted.

A guardrail that receives a context without a :class:`RawTurn` (the redacted-only
path) simply abstains (PASS): it has nothing to scan and must never guess.
"""

from dataclasses import dataclass, field

from doberman.models import SegmentOrigin

#: ``EvalContext.metadata`` key under which the in-memory raw turn rides.
RAW_TURN_KEY = "raw_turn"

#: ``EvalContext.metadata`` key for the hook-precomputed stylometric p-value
#: (TG3.2). Absent ⇒ the prompt-style baseline is immature or unavailable and
#: the stylometric gate abstains. The same precompute-then-read pattern the
#: action path uses for ``metadata['surprise']``.
STYLE_PVALUE_KEY = "style_pvalue"


@dataclass(frozen=True)
class RawSegment:
    """One origin-tagged piece of raw turn text (in memory only, never stored)."""

    origin: SegmentOrigin
    text: str


@dataclass(frozen=True)
class RawTurn:
    """The full, origin-tagged raw text of a turn (in memory only)."""

    segments: tuple[RawSegment, ...] = field(default_factory=tuple)

    @property
    def full_text(self) -> str:
        return "\n".join(segment.text for segment in self.segments)


def raw_turn_from_ctx(ctx) -> "RawTurn | None":
    """Extract the in-memory :class:`RawTurn` from a context, or ``None``."""
    metadata = getattr(ctx, "metadata", None)
    if not isinstance(metadata, dict):
        return None
    raw = metadata.get(RAW_TURN_KEY)
    return raw if isinstance(raw, RawTurn) else None


def style_pvalue_from_ctx(ctx) -> float | None:
    """Extract the precomputed stylometric p-value, or ``None`` (abstain)."""
    metadata = getattr(ctx, "metadata", None)
    if not isinstance(metadata, dict):
        return None
    value = metadata.get(STYLE_PVALUE_KEY)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return max(0.0, min(1.0, float(value)))
    return None
