"""Slice TG1.1 — the `TurnObject` (a redaction-safe representation of a turn).

The turn gate (F11) is the decision engine consulted at a *pre-inference* hook,
on a turn (user prompt + attached/pasted/tool-fetched content) rather than a
tool call. Like the `SecurityObject`, the `TurnObject` is **frozen** and stores
**no raw prompt text** — only HMAC fingerprints, coarse features, and the
*origin* (typed / pasted / tool_fetched) of each content segment, which is the
provenance analogue at turn level (pasted/tool-fetched is untrusted by
construction).
"""

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from doberman.models import (
    ApparentIntent,
    ContentSegment,
    SegmentOrigin,
    TurnObject,
)

_TS = datetime(2026, 6, 10, tzinfo=timezone.utc)


def _segment(origin=SegmentOrigin.typed, fingerprint="hmac:abc", flags=()):
    return ContentSegment(origin=origin, fingerprint=fingerprint, flags=list(flags))


def test_turn_object_builds_with_minimal_fields():
    turn = TurnObject(
        id="turn-1",
        ts=_TS,
        entity_id="ent-1",
        prompt_fingerprint="hmac:deadbeef",
    )
    assert turn.id == "turn-1"
    assert turn.apparent_intent is ApparentIntent.unknown
    assert turn.segments == []
    assert turn.prompt_features == {}


def test_turn_object_is_frozen():
    turn = TurnObject(id="t", ts=_TS, entity_id="e", prompt_fingerprint="hmac:x")
    with pytest.raises(ValidationError):
        turn.id = "mutated"


def test_no_field_can_hold_raw_prompt_text():
    # Structural guarantee: the schema exposes only fingerprints/features/flags,
    # never a raw-text field. If someone adds one, this test must fail.
    forbidden = {"prompt", "prompt_text", "raw_prompt", "text", "content", "raw"}
    assert forbidden.isdisjoint(set(TurnObject.model_fields))
    assert forbidden.isdisjoint(set(ContentSegment.model_fields))


def test_segment_origin_tagging_on_a_mixed_turn():
    turn = TurnObject(
        id="t",
        ts=_TS,
        entity_id="e",
        prompt_fingerprint="hmac:x",
        segments=[
            _segment(SegmentOrigin.typed),
            _segment(SegmentOrigin.pasted),
            _segment(SegmentOrigin.tool_fetched),
        ],
    )
    origins = [s.origin for s in turn.segments]
    assert origins == [SegmentOrigin.typed, SegmentOrigin.pasted, SegmentOrigin.tool_fetched]


def test_pasted_and_tool_fetched_segments_are_untrusted():
    assert SegmentOrigin.pasted.is_untrusted
    assert SegmentOrigin.tool_fetched.is_untrusted
    assert not SegmentOrigin.typed.is_untrusted


def test_turn_with_only_pasted_content_is_valid():
    turn = TurnObject(
        id="t",
        ts=_TS,
        entity_id="e",
        prompt_fingerprint="hmac:x",
        segments=[_segment(SegmentOrigin.pasted)],
    )
    assert turn.has_untrusted_segment


def test_empty_prompt_is_valid_and_carries_no_untrusted_segment():
    turn = TurnObject(id="t", ts=_TS, entity_id="e", prompt_fingerprint="hmac:empty")
    assert not turn.has_untrusted_segment


def test_unknown_segment_origin_is_rejected_at_the_boundary():
    with pytest.raises(ValidationError):
        ContentSegment(origin="smuggled", fingerprint="hmac:x")


def test_apparent_intent_enum_has_sensitive_classes():
    # Tier-1 stylometric gating fires only when intent touches a sensitive
    # capability — those classes must exist and be flaggable.
    assert ApparentIntent.credential_access.is_sensitive
    assert ApparentIntent.destructive.is_sensitive
    assert ApparentIntent.external_send.is_sensitive
    assert not ApparentIntent.benign.is_sensitive
    assert not ApparentIntent.unknown.is_sensitive
