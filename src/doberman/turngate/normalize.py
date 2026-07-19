"""Slice TG1.2 — normalize a raw turn into a TurnObject + an in-memory RawTurn.

Produces two things from one turn:

* a frozen, **redaction-safe** :class:`~doberman.models.TurnObject` — HMAC
  fingerprints + coarse features only, safe to persist; and
* an in-memory :class:`~doberman.turngate.raw.RawTurn` — the raw, origin-tagged
  text the signature scan needs, which is **never** logged or persisted.

The prompt fingerprint folds case / whitespace / punctuation **before** the HMAC,
so case- and spacing-variant resubmissions share a fingerprint (the repeat cache
matches them) while a semantic edit is a genuinely new turn.
"""

import re

from doberman.models import (
    ApparentIntent,
    ContentSegment,
    SegmentOrigin,
    TurnObject,
)
from doberman.storage.fingerprint import fingerprint
from doberman.turngate.raw import RawSegment, RawTurn

_WS = re.compile(r"\s+")
_NON_ALNUM = re.compile(r"[^a-z0-9 ]+")

_CREDENTIAL = re.compile(
    r"\b(api[ _-]?key|secret|token|password|credential|\.env|private key|ssh key|access key)\b",
    re.IGNORECASE,
)
_DESTRUCTIVE = re.compile(
    r"\b(rm -rf|delete|drop table|wipe|format|truncate|destroy|force[- ]push|shred)\b",
    re.IGNORECASE,
)
_EXTERNAL = re.compile(
    r"\b(send|upload|post|exfiltrate|email|curl|webhook)\b|https?://", re.IGNORECASE
)
_ENCODED = re.compile(r"[A-Za-z0-9+/_-]{40,}|\bxn--[a-z0-9-]+", re.IGNORECASE)

#: Cap on how much raw text the *categorizing* scans below run over (the
#: encoded-carrier flag and the per-segment fold): mirrors signatures.py's Tier 0
#: cap so a multi-megabyte hostile paste can't make normalization itself run
#: unbounded. The turn-level `id`/`prompt_fingerprint` still hash the FULL text —
#: TG4's repeat-after-block cache correctness depends on that — only these
#: categorizing scans are capped.
_MAX_SCAN_CHARS = 200_000


def _fold(text: str) -> str:
    """Lower-case, collapse whitespace, and strip punctuation for the fingerprint."""
    return _NON_ALNUM.sub("", _WS.sub(" ", text.lower())).strip()


def _length_bucket(n: int) -> str:
    if n < 80:
        return "short"
    if n < 800:
        return "medium"
    if n < 8000:
        return "long"
    return "huge"


def _infer_intent(text: str) -> ApparentIntent:
    """Coarse apparent-intent inference (sensitive classes take precedence)."""
    if _CREDENTIAL.search(text):
        return ApparentIntent.credential_access
    if _DESTRUCTIVE.search(text):
        return ApparentIntent.destructive
    if _EXTERNAL.search(text):
        return ApparentIntent.external_send
    return ApparentIntent.benign


def normalize_turn(
    prompt: str,
    *,
    entity_id: str,
    ts,
    segments: list[tuple[SegmentOrigin, str]] | None = None,
) -> tuple[TurnObject, RawTurn]:
    """Build the redacted :class:`TurnObject` and the in-memory :class:`RawTurn`.

    With no explicit ``segments`` the whole prompt is one ``typed`` segment.
    Never raises on odd input within reason — callers (the hook) still wrap it in
    a fail-toward-human guard.
    """
    raw_pairs: list[tuple[SegmentOrigin, str]] = (
        list(segments) if segments else [(SegmentOrigin.typed, prompt)]
    )
    raw = RawTurn(segments=tuple(RawSegment(origin=o, text=t) for o, t in raw_pairs))
    full_text = raw.full_text

    content_segments = tuple(
        ContentSegment(
            origin=o,
            fingerprint=fingerprint(_fold(t[:_MAX_SCAN_CHARS])),
            flags=(["encoded"] if _ENCODED.search(t[:_MAX_SCAN_CHARS]) else []),
        )
        for o, t in raw_pairs
    )

    features = {
        "length_bucket": _length_bucket(len(full_text)),
        "n_segments": len(raw_pairs),
        "has_untrusted": any(o.is_untrusted for o, _ in raw_pairs),
        "encoding_flag": bool(_ENCODED.search(full_text[:_MAX_SCAN_CHARS])),
    }

    turn = TurnObject(
        id=fingerprint(f"{entity_id}|{ts}|{_fold(full_text)}"),
        ts=ts,
        entity_id=entity_id,
        prompt_fingerprint=fingerprint(_fold(full_text)),
        prompt_features=features,
        segments=content_segments,
        apparent_intent=_infer_intent(full_text),
    )
    return turn, raw
