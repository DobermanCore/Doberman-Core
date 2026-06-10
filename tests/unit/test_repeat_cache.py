"""Slice TG4.1 — the blocked-turn fingerprint cache.

Remembers *what was just blocked* without remembering the prompt: a per-entity,
short-TTL, LRU-bounded cache keyed by the turn's normalized HMAC fingerprint.
No raw text is ever stored — only the fingerprint key, the block reason, a count,
and an expiry. A semantically different prompt is a different fingerprint (a new
turn); only case/whitespace/punctuation-folded repeats match (folding happens
before the HMAC in ``normalize_turn``).
"""

from dataclasses import fields
from datetime import datetime, timedelta, timezone

import pytest

from doberman.models import ReasonCode
from doberman.turngate.repeat import (
    REPEAT_TTL_SECONDS,
    RepeatRecord,
    cache_size,
    clear_repeat_cache,
    disposition,
    lookup,
    note_denied,
    register_block,
)

_NOW = datetime(2026, 6, 10, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def _clean_cache():
    clear_repeat_cache()
    yield
    clear_repeat_cache()


def test_register_then_lookup_returns_the_record():
    register_block("ent", "hmac:abc", ReasonCode.secret_export, now=_NOW)
    record = lookup("ent", "hmac:abc", now=_NOW)
    assert record is not None
    assert record.block_reason is ReasonCode.secret_export
    assert record.count == 1


def test_lookup_of_a_different_fingerprint_misses():
    register_block("ent", "hmac:abc", ReasonCode.secret_export, now=_NOW)
    assert lookup("ent", "hmac:zzz", now=_NOW) is None


def test_cache_is_per_entity():
    register_block("ent-a", "hmac:abc", ReasonCode.authority_override, now=_NOW)
    assert lookup("ent-b", "hmac:abc", now=_NOW) is None


def test_ttl_expiry_prunes_the_record():
    register_block("ent", "hmac:abc", ReasonCode.secret_export, now=_NOW)
    later = _NOW + timedelta(seconds=REPEAT_TTL_SECONDS + 1)
    assert lookup("ent", "hmac:abc", now=later) is None


def test_disposition_challenges_first_then_locks_out():
    register_block("ent", "hmac:abc", ReasonCode.secret_export, now=_NOW)
    first = lookup("ent", "hmac:abc", now=_NOW)
    assert disposition(first) == "challenge"
    note_denied("ent", "hmac:abc", now=_NOW)
    second = lookup("ent", "hmac:abc", now=_NOW)
    assert disposition(second) == "lockout"


def test_record_stores_no_raw_text():
    register_block("ent", "hmac:abc", ReasonCode.secret_export, now=_NOW)
    field_names = {f.name for f in fields(RepeatRecord)}
    assert {"prompt", "text", "raw", "content"}.isdisjoint(field_names)
    assert field_names == {"block_reason", "count", "expiry"}


def test_cache_is_bounded():
    for i in range(2100):
        register_block("ent", f"hmac:{i}", ReasonCode.secret_export, now=_NOW)
    assert cache_size() <= 1024
