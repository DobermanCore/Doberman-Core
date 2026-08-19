"""Slice TG4.1 + TG4.2 — repeat-after-block escalation (intent-aware recovery).

A near-match resubmission of a just-blocked turn is treated as evidence of
deliberate human intent and routed to a challenge instead of being re-blocked —
the structured escape hatch that justifies Tier 0's breadth. This converts the
worst input-filter failure mode (a user hammering a false positive with no
recourse) into a deferral to the principal.

* **The cache (TG4.1)** is per-entity, short-TTL, and LRU-bounded, keyed by the
  turn's *normalized* HMAC fingerprint (folding happens before the HMAC in
  ``normalize_turn``, so case/whitespace/punctuation repeats match but a
  semantic edit is a new turn). It stores **no raw text** — only the fingerprint
  key, the block reason, a count, and an expiry.
* **The escalation (TG4.2)** routes a repeat to the F7 challenge with proof
  scaled to the block reason (a Tier 0 *signature* block → ``two_factor``: a
  replay loop cannot produce a TOTP, and approving a just-blocked turn is a
  one-shot weakening matching the F10 2FA precedent), restating the original
  block reason and matched pattern. Approval is **single-use** (the caller clears
  the record); a denial increments the count; the third attempt within the TTL
  **locks out** without a challenge (anti-fatigue / anti-bruteforce).

This module is an adapter (it may import auth/engine/models); it never imports
``doberman.proxy``. The cache is process-lifetime and never persisted.
"""

from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone

from doberman.auth.challenge import AuthResult, AuthTier, Prompter, run_auth_challenge
from doberman.models import (
    ActionType,
    Decision,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    TurnObject,
    Verdict,
)

#: How long a blocked-turn fingerprint stays eligible for the escape hatch.
REPEAT_TTL_SECONDS = 600
#: A record at/above this count locks out (the 1st block + 1 denied challenge).
LOCKOUT_AT_COUNT = 2
#: Hard bound on cache size (LRU by insertion order).
MAX_CACHE = 1024

#: Block reasons that came from a Tier 0 *signature* (proof = two_factor).
_TIER0_REASONS: frozenset[ReasonCode] = frozenset(
    {
        ReasonCode.instruction_nullification,
        ReasonCode.authority_override,
        ReasonCode.secret_export,
        ReasonCode.encoded_payload,
        ReasonCode.indirect_injection,
    }
)

#: Human pattern labels for restating a block reason in the challenge prompt.
_REASON_LABEL: dict[ReasonCode, str] = {
    ReasonCode.instruction_nullification: "instruction-nullification pattern",
    ReasonCode.authority_override: "authority-override pattern",
    ReasonCode.secret_export: "credential-export pattern",
    ReasonCode.encoded_payload: "encoded-payload carrier",
    ReasonCode.indirect_injection: "indirect-injection (untrusted content) pattern",
}


@dataclass(frozen=True)
class RepeatRecord:
    """What was blocked, without the prompt: reason + attempt count + expiry."""

    block_reason: ReasonCode
    count: int
    expiry: datetime


#: (entity_id, fingerprint) → record. Process-lifetime; never persisted.
_CACHE: dict[tuple[str, str], RepeatRecord] = {}


def clear_repeat_cache() -> None:
    """Drop every cached record (tests / session teardown)."""
    _CACHE.clear()


def cache_size() -> int:
    return len(_CACHE)


def _now(now: datetime | None) -> datetime:
    return now or datetime.now(timezone.utc)


def register_block(
    entity_id: str, fingerprint: str, block_reason: ReasonCode, *, now: datetime | None = None
) -> RepeatRecord:
    """Record a fresh turn-gate block (count 1) and bound the cache (LRU)."""
    when = _now(now)
    record = RepeatRecord(
        block_reason=block_reason, count=1, expiry=when + timedelta(seconds=REPEAT_TTL_SECONDS)
    )
    key = (entity_id, fingerprint)
    _CACHE.pop(key, None)  # re-insert at the end (most-recent)
    _CACHE[key] = record
    while len(_CACHE) > MAX_CACHE:
        oldest = next(iter(_CACHE))
        _CACHE.pop(oldest, None)
    return record


def lookup(entity_id: str, fingerprint: str, *, now: datetime | None = None) -> RepeatRecord | None:
    """Return a *live* record for this turn, pruning it if the TTL has expired."""
    key = (entity_id, fingerprint)
    record = _CACHE.get(key)
    if record is None:
        return None
    if record.expiry <= _now(now):
        _CACHE.pop(key, None)
        return None
    return record


def note_denied(entity_id: str, fingerprint: str, *, now: datetime | None = None) -> None:
    """Increment the attempt count after a denied/timed-out repeat challenge.

    The expiry is left unchanged so the whole episode stays bounded by the
    original TTL window (a denier cannot extend their own window by retrying).
    """
    key = (entity_id, fingerprint)
    record = _CACHE.get(key)
    if record is not None:
        _CACHE[key] = replace(record, count=record.count + 1)


def clear_record(entity_id: str, fingerprint: str) -> None:
    """Drop one record — used after a *single-use* approval releases the turn."""
    _CACHE.pop((entity_id, fingerprint), None)


def disposition(record: RepeatRecord) -> str:
    """``"lockout"`` once a challenge has already been denied, else ``"challenge"``."""
    return "lockout" if record.count >= LOCKOUT_AT_COUNT else "challenge"


def challenge_tier(block_reason: ReasonCode) -> AuthTier:
    """Proof scaled to the block: Tier 0 signature → 2FA, softer → confirm."""
    return AuthTier.two_factor if block_reason in _TIER0_REASONS else AuthTier.soft_confirm


def restate(block_reason: ReasonCode) -> str:
    """A human label for the original block reason (no raw text)."""
    return _REASON_LABEL.get(block_reason, f"{block_reason} pattern")


def lockout_block(block_reason: ReasonCode) -> GuardrailResult:
    """The BLOCK returned when a repeat has exhausted its challenges (lockout)."""
    return GuardrailResult(
        verdict=Verdict.BLOCK,
        risk=Risk.high,
        reason_codes=[ReasonCode.turn_blocked_repeatedly, block_reason],
        explanation=(
            f"Turn blocked: repeated resubmission of a {restate(block_reason)} after a denied "
            "challenge (locked out for the cooldown window)."
        ),
    )


def _repeat_decision(
    turn: TurnObject, record: RepeatRecord, when: datetime
) -> tuple[SecurityObject, Decision]:
    """Build the synthetic action + AUTH decision the F7 challenge names.

    The challenge risk is set so :func:`select_tier` derives the intended tier
    (high → two_factor for a Tier 0 repeat, low → soft_confirm otherwise), and
    the explanation restates the original block reason + matched pattern.
    """
    tier = challenge_tier(record.block_reason)
    risk = Risk.high if tier is AuthTier.two_factor else Risk.low
    explanation = (
        f"Previously blocked: {restate(record.block_reason)}. "
        "Approve this exact turn anyway? (one-time; nothing is allow-listed)"
    )
    result = GuardrailResult(
        verdict=Verdict.AUTH,
        risk=risk,
        reason_codes=[ReasonCode.repeat_after_block, record.block_reason],
        explanation=explanation,
    )
    decision = Decision(
        action_id=turn.id,
        final_verdict=Verdict.AUTH,
        final_risk=risk,
        objective=result,
        subjective=None,
        reason_codes=list(result.reason_codes),
        explanation=explanation,
        decided_at=when,
    )
    action = SecurityObject(
        id=turn.id,
        ts=turn.ts,
        agent_role="user",
        action_type=ActionType.other,
        tool_name="(turn)",
        target=None,
    )
    return action, decision


def challenge_repeat(
    turn: TurnObject,
    record: RepeatRecord,
    *,
    prompter: Prompter | None = None,
    at: datetime | None = None,
    message_tone: str = "human",
) -> AuthResult:
    """Run the F7 challenge for a repeated, just-blocked turn and return the result.

    On approval the caller releases the turn and clears the record (single-use);
    on denial the caller calls :func:`note_denied`. The proof tier is bound to
    the original block reason (Tier 0 → 2FA). ``message_tone`` (S1, cosmetic
    only) is passed through as data — this module stays config-free, the caller
    (turngate/hook.py, which already has repo_root) resolves it.
    """
    when = _now(at)
    action, decision = _repeat_decision(turn, record, when)
    return run_auth_challenge(
        decision, action, prompter=prompter, at=when, message_tone=message_tone
    )
