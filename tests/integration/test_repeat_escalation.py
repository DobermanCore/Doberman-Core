"""Slice TG4.2 — repeat-after-block escalation with tiered, restated challenges.

A near-match resubmission of a just-blocked turn is evidence of deliberate human
intent: instead of re-blocking, route it to the F7 challenge, with proof scaled
to the block reason (Tier 0 signature → ``two_factor``; softer → confirm) and the
**original block reason restated** in the prompt. Approval is single-use; a
denial/timeout re-blocks and increments the count; the third attempt within the
TTL locks out without a challenge. A replay loop cannot produce a TOTP.
"""

from datetime import datetime, timezone

import pyotp
import pytest

from doberman.auth import totp
from doberman.auth.challenge import AuthTier
from doberman.models import ReasonCode, TurnObject, Verdict
from doberman.turngate.repeat import (
    challenge_repeat,
    challenge_tier,
    clear_repeat_cache,
    disposition,
    lockout_block,
    lookup,
    note_denied,
    register_block,
    restate,
)

_NOW = datetime(2026, 6, 10, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def _clean_cache():
    clear_repeat_cache()
    yield
    clear_repeat_cache()


class RecordingPrompter:
    def __init__(self, *, confirm=True, code=""):
        self._confirm, self._code = confirm, code
        self.messages: list[str] = []

    def confirm(self, message):
        self.messages.append(message)
        return self._confirm

    def read_code(self, message):
        return self._code


def _turn():
    return TurnObject(id="turn-7", ts=_NOW, entity_id="ent", prompt_fingerprint="hmac:abc")


def _valid_code() -> str:
    totp.enroll()
    return pyotp.TOTP(totp._read_secret()).now()


def test_tier0_block_requires_two_factor():
    assert challenge_tier(ReasonCode.secret_export) is AuthTier.two_factor
    assert challenge_tier(ReasonCode.authority_override) is AuthTier.two_factor


def test_softer_block_requires_only_confirm():
    assert challenge_tier(ReasonCode.unusual_for_deployment) is AuthTier.soft_confirm


def test_repeat_challenge_approved_with_valid_2fa():
    code = _valid_code()
    register_block("ent", "hmac:abc", ReasonCode.secret_export, now=_NOW)
    record = lookup("ent", "hmac:abc", now=_NOW)
    result = challenge_repeat(
        _turn(), record, prompter=RecordingPrompter(confirm=True, code=code), at=_NOW
    )
    assert result.approved is True


def test_repeat_challenge_denied_when_refused():
    register_block("ent", "hmac:abc", ReasonCode.secret_export, now=_NOW)
    record = lookup("ent", "hmac:abc", now=_NOW)
    result = challenge_repeat(_turn(), record, prompter=RecordingPrompter(confirm=False), at=_NOW)
    assert result.approved is False


def test_replay_without_a_valid_totp_fails():
    totp.enroll()
    register_block("ent", "hmac:abc", ReasonCode.secret_export, now=_NOW)
    record = lookup("ent", "hmac:abc", now=_NOW)
    result = challenge_repeat(
        _turn(), record, prompter=RecordingPrompter(confirm=True, code="000000"), at=_NOW
    )
    assert result.approved is False


def test_challenge_text_restates_the_block_reason_and_pattern():
    code = _valid_code()
    register_block("ent", "hmac:abc", ReasonCode.secret_export, now=_NOW)
    record = lookup("ent", "hmac:abc", now=_NOW)
    prompter = RecordingPrompter(confirm=True, code=code)
    challenge_repeat(_turn(), record, prompter=prompter, at=_NOW)
    message = prompter.messages[0]
    assert "secret_export" in message
    assert restate(ReasonCode.secret_export).split()[0].lower() in message.lower()


def test_third_attempt_locks_out_without_a_challenge():
    register_block("ent", "hmac:abc", ReasonCode.secret_export, now=_NOW)
    note_denied("ent", "hmac:abc", now=_NOW)  # second attempt denied
    record = lookup("ent", "hmac:abc", now=_NOW)
    assert disposition(record) == "lockout"
    blocked = lockout_block(ReasonCode.secret_export)
    assert blocked.verdict is Verdict.BLOCK
    assert ReasonCode.turn_blocked_repeatedly in blocked.reason_codes
