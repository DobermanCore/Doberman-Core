"""Oversized encoded-blob defense — subjective detector (Base64BlobDetector).

Covers: a large base64 blob in a tool argument raises to AUTH, raise-only;
benign / short content passes; long non-base64 runs that share the charset
(lowercase hex, letters-only, all-digits, repetitive filler) do NOT flag;
the size threshold is configurable; a blob in the target/destination is caught;
the matched blob never appears in the explanation (redaction); and the detector
is wired into SubjectiveGuardrail as a built-in.
"""

import base64
from datetime import datetime, timezone

from doberman.engine.detectors.base64_blob import Base64BlobDetector
from doberman.engine.subjective import SubjectiveGuardrail
from doberman.models import (
    ActionType,
    EvalContext,
    ReasonCode,
    SecurityObject,
    Verdict,
)

# A deterministic, realistic base64 blob: encoding all 256 byte values gives the
# full base64 alphabet (upper + lower + digits + symbols, > 20 distinct chars),
# and repeating pushes it well past the default 1500-char threshold (~2732 chars).
_BIG_BLOB = base64.b64encode(bytes(range(256)) * 8).decode("ascii")
# A small base64 value — below threshold, the shape of a routine token.
_SMALL_BLOB = base64.b64encode(b"a routine short value").decode("ascii")


def _action(*, tool="t", target=None, dest=None):
    return SecurityObject(
        id="b64-1",
        ts=datetime(2026, 6, 12, tzinfo=timezone.utc),
        agent_role="unknown",
        action_type=ActionType.file_write,
        tool_name=tool,
        target=target,
        external_destination=dest,
    )


def _ctx(**raw_arguments):
    return EvalContext(metadata={"raw_arguments": raw_arguments})


def test_oversized_blob_raises_to_auth():
    det = Base64BlobDetector()
    result = det.evaluate(_action(target="x.ts"), _ctx(payload=_BIG_BLOB))
    assert result.verdict is Verdict.AUTH
    assert ReasonCode.oversized_encoded_blob in result.reason_codes
    assert result.explanation  # every AUTH carries a human explanation


def test_short_base64_passes():
    det = Base64BlobDetector()
    assert det.evaluate(_action(target="x.ts"), _ctx(payload=_SMALL_BLOB)).verdict is Verdict.PASS


def test_benign_content_passes():
    det = Base64BlobDetector()
    assert det.evaluate(_action(target="x.ts"), _ctx(content="const y = 2")).verdict is Verdict.PASS


def test_long_lowercase_hex_does_not_flag():
    # A > 2000-char lowercase hex run (e.g. a concatenated digest dump) shares the
    # base64 charset but has no uppercase -> not encoded-binary shaped -> PASS.
    hex_run = "a1b2c3d4e5f60718293a" * 150
    det = Base64BlobDetector()
    assert det.evaluate(_action(target="x.ts"), _ctx(payload=hex_run)).verdict is Verdict.PASS


def test_long_letters_only_does_not_flag():
    # Letters (mixed case) but no digits -> not base64-of-binary shaped -> PASS.
    word_run = "AbCdEfGhIjKlMnOpQrStUvWxYz" * 100
    det = Base64BlobDetector()
    assert det.evaluate(_action(target="x.ts"), _ctx(payload=word_run)).verdict is Verdict.PASS


def test_repetitive_filler_does_not_flag():
    # Mixes the classes but only 3 distinct characters -> below the distinct floor.
    filler = "Ab1" * 800
    det = Base64BlobDetector()
    assert det.evaluate(_action(target="x.ts"), _ctx(payload=filler)).verdict is Verdict.PASS


def test_threshold_is_configurable():
    # A blob below the default threshold flags once the threshold is lowered.
    medium = base64.b64encode(bytes(range(256))).decode("ascii")  # ~344 chars
    assert Base64BlobDetector().evaluate(_action(), _ctx(p=medium)).verdict is Verdict.PASS
    strict = Base64BlobDetector(min_blob_chars=200)
    assert strict.evaluate(_action(), _ctx(p=medium)).verdict is Verdict.AUTH


def test_newline_wrapped_blob_is_caught():
    # PEM/MIME base64 is wrapped at 64/76 columns with newlines; the detector
    # strips line wrapping so the canonical wrapped-key exfil shape still fires.
    wrapped = "\n".join(_BIG_BLOB[i : i + 64] for i in range(0, len(_BIG_BLOB), 64))
    assert "\n" in wrapped
    det = Base64BlobDetector()
    assert det.evaluate(_action(target="x.ts"), _ctx(pem=wrapped)).verdict is Verdict.AUTH


def test_space_separated_short_tokens_do_not_merge():
    # Only newlines are stripped, not spaces — a run of short space-separated
    # base64-ish tokens must NOT be merged into one oversized blob.
    spaced = " ".join(["Ab1Cd2Ef3Gh4"] * 300)  # ~3900 chars, but max run is 12
    det = Base64BlobDetector()
    assert det.evaluate(_action(target="x.ts"), _ctx(text=spaced)).verdict is Verdict.PASS


def test_blob_in_target_is_caught():
    # collect_scan_strings also scans the target/destination, not just raw args.
    det = Base64BlobDetector()
    result = det.evaluate(
        _action(target="data:application/octet-stream;base64," + _BIG_BLOB), _ctx()
    )
    assert result.verdict is Verdict.AUTH


def test_detector_never_blocks():
    # Raise-only: the strongest verdict this detector can emit is AUTH.
    det = Base64BlobDetector()
    result = det.evaluate(_action(target="x.ts"), _ctx(payload=_BIG_BLOB))
    assert result.verdict is not Verdict.BLOCK


def test_blob_is_never_echoed_in_the_explanation():
    det = Base64BlobDetector()
    result = det.evaluate(_action(target="x.ts"), _ctx(payload=_BIG_BLOB))
    assert result.verdict is Verdict.AUTH
    # A slice of the payload must not appear anywhere in the reason/explanation.
    assert _BIG_BLOB[:64] not in result.explanation
    for code in result.reason_codes:
        assert _BIG_BLOB[:64] not in str(code)


def test_builtin_detector_is_wired_into_subjective_guardrail():
    g = SubjectiveGuardrail(load_plugins=False)  # built-ins still load
    ctx = EvalContext(metadata={"abnormality": 0.0, "raw_arguments": {"payload": _BIG_BLOB}})
    assert g.evaluate(_action(target="upload.ts"), ctx).verdict is Verdict.AUTH


def test_subjective_guardrail_can_disable_builtins():
    g = SubjectiveGuardrail(load_plugins=False, load_builtins=False)
    ctx = EvalContext(metadata={"abnormality": 0.0, "raw_arguments": {"payload": _BIG_BLOB}})
    # With built-ins off and a calm baseline, the same action passes.
    assert g.evaluate(_action(target="upload.ts"), ctx).verdict is Verdict.PASS
