"""H1 hardening — normalize()'s redaction unifies on the shared secret detector.

Covers:
(a) shapes the OLD ``_SECRET_SHAPES`` stopgap missed but the shared detector
    (``doberman.engine.rules.secrets.contains_strong_secret``) catches are now
    redacted too (new coverage, layered ON TOP of the stopgap — never instead
    of it).
(b) raise-only: every shape the OLD stopgap already caught is still caught
    (no weakening) and existing benign values still pass through.
(c) fail-closed: an exception raised anywhere in the redaction path (the new
    shared-detector call included) still produces normalize()'s existing
    conservative fallback object — never a raw pass-through.
"""

import pytest

from doberman.engine.rules import secrets as secrets_mod
from doberman.models import ActionType, Risk
from doberman.proxy import normalize as normalize_mod
from doberman.proxy.normalize import MAX_VALUE_LENGTH, REDACTED, normalize

# --- (a) new coverage: shapes the OLD stopgap misses ------------------------
#
# Empirically checked both detectors before picking these fixtures. Azure
# `AccountKey=...`/`SharedAccessKey=...` connection strings and JWTs are
# NOT useful as "old missed this" examples: their own shape requires a 40+
# char base64/unbroken run, which the OLD `_SECRET_SHAPES` catch-all
# (`\b[A-Za-z0-9+/_\-]{40,}\b`) already matches on its own — so they're
# regression cases under (b), not new-coverage cases here. These four are
# genuinely new: short vendor-prefixed keys and a marker string with no
# 40-char unbroken run, none of which trip any OLD pattern.


@pytest.mark.parametrize(
    "secret",
    [
        # GCP service-account key JSON marker — short, no long unbroken run.
        '{"type": "service_account", "project_id": "fake-project"}',
        # Stripe live key — vendor prefix uses "_", not the OLD pattern's
        # literal "sk-", and total length is under the OLD 40-char floor.
        "sk_live_" + ("A1b2C3" * 5),
        # SendGrid key — dotted three-part shape, under the 40-char floor.
        "SG." + ("a1B2c3" * 4) + "." + ("d4E5f6" * 4),
        # DB URI with embedded credentials — broken up by non-alnum chars
        # (":", "@", "."), so no 40-char unbroken run exists.
        "postgres://fakeuser:fakepassword123@db.internal.example.com:5432/prod",
    ],
)
def test_shared_detector_catches_shapes_old_stopgap_missed(secret):
    obj = normalize("fs_write", {"path": "ok.txt", "content": secret})
    assert obj.raw_args_redacted["content"] == REDACTED
    assert secret not in str(obj.raw_args_redacted)


# --- (b) raise-only: every old shape is still caught ------------------------


@pytest.mark.parametrize(
    "secret",
    [
        "AKIAIOSFODNN7EXAMPLE",  # AWS-style key id
        "sk-FAKEFAKEFAKEFAKEFAKE1234",  # api key prefix
        "ghp_FAKEFAKEFAKEFAKEFAKE12345",  # github token
        "-----BEGIN RSA PRIVATE KEY-----",  # PEM header
        "A" * (MAX_VALUE_LENGTH + 1),  # oversized blob
        "x" * 41,  # long unbroken token
    ],
)
def test_old_stopgap_shapes_still_redacted_after_hardening(secret):
    """No regression: hardening only ever ADDS coverage (mirrors
    ``test_normalize.test_secret_shaped_values_are_redacted``)."""
    obj = normalize("fs_write", {"path": "ok.txt", "content": secret})
    assert obj.raw_args_redacted["content"] == REDACTED
    assert secret not in str(obj.raw_args_redacted)


def test_benign_values_still_pass_through_after_hardening():
    """The broader shared-detector coverage must not false-positive on the
    existing benign fixture (guards against the env-assignment check inside
    ``contains_strong_secret`` over-triggering on plain text)."""
    obj = normalize("fs_write", {"path": "a.txt", "content": "hello world", "append": True})
    assert obj.raw_args_redacted == {"path": "a.txt", "content": "hello world", "append": True}


# --- (c) fail-closed: an error in the scrub path is a conservative fallback -


def test_shared_detector_error_falls_back_to_conservative_object(monkeypatch):
    def boom(_text):
        raise RuntimeError("synthetic detector failure")

    monkeypatch.setattr(normalize_mod, "contains_strong_secret", boom)
    obj = normalize("fs_write", {"path": "a.txt", "content": "hello world"})
    assert obj.action_type is ActionType.other
    assert obj.risk is Risk.high
    assert "normalization_failed" in obj.metadata["reason_codes"]
    assert obj.raw_args_redacted == {}  # nothing copied on failure
    assert "hello world" not in str(obj)


def test_underlying_secrets_detector_error_also_falls_back_conservatively(monkeypatch):
    """Same fail-closed guarantee when the failure originates one layer down,
    in the canonical shared detector itself, not in normalize.py's import."""

    def boom(_text):
        raise RuntimeError("synthetic shared-detector failure")

    monkeypatch.setattr(secrets_mod, "_strong_secret_in_text", boom)
    obj = normalize("fs_write", {"path": "a.txt", "content": "hello world"})
    assert obj.action_type is ActionType.other
    assert obj.risk is Risk.high
    assert "normalization_failed" in obj.metadata["reason_codes"]
    assert obj.raw_args_redacted == {}
