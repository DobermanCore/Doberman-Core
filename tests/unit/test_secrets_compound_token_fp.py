"""Weak-path false positives on identifier/path/id shapes, and the rule's own
robustness safeguards.

Two problems this file pins:

1. The weak high-entropy heuristic keyed on Shannon entropy *per character*, which
   measures alphabet variety, not randomness — so an ordinary identifier, a
   relative path, a UUID, or a ``word+number`` build tag (``py311``, ``x86``)
   landed in the same 3.6-4.5 bits/char band as a short base64 token and tripped a
   spurious AUTH (``possible_high_entropy_secret``). One such id in a scratch path
   also poisoned the host-hook taint ledger for the rest of the session. The fix
   exempts digest/UUID-shaped hex ids and short ``word+number`` atoms.

2. The rule must not be *breakable*: a self-check runs at import and, if the rule's
   invariants don't hold, :meth:`SecretLeakageRule.evaluate` degrades to fail-closed
   AUTH instead of raising on every action.

The recall guards below are the raise-only contract: every real credential shape
must still fire on the weak path. Credential-shaped fixtures are assembled from
fragments so this source file never contains a contiguous live-secret shape.
"""

import secrets as _sec
from datetime import datetime, timezone

import pytest

from doberman.engine.rules import secrets as rule
from doberman.engine.rules.secrets import (
    SecretLeakageRule,
    _is_structured_hex_id,
    _looks_like_identifier_or_path,
    _run_invariant_check,
    _weak_secret_in_text,
)
from doberman.models import ActionType, EvalContext, SecurityObject, Verdict

# A fixed dashed UUID and a fixed 40-hex SHA — identifiers, never secrets. Written
# as literals on purpose: the fixed rule must read them as ids (so this very file
# does not self-trip the detector on write).
UUID = "0f8e7d6c-1234-4321-9abc-0123456789ab"
SHA1 = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"
MD5 = "0123456789abcdef0123456789abcdef"


# --------------------------------------------------------------------------- #
# 1) Benign identifier / path / id shapes must NOT trip the weak path (local).  #
# --------------------------------------------------------------------------- #
BENIGN_LOCAL = [
    "gh api repos/DobermanCore/Doberman-Core/actions/runs/32895549297/jobs",
    "gh run view 32895549297 --json jobs",
    "git push origin feat/telemetry/posthog-opt-in",
    "git checkout -b fix/auth/challenge-deadline-fail-closed",
    "python -m pytest tests/unit/test_secrets_compound_token_fp.py -q",
    "cat /tmp/claude/C--Users-dev-Documents-GitHub-Doberman/" + UUID + "/scratchpad/notes.md",
    "C--Users-dev-Documents-GitHub-Doberman",  # the workspace key alone
    UUID,  # a bare UUID alone
    "https://us.i.posthog.com/project/" + UUID + "/events",  # UUID inside a URL
    "docker pull ghcr.io/dobermancore/doberman-core:v0.18.1-py311-slim",
    "node_modules/@scope/some-package-name/dist/esm/index.js",
    "DEFAULT_CHALLENGE_TIMEOUT_S_FOR_GUI_PROMPTER_V2",  # SCREAMING_SNAKE constant
    "build/py311/x86_64/release-v2/sha256sums.txt",  # word+number build tags
    "git checkout " + SHA1,  # a bare git SHA
    "commit " + MD5,  # a bare 32-hex id
]


@pytest.mark.parametrize("text", BENIGN_LOCAL)
def test_benign_shapes_do_not_trip_the_weak_path_locally(text):
    assert _weak_secret_in_text(text) is False


def test_structured_hex_id_recognizes_digests_and_uuids():
    assert _is_structured_hex_id(SHA1) is True  # 40 hex
    assert _is_structured_hex_id(MD5) is True  # 32 hex
    assert _is_structured_hex_id("a" * 64) is True  # 64 hex (sha256)
    assert _is_structured_hex_id(UUID) is True  # dashed uuid
    assert _is_structured_hex_id("a" * 31) is False  # 31 hex — below the id floor
    assert _is_structured_hex_id("g" * 40) is False  # not hex


def test_compound_atom_segments_are_word_like_but_a_prefixed_secret_is_not():
    # ``py311``/``x86`` style build tags decompose into word+number atoms → exempt.
    assert _looks_like_identifier_or_path("py311/x86/sha256/utf8") is True
    # ...but a long hex BODY after a short prefix is NOT an id-segment, so a
    # prefixed credential shape does not get exempted by the compound rule.
    assert _looks_like_identifier_or_path("ghp/" + "a1b2c3d4e5" * 4) is False


# --------------------------------------------------------------------------- #
# 2) Recall guards (raise-only): every real credential must still weak-fire.    #
#    Built from fragments so the file holds no contiguous live-secret shape.     #
# --------------------------------------------------------------------------- #
def _gh_token() -> str:
    return "ghp_" + "16C7e42F292c6912E7710c838347Ae178B4a"


def _akia() -> str:
    return "AKIA" + "IOSFODNN7EXAMPLE1"[:16]


# Tokens that DO reach the weak path (>= 24 chars, no benign word structure).
REAL_WEAK_SECRET_TEXTS = [
    _gh_token(),  # GitHub token: word prefix + long hex body must NOT be exempted
    "sk-" + "ant-" + _sec.token_urlsafe(24),  # Anthropic-style key
    _sec.token_urlsafe(32),  # a shapeless high-entropy token (no word structure)
]


@pytest.mark.parametrize("text", REAL_WEAK_SECRET_TEXTS)
def test_real_credentials_still_fire_on_the_weak_path(text):
    assert _weak_secret_in_text(text) is True


def test_short_strong_credentials_are_caught_by_the_strong_path():
    # An AWS access-key id is 20 chars — below the 24-char weak floor by design, so
    # it is caught by the STRONG path, not the weak heuristic. Pinned so the
    # weak-path recall list is never mistakenly expected to cover it.
    assert rule._strong_secret_in_text(_akia()) is True
    assert _weak_secret_in_text(_akia()) is False  # too short for the weak path


def test_prefixed_hex_credential_is_not_exempted_as_word_plus_id():
    # The exact regression the compound/id exemption could have introduced: a
    # ``gh`` token splits into a word plus a 36-hex body; treating that body as an
    # id would exempt a real token. It must still fire.
    assert _weak_secret_in_text(_gh_token()) is True


# --------------------------------------------------------------------------- #
# 3) Egress asymmetry (ADR 0049) preserved, with the '/' carve-out added.       #
# --------------------------------------------------------------------------- #
def test_word_shaped_payload_without_a_slash_still_fires_on_egress():
    # On the way out, a hyphen/underscore-joined payload is a plausible passphrase
    # and is NOT exempted — the existing egress contract.
    assert (
        _weak_secret_in_text("correct-horse-battery-staple-nine", exempt_identifiers=False) is True
    )


def test_slash_bearing_path_or_ref_is_exempt_even_on_egress():
    # A '/'-bearing token is a path / URL path / git ref, not a passphrase, so it
    # stays exempt on egress — this is what stopped every ``gh api`` and branch-ref
    # from prompting on a push.
    assert (
        _weak_secret_in_text("repos/DobermanCore/Doberman-Core/pulls/460", exempt_identifiers=False)
        is False
    )
    assert _weak_secret_in_text("feat/telemetry/posthog-opt-in", exempt_identifiers=False) is False


# --------------------------------------------------------------------------- #
# 4) Robustness safeguards: self-check + fail-closed degradation.               #
# --------------------------------------------------------------------------- #
def test_invariant_self_check_passes_on_a_healthy_rule():
    assert _run_invariant_check() is True
    assert rule._HEALTHY is True


def _action(action_type=ActionType.file_read, target="notes.md"):
    return SecurityObject(
        id="test-action",
        ts=datetime(2026, 1, 1, tzinfo=timezone.utc),
        agent_role="dev",
        action_type=action_type,
        tool_name="t",
        target=target,
    )


def _ctx(**meta):
    return EvalContext(metadata={"raw_arguments": meta})


def test_a_broken_rule_degrades_to_fail_closed_auth_never_pass(monkeypatch):
    # Simulate the exact incident: a helper starts raising (an edit left a name
    # undefined). The rule must fail closed to AUTH, never PASS, and never raise.
    def _boom(*_a, **_k):
        raise RuntimeError("simulated broken helper")

    monkeypatch.setattr(rule, "_scan_strings", _boom)
    result = SecretLeakageRule().evaluate(_action(), _ctx(path="notes.md"))
    assert result.verdict is Verdict.AUTH


def test_evaluate_never_raises_even_on_garbage_input(monkeypatch):
    monkeypatch.setattr(rule, "_HEALTHY", False)
    # None/None would raise inside the real body; the wrapper must still return AUTH.
    assert SecretLeakageRule().evaluate(None, None).verdict is Verdict.AUTH


def test_evaluate_is_idempotent_and_does_not_mutate_the_action():
    action = _action(ActionType.file_write, target="x.txt")
    before = action.model_dump()
    r1 = SecretLeakageRule().evaluate(action, _ctx(path="x.txt", content="hello world"))
    r2 = SecretLeakageRule().evaluate(action, _ctx(path="x.txt", content="hello world"))
    assert action.model_dump() == before  # no mutation
    assert r1.verdict is r2.verdict  # same input → same verdict
