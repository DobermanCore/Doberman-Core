"""Regression tests for the identifier/relative-path false positive (AN-2).

The WEAK high-entropy path used to flag any >=24-char run of
``[A-Za-z0-9+/=_-]`` — which is the shape of an ordinary identifier
(``DEFAULT_CHALLENGE_TIMEOUT_S``) or relative path
(``migrations/0002_add_last_login``). Measured at roughly a 6:1 false-positive
ratio in real sessions.

These tests exist in three parts, and the third matters as much as the first:

1. the false positives stay suppressed;
2. real credential shapes still fire — this is the raise-only guard, and it must
   fail loudly if the exemption is ever widened into a threshold tweak;
3. the *documented cost* of the trade is pinned, so nobody later mistakes it for
   a free lunch or silently extends it.

See ADR 0049.
"""

import pytest

from doberman.engine.rules.secrets import (
    _looks_like_identifier_or_path,
    _strong_secret_in_text,
    _weak_secret_in_text,
)

# Every one of these was measured firing a spurious AUTH before the fix. The
# last four are this repo's OWN mandated conventions — `feat/<slug>/<slug>`
# branches and SCREAMING_SNAKE constants generate the trigger by design.
BENIGN_COMMANDS = [
    "python migrations/0002_add_last_login.py",
    "git checkout -b fix/auth/challenge-deadline-fail-closed",
    "grep -n DEFAULT_CHALLENGE_TIMEOUT_S src/doberman/auth/challenge.py",
    "pytest tests/unit/test_auth_challenge_timeout.py",
    "cat src/doberman/engine/rules/subjective_baseline_store.py",
    "ls src/doberman/proxy/interception_log_redaction.py",
]


@pytest.mark.parametrize("command", BENIGN_COMMANDS)
def test_ordinary_identifiers_and_paths_do_not_trip_the_weak_path(command):
    assert _weak_secret_in_text(command) is False


# The raise-only guard. If a future change turns the shape exemption into a
# threshold tweak, these break.
REAL_SECRET_TEXTS = [
    "aws_secret=wJalrXUtnFEMIKbPxRfiCYEXAMPLEKEYzz",
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0",
    "ghp_16C7e42F292c6912E7710c838347Ae178B4a",
    "curl -H 'Auth: Bmn3xQ7vKp2LsW9zTr4YhJ6dNc8FgV5aXe1'",
    "svctok-2451234567-2451234567890-AbCdEfGhIjKlMnOpQrStUvWx",
    "dGhpc2lzYXNlY3JldHZhbHVlZm9ydGVzdGluZzEyMw==",
]
# NOTE: the `svctok-` prefix above is deliberately NOT a real vendor prefix.
# An earlier draft used a Slack-shaped `xoxb-` fixture and GitHub push
# protection correctly rejected the push. The property under test is the
# SHAPE (mixed alnum segments must never be mistaken for an identifier), which
# does not need a recognisable vendor format to exercise.


@pytest.mark.parametrize("text", REAL_SECRET_TEXTS)
def test_real_secret_shapes_still_fire(text):
    assert _weak_secret_in_text(text) is True


@pytest.mark.parametrize(
    "token",
    [
        "wJalrXUtnFEMIKbPxRfiCYEXAMPLEKEY",  # base64-ish, no separators
        "svctok-2451234567-2451234567890-AbCdEfGhIjKlMnOpQrStUvWx",  # mixed segments
        "550e8400-e29b-41d4-a716-446655440000",  # hex segments, not word-shaped
        "AbCdEfGhIjKlMnOpQrStUvWxYz012345",
    ],
)
def test_credential_shapes_are_never_treated_as_identifiers(token):
    """A segment that mixes letters and digits is not a word — so no credential
    can be fragmented below the length floor and silently dropped."""
    assert _looks_like_identifier_or_path(token) is False


def test_a_single_long_token_is_never_exempt():
    """The exemption requires >=2 segments; a bare token is always judged whole."""
    assert _looks_like_identifier_or_path("supersecretvaluewithnoseparators") is False


def test_a_long_random_path_segment_still_fires():
    """A path is only exempt when EVERY segment is word-shaped."""
    assert _weak_secret_in_text("cp /tmp/wJalrXUtnFEMIKbPxRfiCYEXAMPLEKEY/out") is True


# --- the documented cost of this trade (ADR 0049) -------------------------
# A word-shaped passphrase is structurally IDENTICAL to a branch name, so the
# shape exemption cannot keep one and drop the other. These tests pin the loss
# deliberately: they are not describing desirable behavior, they are recording
# the price so it stays visible and cannot widen unnoticed.


def test_documented_cost_a_bare_word_shaped_passphrase_no_longer_steps_up():
    assert _weak_secret_in_text("correct-horse-battery-staple-nine") is False


@pytest.mark.parametrize(
    "text",
    [
        "PASSWORD=correct-horse-battery-staple-nine",
        "export SECRET_KEY=correct-horse-battery",
    ],
)
def test_the_compensating_control_a_named_credential_is_still_caught(text):
    """The cost above is bounded by this: give the passphrase a credential NAME
    and the STRONG path catches it regardless of the value's shape. Only a bare,
    unnamed, word-shaped token loses its AUTH step-up."""
    assert _strong_secret_in_text(text) is True


# --- the composition guard (ADR 0049) -------------------------------------
# The identifier exemption is scoped to NON-egress actions. `ExternalDestination
# Rule` PASSes a merely-unknown host in balanced mode and justifies that by
# delegating to this rule ("a secret leaving to any host is still a hard block
# via the secrets rule"). Exempting identifier shapes on an egress path would
# leave BOTH rules covering nothing — a hole neither loosening opened alone.
# Caught by tests/integration/test_benchmark_synthetic_gate.py (ASR 0.0 -> 0.333).

# Only tokens that clear the 3.6 bits/char entropy floor are in scope here — the
# exemption is the ONLY thing this change controls.
IDENTIFIER_SHAPED_PAYLOADS = [
    "correct-horse-battery-staple-nine",  # entropy 3.662
    "BENCHMARK_PAYLOAD_MARKER_DO_NOT_LEAK",  # entropy 3.774
]


@pytest.mark.parametrize("payload", IDENTIFIER_SHAPED_PAYLOADS)
def test_identifier_shapes_are_NOT_exempt_on_an_egress_path(payload):
    """On the way out, a word-shaped token is a plausible payload, not a path."""
    assert _weak_secret_in_text(payload, exempt_identifiers=False) is True


@pytest.mark.parametrize("payload", IDENTIFIER_SHAPED_PAYLOADS)
def test_identifier_shapes_are_exempt_off_the_egress_path(payload):
    """...but the same shape in ordinary shell/file work must not prompt."""
    assert _weak_secret_in_text(payload, exempt_identifiers=True) is False


def test_preexisting_limit_a_low_entropy_passphrase_is_missed_by_the_FLOOR():
    """Not introduced here, and not fixable by the exemption: a word-shaped token
    below the 3.6 bits/char floor was never on the weak path at all — on `main`
    or on this branch. Recorded so the exemption is not blamed for it, and so
    the real remaining gap stays visible."""
    # Named `sample`, not `token`: ruff S105 flags the latter as a hardcoded
    # password on this very string — a third detector agreeing the shape is
    # credential-ish in SOME context, which is exactly why the fix is scoping.
    sample = "MY_RECOVERY_PASSPHRASE_VALUE_HERE"  # entropy 3.559
    assert _weak_secret_in_text(sample, exempt_identifiers=False) is False


def test_the_exemption_defaults_to_on_but_the_rule_disables_it_for_egress():
    """Guard the wiring, not just the helper: `SecretLeakageRule.evaluate` must
    pass `exempt_identifiers=not going_external`. If someone drops that argument
    the default (True) silently reopens the hole, so assert on the source."""
    import inspect

    from doberman.engine.rules import secrets as mod

    src = inspect.getsource(mod.SecretLeakageRule.evaluate)
    assert "_weak_secret_present(strings, exempt_identifiers=not going_external)" in src
