"""#73 — bare-token false positives in the secret scanner (sensitive_secret_access).

`SecretLeakageRule` already suppresses obvious placeholders (``your_key_here``,
``changeme``, ``example_...``) but only on an assignment RHS (``KEY = <value>``).
A BARE credential-shaped token — one with no ``KEY =`` to anchor that allowlist
against — never hit it: a credential regex pattern quoted verbatim in prose, or
a hand-written test fixture built by string concatenation (so it still exercises
the rule at runtime while dodging gitleaks/push-protection on the literal
source), read as secret-shaped and stepped up to AUTH.

See ``_is_benign_fixture_token`` in ``doberman.engine.rules.secrets`` for the
suppression logic and its scope note: it is wired only into the WEAK/
high-entropy path (never a BLOCK by itself) — never into the STRONG
credential-pattern path that can drive ``secret_exfiltration``, so the existing
``NEW_CREDENTIALS`` recall suite in ``test_rule_secrets.py`` (which
deliberately sends EXAMPLE/digit-run-marked synthetic credentials to an
external destination and requires a BLOCK) is unaffected.
"""

from datetime import datetime, timezone

import pytest

from doberman.engine.rules.secrets import SecretLeakageRule
from doberman.models import ActionType, EvalContext, ReasonCode, SecurityObject, Verdict

RULE = SecretLeakageRule()

# Realistic, UNMARKED live-shaped keys (built via `+` so push-protection/gitleaks
# does not flag the literals — same convention as test_rule_secrets.py's FAKE_*
# constants; the runtime value still matches the rule's credential regex).
REALISTIC_ANTHROPIC_KEY = (  # noqa: S105 — synthetic, not a real credential
    "sk-ant-" + "api03-" + "Qx7mZpKdLnRjWsVfYbHtCmGkAeIuOpZxDkLoQrTsBnJh"
)
REALISTIC_AKIA_KEY = "AKIA" + "Q7MZPKDLNRJWSVFY"  # noqa: S105 — synthetic


def _action(action_type=ActionType.file_read, *, target="notes.txt"):
    return SecurityObject(
        id="sec-73",
        ts=datetime(2026, 7, 2, tzinfo=timezone.utc),
        agent_role="unknown",
        action_type=action_type,
        tool_name="t",
        target=target,
    )


def _read(content):
    action = _action(ActionType.file_read, target="notes.txt")
    ctx = EvalContext(metadata={"raw_arguments": {"path": "notes.txt", "content": content}})
    return RULE.evaluate(action, ctx)


# --- Criterion 1: regex-pattern source text quoted verbatim ------------------

REGEX_PATTERN_IN_PROSE = [
    "Our scanner uses the pattern sk-ant-[A-Za-z0-9_-]{20,} to detect Anthropic keys.",
    "GitLab tokens match glpat-[A-Za-z0-9_-]{20,} in our regex list.",
    "AWS keys match AKIA[0-9A-Z]{16} per our detector.",
]


@pytest.mark.parametrize("content", REGEX_PATTERN_IN_PROSE)
def test_credential_regex_pattern_quoted_in_prose_is_not_flagged(content):
    result = _read(content)
    assert result.verdict is Verdict.PASS
    assert ReasonCode.sensitive_secret_access not in result.reason_codes


# --- Criterion 2: fixture markers / ascending digit runs, as BARE tokens -----


def test_concatenated_fixture_source_rendering_as_one_token_is_not_flagged():
    # #73's own reported case: a test-fixture DEFINITION, displayed/read as
    # source text. String concatenation ("sk-ant-" + "api03-" + "...") breaks
    # the credential prefix off from the marker+filler when scanned as raw
    # text, leaving a bare "EXAMPLE0123..." token that must not be flagged.
    content = 'FAKE_ANTHROPIC = "sk-ant-" + "api03-" + "EXAMPLE0123456789abcdefABCDEF0123456789"'
    result = _read(content)
    assert result.verdict is Verdict.PASS
    assert ReasonCode.sensitive_secret_access not in result.reason_codes


def test_bare_token_with_example_marker_is_not_flagged():
    result = _read("token: EXAMPLE0123456789abcdefABCDEFGHIJKLMNOPQRSTUV")
    assert result.verdict is Verdict.PASS
    assert ReasonCode.sensitive_secret_access not in result.reason_codes


def test_bare_token_with_fake_marker_is_not_flagged():
    result = _read("token: FAKE_SECRET_abcdefghijklmnopqrstuvwxyz123456")
    assert result.verdict is Verdict.PASS
    assert ReasonCode.sensitive_secret_access not in result.reason_codes


def test_bare_token_with_ascending_digit_run_is_not_flagged():
    result = _read("token: 0123456789abcdefghijklmnopqrstuvwxyzABCDEF")
    assert result.verdict is Verdict.PASS
    assert ReasonCode.sensitive_secret_access not in result.reason_codes


# --- False-negative guards: a REALISTIC, unmarked secret must still fire -----


def test_realistic_anthropic_key_without_marker_still_fires_bare():
    result = _read(REALISTIC_ANTHROPIC_KEY)
    assert result.verdict is Verdict.AUTH
    assert ReasonCode.sensitive_secret_access in result.reason_codes


def test_realistic_akia_key_without_marker_still_fires_bare():
    result = _read(REALISTIC_AKIA_KEY)
    assert result.verdict is Verdict.AUTH
    assert ReasonCode.sensitive_secret_access in result.reason_codes


def test_realistic_anthropic_key_without_marker_still_fires_as_assignment_rhs():
    result = _read(f"ANTHROPIC_API_KEY={REALISTIC_ANTHROPIC_KEY}")
    assert result.verdict is Verdict.AUTH
    assert ReasonCode.sensitive_secret_access in result.reason_codes


def test_realistic_akia_key_without_marker_still_fires_as_assignment_rhs():
    result = _read(f"AWS_SECRET_KEY={REALISTIC_AKIA_KEY}")
    assert result.verdict is Verdict.AUTH
    assert ReasonCode.sensitive_secret_access in result.reason_codes


# --- Raise-only guards: a marker must not be an attacker's evasion (#73) -----
# A shapeless (no known prefix) secret is judged ONLY by the WEAK path, so if a
# bare fixture marker could suppress it, appending "EXAMPLE" would be a one-line
# bypass of the whole control. Suppression is gated on the *residual* (token
# minus markers/ordered runs) being non-secret-shaped, so these still fire.

SHAPELESS_SECRET = "Xk9mQ2pL7vN4wR8tY3zA6bC1dE5fG0hJwZ7vB3nM"  # noqa: S105 — 40-char random-ish


def test_shapeless_secret_with_appended_example_marker_still_fires():
    result = _read(f"token: {SHAPELESS_SECRET}EXAMPLE")
    assert result.verdict is Verdict.AUTH
    # A shapeless (no known credential shape) token is weak-entropy evidence, so it
    # steps up under possible_high_entropy_secret — the point is it still FIRES
    # (the marker doesn't suppress it), not which secret tier it lands in.
    assert ReasonCode.possible_high_entropy_secret in result.reason_codes


def test_shapeless_secret_with_appended_digit_run_still_fires():
    result = _read(f"token: {SHAPELESS_SECRET}01234567")
    assert result.verdict is Verdict.AUTH
    assert ReasonCode.possible_high_entropy_secret in result.reason_codes


def test_marker_in_key_name_does_not_suppress_a_real_value():
    # The fixture check runs on the value after the '=' split, never the name —
    # a variable merely NAMED with a marker must not hide a real secret RHS.
    result = _read(f"DUMMY_AUTH_VALUE={SHAPELESS_SECRET}")
    assert result.verdict is Verdict.AUTH
    assert ReasonCode.possible_high_entropy_secret in result.reason_codes


# --- Existing assignment-RHS benign suppression still works -----------------


def test_existing_assignment_rhs_placeholder_suppression_still_works():
    result = _read("API_KEY=your_key_here")
    assert result.verdict is Verdict.PASS
    assert ReasonCode.sensitive_secret_access not in result.reason_codes
