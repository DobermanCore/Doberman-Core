"""S1 — the `message_tone` cosmetic display preference ("human" | "technical").

Covers: PolicyDoc round-trip (default not emitted, garbage fails closed to
"human"); config save/load round-trip, including that it is UNGATED (no
possession factor needed, unlike mode/prefs/default-role weakenings) and
rejects an unknown tone; the `doberman message-tone` CLI show/set/invalid
flow; and that the human tone never exposes MORE of a redaction-sensitive
value than the technical tone already did.

`_challenge_message`'s own tone-rendering behavior (exact format per tone) is
covered in tests/unit/test_auth_provider.py; this file focuses on the
config/CLI plumbing plus the redaction guarantee.
"""

from datetime import datetime, timezone

from typer.testing import CliRunner

from doberman import config
from doberman.auth.challenge import AuthTier
from doberman.auth.provider import _challenge_message
from doberman.cli.main import app
from doberman.models import (
    ActionType,
    Decision,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    Verdict,
)
from doberman.policy.checklist import PolicyDoc, recommend_policy

runner = CliRunner()
_NOW = datetime(2026, 6, 8, tzinfo=timezone.utc)


def _action(target="backend/api.ts"):
    return SecurityObject(
        id="act-tone",
        ts=_NOW,
        agent_role="webdev",
        action_type=ActionType.file_write,
        tool_name="fs_write",
        target=target,
    )


def _auth_decision(reasons=(ReasonCode.role_out_of_scope,), risk: Risk = Risk.medium):
    objective = GuardrailResult(
        verdict=Verdict.AUTH, risk=risk, reason_codes=list(reasons), explanation="why"
    )
    return Decision(
        action_id="act-tone",
        final_verdict=Verdict.AUTH,
        final_risk=risk,
        objective=objective,
        reason_codes=list(reasons),
        explanation="why",
        decided_at=_NOW,
    )


# --- PolicyDoc round trip ----------------------------------------------------


def test_default_tone_is_human_and_not_emitted():
    doc = recommend_policy()
    assert doc.message_tone == "human"
    assert "message_tone" not in doc.to_mapping()


def test_technical_tone_is_emitted():
    doc = recommend_policy().with_message_tone("technical")
    assert doc.to_mapping()["message_tone"] == "technical"


def test_round_trips_through_mapping():
    doc = recommend_policy().with_message_tone("technical")
    restored = PolicyDoc.from_mapping(doc.to_mapping())
    assert restored.message_tone == "technical"


def test_garbage_stored_value_fails_closed_to_human():
    mapping = recommend_policy().to_mapping()
    mapping["message_tone"] = "shout-it-from-the-rooftops"
    restored = PolicyDoc.from_mapping(mapping)
    assert restored.message_tone == "human"


def test_missing_key_defaults_to_human():
    mapping = recommend_policy().to_mapping()
    assert "message_tone" not in mapping
    assert PolicyDoc.from_mapping(mapping).message_tone == "human"


# --- config save/load ---------------------------------------------------------


def test_load_defaults_to_human_with_no_saved_policy(tmp_path):
    assert config.load_message_tone(str(tmp_path)) == "human"


def test_save_and_load_round_trip(tmp_path):
    root = str(tmp_path)
    assert config.save_message_tone("technical", root) == "technical"
    assert config.load_message_tone(root) == "technical"
    # Flip back.
    config.save_message_tone("human", root)
    assert config.load_message_tone(root) == "human"


def test_save_rejects_an_unknown_tone(tmp_path):
    import pytest

    with pytest.raises(ValueError, match="unknown message tone"):
        config.save_message_tone("sarcastic", str(tmp_path))
    # Rejected — nothing was written.
    assert config.load_message_tone(str(tmp_path)) == "human"


def test_save_succeeds_with_no_possession_factor_enrolled(tmp_path):
    """Proves it is UNGATED: unlike `save_default_role_enabled`'s disable path
    (drift-gated, fails closed without an enrolled 2FA/password factor — see
    test_default_role_opt_in.py's `test_cli_disable_default_with_no_factor_enrolled_fails_closed`),
    this cosmetic setting writes with no possession factor enrolled at all —
    the isolated_totp_secret/isolated_password_hash autouse fixtures leave
    both unenrolled by default in every test, this one included.
    """
    from doberman.auth import password, totp

    assert totp.is_enrolled() is False
    assert password.is_enrolled() is False
    assert config.save_message_tone("technical", str(tmp_path)) == "technical"
    assert config.load_message_tone(str(tmp_path)) == "technical"


# --- CLI -----------------------------------------------------------------------


def test_cli_shows_the_default_tone(tmp_path):
    result = runner.invoke(app, ["message-tone", "--path", str(tmp_path)])
    assert result.exit_code == 0
    assert result.stdout.strip() == "human"


def test_cli_sets_the_tone_with_no_gate(tmp_path):
    result = runner.invoke(app, ["message-tone", "technical", "--path", str(tmp_path)])
    assert result.exit_code == 0
    assert "technical" in result.stdout
    assert config.load_message_tone(str(tmp_path)) == "technical"
    # And it's reflected back by a no-arg call.
    shown = runner.invoke(app, ["message-tone", "--path", str(tmp_path)])
    assert shown.stdout.strip() == "technical"


def test_cli_rejects_an_invalid_tone(tmp_path):
    result = runner.invoke(app, ["message-tone", "loud", "--path", str(tmp_path)])
    assert result.exit_code == 2
    assert config.load_message_tone(str(tmp_path)) == "human"  # unchanged


def test_cli_status_reports_the_tone(tmp_path):
    result = runner.invoke(app, ["status", "--path", str(tmp_path)])
    assert result.exit_code == 0
    assert "Messages: human" in result.stdout


# --- redaction: human tone never exposes MORE than technical did ---------------


def test_human_tone_shows_the_same_target_as_technical():
    """The exact target is the whole point of an action-specific challenge in
    EITHER tone — a synthetic secret-shaped target appears identically in both,
    never more, never less."""
    target = "backend/.env"  # a realistically sensitive-shaped path, not a raw secret
    action = _action(target)
    decision = _auth_decision()
    technical = _challenge_message(decision, action, AuthTier.soft_confirm, "technical")
    human = _challenge_message(decision, action, AuthTier.soft_confirm, "human")
    assert target in technical
    assert target in human


def test_human_tone_never_repeats_raw_explanation_when_reason_codes_are_present():
    """When reason codes exist, technical shows the raw `decision.explanation`
    verbatim; human summarizes via the shared explain.py descriptions instead
    and does not repeat it — strictly less raw text, never more."""
    decision = _auth_decision()
    decision = decision.model_copy(update={"explanation": "leaked-internal-detail"})
    action = _action()
    technical = _challenge_message(decision, action, AuthTier.soft_confirm, "technical")
    human = _challenge_message(decision, action, AuthTier.soft_confirm, "human")
    assert "leaked-internal-detail" in technical
    assert "leaked-internal-detail" not in human
