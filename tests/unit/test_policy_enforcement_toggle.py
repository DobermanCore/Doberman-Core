"""Gated enforcement-state toggle + strictness-mode ranking (Feature 10).

Covers the `feat/policy/soften-toggle` slice:

* `classify_change` now ranks strictness **modes** (light<balanced<strict<paranoid)
  and **enforcement** states (off<monitor<enforce), so a `mode` or `enforcement`
  downgrade classifies as a **weaken** rather than silently neutral.
* `apply_enforcement_change` is the chokepoint for enforce/monitor/off: softening is
  gated (confirm + the strongest **enrolled** possession factor — TOTP if enrolled,
  else password — fail-closed with no factor enrolled); re-arming is a strengthen
  and applies automatically. Every attempt — including denials — hits the
  append-only ledger.
* `log_change` is the audited-but-not-gated path for the mode dial.
* `PolicyDoc` carries the orthogonal `enforcement` state + optional timed revert and
  round-trips through its mapping.

Security invariants asserted here: a weakening is never silently approved (raise-only);
re-arming is never gated; the disable requires a real possession factor — there is no
confirm-only fallback when nothing is enrolled; every gate fails closed.
"""

from datetime import datetime, timezone

import pytest

from doberman.policy import drift
from doberman.policy.checklist import PolicyDoc
from doberman.policy.drift import (
    Classification,
    apply_enforcement_change,
    classify_change,
    log_change,
    read_policy_changes,
)

_NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


# --- fake prompters --------------------------------------------------------


class _Approve:
    """Present human who confirms and supplies a code (default: TOTP-shaped)."""

    def __init__(self, code="999999"):
        self._code = code

    def confirm(self, message):
        return True

    def read_code(self, message):
        return self._code


class _ConfirmOnly:
    """Confirms but must never be asked for a secret (no factor enrolled)."""

    def confirm(self, message):
        return True

    def read_code(self, message):
        raise AssertionError("no factor is enrolled, so no secret prompt is valid")


class _Decline:
    def confirm(self, message):
        return False

    def read_code(self, message):  # pragma: no cover — never reached after a decline
        raise AssertionError("read_code must not be reached after a declined confirm")


class _Boom:
    """Any interaction is a test failure (used to prove a strengthen is NOT gated)."""

    def confirm(self, message):
        raise AssertionError("a strengthen/re-arm must not prompt")

    def read_code(self, message):
        raise AssertionError("a strengthen/re-arm must not prompt")


class _RaisesOnConfirm:
    def confirm(self, message):
        raise EOFError("input timeout")

    def read_code(self, message):  # pragma: no cover
        raise AssertionError("not reached")


@pytest.fixture
def _enrolled(monkeypatch):
    """2FA enrolled; only the code '999999' verifies."""
    monkeypatch.setattr(drift.totp, "is_enrolled", lambda: True)
    monkeypatch.setattr(drift.totp, "verify", lambda code, **kw: code == "999999")


@pytest.fixture
def _password_enrolled(monkeypatch):
    """Local password enrolled (no TOTP); only 'the-password' verifies."""
    monkeypatch.setattr(drift.password, "is_enrolled", lambda: True)
    monkeypatch.setattr(drift.password, "verify", lambda pw: pw == "the-password")


# --- classify_change: mode + enforcement ranking ---------------------------


def test_mode_downgrade_is_a_weaken():
    assert classify_change({"mode": "strict"}, {"mode": "light"}) is Classification.weaken
    assert classify_change({"mode": "paranoid"}, {"mode": "balanced"}) is Classification.weaken


def test_mode_upgrade_is_a_strengthen():
    assert classify_change({"mode": "light"}, {"mode": "strict"}) is Classification.strengthen


def test_same_mode_is_neutral():
    assert classify_change({"mode": "balanced"}, {"mode": "balanced"}) is Classification.neutral


def test_disabling_enforcement_is_a_weaken():
    assert (
        classify_change({"enforcement": "enforce"}, {"enforcement": "off"}) is Classification.weaken
    )
    assert (
        classify_change({"enforcement": "enforce"}, {"enforcement": "monitor"})
        is Classification.weaken
    )
    assert (
        classify_change({"enforcement": "monitor"}, {"enforcement": "off"}) is Classification.weaken
    )


def test_unrecognized_enforcement_token_is_a_weaken():
    # A typo/corrupt target must never slip past the gate as "neutral":
    # "enforce" (3) outranks the unknown-token rank (2), fail safe.
    assert (
        classify_change({"enforcement": "enforce"}, {"enforcement": "monitr"})
        is Classification.weaken
    )
    assert classify_change({"enforcement": "enforce"}, {"enforcement": ""}) is Classification.weaken


def test_re_arming_enforcement_is_a_strengthen():
    assert (
        classify_change({"enforcement": "off"}, {"enforcement": "enforce"})
        is Classification.strengthen
    )
    assert (
        classify_change({"enforcement": "monitor"}, {"enforcement": "enforce"})
        is Classification.strengthen
    )


# --- apply_enforcement_change: the gate ------------------------------------

_SOFTEN = ({"enforcement": "enforce"}, {"enforcement": "monitor"})
_REARM = ({"enforcement": "off"}, {"enforcement": "enforce"})


async def test_soften_with_2fa_enrolled_and_valid_code_is_approved(tmp_path, _enrolled):
    out = await apply_enforcement_change(
        *_SOFTEN, "quiet hours", repo_root=str(tmp_path), prompter=_Approve(), now=_NOW
    )
    assert out.approved is True
    assert out.method == "two_factor"
    assert out.classification is Classification.weaken
    # The 2FA code must never end up in the ledger.
    rows = await read_policy_changes(str(tmp_path))
    assert rows and "999999" not in str(rows)


async def test_soften_with_no_factor_enrolled_fails_closed(tmp_path):
    # conftest isolates both the TOTP secret and the password hash to empty temp
    # paths → neither factor is enrolled. The off-switch must fail closed instead
    # of falling back to confirm-only — there is no safety-valve bypass anymore.
    out = await apply_enforcement_change(
        *_SOFTEN, "no factor here", repo_root=str(tmp_path), prompter=_ConfirmOnly(), now=_NOW
    )
    assert out.approved is False
    assert out.method == "no_factor_enrolled"


async def test_soften_with_password_enrolled_and_valid_password_is_approved(
    tmp_path, _password_enrolled
):
    out = await apply_enforcement_change(
        *_SOFTEN,
        "quiet hours",
        repo_root=str(tmp_path),
        prompter=_Approve("the-password"),
        now=_NOW,
    )
    assert out.approved is True
    assert out.method == "password"
    # The password must never end up in the ledger.
    rows = await read_policy_changes(str(tmp_path))
    assert rows and "the-password" not in str(rows)


async def test_soften_with_wrong_password_is_denied(tmp_path, _password_enrolled):
    out = await apply_enforcement_change(
        *_SOFTEN, "wrong password", repo_root=str(tmp_path), prompter=_Approve("nope"), now=_NOW
    )
    assert out.approved is False
    assert out.method == "denied"


async def test_soften_with_both_enrolled_totp_wins_password_is_rejected(
    tmp_path, _enrolled, _password_enrolled
):
    # A valid TOTP code still succeeds when both factors are enrolled...
    out = await apply_enforcement_change(
        *_SOFTEN, "totp wins", repo_root=str(tmp_path), prompter=_Approve("999999"), now=_NOW
    )
    assert out.approved is True
    assert out.method == "two_factor"

    # ...but supplying the (correct) password instead of a TOTP code is rejected:
    # the password cannot substitute for TOTP once TOTP is enrolled.
    out = await apply_enforcement_change(
        {"enforcement": "monitor"},
        {"enforcement": "off"},
        "password instead of totp",
        repo_root=str(tmp_path),
        prompter=_Approve("the-password"),
        now=_NOW,
    )
    assert out.approved is False
    assert out.method == "denied"


async def test_soften_declined_is_denied(tmp_path):
    out = await apply_enforcement_change(
        *_SOFTEN, "changed my mind", repo_root=str(tmp_path), prompter=_Decline(), now=_NOW
    )
    assert out.approved is False
    assert out.method == "denied"


async def test_soften_with_wrong_2fa_code_is_denied(tmp_path, monkeypatch):
    monkeypatch.setattr(drift.totp, "is_enrolled", lambda: True)
    monkeypatch.setattr(drift.totp, "verify", lambda code, **kw: False)
    out = await apply_enforcement_change(
        *_SOFTEN, "bad code", repo_root=str(tmp_path), prompter=_Approve(), now=_NOW
    )
    assert out.approved is False
    assert out.method == "denied"


async def test_soften_gate_fails_closed_on_prompter_error(tmp_path):
    out = await apply_enforcement_change(
        *_SOFTEN, "timeout", repo_root=str(tmp_path), prompter=_RaisesOnConfirm(), now=_NOW
    )
    assert out.approved is False
    assert out.method == "denied"


async def test_re_arm_is_auto_approved_and_never_prompts(tmp_path):
    # Strengthen → applies automatically; the _Boom prompter proves no gate ran.
    out = await apply_enforcement_change(
        *_REARM, "back on", repo_root=str(tmp_path), prompter=_Boom(), now=_NOW
    )
    assert out.approved is True
    assert out.method == "auto"
    assert out.classification is Classification.strengthen
    # The auto path is still an attempt — it must land in the ledger too.
    rows = await read_policy_changes(str(tmp_path))
    assert len(rows) == 1
    assert rows[0]["classification"] == "strengthen"
    assert rows[0]["approved"] == 1


@pytest.mark.parametrize(
    ("before", "after"),
    [
        ({"enforcement": "enforce"}, {"enforcement": "monitor"}),
        ({"enforcement": "enforce"}, {"enforcement": "off"}),
        ({"enforcement": "monitor"}, {"enforcement": "off"}),
    ],
)
async def test_every_softening_pair_is_gated_end_to_end(tmp_path, before, after):
    out = await apply_enforcement_change(
        before, after, "pair", repo_root=str(tmp_path), prompter=_Decline(), now=_NOW
    )
    assert out.approved is False
    assert out.classification is Classification.weaken
    rows = await read_policy_changes(str(tmp_path))
    assert rows[0]["approved"] == 0


async def test_soften_to_an_unrecognized_state_is_gated(tmp_path):
    # enforce → typo/garbage goes through the full gate, never auto-approves.
    out = await apply_enforcement_change(
        {"enforcement": "enforce"},
        {"enforcement": "banana"},
        "typo",
        repo_root=str(tmp_path),
        prompter=_Decline(),
        now=_NOW,
    )
    assert out.approved is False
    assert out.classification is Classification.weaken


async def test_extending_a_soften_expiry_is_gated(tmp_path):
    # Pushing the auto-revert deadline later keeps protection down longer — that is
    # a weaken even though rank comparison sees two unknown floats as neutral.
    out = await apply_enforcement_change(
        {"enforcement": "monitor", "enforcement_expires_at": 100.0},
        {"enforcement": "monitor", "enforcement_expires_at": 999.0},
        "just a bit longer",
        repo_root=str(tmp_path),
        prompter=_Decline(),
        now=_NOW,
    )
    assert out.classification is Classification.weaken
    assert out.approved is False


# --- ledger: every attempt recorded, denials included ----------------------


async def test_approved_soften_is_recorded_in_the_ledger(tmp_path, _enrolled):
    await apply_enforcement_change(
        *_SOFTEN, "reason A", repo_root=str(tmp_path), prompter=_Approve(), now=_NOW
    )
    rows = await read_policy_changes(str(tmp_path))
    assert len(rows) == 1
    row = rows[0]
    assert row["rule_id"] == "enforcement"
    assert row["from_state"] == "enforce" and row["to_state"] == "monitor"
    assert row["classification"] == "weaken"
    assert row["approved"] == 1


async def test_denied_soften_is_still_recorded(tmp_path):
    # The denial is the attack signal — it must be in the append-only ledger.
    await apply_enforcement_change(
        *_SOFTEN, "reason B", repo_root=str(tmp_path), prompter=_Decline(), now=_NOW
    )
    rows = await read_policy_changes(str(tmp_path))
    assert len(rows) == 1
    assert rows[0]["approved"] == 0
    assert rows[0]["classification"] == "weaken"


# --- log_change: audited but not gated -------------------------------------


async def test_log_change_records_without_gating(tmp_path):
    # The mode dial: classified + recorded (method="logged"), no prompter interaction.
    out = await log_change(
        {"mode": "strict"}, {"mode": "light"}, "relax for exploration", repo_root=str(tmp_path)
    )
    assert out.approved is True
    assert out.method == "logged"
    assert out.classification is Classification.weaken
    rows = await read_policy_changes(str(tmp_path))
    assert rows[0]["approval_method"] == "logged"
    assert rows[0]["to_state"] == "light"


async def test_log_change_refuses_non_mode_keys(tmp_path):
    # The scope is enforced, not just documented: log_change can never be miswired
    # into rubber-stamping a rule/role/enforcement weakening.
    with pytest.raises(ValueError, match="scoped to the strictness-mode dial"):
        await log_change(
            {"hard_block.secret_exfiltration": "block"},
            {"hard_block.secret_exfiltration": "allow"},
            "oops",
            repo_root=str(tmp_path),
        )
    with pytest.raises(ValueError, match="scoped to the strictness-mode dial"):
        await log_change(
            {"enforcement": "enforce"}, {"enforcement": "off"}, "oops", repo_root=str(tmp_path)
        )
    assert await read_policy_changes(str(tmp_path)) == []


# --- PolicyDoc enforcement fields ------------------------------------------


def _doc(**kw) -> PolicyDoc:
    return PolicyDoc(items=(), **kw)


def test_policydoc_defaults_to_enforce():
    assert _doc().enforcement == "enforce"


def test_with_enforcement_sets_state_and_timer():
    doc = _doc().with_enforcement("monitor", expires_at=1_700_000_000.0, revert="enforce")
    assert doc.enforcement == "monitor"
    assert doc.enforcement_expires_at == 1_700_000_000.0
    assert doc.enforcement_revert == "enforce"


def test_enforcing_policy_mapping_omits_timer_fields():
    mapping = _doc().to_mapping()
    assert mapping["enforcement"] == "enforce"
    assert "enforcement_expires_at" not in mapping
    assert "enforcement_revert" not in mapping


def test_softened_policy_mapping_round_trips(tmp_path):
    doc = _doc(mode="light").with_enforcement("off", expires_at=1_700_000_000.0, revert="enforce")
    mapping = doc.to_mapping()
    assert mapping["enforcement"] == "off"
    assert mapping["enforcement_expires_at"] == 1_700_000_000.0
    assert mapping["enforcement_revert"] == "enforce"

    restored = PolicyDoc.from_mapping(mapping)
    assert restored.enforcement == "off"
    assert restored.enforcement_expires_at == 1_700_000_000.0
    assert restored.enforcement_revert == "enforce"


def test_from_mapping_ignores_a_non_numeric_expiry():
    # str is not an epoch; neither is bool (an int subclass — YAML `true` is a typo).
    for bad in ("soon", True):
        restored = PolicyDoc.from_mapping(
            {"items": [], "enforcement": "monitor", "enforcement_expires_at": bad}
        )
        assert restored.enforcement == "monitor"
        assert restored.enforcement_expires_at is None


def test_indefinite_soften_round_trips_without_expiry():
    # No timer set: the revert target must still survive the round trip.
    doc = _doc().with_enforcement("monitor")
    mapping = doc.to_mapping()
    assert "enforcement_expires_at" not in mapping
    assert mapping["enforcement_revert"] == "enforce"
    restored = PolicyDoc.from_mapping(mapping)
    assert restored.enforcement == "monitor"
    assert restored.enforcement_expires_at is None
    assert restored.enforcement_revert == "enforce"
