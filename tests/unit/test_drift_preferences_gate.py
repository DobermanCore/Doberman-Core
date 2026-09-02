"""C1 slice 2 — subjective preference-vector permanent-lowering gate.

Lowering an SL5 weight requires confirmation plus the strongest enrolled
possession factor (TOTP, otherwise password); raising remains frictionless.
"""

from datetime import datetime, timezone

import pyotp

from doberman.auth import password, totp
from doberman.policy.drift import Classification, apply_preferences_change, read_policy_changes

_NOW = datetime(2026, 7, 16, tzinfo=timezone.utc)
_PASSWORD = "correct horse battery staple"  # noqa: S105 — synthetic test credential


class ScriptedPrompter:
    def __init__(self, *, confirm=True, code=""):
        self._confirm, self._code = confirm, code
        self.confirm_calls = 0
        self.read_code_calls = 0

    def confirm(self, message):
        self.confirm_calls += 1
        return self._confirm

    def read_code(self, message):
        self.read_code_calls += 1
        return self._code


class _RaisingPrompter:
    """Confirms, then blows up reading the code (e.g. the operator walked away)."""

    def confirm(self, message):
        return True

    def read_code(self, message):
        raise TimeoutError("walked away")


def _enrolled_code() -> str:
    totp.enroll()
    return pyotp.TOTP(totp._read_secret()).now()


# --- A: lowering a weight requires the strongest enrolled factor ------------


async def test_lowering_a_weight_with_valid_2fa_is_approved(tmp_path):
    password.enroll(_PASSWORD)  # TOTP must take precedence when both exist.
    code = _enrolled_code()
    outcome = await apply_preferences_change(
        {"confidentiality": 0.7},
        {"confidentiality": 0.3},
        "lower confidentiality",
        repo_root=str(tmp_path),
        prompter=ScriptedPrompter(confirm=True, code=code),
        now=_NOW,
    )
    assert outcome.classification is Classification.weaken
    assert outcome.approved is True
    assert outcome.method == "two_factor"


async def test_lowering_a_weight_denied_when_confirmation_declined(tmp_path):
    # Round 6 item 9: with no factor enrolled the precondition now denies
    # before the confirm step is even reached (`method` would read
    # "no_factor_enrolled" instead) - enroll one so this test still exercises
    # an explicitly DECLINED confirm specifically.
    password.enroll(_PASSWORD)
    outcome = await apply_preferences_change(
        {"confidentiality": 0.7},
        {"confidentiality": 0.3},
        "lower confidentiality",
        repo_root=str(tmp_path),
        prompter=ScriptedPrompter(confirm=False),
        now=_NOW,
    )
    assert outcome.approved is False
    assert outcome.method == "denied"


async def test_lowering_a_weight_denied_when_read_code_raises(tmp_path):
    _enrolled_code()
    outcome = await apply_preferences_change(
        {"confidentiality": 0.7},
        {"confidentiality": 0.3},
        "lower confidentiality",
        repo_root=str(tmp_path),
        prompter=_RaisingPrompter(),
        now=_NOW,
    )
    assert outcome.approved is False
    assert outcome.method == "denied"


async def test_denial_is_still_recorded_in_the_ledger(tmp_path):
    # Round 6 item 9: see the comment in the previous test - enroll a factor
    # so a DECLINED confirm (not the no-factor-enrolled precondition) is what
    # this test exercises.
    password.enroll(_PASSWORD)
    outcome = await apply_preferences_change(
        {"confidentiality": 0.7},
        {"confidentiality": 0.3},
        "lower confidentiality",
        repo_root=str(tmp_path),
        prompter=ScriptedPrompter(confirm=False),
        now=_NOW,
    )
    assert outcome.approved is False
    rows = await read_policy_changes(str(tmp_path))
    assert len(rows) == 1
    assert rows[0]["rule_id"] == "confidentiality"
    assert rows[0]["approved"] == 0
    assert rows[0]["classification"] == "weaken"
    assert rows[0]["approval_method"] == "denied"


async def test_lowering_with_password_only_is_approved_and_recorded(tmp_path):
    password.enroll(_PASSWORD)
    outcome = await apply_preferences_change(
        {"confidentiality": 0.7},
        {"confidentiality": 0.3},
        "lower confidentiality",
        repo_root=str(tmp_path),
        prompter=ScriptedPrompter(confirm=True, code=_PASSWORD),
        now=_NOW,
    )

    assert outcome.approved is True
    assert outcome.method == "password"
    rows = await read_policy_changes(str(tmp_path))
    assert rows[0]["approval_method"] == "password"


async def test_lowering_with_password_only_rejects_wrong_password(tmp_path):
    password.enroll(_PASSWORD)
    outcome = await apply_preferences_change(
        {"confidentiality": 0.7},
        {"confidentiality": 0.3},
        "lower confidentiality",
        repo_root=str(tmp_path),
        prompter=ScriptedPrompter(confirm=True, code="this is the wrong password"),
        now=_NOW,
    )

    assert outcome.approved is False
    assert outcome.method == "denied"


# --- B: raising a weight is frictionless (raise-only) -------------------------


async def test_raising_a_weight_never_prompts(tmp_path):
    # A wrong code + a would-be-approving confirm proves the prompter is truly
    # never invoked on a strengthen, not merely that it happens to succeed.
    prompter = ScriptedPrompter(confirm=True, code="000000")
    outcome = await apply_preferences_change(
        {"confidentiality": 0.3},
        {"confidentiality": 0.7},
        "raise confidentiality",
        repo_root=str(tmp_path),
        prompter=prompter,
        now=_NOW,
    )
    assert outcome.classification is Classification.strengthen
    assert outcome.approved is True
    assert outcome.method == "auto"
    assert prompter.confirm_calls == 0
    assert prompter.read_code_calls == 0


async def test_identical_vector_is_neutral_and_never_prompts(tmp_path):
    prompter = ScriptedPrompter(confirm=True, code="000000")
    outcome = await apply_preferences_change(
        {"confidentiality": 0.5},
        {"confidentiality": 0.5},
        "no-op",
        repo_root=str(tmp_path),
        prompter=prompter,
        now=_NOW,
    )
    assert outcome.classification is Classification.neutral
    assert outcome.approved is True
    assert prompter.confirm_calls == 0


# --- C: mixed change -> weaken (fail safe) -------------------------------------


async def test_mixed_change_classifies_as_weaken(tmp_path):
    code = _enrolled_code()
    outcome = await apply_preferences_change(
        {"confidentiality": 0.3, "blast_radius": 0.8},
        {"confidentiality": 0.6, "blast_radius": 0.4},
        "mixed",
        repo_root=str(tmp_path),
        prompter=ScriptedPrompter(confirm=True, code=code),
        now=_NOW,
    )
    assert outcome.classification is Classification.weaken
    assert outcome.approved is True
    assert outcome.method == "two_factor"


# --- H: confirm-only can never approve a weaken (possession factor mandatory) -


async def test_confirm_true_but_wrong_code_still_denied(tmp_path):
    password.enroll(_PASSWORD)
    totp.enroll()  # enrolled, so even the correct password cannot replace TOTP
    outcome = await apply_preferences_change(
        {"confidentiality": 0.7},
        {"confidentiality": 0.3},
        "lower confidentiality",
        repo_root=str(tmp_path),
        prompter=ScriptedPrompter(confirm=True, code=_PASSWORD),
        now=_NOW,
    )
    assert outcome.approved is False
    assert outcome.method == "denied"


async def test_confirm_only_cannot_approve_when_nothing_is_enrolled(tmp_path):
    prompter = ScriptedPrompter(confirm=True, code="123456")
    outcome = await apply_preferences_change(
        {"confidentiality": 0.7},
        {"confidentiality": 0.3},
        "lower confidentiality",
        repo_root=str(tmp_path),
        prompter=prompter,
        now=_NOW,
    )
    assert outcome.approved is False
    assert outcome.method == "no_factor_enrolled"
    assert prompter.read_code_calls == 0


# --- extra edge cases: removed dimension / non-numeric junk -> weaken ---------


async def test_removed_dimension_is_a_weaken(tmp_path):
    code = _enrolled_code()
    outcome = await apply_preferences_change(
        {"confidentiality": 0.5, "blast_radius": 0.5},
        {"confidentiality": 0.5},
        "drop blast_radius",
        repo_root=str(tmp_path),
        prompter=ScriptedPrompter(confirm=True, code=code),
        now=_NOW,
    )
    assert outcome.classification is Classification.weaken


async def test_added_dimension_alone_is_a_strengthen(tmp_path):
    prompter = ScriptedPrompter(confirm=True, code="000000")
    outcome = await apply_preferences_change(
        {"confidentiality": 0.5},
        {"confidentiality": 0.5, "blast_radius": 0.5},
        "add blast_radius",
        repo_root=str(tmp_path),
        prompter=prompter,
        now=_NOW,
    )
    assert outcome.classification is Classification.strengthen
    assert outcome.approved is True
    assert prompter.confirm_calls == 0


async def test_non_numeric_value_is_treated_as_weaken_not_a_crash(tmp_path):
    code = _enrolled_code()
    outcome = await apply_preferences_change(
        {"confidentiality": 0.5},
        {"confidentiality": "not-a-number"},
        "junk",
        repo_root=str(tmp_path),
        prompter=ScriptedPrompter(confirm=True, code=code),
        now=_NOW,
    )
    assert outcome.classification is Classification.weaken
    assert outcome.approved is True
    assert outcome.method == "two_factor"
