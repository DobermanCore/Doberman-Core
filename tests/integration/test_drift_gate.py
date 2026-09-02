"""Slice 10.2 — weakening is gated behind 2FA + a diff; strengthen/neutral apply."""

import inspect
from datetime import datetime, timezone

import pyotp
import pytest

from doberman.auth import password, totp
from doberman.policy.drift import Classification, apply_change

_NOW = datetime(2026, 6, 8, tzinfo=timezone.utc)
_PASSWORD = "correct horse battery staple"  # noqa: S105 — synthetic test credential


class ScriptedPrompter:
    def __init__(self, *, confirm=True, code="", raises=None):
        self._confirm, self._code, self._raises = confirm, code, raises
        self.diffs: list[str] = []

    def confirm(self, message):
        self.diffs.append(message)
        if self._raises is not None:
            raise self._raises
        return self._confirm

    def read_code(self, message):
        return self._code


def _enrolled_code() -> str:
    totp.enroll()
    return pyotp.TOTP(totp._read_secret()).now()


@pytest.mark.guarantee("raise-only-drift", host="mcp-proxy")
async def test_weaken_requires_2fa_and_shows_a_diff(tmp_path):
    code = _enrolled_code()
    prompter = ScriptedPrompter(confirm=True, code=code)
    outcome = await apply_change(
        {"r": "block"},
        {"r": "auth"},
        "loosen r",
        repo_root=str(tmp_path),
        prompter=prompter,
        now=_NOW,
    )
    assert outcome.classification is Classification.weaken
    assert outcome.approved is True
    assert outcome.method == "two_factor"
    assert "WEAKENING" in prompter.diffs[0]
    assert "block → auth" in prompter.diffs[0]  # the rendered Before/After


async def test_weaken_denied_when_confirmation_refused(tmp_path):
    # Round 6 item 9: with no factor enrolled the precondition now denies
    # before the confirm step is even reached (`method` would read
    # "no_factor_enrolled" instead) - enroll one so this test still exercises
    # an explicitly REFUSED confirmation specifically (mirrors
    # test_drift_preferences_gate.py's equivalent fix).
    password.enroll(_PASSWORD)
    outcome = await apply_change(
        {"r": "block"},
        {"r": "allow"},
        "loosen",
        repo_root=str(tmp_path),
        prompter=ScriptedPrompter(confirm=False),
        now=_NOW,
    )
    assert outcome.approved is False
    assert outcome.method == "denied"


async def test_weaken_denied_when_nothing_enrolled(tmp_path):
    """The precondition-first gate (round 6 item 9): with NEITHER TOTP nor a
    password enrolled, a weaken is denied on the enrollment check alone - the
    confirm step is never even reached, so a confirm=True prompter still gets
    denied with reason "no_factor_enrolled", not "denied"."""
    prompter = ScriptedPrompter(confirm=True, code="123456")
    outcome = await apply_change(
        {"r": "block"},
        {"r": "allow"},
        "loosen",
        repo_root=str(tmp_path),
        prompter=prompter,
        now=_NOW,
    )
    assert outcome.approved is False
    assert outcome.method == "no_factor_enrolled"
    assert prompter.diffs == []  # confirm() was never called


async def test_weaken_denied_on_wrong_2fa_code(tmp_path):
    totp.enroll()
    outcome = await apply_change(
        {"r": "block"},
        {"r": "allow"},
        "loosen",
        repo_root=str(tmp_path),
        prompter=ScriptedPrompter(confirm=True, code="000000"),
        now=_NOW,
    )
    assert outcome.approved is False


async def test_weaken_denied_on_prompter_failure(tmp_path):
    totp.enroll()  # a factor must be enrolled for the raise to actually happen
    outcome = await apply_change(
        {"r": "block"},
        {"r": "allow"},
        "loosen",
        repo_root=str(tmp_path),
        prompter=ScriptedPrompter(raises=TimeoutError("walked away")),
        now=_NOW,
    )
    assert outcome.approved is False


async def test_strengthen_applies_without_a_challenge(tmp_path):
    # No prompter needed: a strengthening change is auto-approved.
    outcome = await apply_change(
        {"r": "auth"}, {"r": "block"}, "tighten", repo_root=str(tmp_path), now=_NOW
    )
    assert outcome.classification is Classification.strengthen
    assert outcome.approved is True
    assert outcome.method == "auto"


async def test_neutral_applies_automatically(tmp_path):
    outcome = await apply_change(
        {"r": "block"}, {"r": "block"}, "no-op", repo_root=str(tmp_path), now=_NOW
    )
    assert outcome.classification is Classification.neutral
    assert outcome.approved is True


def test_policy_ledger_is_only_written_by_apply_change():
    # The poisoning defense relies on a single write path: only the drift module
    # ever inserts into the policy_changes ledger.
    import doberman.policy.drift as drift_module

    src = inspect.getsource(drift_module)
    assert "INSERT INTO policy_changes" in src
    assert "UPDATE policy_changes" not in src
    assert "DELETE FROM policy_changes" not in src


async def test_apply_mode_change_links_the_observation_to_its_ledger_row(tmp_path):
    from doberman.policy.drift import apply_mode_change, read_policy_changes
    from doberman.storage.policy_catalogue import ORIGIN_CHANGE, read_observations

    root = str(tmp_path)
    assert (
        await apply_mode_change("strict", root, "test tighten") == "strict"
    )  # strengthen: no gate
    rows = await read_policy_changes(root)
    (obs,) = read_observations(root)
    assert obs["origin"] == ORIGIN_CHANGE
    assert obs["ledger_ts"] == rows[0]["ts"]


async def test_establish_ok_first_run_links_the_observation_too(tmp_path):
    from doberman.policy.drift import apply_mode_change, read_policy_changes
    from doberman.storage.policy_catalogue import ORIGIN_CHANGE, read_observations

    root = str(tmp_path)
    result = await apply_mode_change("strict", root, "setup wizard", establish_ok=True)
    assert result == "strict"
    rows = await read_policy_changes(root)
    assert rows and rows[0]["approval_method"] == "logged"
    (obs,) = read_observations(root)
    assert obs["origin"] == ORIGIN_CHANGE
    assert obs["ledger_ts"] == rows[0]["ts"]
