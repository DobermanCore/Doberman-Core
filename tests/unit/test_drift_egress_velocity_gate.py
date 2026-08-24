"""RB.6 slice — egress-velocity threshold gate (tighten-only).

Tightening (lowering burst/fanout/volume_bytes relative to the current
effective policy) applies automatically.  Loosening (raising any threshold
relative to what is currently stored — the ``before`` dict) requires the
strongest enrolled possession factor (TOTP if enrolled, else password) or is
rejected outright — never applied silently.

Classification is always before-vs-after on the *current effective* thresholds,
never against the built-in module defaults.  That means a walk-back toward the
default after a prior gate-approved loosening is correctly flagged as a weaken.

Mirrors test_drift_preferences_gate.py in structure and coverage.
"""

from datetime import datetime, timezone

import pyotp

from doberman.auth import password, totp
from doberman.egress.velocity import (
    _BURST_THRESHOLD,
    _FANOUT_THRESHOLD,
    _VOLUME_THRESHOLD_BYTES,
)
from doberman.policy.drift import (
    Classification,
    apply_egress_velocity_change,
    read_policy_changes,
)

_NOW = datetime(2026, 7, 16, tzinfo=timezone.utc)
_PASSWORD = "correct horse battery staple"  # noqa: S105 — synthetic test credential

# Helpers -----------------------------------------------------------------


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


# A: loosening requires the strongest enrolled factor ----------------------


async def test_loosening_burst_with_valid_2fa_is_approved(tmp_path):
    password.enroll(_PASSWORD)
    code = _enrolled_code()
    outcome = await apply_egress_velocity_change(
        {"burst": _BURST_THRESHOLD},
        {"burst": _BURST_THRESHOLD + 5},  # higher → less sensitive → weaken
        "loosen burst for high-volume deployment",
        repo_root=str(tmp_path),
        prompter=ScriptedPrompter(confirm=True, code=code),
        now=_NOW,
    )
    assert outcome.classification is Classification.weaken
    assert outcome.approved is True
    assert outcome.method == "two_factor"


async def test_loosening_denied_when_confirmation_declined(tmp_path):
    outcome = await apply_egress_velocity_change(
        {"burst": _BURST_THRESHOLD},
        {"burst": _BURST_THRESHOLD + 5},
        "loosen burst",
        repo_root=str(tmp_path),
        prompter=ScriptedPrompter(confirm=False),
        now=_NOW,
    )
    assert outcome.approved is False
    assert outcome.method == "denied"


async def test_loosening_denied_when_read_code_raises(tmp_path):
    _enrolled_code()
    outcome = await apply_egress_velocity_change(
        {"burst": _BURST_THRESHOLD},
        {"burst": _BURST_THRESHOLD + 5},
        "loosen burst",
        repo_root=str(tmp_path),
        prompter=_RaisingPrompter(),
        now=_NOW,
    )
    assert outcome.approved is False
    assert outcome.method == "denied"


async def test_denial_is_still_recorded_in_the_ledger(tmp_path):
    outcome = await apply_egress_velocity_change(
        {"burst": _BURST_THRESHOLD},
        {"burst": _BURST_THRESHOLD + 5},
        "loosen burst",
        repo_root=str(tmp_path),
        prompter=ScriptedPrompter(confirm=False),
        now=_NOW,
    )
    assert outcome.approved is False
    changes = await read_policy_changes(str(tmp_path))
    assert len(changes) >= 1
    assert changes[0]["approved"] == 0


# B: tightening is frictionless -------------------------------------------


async def test_tightening_burst_applies_automatically(tmp_path):
    outcome = await apply_egress_velocity_change(
        {"burst": _BURST_THRESHOLD},
        {"burst": _BURST_THRESHOLD - 5},  # lower → more sensitive → strengthen
        "tighten burst for paranoid mode",
        repo_root=str(tmp_path),
        prompter=ScriptedPrompter(confirm=False),  # prompter never called
        now=_NOW,
    )
    assert outcome.classification is Classification.strengthen
    assert outcome.approved is True
    assert outcome.method == "auto"


async def test_tightening_volume_applies_automatically(tmp_path):
    outcome = await apply_egress_velocity_change(
        {"volume_bytes": _VOLUME_THRESHOLD_BYTES},
        {"volume_bytes": _VOLUME_THRESHOLD_BYTES // 2},
        "tighten volume",
        repo_root=str(tmp_path),
        prompter=ScriptedPrompter(confirm=False),
        now=_NOW,
    )
    assert outcome.classification is Classification.strengthen
    assert outcome.approved is True


async def test_tightening_fanout_applies_automatically(tmp_path):
    outcome = await apply_egress_velocity_change(
        {"fanout": _FANOUT_THRESHOLD},
        {"fanout": _FANOUT_THRESHOLD - 3},
        "tighten fanout",
        repo_root=str(tmp_path),
        prompter=ScriptedPrompter(confirm=False),
        now=_NOW,
    )
    assert outcome.classification is Classification.strengthen
    assert outcome.approved is True


# C: classification is always before-vs-after (current effective thresholds) --


async def test_walkback_toward_default_after_prior_loosening_is_not_a_weaken(tmp_path):
    """The owner's key scenario: someone gate-approved a loosening from 20->25.
    They now want to move from 25->22.  Compared to the current effective
    before (25), 22 is a tighten — the gate must NOT fire.
    Whether 22 is above or below the built-in default (20) is irrelevant;
    only before-vs-after on the stored state matters.
    """
    outcome = await apply_egress_velocity_change(
        {"burst": _BURST_THRESHOLD + 5},  # current effective: 25 (gate-approved loosening)
        {"burst": _BURST_THRESHOLD + 2},  # proposed: 22 — tighter than 25
        "tighten slightly from prior loosened baseline",
        repo_root=str(tmp_path),
        prompter=ScriptedPrompter(confirm=False),  # prompter never invoked on tighten
        now=_NOW,
    )
    assert outcome.classification is Classification.strengthen
    assert outcome.approved is True
    assert outcome.method == "auto"


async def test_raising_from_loosened_baseline_further_is_a_weaken(tmp_path):
    """From a gate-approved loosened baseline (burst=25), going to 30 is a
    further loosening relative to the current effective before — must gate.
    """
    outcome = await apply_egress_velocity_change(
        {"burst": _BURST_THRESHOLD + 5},  # current effective: 25
        {"burst": _BURST_THRESHOLD + 10},  # proposed: 30 — looser than 25
        "loosen further",
        repo_root=str(tmp_path),
        prompter=ScriptedPrompter(confirm=False),
        now=_NOW,
    )
    assert outcome.classification is Classification.weaken
    assert outcome.approved is False


# D: mixed-dimension changes fail safe (any loosen wins) ------------------


async def test_mixed_tighten_and_loosen_is_a_weaken(tmp_path):
    outcome = await apply_egress_velocity_change(
        {"burst": _BURST_THRESHOLD, "fanout": _FANOUT_THRESHOLD},
        {"burst": _BURST_THRESHOLD - 2, "fanout": _FANOUT_THRESHOLD + 2},  # fanout loosens
        "mixed change",
        repo_root=str(tmp_path),
        prompter=ScriptedPrompter(confirm=False),
        now=_NOW,
    )
    assert outcome.classification is Classification.weaken
    assert outcome.approved is False


# E: identical change is neutral (no gate, no friction) -------------------


async def test_identical_change_is_neutral(tmp_path):
    outcome = await apply_egress_velocity_change(
        {"burst": _BURST_THRESHOLD},
        {"burst": _BURST_THRESHOLD},
        "no-op change",
        repo_root=str(tmp_path),
        prompter=ScriptedPrompter(confirm=False),
        now=_NOW,
    )
    assert outcome.classification is Classification.neutral
    assert outcome.approved is True
    assert outcome.method == "auto"
