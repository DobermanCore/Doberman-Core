"""CLI coverage for the ``doberman egress-velocity`` command (issue #457).

Mirrors test_cli_lowering_gate.py in structure:
- Loosening (raising burst/volume-bytes/fanout relative to the current
  effective value) requires the strongest enrolled possession factor.
- Tightening (lowering) is frictionless — the prompter must never be called.
- The show path (no arguments) prints the three active thresholds.
- Bad knob names and missing values exit with code 2.
"""

import asyncio

import pyotp
import pytest
from typer.testing import CliRunner

from doberman.auth import password, totp
from doberman.cli.main import app
from doberman.config import load_policy, save_policy
from doberman.egress.velocity import (
    _BURST_THRESHOLD,
    _FANOUT_THRESHOLD,
    _VOLUME_THRESHOLD_BYTES,
    VelocityThresholds,
)
from doberman.policy.checklist import recommend_policy
from doberman.policy.drift import read_policy_changes

runner = CliRunner()

_PASSWORD = "correct horse battery staple"  # noqa: S105 — synthetic test credential


# ---------------------------------------------------------------------------
# Prompter stubs (same shapes as test_cli_lowering_gate.py)
# ---------------------------------------------------------------------------


class _Decline:
    def confirm(self, message):
        return False

    def read_code(self, message):  # pragma: no cover
        raise AssertionError("read_code must not be reached after a declined confirm")


class _Boom:
    """Any prompt is a failure — proves a tighten is never gated."""

    def confirm(self, message):
        raise AssertionError("a tighten must not prompt")

    def read_code(self, message):
        raise AssertionError("a tighten must not prompt")


class _Approve:
    def __init__(self, code):
        self._code = code

    def confirm(self, message):
        return True

    def read_code(self, message):
        return self._code


class _ConfirmOnly:
    def confirm(self, message):
        return True

    def read_code(self, message):
        raise AssertionError("no factor is enrolled, so no secret prompt is valid")


def _use_prompter(monkeypatch, prompter_factory):
    monkeypatch.setattr("doberman.auth.provider.CliPrompter", prompter_factory)


def _enrolled_code() -> str:
    totp.enroll()
    secret = totp._read_secret()
    assert secret is not None
    return pyotp.TOTP(secret).now()


def _assert_single_ledger_method(root: str, method: str, *, approved: int) -> None:
    rows = asyncio.run(read_policy_changes(root))
    assert len(rows) == 1
    assert rows[0]["approval_method"] == method
    assert rows[0]["approved"] == approved


# ---------------------------------------------------------------------------
# A: show path (no arguments)
# ---------------------------------------------------------------------------


def test_show_displays_built_in_defaults_when_no_policy_saved(tmp_path):
    result = runner.invoke(app, ["egress-velocity", "--path", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "burst" in result.output
    assert "volume-bytes" in result.output
    assert "fanout" in result.output
    assert str(_BURST_THRESHOLD) in result.output
    assert str(_FANOUT_THRESHOLD) in result.output


def test_show_displays_custom_thresholds_when_policy_saved(tmp_path):
    root = str(tmp_path)
    doc = recommend_policy().with_egress_velocity_thresholds(
        VelocityThresholds(burst=5, volume_bytes=1024, fanout=2)
    )
    save_policy(doc, root)
    result = runner.invoke(app, ["egress-velocity", "--path", root])
    assert result.exit_code == 0, result.output
    assert "5" in result.output
    assert "1024" in result.output
    assert "2" in result.output


# ---------------------------------------------------------------------------
# B: tightening is frictionless — prompter must never be invoked
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("knob", "tighter_value"),
    [
        ("burst", _BURST_THRESHOLD - 5),
        ("volume-bytes", _VOLUME_THRESHOLD_BYTES // 2),
        ("fanout", _FANOUT_THRESHOLD - 3),
    ],
)
def test_tightening_applies_automatically_without_prompting(
    knob, tighter_value, tmp_path, monkeypatch
):
    root = str(tmp_path)
    _use_prompter(monkeypatch, _Boom)  # would raise if called

    result = runner.invoke(app, ["egress-velocity", knob, str(tighter_value), "--path", root])

    assert result.exit_code == 0, result.output
    assert str(tighter_value) in result.output
    _assert_single_ledger_method(root, "auto", approved=1)

    # Confirm the value was actually persisted.
    doc = load_policy(root)
    assert doc is not None
    t = doc.egress_velocity_thresholds
    assert t is not None
    key = knob.replace("-", "_")
    assert getattr(t, key) == tighter_value


# ---------------------------------------------------------------------------
# C: loosening requires the strongest enrolled possession factor
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("knob", "looser_value"),
    [
        ("burst", _BURST_THRESHOLD + 5),
        ("volume-bytes", _VOLUME_THRESHOLD_BYTES * 2),
        ("fanout", _FANOUT_THRESHOLD + 3),
    ],
)
def test_loosening_with_enrolled_2fa_and_valid_totp_is_approved(
    knob, looser_value, tmp_path, monkeypatch
):
    root = str(tmp_path)
    password.enroll(_PASSWORD)
    code = _enrolled_code()
    _use_prompter(monkeypatch, lambda: _Approve(code))

    result = runner.invoke(app, ["egress-velocity", knob, str(looser_value), "--path", root])

    assert result.exit_code == 0, result.output
    _assert_single_ledger_method(root, "two_factor", approved=1)

    doc = load_policy(root)
    assert doc is not None and doc.egress_velocity_thresholds is not None
    key = knob.replace("-", "_")
    assert getattr(doc.egress_velocity_thresholds, key) == looser_value


def test_loosening_denied_when_confirm_declined(tmp_path, monkeypatch):
    root = str(tmp_path)
    _use_prompter(monkeypatch, lambda: _Decline())

    result = runner.invoke(
        app, ["egress-velocity", "burst", str(_BURST_THRESHOLD + 5), "--path", root]
    )

    assert result.exit_code == 1
    assert "denied" in result.stderr
    assert load_policy(root) is None  # nothing persisted
    _assert_single_ledger_method(root, "denied", approved=0)


def test_loosening_with_password_only_accepts_correct_password(tmp_path, monkeypatch):
    root = str(tmp_path)
    password.enroll(_PASSWORD)
    _use_prompter(monkeypatch, lambda: _Approve(_PASSWORD))

    result = runner.invoke(
        app, ["egress-velocity", "burst", str(_BURST_THRESHOLD + 5), "--path", root]
    )

    assert result.exit_code == 0, result.output
    _assert_single_ledger_method(root, "password", approved=1)


def test_loosening_with_password_only_rejects_wrong_password(tmp_path, monkeypatch):
    root = str(tmp_path)
    password.enroll(_PASSWORD)
    _use_prompter(monkeypatch, lambda: _Approve("wrong password"))

    result = runner.invoke(
        app, ["egress-velocity", "burst", str(_BURST_THRESHOLD + 5), "--path", root]
    )

    assert result.exit_code == 1
    assert load_policy(root) is None
    _assert_single_ledger_method(root, "denied", approved=0)


def test_loosening_with_no_factor_enrolled_fails_closed(tmp_path, monkeypatch):
    root = str(tmp_path)
    _use_prompter(monkeypatch, _ConfirmOnly)

    result = runner.invoke(
        app, ["egress-velocity", "burst", str(_BURST_THRESHOLD + 5), "--path", root]
    )

    assert result.exit_code == 1
    assert load_policy(root) is None
    _assert_single_ledger_method(root, "no_factor_enrolled", approved=0)


# ---------------------------------------------------------------------------
# D: denial is recorded in the append-only ledger
# ---------------------------------------------------------------------------


def test_denied_loosening_is_recorded_in_ledger(tmp_path, monkeypatch):
    root = str(tmp_path)
    _use_prompter(monkeypatch, lambda: _Decline())

    runner.invoke(app, ["egress-velocity", "fanout", str(_FANOUT_THRESHOLD + 3), "--path", root])

    rows = asyncio.run(read_policy_changes(root))
    assert len(rows) == 1
    assert rows[0]["approved"] == 0


# ---------------------------------------------------------------------------
# E: owner's key scenario — walkback from a gate-approved loosened baseline
#    is a strengthen (frictionless), not a weaken
# ---------------------------------------------------------------------------


def test_tightening_from_loosened_baseline_is_frictionless(tmp_path, monkeypatch):
    """A gate-approved loosening puts burst at THRESHOLD+5.  Moving to
    THRESHOLD+2 is tighter than the current stored value, so it must apply
    automatically without prompting — even though THRESHOLD+2 is still above
    the built-in default.
    """
    root = str(tmp_path)
    # Establish a loosened baseline (THRESHOLD+5) via gate approval.
    password.enroll(_PASSWORD)
    code = _enrolled_code()
    _use_prompter(monkeypatch, lambda: _Approve(code))
    r = runner.invoke(app, ["egress-velocity", "burst", str(_BURST_THRESHOLD + 5), "--path", root])
    assert r.exit_code == 0, r.output

    # Now tighten to THRESHOLD+2 — must be frictionless.
    _use_prompter(monkeypatch, _Boom)  # would raise if gate is invoked
    r2 = runner.invoke(app, ["egress-velocity", "burst", str(_BURST_THRESHOLD + 2), "--path", root])
    assert r2.exit_code == 0, r2.output
    doc = load_policy(root)
    assert doc is not None
    assert doc.egress_velocity_thresholds is not None
    assert doc.egress_velocity_thresholds.burst == _BURST_THRESHOLD + 2


# ---------------------------------------------------------------------------
# F: bad input — exit code 2, nothing persisted
# ---------------------------------------------------------------------------


def test_unknown_knob_exits_with_code_2(tmp_path):
    result = runner.invoke(app, ["egress-velocity", "unknown-knob", "10", "--path", str(tmp_path)])
    assert result.exit_code == 2
    assert load_policy(str(tmp_path)) is None


def test_missing_value_exits_with_code_2(tmp_path):
    result = runner.invoke(app, ["egress-velocity", "burst", "--path", str(tmp_path)])
    assert result.exit_code == 2


def test_non_positive_value_exits_with_code_2(tmp_path):
    result = runner.invoke(app, ["egress-velocity", "burst", "0", "--path", str(tmp_path)])
    assert result.exit_code == 2
