"""CLI: ``doberman enforcement <enforce|monitor|off>`` (UX-A).

Wires the gated setter :func:`doberman.policy.drift.apply_enforcement_change` to a
command so a user finally has an in-product way to turn Doberman's enforcement
down. The security-critical property is the round trip: a soften set through this
command persists the exact fields the ledger recorded, so the read-side
:func:`effective_enforcement` clamp *confirms* it -- while a soften hand-edited
straight into the yaml (no approved ledger row) is still clamped back to
``enforce``.

Covers: show, the gated soften round trip (TOTP if enrolled, else the local
password), denial leaves state unchanged (fail closed), no factor enrolled fails
closed (there is no confirm-only fallback anymore), unknown state rejected,
re-arm is never gated, and the hand-edit tamper contrast.
"""

import asyncio

import pyotp
import yaml
from typer.testing import CliRunner

from doberman import config
from doberman.auth import password, totp
from doberman.cli.main import app
from doberman.policy.drift import read_policy_changes

runner = CliRunner()

_PASSWORD = "correct horse battery staple"  # noqa: S105 — synthetic test credential


class _Approve:
    """Present operator: confirms and supplies one out-of-band factor."""

    def __init__(self, code="999999"):
        self._code = code

    def confirm(self, message):
        return True

    def read_code(self, message):
        return self._code


class _ConfirmOnly:
    """Confirms but has no factor to give -- read_code must never be reached
    when no factor is enrolled (there is no confirm-only fallback anymore)."""

    def confirm(self, message):
        return True

    def read_code(self, message):
        raise AssertionError("no factor is enrolled, so no secret prompt is valid")


class _Decline:
    def confirm(self, message):
        return False

    def read_code(self, message):  # pragma: no cover -- never reached after a decline
        raise AssertionError("read_code must not be reached after a declined confirm")


class _Boom:
    """Any prompt is a failure -- proves a re-arm (strengthen) is never gated."""

    def confirm(self, message):
        raise AssertionError("a re-arm must not prompt")

    def read_code(self, message):
        raise AssertionError("a re-arm must not prompt")


def _use_prompter(monkeypatch, prompter_factory):
    # apply_enforcement_change lazily does `from doberman.auth.provider import CliPrompter`
    # only on the weaken path, so patch the class it constructs there.
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


def _assert_latest_ledger_method(root: str, method: str, *, approved: int) -> None:
    # read_policy_changes returns newest first -> row 0 is the most recent change.
    rows = asyncio.run(read_policy_changes(root))
    assert rows[0]["approval_method"] == method
    assert rows[0]["approved"] == approved


def test_show_defaults_to_enforce(tmp_path):
    result = runner.invoke(app, ["enforcement", "--path", str(tmp_path)])
    assert result.exit_code == 0
    assert result.stdout.strip() == "enforce"


def test_set_off_with_totp_enrolled_and_valid_code_is_gated_persisted_and_effective(
    tmp_path, monkeypatch
):
    code = _enrolled_code()
    _use_prompter(monkeypatch, lambda: _Approve(code))
    result = runner.invoke(app, ["enforcement", "off", "--path", str(tmp_path)])
    assert result.exit_code == 0
    assert "enforcement set to off" in result.stdout
    # Persisted on disk AND the ledger confirms it -> the effective state is really off.
    assert config.load_enforcement(str(tmp_path))[0] == "off"
    assert config.resolve_enforcement_sync(str(tmp_path)) == "off"
    _assert_single_ledger_method(str(tmp_path), "two_factor", approved=1)


def test_set_off_with_totp_enrolled_and_wrong_code_is_denied(tmp_path, monkeypatch):
    _enrolled_code()  # enroll, but supply a code that never verifies
    _use_prompter(monkeypatch, lambda: _Approve("000000"))
    result = runner.invoke(app, ["enforcement", "off", "--path", str(tmp_path)])
    assert result.exit_code == 1
    assert config.resolve_enforcement_sync(str(tmp_path)) == "enforce"
    _assert_single_ledger_method(str(tmp_path), "denied", approved=0)


def test_set_off_with_password_only_accepts_password(tmp_path, monkeypatch):
    password.enroll(_PASSWORD)
    _use_prompter(monkeypatch, lambda: _Approve(_PASSWORD))
    result = runner.invoke(app, ["enforcement", "off", "--path", str(tmp_path)])
    assert result.exit_code == 0
    assert config.resolve_enforcement_sync(str(tmp_path)) == "off"
    _assert_single_ledger_method(str(tmp_path), "password", approved=1)


def test_set_off_with_password_only_rejects_wrong_password(tmp_path, monkeypatch):
    password.enroll(_PASSWORD)
    _use_prompter(monkeypatch, lambda: _Approve("wrong password"))
    result = runner.invoke(app, ["enforcement", "off", "--path", str(tmp_path)])
    assert result.exit_code == 1
    assert config.resolve_enforcement_sync(str(tmp_path)) == "enforce"
    _assert_single_ledger_method(str(tmp_path), "denied", approved=0)


def test_set_off_with_both_enrolled_totp_wins_password_is_rejected(tmp_path, monkeypatch):
    password.enroll(_PASSWORD)  # TOTP must win when both factors are enrolled.
    code = _enrolled_code()
    # A valid TOTP code softens...
    _use_prompter(monkeypatch, lambda: _Approve(code))
    result = runner.invoke(app, ["enforcement", "off", "--path", str(tmp_path)])
    assert result.exit_code == 0
    assert config.resolve_enforcement_sync(str(tmp_path)) == "off"
    _assert_single_ledger_method(str(tmp_path), "two_factor", approved=1)

    # Re-arm (a strengthen) back to enforce so a further soften attempt is possible
    # -- re-arming is never gated, so no factor is needed here.
    _use_prompter(monkeypatch, _Boom)
    assert runner.invoke(app, ["enforcement", "enforce", "--path", str(tmp_path)]).exit_code == 0

    # ...but supplying the (correct) PASSWORD instead of a TOTP code to soften again
    # is rejected: the password cannot substitute for TOTP once TOTP is enrolled.
    _use_prompter(monkeypatch, lambda: _Approve(_PASSWORD))
    result = runner.invoke(app, ["enforcement", "monitor", "--path", str(tmp_path)])
    assert result.exit_code == 1
    assert config.resolve_enforcement_sync(str(tmp_path)) == "enforce"  # unchanged


def test_set_monitor_round_trips(tmp_path, monkeypatch):
    password.enroll(_PASSWORD)
    _use_prompter(monkeypatch, lambda: _Approve(_PASSWORD))
    result = runner.invoke(app, ["enforcement", "monitor", "--path", str(tmp_path)])
    assert result.exit_code == 0
    assert config.resolve_enforcement_sync(str(tmp_path)) == "monitor"


def test_denied_soften_leaves_state_unchanged(tmp_path, monkeypatch):
    password.enroll(_PASSWORD)
    _use_prompter(monkeypatch, _Decline)
    result = runner.invoke(app, ["enforcement", "off", "--path", str(tmp_path)])
    assert result.exit_code == 1
    # Nothing persisted; effective stays enforce (fail closed).
    assert config.load_enforcement(str(tmp_path))[0] == "enforce"
    assert config.resolve_enforcement_sync(str(tmp_path)) == "enforce"


def test_set_off_with_no_factor_enrolled_fails_closed(tmp_path, monkeypatch):
    # Neither TOTP nor password enrolled (conftest isolates both to empty temp
    # paths): the off-switch must not be reachable via confirm-only anymore.
    _use_prompter(monkeypatch, _ConfirmOnly)
    result = runner.invoke(app, ["enforcement", "off", "--path", str(tmp_path)])
    assert result.exit_code == 1
    assert config.load_enforcement(str(tmp_path))[0] == "enforce"
    assert config.resolve_enforcement_sync(str(tmp_path)) == "enforce"
    _assert_single_ledger_method(str(tmp_path), "no_factor_enrolled", approved=0)


def test_unknown_state_is_rejected(tmp_path):
    result = runner.invoke(app, ["enforcement", "banana", "--path", str(tmp_path)])
    assert result.exit_code == 2
    # A typo never reaches the gate or the policy file.
    assert config.load_enforcement(str(tmp_path))[0] == "enforce"


def test_no_op_is_a_friendly_noop(tmp_path):
    result = runner.invoke(app, ["enforcement", "enforce", "--path", str(tmp_path)])
    assert result.exit_code == 0
    assert "already enforce" in result.stdout


def test_re_arm_is_never_gated(tmp_path, monkeypatch):
    password.enroll(_PASSWORD)
    _use_prompter(monkeypatch, lambda: _Approve(_PASSWORD))
    assert runner.invoke(app, ["enforcement", "off", "--path", str(tmp_path)]).exit_code == 0
    # Re-arming is a strengthen: it must apply with no prompt at all.
    _use_prompter(monkeypatch, _Boom)
    result = runner.invoke(app, ["enforcement", "enforce", "--path", str(tmp_path)])
    assert result.exit_code == 0
    assert "enforcement set to enforce" in result.stdout
    assert config.resolve_enforcement_sync(str(tmp_path)) == "enforce"
    _assert_latest_ledger_method(str(tmp_path), "auto", approved=1)


def test_hand_edited_off_without_ledger_is_clamped(tmp_path):
    # Why the command exists: writing `enforcement: off` straight into the yaml with
    # no approved ledger row is tamper -> the read-side clamp forces enforce.
    ddir = tmp_path / ".doberman"
    ddir.mkdir()
    (ddir / "policies.yaml").write_text(
        yaml.safe_dump({"items": [], "enforcement": "off"}), encoding="utf-8"
    )
    assert config.load_enforcement(str(tmp_path))[0] == "off"  # raw on-disk claim
    assert config.resolve_enforcement_sync(str(tmp_path)) == "enforce"  # clamped
