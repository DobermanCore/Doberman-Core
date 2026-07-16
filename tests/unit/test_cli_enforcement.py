"""CLI: ``doberman enforcement <enforce|monitor|off>`` (UX-A).

Wires the gated setter :func:`doberman.policy.drift.apply_enforcement_change` to a
command so a user finally has an in-product way to turn Doberman's enforcement
down. The security-critical property is the round trip: a soften set through this
command persists the exact fields the ledger recorded, so the read-side
:func:`effective_enforcement` clamp *confirms* it -- while a soften hand-edited
straight into the yaml (no approved ledger row) is still clamped back to
``enforce``.

Covers: show, the confirm-gated soften round trip, denial leaves state unchanged
(fail closed), unknown state rejected, re-arm is never gated, and the hand-edit
tamper contrast. 2FA is unenrolled here (the ``isolated_totp_secret`` conftest
fixture points the secret at an empty temp path), so the gate takes the
confirm-only safety-valve path.
"""

import yaml
from typer.testing import CliRunner

from doberman import config
from doberman.cli.main import app

runner = CliRunner()


class _Approve:
    """Present operator who confirms (and would supply a code if asked)."""

    def confirm(self, message):
        return True

    def read_code(self, message):  # pragma: no cover -- unenrolled path never asks
        return "999999"


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


def _use_prompter(monkeypatch, prompter_cls):
    # apply_enforcement_change lazily does `from doberman.auth.provider import CliPrompter`
    # only on the weaken path, so patch the class it constructs there.
    monkeypatch.setattr("doberman.auth.provider.CliPrompter", prompter_cls)


def test_show_defaults_to_enforce(tmp_path):
    result = runner.invoke(app, ["enforcement", "--path", str(tmp_path)])
    assert result.exit_code == 0
    assert result.stdout.strip() == "enforce"


def test_set_off_is_confirm_gated_persisted_and_effective(tmp_path, monkeypatch):
    _use_prompter(monkeypatch, _Approve)
    result = runner.invoke(app, ["enforcement", "off", "--path", str(tmp_path)])
    assert result.exit_code == 0
    assert "enforcement set to off" in result.stdout
    # Persisted on disk AND the ledger confirms it -> the effective state is really off.
    assert config.load_enforcement(str(tmp_path))[0] == "off"
    assert config.resolve_enforcement_sync(str(tmp_path)) == "off"


def test_set_monitor_round_trips(tmp_path, monkeypatch):
    _use_prompter(monkeypatch, _Approve)
    result = runner.invoke(app, ["enforcement", "monitor", "--path", str(tmp_path)])
    assert result.exit_code == 0
    assert config.resolve_enforcement_sync(str(tmp_path)) == "monitor"


def test_denied_soften_leaves_state_unchanged(tmp_path, monkeypatch):
    _use_prompter(monkeypatch, _Decline)
    result = runner.invoke(app, ["enforcement", "off", "--path", str(tmp_path)])
    assert result.exit_code == 1
    # Nothing persisted; effective stays enforce (fail closed).
    assert config.load_enforcement(str(tmp_path))[0] == "enforce"
    assert config.resolve_enforcement_sync(str(tmp_path)) == "enforce"


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
    _use_prompter(monkeypatch, _Approve)
    assert runner.invoke(app, ["enforcement", "off", "--path", str(tmp_path)]).exit_code == 0
    # Re-arming is a strengthen: it must apply with no prompt at all.
    _use_prompter(monkeypatch, _Boom)
    result = runner.invoke(app, ["enforcement", "enforce", "--path", str(tmp_path)])
    assert result.exit_code == 0
    assert "enforcement set to enforce" in result.stdout
    assert config.resolve_enforcement_sync(str(tmp_path)) == "enforce"


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
