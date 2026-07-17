"""#79 / C1 slice 2 — mode changes are ledgered through the lowering gate.

A downgrade requires the strongest enrolled possession factor (TOTP, otherwise
password) and fails closed without one; an upgrade stays frictionless. A no-op
writes no row, and a gate failure never applies the change.
"""

import asyncio

import pyotp
from typer.testing import CliRunner

from doberman.auth import password, totp
from doberman.cli import main as cli_main
from doberman.cli.main import app
from doberman.config import load_mode
from doberman.policy.drift import read_policy_changes

runner = CliRunner()
_PASSWORD = "correct horse battery staple"  # noqa: S105 — synthetic test credential


def test_mode_downgrade_without_a_factor_is_denied_and_records_a_weaken_row(tmp_path, monkeypatch):
    root = str(tmp_path)
    # Fresh repo has no saved policy -> default mode is "balanced"; light is a
    # downgrade. Nothing is enrolled, so the possession-factor gate denies it.

    class _ConfirmOnly:
        def confirm(self, message):
            return True

        def read_code(self, message):
            raise AssertionError("no factor is enrolled, so no secret prompt is valid")

    monkeypatch.setattr("doberman.auth.provider.CliPrompter", _ConfirmOnly)

    result = runner.invoke(app, ["mode", "light", "--path", root])
    assert result.exit_code == 1
    assert "denied" in result.output.lower()
    assert load_mode(root) == "balanced"  # unchanged

    rows = asyncio.run(read_policy_changes(root))
    assert len(rows) == 1
    row = rows[0]
    assert row["rule_id"] == "mode"
    assert row["classification"] == "weaken"
    assert row["approval_method"] == "no_factor_enrolled"
    assert row["approved"] == 0
    assert row["from_state"] == "balanced"
    assert row["to_state"] == "light"


def test_mode_downgrade_with_valid_2fa_is_approved_and_records_a_weaken_row(tmp_path, monkeypatch):
    root = str(tmp_path)
    password.enroll(_PASSWORD)  # TOTP is required when both factors exist.
    totp.enroll()
    code = pyotp.TOTP(totp._read_secret()).now()

    class _Approve:
        def confirm(self, message):
            return True

        def read_code(self, message):
            return code

    # apply_change lazily does `from doberman.auth.provider import CliPrompter`
    # only on the weaken path, so patch the name it constructs there.
    monkeypatch.setattr("doberman.auth.provider.CliPrompter", _Approve)

    result = runner.invoke(app, ["mode", "light", "--path", root])
    assert result.exit_code == 0, result.output
    assert load_mode(root) == "light"

    rows = asyncio.run(read_policy_changes(root))
    assert len(rows) == 1
    row = rows[0]
    assert row["classification"] == "weaken"
    assert row["approval_method"] == "two_factor"
    assert row["approved"] == 1


def test_mode_downgrade_with_password_only_records_password_approval(tmp_path, monkeypatch):
    root = str(tmp_path)
    password.enroll(_PASSWORD)

    class _Approve:
        def confirm(self, message):
            return True

        def read_code(self, message):
            return _PASSWORD

    monkeypatch.setattr("doberman.auth.provider.CliPrompter", _Approve)

    result = runner.invoke(app, ["mode", "light", "--path", root])

    assert result.exit_code == 0, result.output
    assert load_mode(root) == "light"
    rows = asyncio.run(read_policy_changes(root))
    assert len(rows) == 1
    assert rows[0]["approval_method"] == "password"
    assert rows[0]["approved"] == 1


def test_mode_upgrade_from_default_records_a_strengthen_row(tmp_path):
    root = str(tmp_path)
    result = runner.invoke(app, ["mode", "strict", "--path", root])
    assert result.exit_code == 0, result.output

    rows = asyncio.run(read_policy_changes(root))
    assert len(rows) == 1
    row = rows[0]
    assert row["classification"] == "strengthen"
    assert row["approval_method"] == "auto"
    assert row["approved"] == 1
    assert row["from_state"] == "balanced"
    assert row["to_state"] == "strict"


def test_same_mode_invocation_records_nothing(tmp_path):
    root = str(tmp_path)
    # Default is already "balanced"; re-asserting it is a no-op.
    result = runner.invoke(app, ["mode", "balanced", "--path", root])
    assert result.exit_code == 0, result.output
    assert asyncio.run(read_policy_changes(root)) == []


def test_gate_failure_never_applies_the_mode_change(tmp_path, monkeypatch):
    """Fail closed: if the gate chokepoint itself blows up, the mode change
    must NOT apply (this replaces the old fail-OPEN `log_change`-failure test
    -- the previous behavior silently applied the change despite the failure,
    which is exactly the bug this slice removes).
    """
    root = str(tmp_path)

    async def _boom(*args, **kwargs):
        raise RuntimeError("gate exploded")

    monkeypatch.setattr(cli_main, "apply_change", _boom)

    result = runner.invoke(app, ["mode", "light", "--path", root])

    assert result.exit_code != 0
    assert load_mode(root) == "balanced"  # unchanged -- the gate failure denied the change
