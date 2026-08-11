"""Feature 7 CLI surface — `doberman 2fa setup`, `revoke`, and `status`.

These tests are synchronous on purpose: the CLI calls ``asyncio.run`` internally,
which cannot nest inside a running event loop. Seeding async state uses
``asyncio.run`` directly.
"""

import asyncio
from datetime import datetime, timezone

import pyotp
from typer.testing import CliRunner

from doberman.auth import totp
from doberman.cli.main import app
from doberman.storage.db import grant_elevation

runner = CliRunner()


def test_2fa_setup_enrolls_and_guards_overwrite():
    assert totp.is_enrolled() is False
    result = runner.invoke(app, ["2fa", "setup"])
    assert result.exit_code == 0
    assert "otpauth://" in result.stdout
    assert totp.is_enrolled() is True

    again = runner.invoke(app, ["2fa", "setup"])
    assert again.exit_code == 1  # refuses to silently overwrite

    first = totp._read_secret()
    assert first is not None
    current_code = pyotp.TOTP(first).now()
    forced = runner.invoke(app, ["2fa", "setup", "--force"], input=f"{current_code}\n")
    assert forced.exit_code == 0
    assert "Current 2FA code" in forced.stdout
    assert totp._read_secret() != first


def test_2fa_setup_force_rejects_wrong_current_code():
    totp.enroll()
    first = totp._read_secret()

    result = runner.invoke(app, ["2fa", "setup", "--force"], input="not-a-code\n")

    assert result.exit_code == 1
    assert "current 2FA code" in result.stderr
    assert totp._read_secret() == first


def test_status_reports_2fa_and_no_elevations(tmp_path):
    result = runner.invoke(app, ["status", "--path", str(tmp_path)])
    assert result.exit_code == 0
    assert "2FA:" in result.stdout
    assert "Elevations: (none active)" in result.stdout


def test_status_lists_then_revoke_removes_an_elevation(tmp_path):
    root = str(tmp_path)
    # Seed with real "now" — `doberman status` evaluates activity against the
    # wall clock, so a fixed past timestamp would read as already-expired.
    grant = asyncio.run(
        grant_elevation(root, "backend/api.ts", "task", now=datetime.now(timezone.utc))
    )

    listed = runner.invoke(app, ["status", "--path", root])
    assert grant.id in listed.stdout
    assert "backend/api.ts" in listed.stdout

    revoked = runner.invoke(app, ["revoke", grant.id, "--path", root])
    assert revoked.exit_code == 0
    assert "revoked" in revoked.stdout

    after = runner.invoke(app, ["status", "--path", root])
    assert "none active" in after.stdout


def test_revoke_unknown_id_errors(tmp_path):
    result = runner.invoke(app, ["revoke", "no-such-id", "--path", str(tmp_path)])
    assert result.exit_code == 1
    assert result.stderr == "error: no elevation with id no-such-id\n"
