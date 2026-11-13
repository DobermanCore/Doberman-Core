"""`doctor`'s Claude Code sandbox check: an agent that can write and run a script can read
Doberman's 2FA secret unless the command sandbox is on, cannot be escaped, and denies reads
of the secret's folder. The check only advises (never critical) and never reports OK when
any of that is missing."""

from __future__ import annotations

import json
from pathlib import Path

from doberman.cli.doctor import CheckStatus, _check_agent_sandbox, run_checks

_SAFE = {
    "enabled": True,
    "allowUnsandboxedCommands": False,
    "failIfUnavailable": True,
    "filesystem": {"denyRead": ["~/secrets-home"]},
}


def _write(file: Path, sandbox: dict) -> None:
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_text(json.dumps({"sandbox": sandbox}), encoding="utf-8")


def _check(tmp_path: Path, platform: str = "linux"):
    home, repo = tmp_path / "home", tmp_path / "repo"
    repo.mkdir(exist_ok=True)
    return _check_agent_sandbox(
        str(repo), home=home, platform=platform, secret_dir=home / "secrets-home" / "doberman"
    )


def test_native_windows_warns_that_commands_run_unsandboxed(tmp_path):
    _write(tmp_path / "home" / ".claude" / "settings.json", _SAFE)
    result = _check(tmp_path, platform="win32")
    assert result.status is CheckStatus.WARN
    assert "native Windows" in result.detail
    assert result.critical is False


def test_no_settings_warns(tmp_path):
    assert _check(tmp_path).status is CheckStatus.WARN


def test_sandbox_off_warns(tmp_path):
    _write(tmp_path / "home" / ".claude" / "settings.json", {**_SAFE, "enabled": False})
    result = _check(tmp_path)
    assert result.status is CheckStatus.WARN
    assert "off" in result.detail


def test_escape_hatch_left_open_warns(tmp_path):
    sandbox = {k: v for k, v in _SAFE.items() if k != "allowUnsandboxedCommands"}
    _write(tmp_path / "home" / ".claude" / "settings.json", sandbox)
    result = _check(tmp_path)
    assert result.status is CheckStatus.WARN
    assert "allowUnsandboxedCommands" in result.detail


def test_secret_folder_still_readable_warns(tmp_path):
    _write(
        tmp_path / "home" / ".claude" / "settings.json",
        {**_SAFE, "filesystem": {"denyRead": ["~/.ssh"]}},
    )
    result = _check(tmp_path)
    assert result.status is CheckStatus.WARN
    assert "denyRead" in result.detail


def test_allow_read_reopening_the_secret_folder_warns(tmp_path):
    _write(
        tmp_path / "home" / ".claude" / "settings.json",
        {**_SAFE, "filesystem": {"denyRead": ["~/"], "allowRead": ["~/secrets-home"]}},
    )
    assert _check(tmp_path).status is CheckStatus.WARN


def test_fully_configured_sandbox_is_ok(tmp_path):
    _write(tmp_path / "home" / ".claude" / "settings.json", _SAFE)
    assert _check(tmp_path).status is CheckStatus.OK


def test_home_wide_deny_covers_the_secret_folder(tmp_path):
    _write(
        tmp_path / "home" / ".claude" / "settings.json",
        {**_SAFE, "filesystem": {"denyRead": ["~/"], "allowRead": ["."]}},
    )
    assert _check(tmp_path).status is CheckStatus.OK


def test_project_local_settings_override_user_settings(tmp_path):
    _write(tmp_path / "home" / ".claude" / "settings.json", _SAFE)
    _write(tmp_path / "repo" / ".claude" / "settings.local.json", {"enabled": False})
    assert _check(tmp_path).status is CheckStatus.WARN


def test_corrupt_settings_never_report_ok(tmp_path):
    bad = tmp_path / "repo" / ".claude" / "settings.json"
    bad.parent.mkdir(parents=True)
    bad.write_text("{not json", encoding="utf-8")
    _write(tmp_path / "home" / ".claude" / "settings.json", _SAFE)
    names = {r.name: r for r in run_checks(str(tmp_path / "repo"))}
    assert names["Agent sandbox"].status is not CheckStatus.OK
    assert names["Agent sandbox"].critical is False
