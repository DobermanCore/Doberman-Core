from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from doberman.cli.main import app
from doberman.hosthooks import integrity
from doberman.hosthooks.install import (
    doberman_groups,
    load_settings,
    merge_doberman_hooks,
    resolve_settings_path,
)


@pytest.fixture
def manifest_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    key = tmp_path / "fp.key"
    manifest = tmp_path / "manifest.json"
    monkeypatch.setenv("DOBERMAN_KEY_FILE", str(key))
    monkeypatch.setenv(integrity.MANIFEST_ENV, str(manifest))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    return manifest


PRE = {"matcher": "Bash", "hooks": [{"type": "command", "command": "doberman hook pre"}]}
POST = {"matcher": "Bash", "hooks": [{"type": "command", "command": "doberman hook post"}]}
START = {"hooks": [{"type": "command", "command": "doberman session-summary"}]}
GROUPS = {"PreToolUse": [PRE], "PostToolUse": [POST], "SessionStart": [START]}


def test_record_then_verify_is_intact(manifest_env: Path, tmp_path: Path) -> None:
    settings = tmp_path / "repo" / ".claude" / "settings.json"
    integrity.record_install("claude", "project", settings, GROUPS)
    status = integrity.verify_install("claude", "project", settings, GROUPS)
    assert status.state == "intact"
    assert status.diverged_events == ()
    assert status.critical is False


def test_missing_pretooluse_is_critical_divergence(manifest_env: Path, tmp_path: Path) -> None:
    settings = tmp_path / "repo" / ".claude" / "settings.json"
    integrity.record_install("claude", "project", settings, GROUPS)
    stripped = {"PostToolUse": [POST], "SessionStart": [START]}
    status = integrity.verify_install("claude", "project", settings, stripped)
    assert status.state == "diverged"
    assert status.diverged_events == ("PreToolUse",)
    assert status.critical is True


def test_changed_sessionstart_is_non_critical_divergence(
    manifest_env: Path, tmp_path: Path
) -> None:
    settings = tmp_path / "repo" / ".claude" / "settings.json"
    integrity.record_install("claude", "project", settings, GROUPS)
    changed = dict(
        GROUPS,
        SessionStart=[
            {"hooks": [{"type": "command", "command": "doberman session-summary --quiet"}]}
        ],
    )
    status = integrity.verify_install("claude", "project", settings, changed)
    assert status.state == "diverged"
    assert status.diverged_events == ("SessionStart",)
    assert status.critical is False


def test_addition_of_foreign_group_is_not_divergence(manifest_env: Path, tmp_path: Path) -> None:
    settings = tmp_path / "repo" / ".claude" / "settings.json"
    integrity.record_install("claude", "project", settings, GROUPS)
    # The caller only passes Doberman-owned groups; a new event key with no
    # Doberman group is simply ignored.
    status = integrity.verify_install("claude", "project", settings, dict(GROUPS, Stop=[]))
    assert status.state == "intact"


def test_no_entry_is_absent(manifest_env: Path, tmp_path: Path) -> None:
    settings = tmp_path / "repo" / ".claude" / "settings.json"
    status = integrity.verify_install("claude", "project", settings, GROUPS)
    assert status.state == "absent"
    assert status.critical is False


def test_clear_removes_only_that_entry(manifest_env: Path, tmp_path: Path) -> None:
    a = tmp_path / "a" / ".claude" / "settings.json"
    b = tmp_path / "b" / ".claude" / "settings.json"
    integrity.record_install("claude", "project", a, GROUPS)
    integrity.record_install("claude", "project", b, GROUPS)
    integrity.clear_install("claude", "project", a)
    assert integrity.verify_install("claude", "project", a, {}).state == "absent"
    assert integrity.verify_install("claude", "project", b, GROUPS).state == "intact"
    integrity.clear_install("claude", "project", a)  # idempotent, no raise


def test_manifest_holds_no_paths_or_commands(manifest_env: Path, tmp_path: Path) -> None:
    settings = tmp_path / "repo" / ".claude" / "settings.json"
    secret_group = {
        "hooks": [{"type": "command", "command": "doberman hook pre --token SECRET-XYZ-123"}]
    }
    integrity.record_install("claude", "project", settings, {"PreToolUse": [secret_group]})
    raw = manifest_env.read_text(encoding="utf-8")
    assert str(tmp_path) not in raw
    assert "repo" not in raw
    assert "SECRET-XYZ-123" not in raw
    assert "doberman hook pre" not in raw
    data = json.loads(raw)
    entry = data["entries"][0]
    assert entry["path_fp"].startswith("hmac:")
    assert entry["groups"]["PreToolUse"].startswith("hmac:")


def test_corrupt_manifest_reads_as_absent(manifest_env: Path, tmp_path: Path) -> None:
    manifest_env.write_text("{not json", encoding="utf-8")
    settings = tmp_path / "repo" / ".claude" / "settings.json"
    status = integrity.verify_install("claude", "project", settings, GROUPS)
    assert status.state == "absent"


def test_missing_key_never_raises_from_verify(
    manifest_env: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = tmp_path / "repo" / ".claude" / "settings.json"
    integrity.record_install("claude", "project", settings, GROUPS)
    monkeypatch.setenv(
        "DOBERMAN_KEY_FILE",
        str(tmp_path / "missing" / "dir" / "that" / "cannot" / "be" / "made" / "\0bad"),
    )
    status = integrity.verify_install("claude", "project", settings, GROUPS)
    assert status.state == "absent"


def test_note_divergence_records_first_and_last_seen(manifest_env: Path, tmp_path: Path) -> None:
    settings = tmp_path / "repo" / ".claude" / "settings.json"
    integrity.record_install("claude", "project", settings, GROUPS)
    integrity.note_divergence("claude", "project", settings, ("PreToolUse",))
    integrity.note_divergence("claude", "project", settings, ("PreToolUse",))
    data = json.loads(manifest_env.read_text(encoding="utf-8"))
    div = data["entries"][0]["diverged"]
    assert div["events"] == ["PreToolUse"]
    assert div["count"] == 2
    assert div["first_seen"] <= div["last_seen"]
    status = integrity.verify_install("claude", "project", settings, GROUPS)
    assert status.state == "intact"
    assert status.divergence_seen == div["last_seen"]


def test_record_install_clears_old_divergence(manifest_env: Path, tmp_path: Path) -> None:
    settings = tmp_path / "repo" / ".claude" / "settings.json"
    integrity.record_install("claude", "project", settings, GROUPS)
    integrity.note_divergence("claude", "project", settings, ("PreToolUse",))
    integrity.record_install("claude", "project", settings, GROUPS)
    assert integrity.verify_install("claude", "project", settings, GROUPS).divergence_seen is None


def test_user_config_dir_backs_the_key_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from doberman.storage import fingerprint as fp

    monkeypatch.delenv("DOBERMAN_KEY_FILE", raising=False)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    assert fp._default_key_path() == fp.user_config_dir() / "fingerprint.key"


# ---------------------------------------------------------------------------
# CLI wiring — install-hooks / uninstall-hooks record and clear the manifest
# ---------------------------------------------------------------------------


def test_doberman_groups_extracts_only_our_groups() -> None:
    foreign = {"matcher": "Bash", "hooks": [{"type": "command", "command": "echo hi"}]}
    merged = merge_doberman_hooks({"hooks": {"PreToolUse": [foreign]}})
    groups = doberman_groups(merged)
    assert set(groups) == {"PreToolUse", "PostToolUse", "SessionStart"}
    assert foreign not in groups["PreToolUse"]
    assert doberman_groups({}) == {}


def test_install_hooks_records_manifest(manifest_env: Path, tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir(exist_ok=True)
    result = CliRunner().invoke(app, ["install-hooks", "--path", str(repo)])
    assert result.exit_code == 0, result.output
    settings_path = resolve_settings_path("project", str(repo))
    groups = doberman_groups(load_settings(settings_path))
    assert integrity.verify_install("claude", "project", settings_path, groups).state == "intact"


def test_install_hooks_already_wired_still_records(manifest_env: Path, tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir(exist_ok=True)
    runner = CliRunner()
    assert runner.invoke(app, ["install-hooks", "--path", str(repo)]).exit_code == 0
    manifest_env.unlink()  # simulate a pre-manifest install
    assert runner.invoke(app, ["install-hooks", "--path", str(repo)]).exit_code == 0
    settings_path = resolve_settings_path("project", str(repo))
    groups = doberman_groups(load_settings(settings_path))
    assert integrity.verify_install("claude", "project", settings_path, groups).state == "intact"


def test_install_hooks_dry_run_writes_no_manifest(manifest_env: Path, tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir(exist_ok=True)
    result = CliRunner().invoke(app, ["install-hooks", "--path", str(repo), "--dry-run"])
    assert result.exit_code == 0, result.output
    assert not manifest_env.exists()


def test_uninstall_hooks_clears_manifest_first(manifest_env: Path, tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir(exist_ok=True)
    runner = CliRunner()
    assert runner.invoke(app, ["install-hooks", "--path", str(repo)]).exit_code == 0
    assert runner.invoke(app, ["uninstall-hooks", "--path", str(repo)]).exit_code == 0
    settings_path = resolve_settings_path("project", str(repo))
    assert integrity.verify_install("claude", "project", settings_path, {}).state == "absent"


def test_manifest_write_failure_does_not_fail_install(
    manifest_env: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir(exist_ok=True)
    monkeypatch.setenv(integrity.MANIFEST_ENV, str(tmp_path))  # a directory: unwritable as a file
    result = CliRunner().invoke(app, ["install-hooks", "--path", str(repo)])
    assert result.exit_code == 0, result.output
    assert "manifest" in result.output.lower()


def test_codex_install_records_and_uninstall_clears(manifest_env: Path, tmp_path: Path) -> None:
    from doberman.hosthooks.install_codex import codex_doberman_groups, resolve_codex_hooks_path

    repo = tmp_path / "repo"
    repo.mkdir(exist_ok=True)
    runner = CliRunner()
    assert (
        runner.invoke(app, ["install-hooks", "--host", "codex", "--path", str(repo)]).exit_code == 0
    )
    # No --global -> the Codex repo scope (the Claude "project" scope's analog).
    hooks_path = resolve_codex_hooks_path("repo", str(repo))
    groups = codex_doberman_groups(load_settings(hooks_path))
    assert groups["PreToolUse"]
    assert integrity.verify_install("codex", "repo", hooks_path, groups).state == "intact"
    assert (
        runner.invoke(app, ["uninstall-hooks", "--host", "codex", "--path", str(repo)]).exit_code
        == 0
    )
    assert integrity.verify_install("codex", "repo", hooks_path, groups).state == "absent"
