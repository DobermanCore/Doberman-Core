from __future__ import annotations

import json
from pathlib import Path

import pytest

from doberman.hosthooks import integrity


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
