"""Unit tests for the foreign lifecycle hook fingerprint ledger (issue #821)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from doberman.cli.doctor import CheckStatus, run_checks
from doberman.cli.main import app
from doberman.hosthooks import claude_code, integrity
from doberman.hosthooks.install import resolve_settings_path
from doberman.hosthooks.install_codex import resolve_codex_hooks_path
from doberman.hosthooks.install_cursor import resolve_cursor_hooks_path


@pytest.fixture
def ledger_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    key = tmp_path / "fp.key"
    manifest = tmp_path / "manifest.json"
    monkeypatch.setenv("DOBERMAN_KEY_FILE", str(key))
    monkeypatch.setenv(integrity.MANIFEST_ENV, str(manifest))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    repo = tmp_path / "repo"
    repo.mkdir(exist_ok=True)
    return repo, manifest


def _hook_integrity_row(repo: Path):
    return next(r for r in run_checks(str(repo)) if r.name == "Hook integrity")


def test_install_records_foreign_ledger_without_raw_commands_or_paths(
    ledger_env: tuple[Path, Path],
) -> None:
    repo, manifest = ledger_env
    settings_path = resolve_settings_path("project", str(repo))
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    foreign_cmd = "curl -s https://example.invalid/boot --header MARKER-XYZ-99"
    settings_path.write_text(
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {"matcher": "*", "hooks": [{"type": "command", "command": foreign_cmd}]}
                    ]
                }
            }
        ),
        encoding="utf-8",
    )

    res = CliRunner().invoke(app, ["install-hooks", "--path", str(repo)])
    assert res.exit_code == 0

    raw = manifest.read_text(encoding="utf-8")
    assert foreign_cmd not in raw
    assert "MARKER-XYZ-99" not in raw
    assert str(repo) not in raw
    data = json.loads(raw)
    entry = data["entries"][0]
    assert len(entry["foreign_ledger"]["PreToolUse"]) == 1
    assert entry["foreign_ledger"]["PreToolUse"][0].startswith("hmac:")

    # Existing foreign hook present at install time produces no alarm.
    status = next(
        s for s in integrity.check_all(str(repo)) if s.host == "claude" and s.scope == "project"
    )
    assert status.state == "intact"
    assert status.foreign_changed_events == ()
    assert _hook_integrity_row(repo).status is CheckStatus.OK
    assert integrity.hook_warning(str(repo)) is None


def test_added_and_modified_claude_foreign_hook_reported_separately_from_diverged(
    ledger_env: tuple[Path, Path],
) -> None:
    repo, _manifest = ledger_env
    assert CliRunner().invoke(app, ["install-hooks", "--path", str(repo)]).exit_code == 0

    settings_path = resolve_settings_path("project", str(repo))
    data = json.loads(settings_path.read_text(encoding="utf-8"))
    foreign_cmd = "echo foreign-payload-alpha"
    data["hooks"].setdefault("PreToolUse", []).append(
        {"matcher": "*", "hooks": [{"type": "command", "command": foreign_cmd}]}
    )
    settings_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    status = next(
        s for s in integrity.check_all(str(repo)) if s.host == "claude" and s.scope == "project"
    )
    # Doberman's own hooks are intact; foreign additions stay separate from diverged.
    assert status.state == "intact"
    assert status.diverged_events == ()
    assert status.foreign_changed_events == ("PreToolUse",)

    row = _hook_integrity_row(repo)
    assert row.status is CheckStatus.WARN
    assert row.critical is False
    assert "foreign hook" in row.detail
    assert "PreToolUse" in row.detail
    assert foreign_cmd not in row.detail

    warning = integrity.hook_warning(str(repo))
    assert warning is not None
    assert "foreign hook" in warning
    assert "claude project: PreToolUse" in warning
    assert foreign_cmd not in warning

    # Hook verdict on a benign tool call is never altered by a foreign ledger warning.
    verdict = claude_code.evaluate_pre(
        {"tool_name": "Read", "tool_input": {"file_path": "README.md"}, "cwd": str(repo)}
    )
    assert verdict is None

    # Re-running install-hooks updates the ledger and clears the warning.
    assert CliRunner().invoke(app, ["install-hooks", "--path", str(repo)]).exit_code == 0
    assert _hook_integrity_row(repo).status is CheckStatus.OK
    assert integrity.hook_warning(str(repo)) is None

    # Mutating that recorded foreign hook command trips the ledger again.
    data = json.loads(settings_path.read_text(encoding="utf-8"))
    for group in data["hooks"]["PreToolUse"]:
        for h in group.get("hooks", []):
            if h.get("command") == foreign_cmd:
                h["command"] = "echo foreign-payload-beta"
    settings_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    status_after_edit = next(
        s for s in integrity.check_all(str(repo)) if s.host == "claude" and s.scope == "project"
    )
    assert status_after_edit.state == "intact"
    assert status_after_edit.foreign_changed_events == ("PreToolUse",)
    assert _hook_integrity_row(repo).status is CheckStatus.WARN


def test_codex_and_cursor_foreign_hooks_detected(ledger_env: tuple[Path, Path]) -> None:
    repo, _manifest = ledger_env
    assert (
        CliRunner().invoke(app, ["install-hooks", "--host", "codex", "--path", str(repo)]).exit_code
        == 0
    )
    assert (
        CliRunner()
        .invoke(app, ["install-hooks", "--host", "cursor", "--path", str(repo)])
        .exit_code
        == 0
    )

    codex_path = resolve_codex_hooks_path("repo", str(repo))
    codex_data = json.loads(codex_path.read_text(encoding="utf-8"))
    codex_data["hooks"].setdefault("SessionStart", []).append(
        {"hooks": [{"type": "command", "command": "echo codex-foreign"}]}
    )
    codex_path.write_text(json.dumps(codex_data), encoding="utf-8")

    cursor_path = resolve_cursor_hooks_path("project", str(repo))
    cursor_data = json.loads(cursor_path.read_text(encoding="utf-8"))
    cursor_data["hooks"].setdefault("beforeShellExecution", []).append(
        {"command": "echo cursor-foreign", "timeout": 10}
    )
    cursor_path.write_text(json.dumps(cursor_data), encoding="utf-8")

    statuses = {(s.host, s.scope): s for s in integrity.check_all(str(repo))}
    assert statuses[("codex", "repo")].state == "intact"
    assert statuses[("codex", "repo")].foreign_changed_events == ("SessionStart",)
    assert statuses[("cursor", "project")].state == "intact"
    assert statuses[("cursor", "project")].foreign_changed_events == ("beforeShellExecution",)

    warning = integrity.hook_warning(str(repo))
    assert warning is not None
    assert "codex repo: SessionStart" in warning
    assert "cursor project: beforeShellExecution" in warning
    assert "codex-foreign" not in warning
    assert "cursor-foreign" not in warning


def test_malformed_settings_file_degrades_without_raising(
    ledger_env: tuple[Path, Path],
) -> None:
    repo, _manifest = ledger_env
    assert CliRunner().invoke(app, ["install-hooks", "--path", str(repo)]).exit_code == 0

    settings_path = resolve_settings_path("project", str(repo))
    settings_path.write_text("{not valid json", encoding="utf-8")

    statuses = integrity.check_all(str(repo))
    claude_project = next(s for s in statuses if s.host == "claude" and s.scope == "project")
    assert claude_project.state == "absent"
    assert claude_project.foreign_changed_events == ()
    assert integrity.hook_warning(str(repo)) is None
