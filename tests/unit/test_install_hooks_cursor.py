"""Install/uninstall Doberman's Cursor hook into a hooks.json (Cursor adapter slice 2).

Mirrors ``test_install_hooks_codex.py`` for Cursor's FLAT hooks.json shape
(``{"version": 1, "hooks": {"<event>": [{"command", "timeout", "failClosed"}]}}``):
idempotent merge, foreign-entry preservation, no-op remove, scope path resolution,
weak-registration diagnosis, install-manifest integrity, doctor's "Cursor hooks"
check, and the CLI wiring (``install-hooks``/``uninstall-hooks --host cursor``).

The per-test isolation fixtures in ``tests/conftest.py`` (``isolated_install_manifest``,
``isolated_fingerprint_key``, ``isolated_password_hash``, ...) are ``autouse`` — no
local fixture is needed to keep these tests off the real per-user manifest/key/state.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from doberman.cli.main import app
from doberman.hosthooks import integrity
from doberman.hosthooks.cursor import (
    EVENT_MCP,
    EVENT_PRE_TOOL,
    EVENT_READ,
    EVENT_SESSION_START,
    EVENT_SHELL,
)
from doberman.hosthooks.install import load_settings, write_settings
from doberman.hosthooks.install_cursor import (
    DEFAULT_APPROVAL_TIMEOUT_S,
    GATE_EVENTS,
    cursor_doberman_groups,
    cursor_hook_install_states,
    merge_cursor_hooks,
    registration_issues,
    remove_cursor_hooks,
    resolve_cursor_hooks_path,
)

runner = CliRunner()

_ALL_EVENTS = (*GATE_EVENTS, EVENT_SESSION_START)


# ---------------------------------------------------------------------------
# merge_cursor_hooks
# ---------------------------------------------------------------------------


def test_merge_registers_all_five_events():
    merged = merge_cursor_hooks({})
    for event in _ALL_EVENTS:
        assert event in merged["hooks"]
        assert merged["hooks"][event][0]["command"] == "doberman hook cursor"


def test_merge_gate_entries_are_failclosed_with_a_long_enough_timeout():
    merged = merge_cursor_hooks({})
    for event in GATE_EVENTS:
        entry = merged["hooks"][event][0]
        assert entry["failClosed"] is True
        assert entry["timeout"] >= DEFAULT_APPROVAL_TIMEOUT_S


def test_merge_session_start_entry_is_not_failclosed():
    merged = merge_cursor_hooks({})
    entry = merged["hooks"][EVENT_SESSION_START][0]
    assert entry["failClosed"] is False


def test_merge_adds_version_when_absent():
    merged = merge_cursor_hooks({})
    assert merged["version"] == 1


def test_merge_keeps_an_existing_version():
    merged = merge_cursor_hooks({"version": 2})
    assert merged["version"] == 2


def test_merge_is_idempotent():
    once = merge_cursor_hooks({})
    twice = merge_cursor_hooks(once)
    for event in _ALL_EVENTS:
        doberman_entries = [
            e for e in twice["hooks"][event] if "doberman hook " in e.get("command", "")
        ]
        assert len(doberman_entries) == 1  # replaced, never duplicated


def test_merge_preserves_foreign_entries_and_events_and_other_keys():
    existing = {
        "hooks": {
            EVENT_PRE_TOOL: [{"command": "some-other-tool", "timeout": 5, "failClosed": True}],
            "afterFileEdit": [{"command": "formatter.sh", "timeout": 5}],
        },
        "other_key": 42,
    }
    merged = merge_cursor_hooks(existing)
    commands = [e["command"] for e in merged["hooks"][EVENT_PRE_TOOL]]
    assert "some-other-tool" in commands  # foreign entry in the same event kept
    assert "doberman hook cursor" in commands
    assert merged["hooks"]["afterFileEdit"][0]["command"] == "formatter.sh"  # foreign event kept
    assert merged["other_key"] == 42


def test_merge_does_not_mutate_input():
    original = {"hooks": {EVENT_PRE_TOOL: []}}
    merge_cursor_hooks(original)
    assert original == {"hooks": {EVENT_PRE_TOOL: []}}


# ---------------------------------------------------------------------------
# remove_cursor_hooks
# ---------------------------------------------------------------------------


def test_remove_is_noop_when_absent():
    settings = {"version": 1, "hooks": {EVENT_PRE_TOOL: [{"command": "not-doberman"}]}}
    assert remove_cursor_hooks(settings) == settings


def test_remove_strips_doberman_and_keeps_foreign():
    merged = merge_cursor_hooks(
        {"hooks": {EVENT_PRE_TOOL: [{"command": "keep-me", "timeout": 5, "failClosed": True}]}}
    )
    cleaned = remove_cursor_hooks(merged)
    commands = [e["command"] for e in cleaned["hooks"][EVENT_PRE_TOOL]]
    assert commands == ["keep-me"]


def test_remove_drops_empty_hooks_key():
    merged = merge_cursor_hooks({})
    cleaned = remove_cursor_hooks(merged)
    assert "hooks" not in cleaned  # only Doberman was present -> hooks removed entirely


def test_remove_keeps_version():
    merged = merge_cursor_hooks({"version": 1})
    cleaned = remove_cursor_hooks(merged)
    assert cleaned["version"] == 1


def test_round_trip_stays_valid_json_and_bak_is_written(tmp_path):
    target = tmp_path / ".cursor" / "hooks.json"
    target.parent.mkdir(parents=True)
    target.write_text('{"version": 1, "hooks": {}}', encoding="utf-8")
    write_settings(target, merge_cursor_hooks(load_settings(target)))
    assert target.with_suffix(".json.bak").exists()
    assert "doberman hook cursor" in target.read_text(encoding="utf-8")

    write_settings(target, remove_cursor_hooks(load_settings(target)))
    json.loads(target.read_text(encoding="utf-8"))  # still valid JSON
    assert "doberman hook cursor" not in target.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# resolve_cursor_hooks_path / cursor_hook_install_states
# ---------------------------------------------------------------------------


def test_resolve_paths():
    assert resolve_cursor_hooks_path("user", "/repo") == Path.home() / ".cursor" / "hooks.json"
    assert resolve_cursor_hooks_path("project", "/repo") == Path("/repo") / ".cursor" / "hooks.json"


@pytest.mark.parametrize("scope", ["repo", "local"])
def test_resolve_rejects_unknown_scope(scope):
    with pytest.raises(ValueError):
        resolve_cursor_hooks_path(scope, "/repo")


def test_install_states_scope_order_and_project_detection(tmp_path):
    (tmp_path / ".cursor").mkdir()
    write_settings(tmp_path / ".cursor" / "hooks.json", merge_cursor_hooks({}))
    states = cursor_hook_install_states(str(tmp_path))
    assert [s for s, _p, _ok in states] == ["user", "project"]
    project = next(s for s in states if s[0] == "project")
    assert project[2] is True


def test_install_states_never_raises_on_bad_json(tmp_path):
    (tmp_path / ".cursor").mkdir()
    (tmp_path / ".cursor" / "hooks.json").write_text("NOT JSON", encoding="utf-8")
    states = cursor_hook_install_states(str(tmp_path))
    assert [s for s, _p, _ok in states] == ["user", "project"]
    project = next(s for s in states if s[0] == "project")
    assert project[2] is False


# ---------------------------------------------------------------------------
# registration_issues
# ---------------------------------------------------------------------------


def _complete_settings() -> dict:
    return merge_cursor_hooks({})


def test_registration_issues_empty_for_a_complete_registration():
    assert registration_issues(_complete_settings()) == []


def test_missing_gate_event_is_critical():
    settings = _complete_settings()
    del settings["hooks"][EVENT_SHELL]
    issues = registration_issues(settings)
    assert (f"{EVENT_SHELL}: not registered", True) in issues


def test_failclosed_false_is_critical():
    settings = _complete_settings()
    settings["hooks"][EVENT_MCP][0]["failClosed"] = False
    issues = registration_issues(settings)
    assert any(msg.startswith(f"{EVENT_MCP}: failClosed is not true") and c for msg, c in issues)


def test_low_timeout_is_non_critical():
    settings = _complete_settings()
    settings["hooks"][EVENT_READ][0]["timeout"] = 30
    issues = registration_issues(settings)
    assert any(
        msg.startswith(f"{EVENT_READ}: timeout 30s is below") and c is False for msg, c in issues
    )


def test_missing_session_start_is_non_critical():
    settings = _complete_settings()
    del settings["hooks"][EVENT_SESSION_START]
    issues = registration_issues(settings)
    assert (
        "sessionStart: not registered (no session heartbeat; doctor cannot tell "
        "whether hooks fire)",
        False,
    ) in issues


def test_foreign_only_entry_counts_as_not_registered():
    settings = {"hooks": {EVENT_PRE_TOOL: [{"command": "someone-elses-tool", "timeout": 999}]}}
    issues = registration_issues(settings)
    assert (f"{EVENT_PRE_TOOL}: not registered", True) in issues


# ---------------------------------------------------------------------------
# CLI: install-hooks / uninstall-hooks --host cursor
# ---------------------------------------------------------------------------


def test_cli_install_writes_hooks_json_and_records_manifest(tmp_path):
    repo = tmp_path / "project"
    repo.mkdir()
    result = runner.invoke(app, ["install-hooks", "--host", "cursor", "--path", str(repo)])
    assert result.exit_code == 0, result.output
    assert "wrote" in result.output

    hooks_path = resolve_cursor_hooks_path("project", str(repo))
    assert hooks_path.exists()
    groups = cursor_doberman_groups(load_settings(hooks_path))
    assert integrity.verify_install("cursor", "project", hooks_path, groups).state == "intact"


def test_cli_install_second_run_says_already_wired(tmp_path):
    repo = tmp_path / "project"
    repo.mkdir()
    runner.invoke(app, ["install-hooks", "--host", "cursor", "--path", str(repo)])
    result = runner.invoke(app, ["install-hooks", "--host", "cursor", "--path", str(repo)])
    assert result.exit_code == 0, result.output
    assert "already wired" in result.output


def test_cli_install_dry_run_writes_nothing_and_names_the_five_events(tmp_path):
    repo = tmp_path / "project"
    repo.mkdir()
    result = runner.invoke(
        app, ["install-hooks", "--host", "cursor", "--path", str(repo), "--dry-run"]
    )
    assert result.exit_code == 0, result.output
    assert not (repo / ".cursor" / "hooks.json").exists()
    for event in _ALL_EVENTS:
        assert event in result.output


def test_cli_install_local_exits_2(tmp_path):
    repo = tmp_path / "project"
    repo.mkdir()
    result = runner.invoke(
        app, ["install-hooks", "--host", "cursor", "--local", "--path", str(repo)]
    )
    assert result.exit_code == 2


def test_cli_install_global_writes_under_home(tmp_path, monkeypatch):
    fake_home = tmp_path / "fake-home"
    fake_home.mkdir()
    monkeypatch.setattr(Path, "home", lambda: fake_home)
    repo = tmp_path / "project"
    repo.mkdir()

    result = runner.invoke(
        app, ["install-hooks", "--host", "cursor", "--global", "--path", str(repo)]
    )
    assert result.exit_code == 0, result.output
    assert (fake_home / ".cursor" / "hooks.json").exists()


def test_cli_uninstall_removes_entries_and_clears_manifest_then_repeat_says_none_found(tmp_path):
    repo = tmp_path / "project"
    repo.mkdir()
    runner.invoke(app, ["install-hooks", "--host", "cursor", "--path", str(repo)])
    hooks_path = resolve_cursor_hooks_path("project", str(repo))

    result = runner.invoke(app, ["uninstall-hooks", "--host", "cursor", "--path", str(repo)])
    assert result.exit_code == 0, result.output
    assert "doberman hook cursor" not in hooks_path.read_text(encoding="utf-8")
    assert integrity.verify_install("cursor", "project", hooks_path, {}).state == "absent"

    repeat = runner.invoke(app, ["uninstall-hooks", "--host", "cursor", "--path", str(repo)])
    assert "No Doberman Cursor hooks found" in repeat.output


def test_unknown_host_error_names_cursor(tmp_path):
    result = runner.invoke(app, ["install-hooks", "--host", "bogus", "--path", str(tmp_path)])
    assert result.exit_code == 2
    assert "cursor" in result.output.lower()

    result = runner.invoke(app, ["uninstall-hooks", "--host", "bogus", "--path", str(tmp_path)])
    assert result.exit_code == 2
    assert "cursor" in result.output.lower()


# ---------------------------------------------------------------------------
# Install-integrity manifest
# ---------------------------------------------------------------------------


def test_integrity_intact_after_install_then_diverges_when_failclosed_flips(tmp_path):
    repo = tmp_path / "project"
    repo.mkdir()
    runner.invoke(app, ["install-hooks", "--host", "cursor", "--path", str(repo)])
    hooks_path = resolve_cursor_hooks_path("project", str(repo))

    statuses = integrity.check_all(str(repo))
    cursor_status = next(s for s in statuses if s.host == "cursor" and s.scope == "project")
    assert cursor_status.state == "intact"

    data = json.loads(hooks_path.read_text(encoding="utf-8"))
    data["hooks"][EVENT_PRE_TOOL][0]["failClosed"] = False
    hooks_path.write_text(json.dumps(data), encoding="utf-8")

    statuses = integrity.check_all(str(repo))
    cursor_status = next(s for s in statuses if s.host == "cursor" and s.scope == "project")
    assert cursor_status.state == "diverged"
    assert cursor_status.critical is True
    assert EVENT_PRE_TOOL in cursor_status.diverged_events

    warning = integrity.hook_warning(str(repo))
    assert warning is not None
    assert "cursor project" in warning


# ---------------------------------------------------------------------------
# doctor's "Cursor hooks" check
# ---------------------------------------------------------------------------


def test_doctor_not_installed_is_ok_and_mentions_host_cursor(tmp_path):
    from doberman.cli.doctor import CheckStatus, run_checks

    check = next(r for r in run_checks(str(tmp_path)) if r.name == "Cursor hooks")
    assert check.status is CheckStatus.OK
    assert "--host cursor" in check.detail


def test_doctor_installed_no_marker_warns(tmp_path):
    from doberman.cli.doctor import CheckStatus, run_checks

    repo = tmp_path / "project"
    repo.mkdir()
    runner.invoke(app, ["install-hooks", "--host", "cursor", "--path", str(repo)])

    check = next(r for r in run_checks(str(repo)) if r.name == "Cursor hooks")
    assert check.status is CheckStatus.WARN
    assert "no Cursor session has called back yet" in check.detail


def test_doctor_installed_with_marker_is_ok_with_timestamp(tmp_path):
    from doberman.cli.doctor import CheckStatus, run_checks
    from doberman.hosthooks.cursor import record_session_start

    repo = tmp_path / "project"
    repo.mkdir()
    runner.invoke(app, ["install-hooks", "--host", "cursor", "--path", str(repo)])
    record_session_start(str(repo))

    check = next(r for r in run_checks(str(repo)) if r.name == "Cursor hooks")
    assert check.status is CheckStatus.OK
    assert "last session start" in check.detail


def test_doctor_failclosed_false_is_critical_fail(tmp_path):
    from doberman.cli.doctor import CheckStatus, run_checks

    repo = tmp_path / "project"
    repo.mkdir()
    runner.invoke(app, ["install-hooks", "--host", "cursor", "--path", str(repo)])
    hooks_path = resolve_cursor_hooks_path("project", str(repo))
    data = json.loads(hooks_path.read_text(encoding="utf-8"))
    data["hooks"][EVENT_SHELL][0]["failClosed"] = False
    hooks_path.write_text(json.dumps(data), encoding="utf-8")

    check = next(r for r in run_checks(str(repo)) if r.name == "Cursor hooks")
    assert check.status is CheckStatus.FAIL
    assert check.critical is True


def test_doctor_low_timeout_warns(tmp_path):
    from doberman.cli.doctor import CheckStatus, run_checks

    repo = tmp_path / "project"
    repo.mkdir()
    runner.invoke(app, ["install-hooks", "--host", "cursor", "--path", str(repo)])
    hooks_path = resolve_cursor_hooks_path("project", str(repo))
    data = json.loads(hooks_path.read_text(encoding="utf-8"))
    data["hooks"][EVENT_READ][0]["timeout"] = 30
    hooks_path.write_text(json.dumps(data), encoding="utf-8")

    check = next(r for r in run_checks(str(repo)) if r.name == "Cursor hooks")
    assert check.status is CheckStatus.WARN


def test_doctor_host_hooks_check_lists_cursor_project(tmp_path):
    from doberman.cli.doctor import run_checks

    repo = tmp_path / "project"
    repo.mkdir()
    runner.invoke(app, ["install-hooks", "--host", "cursor", "--path", str(repo)])

    check = next(r for r in run_checks(str(repo)) if r.name == "Host hooks")
    assert "cursor:project" in check.detail


def test_run_checks_order_has_cursor_hooks_right_after_hook_integrity(tmp_path):
    from doberman.cli.doctor import run_checks

    names = [r.name for r in run_checks(str(tmp_path))]
    assert names.index("Cursor hooks") == names.index("Hook integrity") + 1


# ---------------------------------------------------------------------------
# doberman uninstall (project-scoped) also cleans up Cursor
# ---------------------------------------------------------------------------


def test_project_uninstall_targets_lists_cursor_when_installed(tmp_path):
    from doberman.cli.main import _project_uninstall_targets

    repo = tmp_path / "project"
    repo.mkdir()
    runner.invoke(app, ["install-hooks", "--host", "cursor", "--path", str(repo)])

    targets = _project_uninstall_targets(str(repo))
    assert any(desc == "Cursor hooks (project)" for desc, _p in targets)


def test_gate_passed_uninstall_removes_cursor_project_hooks(tmp_path, monkeypatch):
    from doberman.auth import password
    from doberman.cli import main as cli_main
    from doberman.config import save_policy
    from doberman.policy.checklist import recommend_policy

    class _Correct:
        def confirm(self, message):
            return True

        def read_code(self, message):
            return _password

    _password = "correct horse battery staple"  # noqa: S105 — synthetic test credential
    password.enroll(_password)
    monkeypatch.setattr(cli_main, "CliPrompter", lambda: _Correct())

    repo = tmp_path / "project"
    repo.mkdir()
    runner.invoke(app, ["install-hooks", "--host", "cursor", "--path", str(repo)])
    hooks_path = resolve_cursor_hooks_path("project", str(repo))
    save_policy(recommend_policy(), str(repo))

    result = runner.invoke(app, ["uninstall", "--path", str(repo), "--yes"])

    assert result.exit_code == 0, result.output
    assert "doberman hook cursor" not in hooks_path.read_text(encoding="utf-8")
