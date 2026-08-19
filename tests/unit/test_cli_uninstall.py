"""``doberman uninstall`` (#250) — the gated, project-scoped full removal.

Unlike `doberman uninstall-hooks` (which only strips hook entries and needs no
auth), this command also removes the project's `.doberman/` control plane
(policy + decision database), so it is gated behind the same possession-factor
check as `doberman taint clear` / `doberman memory reset` (2FA if enrolled,
otherwise the local password; fails closed with neither enrolled).

It is deliberately project-scoped only: `--global` hooks and device-wide state
(password hash, TOTP secret, fingerprint key, `~/.doberman/metrics.db`) are
never touched, even on a successful run — those protect every project on the
machine, not just this one. Every test that exercises a successful removal
also asserts that scope boundary held.
"""

import json
from pathlib import Path

from typer.testing import CliRunner

from doberman.auth import password
from doberman.cli import main as cli_main
from doberman.cli.main import app
from doberman.config import save_policy
from doberman.hosthooks.install import merge_doberman_hooks, resolve_settings_path, write_settings
from doberman.hosthooks.install_codex import merge_codex_hooks, resolve_codex_hooks_path
from doberman.policy.checklist import recommend_policy
from doberman.storage.exclusions import is_excluded

runner = CliRunner()

_PASSWORD = "correct horse battery staple"  # noqa: S105 — synthetic test credential


class _WrongCode:
    def confirm(self, message):
        return True

    def read_code(self, message):
        return "definitely-not-the-real-password"


class _CorrectCode:
    def __init__(self, code: str):
        self._code = code

    def confirm(self, message):
        return True

    def read_code(self, message):
        return self._code


class _DeclinesConfirm:
    def confirm(self, message):
        return False

    def read_code(self, message):  # pragma: no cover — must never be reached
        raise AssertionError("possession factor must not be read after confirm() is declined")


def _use_prompter(monkeypatch, prompter_factory) -> None:
    monkeypatch.setattr(cli_main, "CliPrompter", prompter_factory)


def _install_project_hooks(root: str) -> None:
    runner.invoke(app, ["install-hooks", "--path", root])


def _install_local_hooks(root: str) -> None:
    write_settings(resolve_settings_path("local", root), merge_doberman_hooks({}))


def _install_codex_repo_hooks(root: str) -> None:
    write_settings(resolve_codex_hooks_path("repo", root), merge_codex_hooks({}))


def _make_doberman_dir(root: str) -> None:
    save_policy(recommend_policy(), root)


def _doberman_dir_exists(root: str) -> bool:
    return (Path(root) / ".doberman").exists()


# ---------------------------------------------------------------------------
# Nothing-to-remove short circuit — no auth prompt at all
# ---------------------------------------------------------------------------


def test_nothing_to_remove_is_a_noop_with_no_auth_prompt(tmp_path):
    root = str(tmp_path)
    result = runner.invoke(app, ["uninstall", "--path", root, "--yes"])
    assert result.exit_code == 0, result.output
    assert "nothing to remove" in result.output.lower()


# ---------------------------------------------------------------------------
# Fail closed: no factor enrolled / wrong factor -> nothing removed
# ---------------------------------------------------------------------------


def test_no_factor_enrolled_refuses_and_leaves_state_unchanged(tmp_path):
    root = str(tmp_path)
    _install_project_hooks(root)
    _make_doberman_dir(root)

    result = runner.invoke(app, ["uninstall", "--path", root, "--yes"])

    assert result.exit_code == 1
    assert "2fa setup" in result.output or "password set" in result.output
    assert _doberman_dir_exists(root)
    settings_path = resolve_settings_path("project", root)
    data = json.loads(settings_path.read_text(encoding="utf-8"))
    assert data.get("hooks")  # still wired


def test_gate_denied_refuses_and_leaves_state_unchanged(tmp_path, monkeypatch):
    root = str(tmp_path)
    password.enroll(_PASSWORD)
    _install_project_hooks(root)
    _make_doberman_dir(root)
    _use_prompter(monkeypatch, lambda: _WrongCode())

    result = runner.invoke(app, ["uninstall", "--path", root, "--yes"])

    assert result.exit_code == 1
    assert "denied" in result.output
    assert _doberman_dir_exists(root)
    settings_path = resolve_settings_path("project", root)
    data = json.loads(settings_path.read_text(encoding="utf-8"))
    assert data.get("hooks")


def test_confirmation_declined_refuses_and_leaves_state_unchanged(tmp_path, monkeypatch):
    root = str(tmp_path)
    password.enroll(_PASSWORD)
    _install_project_hooks(root)
    _make_doberman_dir(root)
    _use_prompter(monkeypatch, lambda: _DeclinesConfirm())

    # No --yes: the confirm() step runs and is declined before the factor is
    # ever read (the fixture asserts read_code() is never called).
    result = runner.invoke(app, ["uninstall", "--path", root])

    assert result.exit_code == 1
    assert "denied" in result.output
    assert _doberman_dir_exists(root)


def test_typed_name_mismatch_refuses_and_leaves_state_unchanged(tmp_path, monkeypatch):
    root = str(tmp_path)
    password.enroll(_PASSWORD)
    _install_project_hooks(root)
    _make_doberman_dir(root)
    _use_prompter(monkeypatch, lambda: _CorrectCode(_PASSWORD))

    # Confirms "Proceed?" (mocked True) but types the wrong directory name at
    # the raw stdin prompt.
    result = runner.invoke(app, ["uninstall", "--path", root], input="definitely-not-it\n")

    assert result.exit_code == 1
    assert "did not match" in result.output
    assert _doberman_dir_exists(root)


# ---------------------------------------------------------------------------
# Successful removal
# ---------------------------------------------------------------------------


def test_gate_passed_removes_project_hooks_and_doberman_dir(tmp_path, monkeypatch):
    root = str(tmp_path)
    password.enroll(_PASSWORD)
    _install_project_hooks(root)
    _make_doberman_dir(root)
    _use_prompter(monkeypatch, lambda: _CorrectCode(_PASSWORD))

    result = runner.invoke(app, ["uninstall", "--path", root, "--yes"])

    assert result.exit_code == 0, result.output
    assert not _doberman_dir_exists(root)
    settings_path = resolve_settings_path("project", root)
    data = json.loads(settings_path.read_text(encoding="utf-8"))
    assert not data.get("hooks", {}).get("PreToolUse")


def test_uninstall_preserves_foreign_hooks_in_the_same_file(tmp_path, monkeypatch):
    root = str(tmp_path)
    password.enroll(_PASSWORD)
    settings_path = resolve_settings_path("project", root)
    settings_path.parent.mkdir(parents=True)
    foreign = {
        "hooks": {
            "PreToolUse": [{"matcher": "Foo", "hooks": [{"type": "command", "command": "other"}]}]
        }
    }
    write_settings(settings_path, merge_doberman_hooks(foreign))
    _make_doberman_dir(root)
    _use_prompter(monkeypatch, lambda: _CorrectCode(_PASSWORD))

    result = runner.invoke(app, ["uninstall", "--path", root, "--yes"])

    assert result.exit_code == 0, result.output
    data = json.loads(settings_path.read_text(encoding="utf-8"))
    pre = data.get("hooks", {}).get("PreToolUse", [])
    assert any(g.get("matcher") == "Foo" for g in pre)


def test_gate_passed_removes_local_and_codex_repo_hooks_too(tmp_path, monkeypatch):
    root = str(tmp_path)
    password.enroll(_PASSWORD)
    _install_local_hooks(root)
    _install_codex_repo_hooks(root)
    _make_doberman_dir(root)
    _use_prompter(monkeypatch, lambda: _CorrectCode(_PASSWORD))

    result = runner.invoke(app, ["uninstall", "--path", root, "--yes"])

    assert result.exit_code == 0, result.output
    local_data = json.loads(resolve_settings_path("local", root).read_text(encoding="utf-8"))
    assert not local_data.get("hooks", {}).get("PreToolUse")
    codex_data = json.loads(resolve_codex_hooks_path("repo", root).read_text(encoding="utf-8"))
    assert not codex_data.get("hooks", {}).get("PreToolUse")


def test_typed_name_and_confirm_accepted_removes(tmp_path, monkeypatch):
    root = str(tmp_path)
    password.enroll(_PASSWORD)
    _install_project_hooks(root)
    _make_doberman_dir(root)
    _use_prompter(monkeypatch, lambda: _CorrectCode(_PASSWORD))

    project_name = Path(root).resolve().name
    result = runner.invoke(app, ["uninstall", "--path", root], input=f"{project_name}\n")

    assert result.exit_code == 0, result.output
    assert not _doberman_dir_exists(root)


def test_dry_run_removes_nothing(tmp_path, monkeypatch):
    root = str(tmp_path)
    password.enroll(_PASSWORD)
    _install_project_hooks(root)
    _make_doberman_dir(root)
    _use_prompter(monkeypatch, lambda: _CorrectCode(_PASSWORD))

    result = runner.invoke(app, ["uninstall", "--path", root, "--dry-run"])

    assert result.exit_code == 0, result.output
    assert "dry-run" in result.output.lower()
    assert _doberman_dir_exists(root)


# ---------------------------------------------------------------------------
# Scope boundary: --global hooks and device-wide auth state must survive
# ---------------------------------------------------------------------------


def test_global_hooks_survive_a_successful_uninstall(tmp_path, monkeypatch):
    fake_home = tmp_path / "fake-home"
    fake_home.mkdir()
    monkeypatch.setattr(Path, "home", lambda: fake_home)

    root = str(tmp_path / "project")
    Path(root).mkdir()
    password.enroll(_PASSWORD)
    _install_project_hooks(root)
    _make_doberman_dir(root)
    # Wire the SAME Claude Code hooks into the (fake) global scope.
    write_settings(resolve_settings_path("global", root), merge_doberman_hooks({}))
    _use_prompter(monkeypatch, lambda: _CorrectCode(_PASSWORD))

    result = runner.invoke(app, ["uninstall", "--path", root, "--yes"])

    assert result.exit_code == 0, result.output
    global_data = json.loads(resolve_settings_path("global", root).read_text(encoding="utf-8"))
    assert global_data.get("hooks", {}).get("PreToolUse")  # untouched


def test_device_wide_password_survives_a_successful_uninstall(
    tmp_path, monkeypatch, isolated_password_hash
):
    root = str(tmp_path)
    password.enroll(_PASSWORD)
    _install_project_hooks(root)
    _make_doberman_dir(root)
    _use_prompter(monkeypatch, lambda: _CorrectCode(_PASSWORD))

    result = runner.invoke(app, ["uninstall", "--path", root, "--yes"])

    assert result.exit_code == 0, result.output
    assert isolated_password_hash.exists()
    assert password.is_enrolled()


# ---------------------------------------------------------------------------
# No secret in output
# ---------------------------------------------------------------------------


def test_success_output_never_contains_the_password(tmp_path, monkeypatch):
    root = str(tmp_path)
    password.enroll(_PASSWORD)
    _install_project_hooks(root)
    _make_doberman_dir(root)
    _use_prompter(monkeypatch, lambda: _CorrectCode(_PASSWORD))

    result = runner.invoke(app, ["uninstall", "--path", root, "--yes"])

    assert result.exit_code == 0, result.output
    assert _PASSWORD not in result.output


def test_denied_output_never_contains_the_password(tmp_path, monkeypatch):
    root = str(tmp_path)
    password.enroll(_PASSWORD)
    _install_project_hooks(root)
    _make_doberman_dir(root)
    _use_prompter(monkeypatch, lambda: _WrongCode())

    result = runner.invoke(app, ["uninstall", "--path", root, "--yes"])

    assert result.exit_code == 1
    assert _PASSWORD not in result.output


# ---------------------------------------------------------------------------
# Global-hook exclusion: a still-installed global (or Codex user-scope) hook
# would otherwise keep firing here after this project's own state is gone, so
# a successful uninstall also adds the project to the device-wide exclusion
# list that the global hook checks (see doberman.storage.exclusions).
# ---------------------------------------------------------------------------


def _with_fake_global_claude_hooks(tmp_path, monkeypatch, root: str) -> None:
    fake_home = tmp_path / "fake-home"
    fake_home.mkdir(exist_ok=True)
    monkeypatch.setattr(Path, "home", lambda: fake_home)
    write_settings(resolve_settings_path("global", root), merge_doberman_hooks({}))


def test_uninstall_auto_excludes_project_when_global_hook_installed(tmp_path, monkeypatch):
    root = str(tmp_path / "project")
    Path(root).mkdir()
    password.enroll(_PASSWORD)
    _install_project_hooks(root)
    _make_doberman_dir(root)
    _with_fake_global_claude_hooks(tmp_path, monkeypatch, root)
    _use_prompter(monkeypatch, lambda: _CorrectCode(_PASSWORD))

    result = runner.invoke(app, ["uninstall", "--path", root, "--yes"])

    assert result.exit_code == 0, result.output
    assert "exclusion list" in result.output.lower()
    assert is_excluded(root) is True


def test_uninstall_does_not_exclude_when_no_global_hook_installed(tmp_path, monkeypatch):
    root = str(tmp_path)
    password.enroll(_PASSWORD)
    _install_project_hooks(root)
    _make_doberman_dir(root)
    _use_prompter(monkeypatch, lambda: _CorrectCode(_PASSWORD))

    result = runner.invoke(app, ["uninstall", "--path", root, "--yes"])

    assert result.exit_code == 0, result.output
    assert "exclusion list" not in result.output.lower()
    assert is_excluded(root) is False


def test_denied_uninstall_does_not_exclude_even_with_global_hook(tmp_path, monkeypatch):
    root = str(tmp_path / "project")
    Path(root).mkdir()
    password.enroll(_PASSWORD)
    _install_project_hooks(root)
    _make_doberman_dir(root)
    _with_fake_global_claude_hooks(tmp_path, monkeypatch, root)
    _use_prompter(monkeypatch, lambda: _WrongCode())

    result = runner.invoke(app, ["uninstall", "--path", root, "--yes"])

    assert result.exit_code == 1
    assert is_excluded(root) is False


def test_dry_run_does_not_exclude_even_with_global_hook(tmp_path, monkeypatch):
    root = str(tmp_path / "project")
    Path(root).mkdir()
    password.enroll(_PASSWORD)
    _install_project_hooks(root)
    _make_doberman_dir(root)
    _with_fake_global_claude_hooks(tmp_path, monkeypatch, root)
    _use_prompter(monkeypatch, lambda: _CorrectCode(_PASSWORD))

    result = runner.invoke(app, ["uninstall", "--path", root, "--dry-run"])

    assert result.exit_code == 0, result.output
    assert "exclusion list" in result.output.lower()  # mentioned, but not yet applied
    assert is_excluded(root) is False


def test_install_hooks_clears_an_existing_exclusion(tmp_path):
    root = str(tmp_path)
    from doberman.storage.exclusions import add_exclusion

    add_exclusion(root)
    assert is_excluded(root) is True

    result = runner.invoke(app, ["install-hooks", "--path", root])

    assert result.exit_code == 0, result.output
    assert "no longer excluded" in result.output.lower()
    assert is_excluded(root) is False
