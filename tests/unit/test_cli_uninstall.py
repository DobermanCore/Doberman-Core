"""``doberman uninstall`` — gated project or device-wide removal.

Unlike `doberman uninstall-hooks` (which only strips hook entries and needs no
auth), this command also removes the project's `.doberman/` control plane
(policy + decision database), so it is gated behind the same possession-factor
check as `doberman taint clear` / `doberman memory reset` (2FA if enrolled,
otherwise the local password; fails closed with neither enrolled).

Without ``--global`` the command remains strictly project-scoped.  The global
form deliberately removes every writable hook scope and device-wide secret/state
before scheduling package removal, behind the same fail-closed factor gate.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from doberman.auth import password
from doberman.cli import main as cli_main
from doberman.cli.main import app
from doberman.config import save_policy
from doberman.hosthooks import install_codex
from doberman.hosthooks.install import merge_doberman_hooks, resolve_settings_path, write_settings
from doberman.hosthooks.install_codex import merge_codex_hooks, resolve_codex_hooks_path
from doberman.policy.checklist import recommend_policy

runner = CliRunner()

_PASSWORD = "correct horse battery staple"  # noqa: S105 — synthetic test credential


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    """No uninstall probe may inspect the real Claude/Codex user settings."""
    fake_home = tmp_path / "home"
    fake_home.mkdir(exist_ok=True)
    monkeypatch.setattr(Path, "home", lambda: fake_home)
    monkeypatch.setattr(install_codex, "_PLUGIN_ROOT", fake_home / ".codex" / "plugins" / "cache")
    return fake_home


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


def _install_global_hooks(root: str) -> None:
    write_settings(resolve_settings_path("global", root), merge_doberman_hooks({"theme": "dark"}))


def _install_codex_user_hooks(root: str) -> None:
    write_settings(resolve_codex_hooks_path("user", root), merge_codex_hooks({"notify": "foreign"}))


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
# Device-wide removal (--global)
# ---------------------------------------------------------------------------


def _seed_global_targets(
    tmp_path,
    monkeypatch,
    isolated_totp_secret,
    isolated_password_hash,
    isolated_fingerprint_key,
    isolated_device_metrics_home,
):
    fake_home = tmp_path / "fake-home"
    fake_home.mkdir(exist_ok=True)
    monkeypatch.setattr(Path, "home", lambda: fake_home)
    root = tmp_path / "project"
    root.mkdir(exist_ok=True)
    root_text = str(root)

    password.enroll(_PASSWORD)
    isolated_totp_secret.write_text("", encoding="utf-8")  # target exists, but is not enrolled
    isolated_fingerprint_key.write_bytes(b"x" * 32)
    device_dir = isolated_device_metrics_home / ".doberman"
    device_dir.mkdir(parents=True)
    (device_dir / "metrics.db").write_bytes(b"metrics")
    (device_dir / "telemetry-state.json").write_text("{}", encoding="utf-8")

    for scope in ("project", "local"):
        write_settings(
            resolve_settings_path(scope, root_text),
            merge_doberman_hooks({"foreign": scope}),
        )
    _install_global_hooks(root_text)
    write_settings(
        resolve_codex_hooks_path("repo", root_text),
        merge_codex_hooks({"foreign": "repo"}),
    )
    _install_codex_user_hooks(root_text)
    _make_doberman_dir(root_text)
    return root_text, device_dir


def _plain_package(monkeypatch):
    argv = [sys.executable, "-m", "pip", "uninstall", "-y", "doberman-core"]
    monkeypatch.setattr(cli_main, "_package_remover", lambda: ("pip", argv))
    return argv


def test_global_dry_run_lists_every_target_and_removes_nothing(
    tmp_path,
    monkeypatch,
    isolated_totp_secret,
    isolated_password_hash,
    isolated_fingerprint_key,
    isolated_device_metrics_home,
):
    root, device_dir = _seed_global_targets(
        tmp_path,
        monkeypatch,
        isolated_totp_secret,
        isolated_password_hash,
        isolated_fingerprint_key,
        isolated_device_metrics_home,
    )
    argv = _plain_package(monkeypatch)

    result = runner.invoke(app, ["uninstall", "--global", "--path", root, "--dry-run"])

    assert result.exit_code == 0, result.output
    for label in (
        "Claude Code hooks (global)",
        "Claude Code hooks (project)",
        "Claude Code hooks (local)",
        "Codex CLI hooks (user)",
        "Codex CLI hooks (repo)",
        "Codex CLI hooks (plugin scope; not writable)",
        ".doberman/ (policy + decision database)",
        "TOTP enrollment",
        "password enrollment",
        "fingerprint key",
        "device-wide state directory",
        "package",
    ):
        assert label in result.output
    assert "codex plugin remove" in result.output
    assert subprocess.list2cmdline(argv) in result.output
    assert _doberman_dir_exists(root)
    assert isolated_totp_secret.exists()
    assert isolated_password_hash.exists()
    assert isolated_fingerprint_key.exists()
    assert device_dir.exists()
    assert json.loads(resolve_settings_path("global", root).read_text(encoding="utf-8"))["hooks"]


def test_global_no_factor_refuses_without_removing_anything(
    tmp_path, monkeypatch, isolated_totp_secret, isolated_fingerprint_key
):
    fake_home = tmp_path / "fake-home"
    fake_home.mkdir()
    monkeypatch.setattr(Path, "home", lambda: fake_home)
    root = str(tmp_path / "project")
    Path(root).mkdir()
    _install_global_hooks(root)
    _make_doberman_dir(root)
    isolated_totp_secret.write_text("", encoding="utf-8")
    isolated_fingerprint_key.write_bytes(b"x" * 32)
    _plain_package(monkeypatch)

    result = runner.invoke(app, ["uninstall", "--global", "--path", root, "--yes"])

    assert result.exit_code == 1
    assert "2fa setup" in result.output or "password set" in result.output
    assert _doberman_dir_exists(root)
    assert isolated_totp_secret.exists()
    assert isolated_fingerprint_key.exists()
    assert json.loads(resolve_settings_path("global", root).read_text(encoding="utf-8"))["hooks"]


def test_global_wrong_factor_keeps_factor_files_and_all_targets(
    tmp_path,
    monkeypatch,
    isolated_totp_secret,
    isolated_password_hash,
    isolated_fingerprint_key,
    isolated_device_metrics_home,
):
    root, device_dir = _seed_global_targets(
        tmp_path,
        monkeypatch,
        isolated_totp_secret,
        isolated_password_hash,
        isolated_fingerprint_key,
        isolated_device_metrics_home,
    )
    _plain_package(monkeypatch)
    _use_prompter(monkeypatch, lambda: _WrongCode())

    result = runner.invoke(app, ["uninstall", "--global", "--path", root, "--yes"])

    assert result.exit_code == 1
    assert "denied" in result.output
    assert isolated_totp_secret.exists()
    assert isolated_password_hash.exists()
    assert isolated_fingerprint_key.exists()
    assert device_dir.exists()
    assert _doberman_dir_exists(root)


def test_global_typed_word_mismatch_refuses_unchanged(
    tmp_path,
    monkeypatch,
    isolated_totp_secret,
    isolated_password_hash,
    isolated_fingerprint_key,
    isolated_device_metrics_home,
):
    root, device_dir = _seed_global_targets(
        tmp_path,
        monkeypatch,
        isolated_totp_secret,
        isolated_password_hash,
        isolated_fingerprint_key,
        isolated_device_metrics_home,
    )
    _plain_package(monkeypatch)
    _use_prompter(monkeypatch, lambda: _CorrectCode(_PASSWORD))

    result = runner.invoke(app, ["uninstall", "--global", "--path", root], input="NOT-DOBERMAN\n")

    assert result.exit_code == 1
    assert "did not match" in result.output
    assert isolated_password_hash.exists()
    assert device_dir.exists()
    assert _doberman_dir_exists(root)


def test_global_success_removes_all_writable_targets_then_schedules_package(
    tmp_path,
    monkeypatch,
    isolated_totp_secret,
    isolated_password_hash,
    isolated_fingerprint_key,
    isolated_device_metrics_home,
):
    root, device_dir = _seed_global_targets(
        tmp_path,
        monkeypatch,
        isolated_totp_secret,
        isolated_password_hash,
        isolated_fingerprint_key,
        isolated_device_metrics_home,
    )
    argv = _plain_package(monkeypatch)
    _use_prompter(monkeypatch, lambda: _CorrectCode(_PASSWORD))
    monkeypatch.setattr(cli_main, "_WINDOWS", True)
    popen_calls = []
    monkeypatch.setattr(cli_main.subprocess, "Popen", lambda *a, **kw: popen_calls.append((a, kw)))
    monkeypatch.setattr(
        cli_main.subprocess,
        "run",
        lambda *a, **kw: (_ for _ in ()).throw(AssertionError("must not run synchronously")),
    )

    result = runner.invoke(app, ["uninstall", "--global", "--path", root, "--yes"])

    assert result.exit_code == 0, result.output
    for scope in ("global", "project", "local"):
        data = json.loads(resolve_settings_path(scope, root).read_text(encoding="utf-8"))
        assert not data.get("hooks", {}).get("PreToolUse")
        assert data.get("foreign") == scope or data.get("theme") == "dark"
    for scope in ("user", "repo"):
        data = json.loads(resolve_codex_hooks_path(scope, root).read_text(encoding="utf-8"))
        assert not data.get("hooks", {}).get("PreToolUse")
        assert data.get("notify") == "foreign" or data.get("foreign") == "repo"
    assert not _doberman_dir_exists(root)
    assert not isolated_totp_secret.exists()
    assert not isolated_password_hash.exists()
    assert not isolated_fingerprint_key.exists()
    assert not device_dir.exists()
    assert len(popen_calls) == 1
    popen_args, popen_kwargs = popen_calls[0]
    assert popen_args[0][:2] == ["cmd", "/c"]
    assert subprocess.list2cmdline(argv) in popen_args[0][2]
    assert popen_kwargs["stdin"] is subprocess.DEVNULL
    assert "package removal scheduled" in result.output
    assert "fresh `doberman setup` re-enrolls" in result.output


def test_global_keep_package_prints_command_without_spawning(
    tmp_path, monkeypatch, isolated_password_hash
):
    root = str(tmp_path / "project")
    Path(root).mkdir()
    password.enroll(_PASSWORD)
    _make_doberman_dir(root)
    _use_prompter(monkeypatch, lambda: _CorrectCode(_PASSWORD))
    argv = _plain_package(monkeypatch)
    monkeypatch.setattr(
        cli_main.subprocess,
        "Popen",
        lambda *a, **kw: (_ for _ in ()).throw(AssertionError("must not spawn")),
    )
    monkeypatch.setattr(
        cli_main.subprocess,
        "run",
        lambda *a, **kw: (_ for _ in ()).throw(AssertionError("must not run")),
    )

    result = runner.invoke(
        app, ["uninstall", "--global", "--keep-package", "--path", root, "--yes"]
    )

    assert result.exit_code == 0, result.output
    assert subprocess.list2cmdline(argv) in result.output
    assert "package left in place (--keep-package)" in result.output


def test_package_remover_detects_pipx_from_python_or_console_script(monkeypatch, tmp_path):
    pipx_python = tmp_path / "pipx" / "venvs" / "doberman-core" / "Scripts" / "python.exe"
    monkeypatch.setattr(cli_main.sys, "executable", str(pipx_python))
    monkeypatch.setattr(cli_main.shutil, "which", lambda _name: None)
    assert cli_main._package_remover() == ("pipx", ["pipx", "uninstall", "doberman-core"])

    monkeypatch.setattr(cli_main.sys, "executable", str(tmp_path / "python.exe"))
    console = tmp_path / "PIPX" / "VENVS" / "doberman-core" / "bin" / "doberman"
    monkeypatch.setattr(cli_main.shutil, "which", lambda _name: str(console))
    assert cli_main._package_remover() == ("pipx", ["pipx", "uninstall", "doberman-core"])


def test_package_remover_detects_editable_checkout(monkeypatch, tmp_path):
    checkout = tmp_path / "checkout"
    package = checkout / "src" / "doberman"
    package.mkdir(parents=True)
    init_file = package / "__init__.py"
    init_file.write_text("", encoding="utf-8")
    (checkout / "pyproject.toml").write_text("[project]\nname='doberman-core'\n", encoding="utf-8")
    monkeypatch.setattr(cli_main.sys, "executable", str(tmp_path / "python"))
    monkeypatch.setattr(cli_main.shutil, "which", lambda _name: None)
    monkeypatch.setattr(cli_main.doberman, "__file__", str(init_file))

    assert cli_main._package_remover() == ("development", [])


def test_package_remover_defaults_to_current_python_pip(monkeypatch, tmp_path):
    python = tmp_path / "python"
    monkeypatch.setattr(cli_main.sys, "executable", str(python))
    monkeypatch.setattr(cli_main.shutil, "which", lambda _name: None)
    monkeypatch.setattr(
        cli_main.doberman, "__file__", str(tmp_path / "site" / "doberman" / "__init__.py")
    )

    assert cli_main._package_remover() == (
        "pip",
        [str(python), "-m", "pip", "uninstall", "-y", "doberman-core"],
    )


def test_posix_package_removal_runs_synchronously_and_reports_exit(monkeypatch):
    argv = ["python", "-m", "pip", "uninstall", "-y", "doberman-core"]
    calls = []

    class _Completed:
        returncode = 7

    monkeypatch.setattr(cli_main, "_WINDOWS", False)
    monkeypatch.setattr(
        cli_main.subprocess,
        "run",
        lambda *args, **kwargs: calls.append((args, kwargs)) or _Completed(),
    )
    errors = []

    cli_main._launch_package_removal(argv, errors)

    assert calls == [((argv,), {"check": False})]
    assert errors == ["package removal (python -m pip uninstall -y doberman-core): exit code 7"]


def test_global_failure_continues_and_reports_error(
    tmp_path,
    monkeypatch,
    isolated_totp_secret,
    isolated_password_hash,
    isolated_fingerprint_key,
    isolated_device_metrics_home,
):
    root, device_dir = _seed_global_targets(
        tmp_path,
        monkeypatch,
        isolated_totp_secret,
        isolated_password_hash,
        isolated_fingerprint_key,
        isolated_device_metrics_home,
    )
    _plain_package(monkeypatch)
    _use_prompter(monkeypatch, lambda: _CorrectCode(_PASSWORD))
    monkeypatch.setattr(cli_main, "_WINDOWS", True)
    popen_calls = []
    monkeypatch.setattr(
        cli_main.subprocess, "Popen", lambda *a, **kw: popen_calls.append((a, kw)) or object()
    )
    real_rmtree = cli_main.shutil.rmtree
    project_state = Path(root) / ".doberman"

    def fail_one_rmtree(path):
        if Path(path) == project_state:
            raise OSError("synthetic rmtree failure")
        return real_rmtree(path)

    monkeypatch.setattr(cli_main.shutil, "rmtree", fail_one_rmtree)

    result = runner.invoke(app, ["uninstall", "--global", "--path", root, "--yes"])

    assert result.exit_code == 1
    assert "synthetic rmtree failure" in result.output
    assert project_state.exists()
    assert not isolated_totp_secret.exists()
    assert not isolated_password_hash.exists()
    assert not isolated_fingerprint_key.exists()
    assert not device_dir.exists()
    assert len(popen_calls) == 1
    assert (
        not json.loads(resolve_settings_path("global", root).read_text(encoding="utf-8"))
        .get("hooks", {})
        .get("PreToolUse")
    )
