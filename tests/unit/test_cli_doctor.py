"""Unit tests for `doberman doctor` (issue #94) — the read-only health self-check.

`doctor` composes existing helpers into one green/red checklist. It must:
* report OK on a healthy fixture and exit 0;
* report the correct failure line when hooks / config / DB are missing and exit non-zero;
* fail *closed* — an indeterminate critical check is a warning that still fails the run,
  never a false "all good";
* stay strictly read-only — diagnosing must never create config, the DB, or the key.

Every check is driven with `tmp_path` fixtures; the autouse fixtures in `conftest.py`
already isolate the fingerprint key / TOTP secret / device-metrics home per test, so no
test ever touches real per-user state.
"""

import asyncio
import os
from datetime import datetime, timezone

import pytest
from typer.testing import CliRunner

from doberman.cli import doctor as doctor_mod
from doberman.cli.doctor import CheckStatus, run_checks
from doberman.cli.main import app
from doberman.config import save_policy
from doberman.hosthooks.install import (
    merge_doberman_hooks,
    resolve_settings_path,
    write_settings,
)
from doberman.models import (
    ActionType,
    Decision,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    Verdict,
)
from doberman.policy.checklist import recommend_policy
from doberman.storage.log import record_decision

runner = CliRunner()
_NOW = datetime(2026, 7, 11, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def _doberman_on_path(monkeypatch):
    """Pin `doberman` as resolvable so the healthy fixture never depends on the test
    runner's PATH; the hook-command tests below override this explicitly."""
    import shutil

    real_which = shutil.which
    monkeypatch.setattr(
        shutil,
        "which",
        lambda name, *a, **k: (
            "/venv/bin/doberman" if name == "doberman" else real_which(name, *a, **k)
        ),
    )


# ---------------------------------------------------------------------------
# Fixture builders
# ---------------------------------------------------------------------------


def _install_hooks(root: str) -> None:
    write_settings(resolve_settings_path("local", root), merge_doberman_hooks({}))


def _save_config(root: str) -> None:
    save_policy(recommend_policy(), root)


def _seed_db(root: str) -> None:
    objective = GuardrailResult(
        verdict=Verdict.BLOCK,
        risk=Risk.critical,
        reason_codes=[ReasonCode.destructive_command],
        explanation="destructive command blocked",
    )
    decision = Decision(
        action_id="act-doctor-1",
        final_verdict=Verdict.BLOCK,
        final_risk=Risk.critical,
        objective=objective,
        reason_codes=[ReasonCode.destructive_command],
        explanation="destructive command blocked",
        decided_at=_NOW,
    )
    action = SecurityObject(
        id="act-doctor-1",
        ts=_NOW,
        agent_role="cli",
        action_type=ActionType.shell_exec,
        tool_name="bash",
        target="rm -rf /",
    )
    asyncio.run(record_decision(decision, action, repo_root=root, auth_result="blocked"))


def _make_healthy(root: str) -> None:
    _install_hooks(root)
    _save_config(root)
    _seed_db(root)


# ---------------------------------------------------------------------------
# Healthy path
# ---------------------------------------------------------------------------


def test_doctor_healthy_fixture_exits_zero(tmp_path):
    root = str(tmp_path)
    _make_healthy(root)

    result = runner.invoke(app, ["doctor", "--path", root])
    assert result.exit_code == 0
    assert "Doberman doctor" in result.stdout
    assert "All critical checks passed." in result.stdout
    # Every critical check is green.
    assert "[FAIL]" not in result.stdout
    assert "Host hooks: installed" in result.stdout
    assert "Decision DB: reachable" in result.stdout


# ---------------------------------------------------------------------------
# Each critical check missing → correct failure line + non-zero exit
# ---------------------------------------------------------------------------


def test_doctor_hooks_missing_fails(tmp_path):
    root = str(tmp_path)
    _save_config(root)
    _seed_db(root)  # everything healthy EXCEPT hooks

    result = runner.invoke(app, ["doctor", "--path", root])
    assert result.exit_code == 1
    assert "[FAIL] Host hooks: not installed" in result.stdout
    assert "error: 1 critical check(s) not healthy" in result.stdout


def test_doctor_config_missing_fails(tmp_path):
    root = str(tmp_path)
    _install_hooks(root)
    _seed_db(root)  # healthy EXCEPT config

    result = runner.invoke(app, ["doctor", "--path", root])
    assert result.exit_code == 1
    assert "[FAIL] Config: no policy saved" in result.stdout


def test_doctor_config_corrupt_fails_closed(tmp_path):
    root = str(tmp_path)
    _install_hooks(root)
    _seed_db(root)
    # A present-but-unparseable policy file must FAIL, never read as OK.
    policy_file = tmp_path / ".doberman" / "policies.yaml"
    policy_file.parent.mkdir(parents=True, exist_ok=True)
    policy_file.write_text("this: is: not: valid: yaml: {", encoding="utf-8")

    result = runner.invoke(app, ["doctor", "--path", root])
    assert result.exit_code == 1
    assert "[FAIL] Config:" in result.stdout
    assert "failed to load" in result.stdout


def test_doctor_db_missing_warns_but_passes(tmp_path):
    # A fresh install has no decision DB until the first gated decision — that
    # is healthy, not a critical failure (P0-2, 2026-08-16 e2e review).
    root = str(tmp_path)
    _install_hooks(root)
    _save_config(root)  # fresh install: no decision DB yet

    result = runner.invoke(app, ["doctor", "--path", root])
    assert result.exit_code == 0
    assert "[warn] Decision DB: not created yet" in result.stdout
    assert "may not be protecting you" not in result.stdout


def test_doctor_db_unreadable_still_fails(tmp_path):
    # The loosening is scoped to ABSENT only: a present-but-corrupt DB is a
    # real health failure and must stay critical.
    root = str(tmp_path)
    _install_hooks(root)
    _save_config(root)
    db_file = tmp_path / ".doberman" / "doberman.db"
    db_file.parent.mkdir(parents=True, exist_ok=True)
    db_file.write_bytes(b"this is not a sqlite database")

    result = runner.invoke(app, ["doctor", "--path", root])
    assert result.exit_code == 1
    assert "[FAIL] Decision DB: present but unreadable" in result.stdout


# ---------------------------------------------------------------------------
# Fail-closed reporting: an indeterminate critical check still fails the run
# ---------------------------------------------------------------------------


def test_doctor_indeterminate_critical_fails_closed(tmp_path, monkeypatch):
    root = str(tmp_path)
    _make_healthy(root)

    def _boom(_path):
        raise RuntimeError("hooks probe exploded")

    # A crashing critical check must degrade to WARN (not OK) and still exit non-zero.
    monkeypatch.setattr(doctor_mod, "_check_hooks", _boom)

    result = runner.invoke(app, ["doctor", "--path", root])
    assert result.exit_code == 1
    assert "[warn] Host hooks: could not be determined" in result.stdout


# ---------------------------------------------------------------------------
# Advisory checks: enforcement dial + 2FA + fingerprint key
# ---------------------------------------------------------------------------


def test_doctor_enforcement_off_warns_but_not_critical(tmp_path, monkeypatch):
    root = str(tmp_path)
    _make_healthy(root)
    # Simulate a softened enforcement dial (monitor/off) without touching the
    # gated change primitives: `_check_enforcement` reads it from config, so patch
    # the read-side resolver there.
    monkeypatch.setattr(
        "doberman.config.resolve_enforcement_sync", lambda *a, **k: "monitor", raising=True
    )

    result = runner.invoke(app, ["doctor", "--path", root])
    # Not blocking is surfaced loudly, but it is an intentional dial → still exit 0.
    assert result.exit_code == 0
    assert "[warn] Enforcement" in result.stdout
    assert "NOT blocking" in result.stdout


def test_doctor_reports_2fa_state(tmp_path):
    results = run_checks(str(tmp_path))
    twofa = next(r for r in results if r.name == "2FA")
    # No secret enrolled in an isolated test → warns, never OK.
    assert twofa.status is CheckStatus.WARN
    assert "not enrolled" in twofa.detail


def test_doctor_reports_password_set(tmp_path, monkeypatch):
    monkeypatch.setattr("doberman.auth.password.is_enrolled", lambda: True)

    results = run_checks(str(tmp_path))

    password_check = next(result for result in results if result.name == "Password")
    assert password_check.status is CheckStatus.OK
    assert password_check.detail == "set"
    assert password_check.critical is False


def test_doctor_reports_missing_optional_password(tmp_path, monkeypatch):
    monkeypatch.setattr("doberman.auth.password.is_enrolled", lambda: False)

    results = run_checks(str(tmp_path))

    password_check = next(result for result in results if result.name == "Password")
    assert password_check.status is CheckStatus.WARN
    assert "not set (optional)" in password_check.detail
    assert "`doberman password set`" in password_check.detail
    assert password_check.critical is False


def test_doctor_lists_password_next_to_2fa(tmp_path):
    results = run_checks(str(tmp_path))
    names = [result.name for result in results]

    assert names.index("Password") == names.index("2FA") + 1


@pytest.mark.skipif(
    os.name == "nt", reason="POSIX file-permission bits are not enforced on Windows (NTFS)"
)
def test_doctor_fingerprint_key_loose_perms_warns(tmp_path, isolated_fingerprint_key):
    # The autouse fixture points DOBERMAN_KEY_FILE at this path; create it world-readable.
    isolated_fingerprint_key.write_bytes(b"x" * 32)
    isolated_fingerprint_key.chmod(0o644)

    results = run_checks(str(tmp_path))
    key = next(r for r in results if r.name == "Fingerprint key")
    assert key.status is CheckStatus.WARN
    assert "group/other-accessible" in key.detail


@pytest.mark.skipif(
    os.name == "nt", reason="POSIX file-permission bits are not enforced on Windows (NTFS)"
)
def test_doctor_fingerprint_key_tight_perms_ok(tmp_path, isolated_fingerprint_key):
    isolated_fingerprint_key.write_bytes(b"x" * 32)
    isolated_fingerprint_key.chmod(0o600)

    results = run_checks(str(tmp_path))
    key = next(r for r in results if r.name == "Fingerprint key")
    assert key.status is CheckStatus.OK


# ---------------------------------------------------------------------------
# Codex CLI detection (Windows npm-shim regression, live-tested)
# ---------------------------------------------------------------------------
#
# A bare `["codex", "--version"]` argv cannot resolve npm's `codex.cmd` shim on
# Windows (CreateProcess doesn't apply PATHEXT to a bare name the way a shell
# does) — `doberman doctor` reported a false "not found" WARN on a box where
# `codex` ran fine from a terminal. `_check_codex_version` now resolves through
# `shutil.which` (PATHEXT-aware) first.


def test_codex_cli_resolved_via_shutil_which_reports_ok(tmp_path, monkeypatch):
    import shutil
    import subprocess

    monkeypatch.setattr(
        shutil, "which", lambda name: "C:\\fake\\codex.cmd" if name == "codex" else None
    )

    class _FakeProc:
        stdout = "codex-cli 0.146.5\n"
        stderr = ""

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _FakeProc())

    results = run_checks(str(tmp_path))
    codex_check = next(r for r in results if r.name == "Codex CLI")
    assert codex_check.status is CheckStatus.OK
    assert "0.146.5" in codex_check.detail


def test_codex_cli_not_found_when_which_resolves_nothing(tmp_path, monkeypatch):
    import shutil

    monkeypatch.setattr(shutil, "which", lambda name: None)

    results = run_checks(str(tmp_path))
    codex_check = next(r for r in results if r.name == "Codex CLI")
    assert codex_check.status is CheckStatus.WARN
    assert "not found" in codex_check.detail


@pytest.mark.parametrize(
    ("row_name", "module", "install_hint"),
    [
        ("Dash extra", "starlette", "doberman[dash]"),
        ("TUI extra", "textual", "doberman[tui]"),
    ],
)
def test_doctor_reports_optional_extra_missing(
    tmp_path, monkeypatch, row_name, module, install_hint
):
    monkeypatch.setattr("doberman.cli.doctor.find_spec", lambda name: None)

    results = run_checks(str(tmp_path))

    check = next(result for result in results if result.name == row_name)
    assert check.status is CheckStatus.WARN
    assert check.detail == f"not installed (optional) - pip install '{install_hint}'"
    assert check.critical is False


@pytest.mark.parametrize(
    ("row_name", "module"),
    [
        ("Dash extra", "starlette"),
        ("TUI extra", "textual"),
    ],
)
def test_doctor_reports_optional_extra_installed(tmp_path, monkeypatch, row_name, module):
    monkeypatch.setattr("doberman.cli.doctor.find_spec", lambda name: object())

    results = run_checks(str(tmp_path))

    check = next(result for result in results if result.name == row_name)
    assert check.status is CheckStatus.OK
    assert check.detail == "installed"
    assert check.critical is False


def test_doctor_lists_optional_extras_after_codex_cli(tmp_path):
    results = run_checks(str(tmp_path))
    names = [result.name for result in results]

    assert names.index("Dash extra") == names.index("Codex CLI") + 1
    assert names.index("TUI extra") == names.index("Dash extra") + 1


# ---------------------------------------------------------------------------
# Read-only invariant: diagnosing never mutates state
# ---------------------------------------------------------------------------


def test_doctor_is_read_only(tmp_path):
    root = str(tmp_path)
    # Run doctor against a bare repo (nothing configured).
    result = runner.invoke(app, ["doctor", "--path", root])
    assert result.exit_code == 1  # unhealthy, but…

    # …it must not have created config, the decision DB, or the fingerprint key.
    assert not (tmp_path / ".doberman" / "policies.yaml").exists()
    assert not (tmp_path / ".doberman" / "doberman.db").exists()


@pytest.mark.parametrize("scope", ["local"])
def test_doctor_hooks_detected_per_scope(tmp_path, scope):
    root = str(tmp_path)
    write_settings(resolve_settings_path(scope, root), merge_doberman_hooks({}))
    results = run_checks(root)
    hooks = next(r for r in results if r.name == "Host hooks")
    assert hooks.status is CheckStatus.OK
    assert scope in hooks.detail


# ---------------------------------------------------------------------------
# Hook command: the bare `doberman` the host will run must resolve (ADR 0086 follow-up)
# ---------------------------------------------------------------------------


def test_hook_command_resolves_reports_ok(tmp_path, monkeypatch):
    import shutil

    monkeypatch.setattr(
        shutil, "which", lambda name: "/venv/bin/doberman" if name == "doberman" else None
    )

    results = run_checks(str(tmp_path))
    check = next(r for r in results if r.name == "Hook command")
    assert check.status is CheckStatus.OK
    assert "/venv/bin/doberman" in check.detail


def test_dangling_hooks_fail_critical_and_name_the_fix(tmp_path, monkeypatch):
    import shutil

    root = str(tmp_path)
    _make_healthy(root)  # hooks installed and everything else green
    monkeypatch.setattr(shutil, "which", lambda name: None)

    result = runner.invoke(app, ["doctor", "--path", root])
    assert result.exit_code == 1
    assert "[FAIL] Hook command: hooks call `doberman`" in result.stdout
    assert "uninstall-hooks" in result.stdout
    assert "error: 1 critical check(s) not healthy" in result.stdout


def test_missing_binary_without_hooks_only_warns(tmp_path, monkeypatch):
    import shutil

    monkeypatch.setattr(shutil, "which", lambda name: None)

    results = run_checks(str(tmp_path))
    check = next(r for r in results if r.name == "Hook command")
    assert check.status is CheckStatus.WARN
    assert not check.critical


def test_dangling_hooks_surface_in_json(tmp_path, monkeypatch):
    import json
    import shutil

    root = str(tmp_path)
    _make_healthy(root)
    monkeypatch.setattr(shutil, "which", lambda name: None)

    result = runner.invoke(app, ["doctor", "--path", root, "--json"])
    payload = json.loads(result.stdout)
    assert result.exit_code == 1
    assert payload["ok"] is False
    assert "Hook command" in payload["critical_failures"]
