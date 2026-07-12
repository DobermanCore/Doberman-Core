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
    assert "critical check(s) not healthy" in result.stdout


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


def test_doctor_db_missing_fails(tmp_path):
    root = str(tmp_path)
    _install_hooks(root)
    _save_config(root)  # healthy EXCEPT the decision DB

    result = runner.invoke(app, ["doctor", "--path", root])
    assert result.exit_code == 1
    assert "[FAIL] Decision DB: not found" in result.stdout


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


def test_doctor_fingerprint_key_loose_perms_warns(tmp_path, isolated_fingerprint_key):
    # The autouse fixture points DOBERMAN_KEY_FILE at this path; create it world-readable.
    isolated_fingerprint_key.write_bytes(b"x" * 32)
    isolated_fingerprint_key.chmod(0o644)

    results = run_checks(str(tmp_path))
    key = next(r for r in results if r.name == "Fingerprint key")
    assert key.status is CheckStatus.WARN
    assert "group/other-accessible" in key.detail


def test_doctor_fingerprint_key_tight_perms_ok(tmp_path, isolated_fingerprint_key):
    isolated_fingerprint_key.write_bytes(b"x" * 32)
    isolated_fingerprint_key.chmod(0o600)

    results = run_checks(str(tmp_path))
    key = next(r for r in results if r.name == "Fingerprint key")
    assert key.status is CheckStatus.OK


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
