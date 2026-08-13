"""D1 — the built-in opt-in least-privilege default role.

Covers: opt-in off is byte-identical to today (no regression); opt-in on with
no role.yaml activates the built-in "default" role (ordinary in-repo edits
pass, out-of-repo/CI-config paths escalate); an explicit role.yaml always
wins over the opt-in even when set; a malformed/garbage opt-in flag fails
closed to dormant; and the CLI enable/disable round trip (disable is gated as
a weaken, enable is a frictionless strengthen).
"""

import asyncio

import pyotp
import yaml
from typer.testing import CliRunner

from doberman import config
from doberman.auth import password, totp
from doberman.cli.main import app
from doberman.engine.objective import ObjectiveGuardrail
from doberman.engine.rules.role_boundary import RoleBoundaryRule
from doberman.models import ActionType, EvalContext, SecurityObject, SourceContext, Verdict
from doberman.policy.drift import read_policy_changes
from doberman.roles.roles import RoleBoundary, classify, load_builtin_roles

runner = CliRunner()
RULE = RoleBoundaryRule()


def _action(target, action_type=ActionType.file_write):
    from datetime import datetime, timezone

    return SecurityObject(
        id="d1-1",
        ts=datetime(2026, 6, 8, tzinfo=timezone.utc),
        agent_role="unspecified",
        action_type=action_type,
        tool_name="fs_write",
        target=target,
        source_context=SourceContext.unknown,
        metadata={},
    )


def _ctx(role, tmp_path):
    return EvalContext(role=role, mode="balanced", metadata={"repo_root": str(tmp_path)})


# --- the built-in "default" role itself -------------------------------------------------


def test_default_role_is_a_registered_builtin():
    roles = load_builtin_roles()
    assert "default" in roles
    role = roles["default"]
    assert role.description


def test_default_role_allows_ordinary_in_repo_edits(tmp_path):
    role = load_builtin_roles()["default"]
    assert classify(role, "src/app.py", root=str(tmp_path)) is RoleBoundary.allowed
    assert classify(role, "README.md", root=str(tmp_path)) is RoleBoundary.allowed


def test_default_role_escalates_ci_and_infra(tmp_path):
    role = load_builtin_roles()["default"]
    assert classify(role, ".github/workflows/ci.yml", root=str(tmp_path)) is RoleBoundary.suspicious
    assert classify(role, "infra/main.tf", root=str(tmp_path)) is RoleBoundary.suspicious


def test_default_role_blocks_outside_repo_root(tmp_path):
    # classify()'s own escapes-root check applies to every active role -- the
    # default role gets this hard floor for free, no glob needed.
    role = load_builtin_roles()["default"]
    assert classify(role, "../../etc/passwd", root=str(tmp_path)) is RoleBoundary.blocked


# --- no-regression guard: opt-in off is byte-identical to today -------------------------


def test_opt_in_not_set_load_active_role_returns_none(tmp_path):
    assert config.load_active_role(str(tmp_path)) is None


def test_opt_in_not_set_role_rule_abstains_exactly_as_today(tmp_path):
    role = config.load_active_role(str(tmp_path))
    result = RULE.evaluate(_action("../../outside/secret.txt"), _ctx(role, tmp_path))
    assert result.verdict is Verdict.PASS


# --- opt-in set, no role.yaml: the default role activates -------------------------------


def test_opt_in_set_activates_default_role(tmp_path):
    config.save_default_role_enabled(True, str(tmp_path))
    role = config.load_active_role(str(tmp_path))
    assert role is not None
    assert role.name == "default"


def test_opt_in_set_ordinary_edit_still_passes(tmp_path):
    config.save_default_role_enabled(True, str(tmp_path))
    role = config.load_active_role(str(tmp_path))
    result = RULE.evaluate(_action("src/app.py"), _ctx(role, tmp_path))
    assert result.verdict is Verdict.PASS


def test_opt_in_set_ci_config_steps_up_to_auth(tmp_path):
    config.save_default_role_enabled(True, str(tmp_path))
    role = config.load_active_role(str(tmp_path))
    result = RULE.evaluate(_action(".github/workflows/ci.yml"), _ctx(role, tmp_path))
    assert result.verdict is Verdict.AUTH


def test_opt_in_set_outside_repo_write_blocks_via_objective_guardrail(tmp_path):
    # End to end: even though the default role's own allowlist doesn't name
    # secrets/control-plane paths, the always-on ProtectedPathRule already
    # blocks anything outside the repo root / credential-shaped regardless of
    # role, and combine() is raise-only -- so the net effect the slice asks
    # for (outside-repo + credential paths escalate) holds without duplicating
    # those globs into the role.
    config.save_default_role_enabled(True, str(tmp_path))
    role = config.load_active_role(str(tmp_path))
    guardrail = ObjectiveGuardrail(load_plugins=False)
    result = guardrail.evaluate(_action("../../outside/secret.txt"), _ctx(role, tmp_path))
    assert result.verdict is Verdict.BLOCK


# --- an explicit role.yaml always wins ---------------------------------------------------


def test_explicit_role_file_wins_over_opt_in(tmp_path):
    config.save_default_role_enabled(True, str(tmp_path))
    cfg = tmp_path / ".doberman"
    cfg.mkdir(exist_ok=True)
    (cfg / "role.yaml").write_text("role: backend\n", encoding="utf-8")
    role = config.load_active_role(str(tmp_path))
    assert role is not None
    assert role.name == "backend"


# --- malformed opt-in flag fails closed to dormant ---------------------------------------


def test_malformed_policies_file_falls_back_to_dormant(tmp_path):
    cfg = tmp_path / ".doberman"
    cfg.mkdir()
    (cfg / "policies.yaml").write_text("- just\n- a\n- list\n", encoding="utf-8")
    assert config.default_role_enabled(str(tmp_path)) is False
    assert config.load_active_role(str(tmp_path)) is None


def test_non_boolean_flag_value_never_enables(tmp_path):
    # A hand-edited/garbage value must never be coerced truthy -- bool("false")
    # is True in Python, so this specifically guards against that trap.
    cfg = tmp_path / ".doberman"
    cfg.mkdir()
    (cfg / "policies.yaml").write_text(
        yaml.safe_dump({"items": [], "default_role_enabled": "false"}), encoding="utf-8"
    )
    assert config.default_role_enabled(str(tmp_path)) is False
    assert config.load_active_role(str(tmp_path)) is None


# --- CLI round trip -----------------------------------------------------------------------


class _Approve:
    def __init__(self, code="999999"):
        self._code = code

    def confirm(self, message):
        return True

    def read_code(self, message):
        return self._code


class _Decline:
    def confirm(self, message):
        return False

    def read_code(self, message):  # pragma: no cover
        raise AssertionError("read_code must not be reached after a declined confirm")


_PASSWORD = "correct horse battery staple"  # noqa: S105 — synthetic test credential


def _use_prompter(monkeypatch, prompter_factory):
    monkeypatch.setattr("doberman.auth.provider.CliPrompter", prompter_factory)


def test_cli_enable_default_writes_flag_with_no_gate(tmp_path):
    result = runner.invoke(app, ["role", "enable-default", "--path", str(tmp_path)])
    assert result.exit_code == 0
    assert config.default_role_enabled(str(tmp_path)) is True
    assert config.load_active_role(str(tmp_path)).name == "default"


def test_cli_enable_default_is_idempotent(tmp_path):
    runner.invoke(app, ["role", "enable-default", "--path", str(tmp_path)])
    result = runner.invoke(app, ["role", "enable-default", "--path", str(tmp_path)])
    assert result.exit_code == 0
    assert "already enabled" in result.stdout


def test_cli_disable_default_requires_possession_factor(tmp_path, monkeypatch):
    runner.invoke(app, ["role", "enable-default", "--path", str(tmp_path)])
    password.enroll(_PASSWORD)
    _use_prompter(monkeypatch, lambda: _Approve(_PASSWORD))
    result = runner.invoke(app, ["role", "disable-default", "--path", str(tmp_path)])
    assert result.exit_code == 0
    assert config.default_role_enabled(str(tmp_path)) is False
    assert config.load_active_role(str(tmp_path)) is None


def test_cli_disable_default_denied_leaves_state_unchanged(tmp_path, monkeypatch):
    runner.invoke(app, ["role", "enable-default", "--path", str(tmp_path)])
    password.enroll(_PASSWORD)
    _use_prompter(monkeypatch, _Decline)
    result = runner.invoke(app, ["role", "disable-default", "--path", str(tmp_path)])
    assert result.exit_code == 1
    assert config.default_role_enabled(str(tmp_path)) is True


def test_cli_disable_default_with_no_factor_enrolled_fails_closed(tmp_path, monkeypatch):
    runner.invoke(app, ["role", "enable-default", "--path", str(tmp_path)])

    class _ConfirmOnly:
        def confirm(self, message):
            return True

        def read_code(self, message):
            raise AssertionError("no factor is enrolled")

    _use_prompter(monkeypatch, _ConfirmOnly)
    result = runner.invoke(app, ["role", "disable-default", "--path", str(tmp_path)])
    assert result.exit_code == 1
    assert config.default_role_enabled(str(tmp_path)) is True


def test_cli_disable_default_when_already_disabled_is_a_noop(tmp_path):
    result = runner.invoke(app, ["role", "disable-default", "--path", str(tmp_path)])
    assert result.exit_code == 0
    assert "already disabled" in result.stdout


def test_cli_enable_records_a_ledger_entry(tmp_path):
    runner.invoke(app, ["role", "enable-default", "--path", str(tmp_path)])
    rows = asyncio.run(read_policy_changes(str(tmp_path)))
    assert len(rows) == 1
    assert rows[0]["approved"] == 1


def _enrolled_code() -> str:
    totp.enroll()
    secret = totp._read_secret()
    assert secret is not None
    return pyotp.TOTP(secret).now()


def test_cli_disable_default_with_totp_enrolled(tmp_path, monkeypatch):
    runner.invoke(app, ["role", "enable-default", "--path", str(tmp_path)])
    code = _enrolled_code()
    _use_prompter(monkeypatch, lambda: _Approve(code))
    result = runner.invoke(app, ["role", "disable-default", "--path", str(tmp_path)])
    assert result.exit_code == 0
    assert config.default_role_enabled(str(tmp_path)) is False
