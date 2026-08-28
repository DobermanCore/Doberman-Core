"""CLI controls for bounded approval memory."""

import asyncio
from datetime import datetime, timedelta, timezone

from typer.testing import CliRunner

from doberman.auth import password
from doberman.cli import main as cli_main
from doberman.cli.main import app
from doberman.config import load_approval_memory_seconds, save_policy
from doberman.policy.checklist import recommend_policy
from doberman.storage.approval_memory import count_live, remember

runner = CliRunner()
NOW = datetime.now(timezone.utc)
PASSWORD = "correct horse battery staple"  # noqa: S105 - synthetic fixture


class _Approve:
    def confirm(self, message: str) -> bool:
        return True

    def read_code(self, message: str) -> str:
        return PASSWORD


class _Wrong:
    def confirm(self, message: str) -> bool:
        return True

    def read_code(self, message: str) -> str:
        return "wrong password"


class _Boom:
    def confirm(self, message: str) -> bool:
        raise AssertionError("strengthening must not prompt")

    def read_code(self, message: str) -> str:
        raise AssertionError("strengthening must not prompt")


def _seed(root: str) -> None:
    # Take the clock here, not at import: `approvals status` compares against the real
    # clock, and a slow CI run can start this test >5 min after collection.
    now = datetime.now(timezone.utc)
    asyncio.run(
        remember(
            "hmac:cli-test",
            repo_root=root,
            session_id=None,
            required_tier="local_auth",
            action_type="shell_exec",
            method="local_auth",
            approved_at=now,
            expires_at=now + timedelta(minutes=5),
        )
    )


def test_status_prints_count_ttl_and_enabled_without_fingerprint(tmp_path):
    root = str(tmp_path)
    _seed(root)

    result = runner.invoke(app, ["approvals", "status", "--path", root])

    assert result.exit_code == 0, result.output
    assert "enabled" in result.output.lower()
    assert "300" in result.output
    assert "1" in result.output
    assert "hmac:cli-test" not in result.output


def test_clear_is_ungated_strengthening(tmp_path, monkeypatch):
    root = str(tmp_path)
    _seed(root)
    monkeypatch.setattr(cli_main, "CliPrompter", _Boom)

    result = runner.invoke(app, ["approvals", "clear", "--path", root])

    assert result.exit_code == 0, result.output
    assert asyncio.run(count_live(NOW, repo_root=root)) == 0


def test_ttl_raise_is_gated_and_wrong_factor_leaves_value_unchanged(tmp_path, monkeypatch):
    root = str(tmp_path)
    password.enroll(PASSWORD)
    monkeypatch.setattr(cli_main, "CliPrompter", _Wrong)

    result = runner.invoke(app, ["approvals", "ttl", "600", "--path", root])

    assert result.exit_code == 1
    assert load_approval_memory_seconds(root) == 300


def test_ttl_raise_applies_after_possession_factor(tmp_path, monkeypatch):
    root = str(tmp_path)
    password.enroll(PASSWORD)
    monkeypatch.setattr(cli_main, "CliPrompter", _Approve)

    result = runner.invoke(app, ["approvals", "ttl", "600", "--path", root])

    assert result.exit_code == 0, result.output
    assert load_approval_memory_seconds(root) == 600


def test_ttl_lower_and_disable_are_ungated_strengthening(tmp_path, monkeypatch):
    root = str(tmp_path)
    save_policy(recommend_policy().with_approval_memory_seconds(600), root)
    monkeypatch.setattr(cli_main, "CliPrompter", _Boom)

    lower = runner.invoke(app, ["approvals", "ttl", "120", "--path", root])
    disabled = runner.invoke(app, ["approvals", "ttl", "0", "--path", root])

    assert lower.exit_code == disabled.exit_code == 0
    assert load_approval_memory_seconds(root) == 0


def test_ttl_rejects_out_of_range(tmp_path):
    result = runner.invoke(app, ["approvals", "ttl", "901", "--path", str(tmp_path)])

    assert result.exit_code != 0
    assert load_approval_memory_seconds(str(tmp_path)) == 300
