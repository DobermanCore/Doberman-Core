"""Unit tests for the opt-in ``doberman doctor --live`` Codex hook canary (#826, #335)."""

from __future__ import annotations

import asyncio
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from typer.testing import CliRunner

from doberman.cli import codex_canary
from doberman.cli.codex_canary import SENTINEL_NAME, CanaryStatus, run_codex_live_canary
from doberman.cli.doctor import CheckResult, CheckStatus, run_checks
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
_NOW = datetime(2026, 8, 9, tzinfo=timezone.utc)


def _seed_block(root: Path, action_id: str) -> None:
    objective = GuardrailResult(
        verdict=Verdict.BLOCK,
        risk=Risk.critical,
        reason_codes=[ReasonCode.destructive_command],
        explanation="destructive command blocked",
    )
    decision = Decision(
        action_id=action_id,
        final_verdict=Verdict.BLOCK,
        final_risk=Risk.critical,
        objective=objective,
        reason_codes=[ReasonCode.destructive_command],
        explanation="destructive command blocked",
        decided_at=_NOW,
    )
    action = SecurityObject(
        id=action_id,
        ts=_NOW,
        agent_role="cli",
        action_type=ActionType.shell_exec,
        tool_name="bash",
        target=f"rm -f {SENTINEL_NAME}",
    )
    asyncio.run(record_decision(decision, action, repo_root=str(root), auth_result="blocked"))


def _make_healthy(root: Path) -> None:
    write_settings(resolve_settings_path("local", str(root)), merge_doberman_hooks({}))
    save_policy(recommend_policy(), str(root))
    _seed_block(root, "act-prior-1")


def _completed(
    argv: list[str], returncode: int = 0, stdout: str = ""
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(argv, returncode, stdout=stdout, stderr="")


def test_doctor_default_omits_live_canary_and_does_not_run_codex(tmp_path, monkeypatch):
    called = False

    def _boom(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("live canary must not run without --live")

    monkeypatch.setattr(codex_canary, "run_codex_live_canary", _boom)
    results = run_checks(str(tmp_path))

    assert not called
    assert all(r.name != "Codex live canary" for r in results)


def test_live_canary_missing_codex_warns_never_ok(tmp_path):
    outcome = run_codex_live_canary(tmp_path, which=lambda name: None)

    assert outcome.status is CanaryStatus.INCONCLUSIVE
    assert outcome.exit_code == 2
    assert "not found" in outcome.detail
    assert not (tmp_path / SENTINEL_NAME).exists()


def test_live_canary_deleted_sentinel_is_critical_fail(tmp_path, monkeypatch):
    def _delete_sentinel(argv: list[str], timeout: int, cwd: str):
        (Path(cwd) / SENTINEL_NAME).unlink()
        return _completed(argv, 0)

    monkeypatch.setattr(
        codex_canary.shutil,
        "which",
        lambda name: f"/fake/{name}" if name in {"codex", "doberman"} else None,
    )
    monkeypatch.setattr(codex_canary, "_default_runner", _delete_sentinel)

    results = run_checks(str(tmp_path), live=True)
    canary = next(r for r in results if r.name == "Codex live canary")

    assert canary.status is CheckStatus.FAIL
    assert canary.critical is True
    assert "deleted" in canary.detail
    assert not (tmp_path / SENTINEL_NAME).exists()


def test_live_canary_intact_with_new_db_deny_is_ok(tmp_path):
    calls: list[list[str]] = []

    def _hook_blocks(argv: list[str], timeout: int, cwd: str):
        calls.append(argv)
        assert (Path(cwd) / SENTINEL_NAME).exists()
        _seed_block(Path(cwd), "act-live-canary-1")
        return _completed(argv, 0)

    outcome = run_codex_live_canary(
        tmp_path,
        runner=_hook_blocks,
        which=lambda name: f"/fake/{name}" if name in {"codex", "doberman"} else None,
    )

    assert outcome.status is CanaryStatus.PROTECTED
    assert outcome.exit_code == 0
    assert len(calls) == 1
    assert calls[0][:4] == [
        "/fake/codex",
        "exec",
        "--dangerously-bypass-hook-trust",
        "--skip-git-repo-check",
    ]
    assert not (tmp_path / SENTINEL_NAME).exists()


def test_live_canary_intact_with_cli_log_deny_is_ok(tmp_path):
    def _fake_runner(argv: list[str], timeout: int, cwd: str):
        if argv[0].endswith("codex"):
            return _completed(argv, 0)
        return _completed(
            argv,
            0,
            stdout=json.dumps(
                {
                    "action_id": "act-canary-log",
                    "final_verdict": "BLOCK",
                    "auth_result": "blocked",
                }
            )
            + "\n",
        )

    outcome = run_codex_live_canary(
        tmp_path,
        runner=_fake_runner,
        which=lambda name: f"/fake/{name}" if name in {"codex", "doberman"} else None,
    )

    assert outcome.status is CanaryStatus.PROTECTED
    assert outcome.exit_code == 0
    assert not (tmp_path / SENTINEL_NAME).exists()


def test_live_canary_ignores_preexisting_db_deny_and_warns(tmp_path):
    _seed_block(tmp_path, "act-old-deny")

    def _model_refused_without_hook(argv: list[str], timeout: int, cwd: str):
        if argv[0].endswith("codex"):
            return _completed(argv, 0)
        # Only the pre-existing row is present in the CLI log as well.
        return _completed(
            argv,
            0,
            stdout=json.dumps(
                {
                    "action_id": "act-old-deny",
                    "final_verdict": "BLOCK",
                    "auth_result": "blocked",
                }
            )
            + "\n",
        )

    outcome = run_codex_live_canary(
        tmp_path,
        runner=_model_refused_without_hook,
        which=lambda name: f"/fake/{name}" if name in {"codex", "doberman"} else None,
    )

    assert outcome.status is CanaryStatus.INCONCLUSIVE
    assert outcome.exit_code == 2
    assert "no new deny" in outcome.detail
    assert not (tmp_path / SENTINEL_NAME).exists()


def test_live_canary_timeout_warns_and_cleans_sentinel(tmp_path):
    def _timeout(argv: list[str], timeout: int, cwd: str):
        raise subprocess.TimeoutExpired(argv, timeout)

    outcome = run_codex_live_canary(
        tmp_path,
        timeout_s=12,
        runner=_timeout,
        which=lambda name: "/fake/codex" if name == "codex" else None,
    )

    assert outcome.status is CanaryStatus.INCONCLUSIVE
    assert outcome.exit_code == 2
    assert "timed out" in outcome.detail
    assert not (tmp_path / SENTINEL_NAME).exists()


def test_live_canary_oserror_warns_and_cleans_sentinel(tmp_path):
    def _broken_exec(argv: list[str], timeout: int, cwd: str):
        raise OSError("spawn failed")

    outcome = run_codex_live_canary(
        tmp_path,
        runner=_broken_exec,
        which=lambda name: "/fake/codex" if name == "codex" else None,
    )

    assert outcome.status is CanaryStatus.INCONCLUSIVE
    assert outcome.exit_code == 2
    assert "OSError" in outcome.detail
    assert not (tmp_path / SENTINEL_NAME).exists()


def test_cli_doctor_live_flag_json_and_exit_code_on_fail(tmp_path, monkeypatch):
    _make_healthy(tmp_path)

    def _delete_sentinel(argv: list[str], timeout: int, cwd: str):
        (Path(cwd) / SENTINEL_NAME).unlink()
        return _completed(argv, 0)

    monkeypatch.setattr(
        "shutil.which",
        lambda name, *a, **k: f"/fake/{name}" if name in {"codex", "doberman"} else None,
    )
    monkeypatch.setattr(codex_canary, "_default_runner", _delete_sentinel)
    # Prevent `_check_codex_version` from spawning a real subprocess on /fake/codex.
    monkeypatch.setattr(
        "doberman.cli.doctor._check_codex_version",
        lambda: CheckResult("Codex CLI", CheckStatus.OK, "0.146.5 (supported)"),
    )

    result = runner.invoke(app, ["doctor", "--path", str(tmp_path), "--live", "--json"])

    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert payload["ok"] is False
    assert "Codex live canary" in payload["critical_failures"]
    canary_row = next(c for c in payload["checks"] if c["name"] == "Codex live canary")
    assert canary_row["status"] == "fail"


def test_cli_doctor_live_flag_warn_does_not_fail_healthy_repo(tmp_path, monkeypatch):
    _make_healthy(tmp_path)

    monkeypatch.setattr(
        "shutil.which",
        lambda name, *a, **k: "/fake/doberman" if name == "doberman" else None,
    )

    result = runner.invoke(app, ["doctor", "--path", str(tmp_path), "--live", "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["ok"] is True
    canary_row = next(c for c in payload["checks"] if c["name"] == "Codex live canary")
    assert canary_row["status"] == "warn"
    assert "not found" in canary_row["detail"]


def test_smoke_entrypoint_delegates_to_shared_canary(monkeypatch):
    from tools.codex_canary import smoke

    monkeypatch.setattr(
        smoke,
        "run_codex_live_canary",
        lambda path=".", install_hooks=True: codex_canary.CanaryOutcome(
            status=CanaryStatus.PROTECTED,
            detail="sentinel intact and Codex PreToolUse hook recorded a deny",
            exit_code=0,
        ),
    )
    assert smoke.main() == 0
