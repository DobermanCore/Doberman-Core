"""Unit tests for the device-global session-metrics rollup (`doberman dashboard`).

Covers ``doberman.storage.device_metrics`` (the rollup store + renderer), its
best-effort wiring into ``doberman.storage.log.record_decision``, and the
``doberman dashboard`` CLI command. The ``isolated_device_metrics_home``
autouse fixture (tests/conftest.py) already points ``DOBERMAN_HOME`` at a temp
dir, so the real per-user rollup is never touched.
"""

from __future__ import annotations

from datetime import datetime, timezone

from typer.testing import CliRunner

import doberman.cli.main as cli_module
from doberman.models import (
    ActionType,
    Decision,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    Verdict,
)
from doberman.storage.device_metrics import read_metrics, record_decision_metric, render_dashboard
from doberman.storage.log import record_decision

runner = CliRunner()

_NOW = datetime(2026, 6, 8, tzinfo=timezone.utc)


def _decision_and_action(verdict: Verdict, action_id: str) -> tuple[Decision, SecurityObject]:
    # A non-PASS verdict must carry at least one reason code (explainability contract).
    reasons = [] if verdict is Verdict.PASS else [ReasonCode.protected_path_blocked]
    objective = GuardrailResult(
        verdict=verdict, risk=Risk.low, reason_codes=reasons, explanation="x"
    )
    decision = Decision(
        action_id=action_id,
        final_verdict=verdict,
        final_risk=Risk.low,
        objective=objective,
        reason_codes=reasons,
        explanation="x",
        decided_at=_NOW,
    )
    action = SecurityObject(
        id=action_id,
        ts=_NOW,
        agent_role="backend",
        action_type=ActionType.file_read,
        tool_name="fs_read",
        target="a.txt",
    )
    return decision, action


# ---------------------------------------------------------------------------
# record_decision_metric / read_metrics
# ---------------------------------------------------------------------------


class TestRecordAndReadMetrics:
    def test_absent_store_reads_all_zeros(self, tmp_path):
        metrics = read_metrics(home=tmp_path / "nope")
        assert metrics == {"total": 0, "pass": 0, "auth": 0, "block": 0, "first_seen": None}

    def test_increments_the_right_counter(self, tmp_path):
        record_decision_metric("PASS", home=tmp_path)
        record_decision_metric("PASS", home=tmp_path)
        record_decision_metric("BLOCK", home=tmp_path)
        metrics = read_metrics(home=tmp_path)
        assert metrics["pass"] == 2
        assert metrics["block"] == 1
        assert metrics["auth"] == 0
        assert metrics["total"] == 3

    def test_pass_auth_block_sequence_totals_correctly(self, tmp_path):
        for verdict in ("PASS", "PASS", "AUTH", "BLOCK", "PASS"):
            record_decision_metric(verdict, home=tmp_path)
        metrics = read_metrics(home=tmp_path)
        assert metrics == {
            "total": 5,
            "pass": 3,
            "auth": 1,
            "block": 1,
            "first_seen": metrics["first_seen"],
        }
        assert metrics["first_seen"] is not None

    def test_first_seen_is_set_once(self, tmp_path):
        record_decision_metric("PASS", home=tmp_path)
        first = read_metrics(home=tmp_path)["first_seen"]
        record_decision_metric("BLOCK", home=tmp_path)
        second = read_metrics(home=tmp_path)["first_seen"]
        assert first == second

    def test_bad_home_does_not_raise(self):
        # A file where a directory is expected: mkdir(parents=True) must fail,
        # and record_decision_metric must swallow it, never raise.
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as td:
            blocked = Path(td) / "not-a-dir"
            blocked.write_text("i am a file, not a directory")
            record_decision_metric("PASS", home=blocked)  # must not raise

    def test_read_metrics_on_bad_home_does_not_raise(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as td:
            blocked = Path(td) / "not-a-dir"
            blocked.write_text("i am a file, not a directory")
            metrics = read_metrics(home=blocked)
            assert metrics["total"] == 0


# ---------------------------------------------------------------------------
# render_dashboard
# ---------------------------------------------------------------------------


class TestRenderDashboard:
    def test_empty_store_shows_no_activity(self):
        panel = render_dashboard({"total": 0, "pass": 0, "auth": 0, "block": 0, "first_seen": None})
        assert "No activity" in panel

    def test_seeded_store_shows_counts_and_percentages(self):
        panel = render_dashboard(
            {"total": 100, "pass": 90, "auth": 7, "block": 3, "first_seen": "2026-06-14"}
        )
        assert "100" in panel
        assert "90" in panel
        assert "7" in panel
        assert "3" in panel
        assert "2026-06-14" in panel
        assert "90.0%" in panel

    def test_output_is_ascii(self):
        panel = render_dashboard(
            {"total": 5, "pass": 3, "auth": 1, "block": 1, "first_seen": "2026-06-14"}
        )
        assert panel.isascii(), f"non-ASCII in dashboard output: {panel!r}"
        panel.encode("cp1252")  # must never raise on a legacy Windows console


# ---------------------------------------------------------------------------
# record_decision chokepoint — best-effort wiring
# ---------------------------------------------------------------------------


class TestRecordDecisionRollupWiring:
    async def test_record_decision_increments_the_device_rollup(self, tmp_path):
        decision, action = _decision_and_action(Verdict.PASS, "act-rollup-1")
        await record_decision(decision, action, repo_root=str(tmp_path))
        # isolated_device_metrics_home fixture points DOBERMAN_HOME at a temp dir.
        assert read_metrics()["pass"] == 1

    async def test_record_decision_survives_a_failing_metric_write(self, tmp_path, monkeypatch):
        def boom(*args, **kwargs):
            raise RuntimeError("metrics db is on fire")

        monkeypatch.setattr("doberman.storage.log.record_decision_metric", boom)
        decision, action = _decision_and_action(Verdict.BLOCK, "act-rollup-2")
        # Must complete without raising even though the rollup write blows up.
        await record_decision(decision, action, repo_root=str(tmp_path))


# ---------------------------------------------------------------------------
# CLI — `doberman dashboard`
# ---------------------------------------------------------------------------


class TestDashboardCLI:
    def test_exits_zero_on_empty_store(self):
        result = runner.invoke(cli_module.app, ["dashboard"])
        assert result.exit_code == 0, result.output
        assert "No activity" in result.output

    def test_shows_seeded_counts(self, tmp_path, monkeypatch):
        for verdict in ("PASS", "PASS", "AUTH", "BLOCK"):
            record_decision_metric(verdict, home=tmp_path)
        # Point the CLI's default home lookup (DOBERMAN_HOME) at the seeded
        # store; monkeypatch reverts this automatically after the test.
        monkeypatch.setenv("DOBERMAN_HOME", str(tmp_path))
        result = runner.invoke(cli_module.app, ["dashboard"])
        assert result.exit_code == 0, result.output
        assert "Interceptions" in result.output
        assert "Auto-passed" in result.output
        assert "Authed" in result.output
        assert "Blocked" in result.output

    def test_output_is_ascii_and_cp1252_safe(self):
        result = runner.invoke(cli_module.app, ["dashboard"])
        assert result.exit_code == 0
        assert result.output.isascii(), f"non-ASCII in dashboard output: {result.output!r}"
        result.output.encode("cp1252")
