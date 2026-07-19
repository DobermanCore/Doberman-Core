"""D4 -- `doberman demo` scripted attack reel through the REAL engine.

Verifies the demo drives the real `normalize -> decide -> record_decision`
pipeline (not stubs), produces the expected verdict for every scenario, never
leaks the synthetic secret used to trip secret-exfiltration detection, never
executes/mutates anything beyond the decision log, never teaches the
subjective baseline / drift / martingale / taint stores, and that its exit
code doubles as a smoke test (0 = every scenario matched, nonzero otherwise).
"""

import asyncio
import socket
from pathlib import Path

from typer.testing import CliRunner

import doberman.demo as demo
from doberman.cli.main import app
from doberman.demo import _FAKE_AWS_KEY, SCENARIOS, Scenario, run_demo
from doberman.models import Verdict
from doberman.storage.db import db_path
from doberman.storage.log import read_decisions

runner = CliRunner()


#: Paths conftest.py's autouse fixtures redirect INTO tmp_path purely for test
#: isolation (in production these live outside the repo entirely, e.g. under
#: the user's home dir) -- not something demo.py itself ever writes into "the
#: repo", so they don't count as a stray mutation of the scanned tree.
_FIXTURE_ISOLATION_FILES = frozenset(
    {"doberman-fingerprint.key", "doberman-totp.secret", "doberman-password.hash"}
)


def _files_outside_storage(root: Path) -> set[str]:
    """Every file path under root except the decision-log storage dir (`.doberman/`)
    and the test-isolation-only fixture files above."""
    return {
        str(p.relative_to(root))
        for p in root.rglob("*")
        if p.is_file() and ".doberman" not in p.parts and p.name not in _FIXTURE_ISOLATION_FILES
    }


def test_each_scenario_yields_its_expected_verdict(tmp_path):
    outcomes = run_demo(mode="balanced", repo_root=str(tmp_path), fast=True)
    assert len(outcomes) == len(SCENARIOS)
    for outcome in outcomes:
        assert outcome.decision.final_verdict == outcome.scenario.expected_verdict
        assert outcome.matched


def test_synthetic_secret_never_appears_in_log_or_output(tmp_path):
    result = runner.invoke(app, ["demo", "--path", str(tmp_path), "--fast"])
    assert _FAKE_AWS_KEY not in result.output

    # Raw DB bytes -- the strongest structural check, catches a leak in any
    # column, not just the ones the CLI happens to print.
    db_file = db_path(str(tmp_path))
    assert db_file.exists()
    assert _FAKE_AWS_KEY.encode() not in db_file.read_bytes()

    rows = asyncio.run(read_decisions(str(tmp_path)))
    assert rows  # sanity: something was actually persisted
    for row in rows:
        for value in row.values():
            assert _FAKE_AWS_KEY not in str(value)


def test_nothing_executed_no_stray_file_mutations(tmp_path):
    before = _files_outside_storage(tmp_path)
    run_demo(mode="balanced", repo_root=str(tmp_path), fast=True)
    after = _files_outside_storage(tmp_path)
    # The only artifact of a run is `.doberman/` (excluded above); nothing else
    # in the tree should ever be created, deleted, or modified.
    assert after == before


def test_no_network_calls_are_made(tmp_path, monkeypatch):
    def _boom(*args, **kwargs):
        raise AssertionError("demo must never touch the network")

    # `socket.create_connection` is the entry point real outbound traffic goes
    # through (urllib/requests/aiohttp etc). Patching the raw `socket.socket.connect`
    # method instead would also break asyncio's own Windows proactor-loop
    # self-pipe (a local loopback socketpair, not real network activity), so
    # this is the accurate place to assert "no outbound connection was made".
    monkeypatch.setattr(socket, "create_connection", _boom)
    run_demo(mode="balanced", repo_root=str(tmp_path), fast=True)  # must not raise


def test_baseline_drift_and_taint_stores_are_untouched(tmp_path, monkeypatch):
    def _boom(*args, **kwargs):
        raise AssertionError("demo must never write baseline/drift/martingale/taint state")

    # These are the state-mutating hooks the real proxy calls AFTER a decision
    # (see doberman.proxy.executor) -- the demo must call none of them; it
    # only evaluates + logs, exactly like a dry run.
    monkeypatch.setattr("doberman.subjective.baseline.observe", _boom)
    monkeypatch.setattr("doberman.subjective.drift.note_allowed", _boom)
    monkeypatch.setattr("doberman.subjective.martingale.note_belief", _boom)
    monkeypatch.setattr("doberman.storage.taint.record_taint", _boom)
    monkeypatch.setattr("doberman.storage.taint.record_taints", _boom)
    monkeypatch.setattr("doberman.storage.taint.record_secret_fingerprints", _boom)

    run_demo(mode="balanced", repo_root=str(tmp_path), fast=True)  # must not raise


def test_exit_code_zero_when_all_scenarios_match(tmp_path):
    result = runner.invoke(app, ["demo", "--path", str(tmp_path), "--fast"])
    assert result.exit_code == 0, result.output


def test_exit_code_nonzero_when_a_scenario_mismatches(tmp_path, monkeypatch):
    # Force one benign scenario to expect a verdict it will never get, so the
    # smoke-test half of the command's duality (exit code) is exercised.
    bad_scenarios = tuple(
        Scenario(
            name=s.name,
            tool_name=s.tool_name,
            args=s.args,
            expected_verdict=Verdict.AUTH if s.name == "Benign file read" else s.expected_verdict,
            label=s.label,
        )
        for s in SCENARIOS
    )
    monkeypatch.setattr(demo, "SCENARIOS", bad_scenarios)

    result = runner.invoke(app, ["demo", "--path", str(tmp_path), "--fast"])
    assert result.exit_code != 0


def test_fast_flag_never_paces(tmp_path, monkeypatch):
    async def _boom():
        raise AssertionError("--fast must never sleep/pace")

    monkeypatch.setattr(demo, "_pace", _boom)
    run_demo(mode="balanced", repo_root=str(tmp_path), fast=True)  # must not raise


def test_without_fast_paces_between_every_scenario_but_the_last(tmp_path, monkeypatch):
    calls = []

    async def _fake_pace():
        calls.append(1)

    monkeypatch.setattr(demo, "_pace", _fake_pace)
    run_demo(mode="balanced", repo_root=str(tmp_path), fast=False)
    assert len(calls) == len(SCENARIOS) - 1
