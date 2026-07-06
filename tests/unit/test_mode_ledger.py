"""#79 — every user-initiated mode-dial change is recorded in the append-only
policy-change ledger via `doberman.policy.drift.log_change` (audited-but-not-
gated, F10). The mode dial stays frictionless: logging never blocks the change,
and a same-mode no-op never writes a confusing ledger row.
"""

import asyncio

from typer.testing import CliRunner

from doberman.cli import main as cli_main
from doberman.cli.main import app
from doberman.config import load_mode
from doberman.policy.drift import read_policy_changes

runner = CliRunner()


def test_mode_downgrade_from_default_records_a_weaken_row(tmp_path):
    root = str(tmp_path)
    # Fresh repo has no saved policy -> default mode is "balanced"; light is a downgrade.
    result = runner.invoke(app, ["mode", "light", "--path", root])
    assert result.exit_code == 0, result.output

    rows = asyncio.run(read_policy_changes(root))
    assert len(rows) == 1
    row = rows[0]
    assert row["rule_id"] == "mode"
    assert row["classification"] == "weaken"
    assert row["approval_method"] == "logged"
    assert row["approved"] == 1
    assert row["from_state"] == "balanced"
    assert row["to_state"] == "light"


def test_mode_upgrade_from_default_records_a_strengthen_row(tmp_path):
    root = str(tmp_path)
    result = runner.invoke(app, ["mode", "strict", "--path", root])
    assert result.exit_code == 0, result.output

    rows = asyncio.run(read_policy_changes(root))
    assert len(rows) == 1
    row = rows[0]
    assert row["classification"] == "strengthen"
    assert row["approval_method"] == "logged"
    assert row["from_state"] == "balanced"
    assert row["to_state"] == "strict"


def test_same_mode_invocation_records_nothing(tmp_path):
    root = str(tmp_path)
    # Default is already "balanced"; re-asserting it is a no-op.
    result = runner.invoke(app, ["mode", "balanced", "--path", root])
    assert result.exit_code == 0, result.output
    assert asyncio.run(read_policy_changes(root)) == []


def test_ledger_failure_never_blocks_the_mode_change(tmp_path, monkeypatch):
    root = str(tmp_path)

    async def _boom(*args, **kwargs):
        raise RuntimeError("ledger db exploded")

    monkeypatch.setattr(cli_main, "log_change", _boom)

    result = runner.invoke(app, ["mode", "light", "--path", root])

    assert result.exit_code == 0, result.output
    assert "warning" in result.output.lower()
    assert load_mode(root) == "light"  # the mode change still applied despite the ledger failure
