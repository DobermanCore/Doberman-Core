"""Slice 10.3 — the append-only policy-change ledger (applied + denied recorded)."""

import asyncio
from datetime import datetime, timezone

from typer.testing import CliRunner

from doberman.cli.main import app
from doberman.policy.drift import apply_change, read_policy_changes

runner = CliRunner()
_NOW = datetime(2026, 6, 8, tzinfo=timezone.utc)


class DenyPrompter:
    def confirm(self, message):
        return False

    def read_code(self, message):
        return ""


async def test_applied_and_denied_changes_are_both_recorded(tmp_path):
    root = str(tmp_path)
    # A strengthening applies; a weakening is denied — BOTH are in the ledger.
    await apply_change({"r": "auth"}, {"r": "block"}, "tighten", repo_root=root, now=_NOW)
    await apply_change(
        {"r": "block"},
        {"r": "allow"},
        "loosen",
        repo_root=root,
        prompter=DenyPrompter(),
        now=_NOW,
    )
    rows = await read_policy_changes(root)
    assert len(rows) == 2
    by_class = {r["classification"]: r for r in rows}
    assert by_class["strengthen"]["approved"] == 1
    assert by_class["weaken"]["approved"] == 0  # the denied attempt — the attack signal


def test_denied_weakening_is_the_attack_signal_in_history(tmp_path):
    # Sync test: the CLI calls asyncio.run internally, which cannot nest inside a
    # running loop — so we seed the ledger with asyncio.run directly.
    root = str(tmp_path)
    asyncio.run(
        apply_change(
            {"r": "block"},
            {"r": "allow"},
            "sneaky",
            repo_root=root,
            prompter=DenyPrompter(),
            now=_NOW,
        )
    )
    result = runner.invoke(app, ["policy-history", "--path", root])
    assert result.exit_code == 0
    assert "weaken" in result.stdout
    assert "DENIED" in result.stdout
    assert "block → allow" in result.stdout


def test_policy_history_empty(tmp_path):
    result = runner.invoke(app, ["policy-history", "--path", str(tmp_path)])
    assert result.exit_code == 0
    assert "no policy changes recorded yet" in result.stdout
