"""Subj1 — ``doberman memory reset``: the gated wipe of learned behavioral
memory (the subjective baseline + revealed-preference tables).

Mirrors ``test_cli_taint_clear.py``'s shape exactly (same gate, same helper
classes): the no-factor and denied-factor paths must leave every row
untouched (the security test — fail-closed), a successful reset actually
clears the targeted scope, a successful reset writes one ledger row via the
existing policy-change ledger (``apply_change``), and nothing secret-shaped
(the password, the entity id) is ever echoed on either path.
"""

import asyncio
from datetime import datetime, timezone

from typer.testing import CliRunner

from doberman.auth import password
from doberman.cli import main as cli_main
from doberman.cli.main import app
from doberman.policy.drift import read_policy_changes
from doberman.storage.memory import BASELINE_TABLES

runner = CliRunner()

_PASSWORD = "correct horse battery staple"  # noqa: S105 — synthetic test credential
_NOW = datetime(2026, 8, 13, tzinfo=timezone.utc)


class _WrongCode:
    def confirm(self, message):  # pragma: no cover — memory reset never confirms
        raise AssertionError("memory reset must gate on a possession factor, not confirm()")

    def read_code(self, message):
        return "definitely-not-the-real-password"


class _CorrectCode:
    def __init__(self, code: str):
        self._code = code

    def confirm(self, message):  # pragma: no cover — memory reset never confirms
        raise AssertionError("memory reset must gate on a possession factor, not confirm()")

    def read_code(self, message):
        return self._code


def _use_prompter(monkeypatch, prompter_factory) -> None:
    monkeypatch.setattr(cli_main, "CliPrompter", prompter_factory)


async def _seed(root: str, eid: str) -> None:
    from doberman.storage.db import open_db

    stamp = _NOW.isoformat()
    async with open_db(root) as conn:
        await conn.execute(
            "INSERT INTO baseline_counts "
            "(entity_id, feature_key, role, count, first_seen, last_seen, last_touched) "
            "VALUES (?, '__total__', 'r', 1, ?, ?, ?)",
            (eid, stamp, stamp, stamp),
        )
        await conn.commit()


def _row_count(root: str, eid: str) -> int:
    from doberman.storage.db import open_db

    async def _count():
        async with open_db(root) as conn:
            async with conn.execute(
                "SELECT COUNT(*) FROM baseline_counts WHERE entity_id = ?", (eid,)
            ) as cur:
                return (await cur.fetchone())[0]

    return asyncio.run(_count())


def test_no_factor_enrolled_refuses_and_leaves_memory_unchanged(tmp_path):
    root = str(tmp_path)
    asyncio.run(_seed(root, "hmac:aaa"))

    result = runner.invoke(app, ["memory", "reset", "--path", root])

    assert result.exit_code == 1
    assert "2fa setup" in result.output or "password set" in result.output
    assert _row_count(root, "hmac:aaa") == 1


def test_gate_denied_refuses_and_leaves_memory_unchanged(tmp_path, monkeypatch):
    root = str(tmp_path)
    password.enroll(_PASSWORD)
    asyncio.run(_seed(root, "hmac:aaa"))
    _use_prompter(monkeypatch, lambda: _WrongCode())

    result = runner.invoke(app, ["memory", "reset", "--path", root])

    assert result.exit_code == 1
    assert "denied" in result.output
    assert _row_count(root, "hmac:aaa") == 1


def test_gate_passed_clears_all_entities(tmp_path, monkeypatch):
    root = str(tmp_path)
    password.enroll(_PASSWORD)
    asyncio.run(_seed(root, "hmac:aaa"))
    asyncio.run(_seed(root, "hmac:bbb"))
    _use_prompter(monkeypatch, lambda: _CorrectCode(_PASSWORD))

    result = runner.invoke(app, ["memory", "reset", "--path", root])

    assert result.exit_code == 0, result.output
    assert _row_count(root, "hmac:aaa") == 0
    assert _row_count(root, "hmac:bbb") == 0


def test_gate_passed_scoped_to_one_entity_leaves_others(tmp_path, monkeypatch):
    root = str(tmp_path)
    password.enroll(_PASSWORD)
    asyncio.run(_seed(root, "hmac:aaa"))
    asyncio.run(_seed(root, "hmac:bbb"))
    _use_prompter(monkeypatch, lambda: _CorrectCode(_PASSWORD))

    result = runner.invoke(app, ["memory", "reset", "--entity", "hmac:aaa", "--path", root])

    assert result.exit_code == 0, result.output
    assert _row_count(root, "hmac:aaa") == 0
    assert _row_count(root, "hmac:bbb") == 1


def test_successful_reset_writes_one_ledger_row(tmp_path, monkeypatch):
    root = str(tmp_path)
    password.enroll(_PASSWORD)
    asyncio.run(_seed(root, "hmac:aaa"))
    _use_prompter(monkeypatch, lambda: _CorrectCode(_PASSWORD))

    result = runner.invoke(app, ["memory", "reset", "--path", root])

    assert result.exit_code == 0, result.output
    rows = asyncio.run(read_policy_changes(root))
    reset_rows = [r for r in rows if r["rule_id"] == "memory.reset"]
    assert len(reset_rows) == 1
    assert reset_rows[0]["approved"] == 1
    assert reset_rows[0]["classification"] == "neutral"


def test_denied_reset_writes_no_ledger_row(tmp_path, monkeypatch):
    root = str(tmp_path)
    password.enroll(_PASSWORD)
    asyncio.run(_seed(root, "hmac:aaa"))
    _use_prompter(monkeypatch, lambda: _WrongCode())

    result = runner.invoke(app, ["memory", "reset", "--path", root])

    assert result.exit_code == 1
    rows = asyncio.run(read_policy_changes(root))
    assert [r for r in rows if r["rule_id"] == "memory.reset"] == []


def test_success_output_never_contains_a_secret_or_entity_value(tmp_path, monkeypatch):
    root = str(tmp_path)
    password.enroll(_PASSWORD)
    asyncio.run(_seed(root, "hmac:aaa"))
    _use_prompter(monkeypatch, lambda: _CorrectCode(_PASSWORD))

    result = runner.invoke(app, ["memory", "reset", "--entity", "hmac:aaa", "--path", root])

    assert result.exit_code == 0, result.output
    assert "hmac:aaa" not in result.output
    assert root not in result.output
    assert _PASSWORD not in result.output


def test_denied_output_never_contains_a_secret_or_entity_value(tmp_path, monkeypatch):
    root = str(tmp_path)
    password.enroll(_PASSWORD)
    asyncio.run(_seed(root, "hmac:aaa"))
    _use_prompter(monkeypatch, lambda: _WrongCode())

    result = runner.invoke(app, ["memory", "reset", "--entity", "hmac:aaa", "--path", root])

    assert result.exit_code == 1
    assert "hmac:aaa" not in result.output
    assert root not in result.output
    assert _PASSWORD not in result.output


def test_bare_memory_command_is_unaffected_by_the_reset_subcommand(tmp_path):
    # Backward compatibility: `doberman memory` (no subcommand) must still show
    # the plain-language summary now that `memory` is a Typer group.
    result = runner.invoke(app, ["memory", "--path", str(tmp_path)])
    assert result.exit_code == 0
    assert "Doberman learned memory" in result.output


def test_reset_covers_every_baseline_table_not_just_counts(tmp_path, monkeypatch):
    # reset_memory (storage layer) already has full per-table coverage tests;
    # this pins the CLI wires all five tables into its reported total, not
    # just baseline_counts.
    from doberman.storage.db import open_db

    root = str(tmp_path)
    password.enroll(_PASSWORD)

    async def _seed_all_tables():
        stamp = _NOW.isoformat()
        async with open_db(root) as conn:
            for table in BASELINE_TABLES:
                if table == "baseline_counts":
                    await conn.execute(
                        "INSERT INTO baseline_counts "
                        "(entity_id, feature_key, role, count, last_touched) "
                        "VALUES ('hmac:aaa', '__total__', 'r', 1, ?)",
                        (stamp,),
                    )
                elif table == "baseline_transitions":
                    await conn.execute(
                        "INSERT INTO baseline_transitions "
                        "(entity_id, from_state, to_state, count, last_touched) "
                        "VALUES ('hmac:aaa', '1:x', 'y', 1, ?)",
                        (stamp,),
                    )
                elif table == "baseline_state":
                    await conn.execute(
                        "INSERT INTO baseline_state (entity_id, last_state, last_touched) "
                        "VALUES ('hmac:aaa', 'y', ?)",
                        (stamp,),
                    )
                elif table == "score_history":
                    await conn.execute(
                        "INSERT INTO score_history (entity_id, ts, kind, value, last_touched) "
                        "VALUES ('hmac:aaa', ?, 'novelty', 0.5, ?)",
                        (stamp, stamp),
                    )
                elif table == "preference_feedback":
                    await conn.execute(
                        "INSERT INTO preference_feedback "
                        "(entity_id, dimension, approvals, updated_at, last_touched) "
                        "VALUES ('hmac:aaa', 'confidentiality', 1, ?, ?)",
                        (stamp, stamp),
                    )
            await conn.commit()

    asyncio.run(_seed_all_tables())
    _use_prompter(monkeypatch, lambda: _CorrectCode(_PASSWORD))

    result = runner.invoke(app, ["memory", "reset", "--path", root])

    assert result.exit_code == 0, result.output
    assert f"across {len(BASELINE_TABLES)} table(s)" in result.output
    assert "5 row(s)" in result.output
