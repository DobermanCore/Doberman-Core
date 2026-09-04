"""Issue #326 — seed the per-entity streaming baseline from operator-supplied allowed-action
traces (``doberman memory seed``).

Load-bearing properties: allowed-only (a non-PASS or malformed row refuses the WHOLE file, never
a partial replay), redaction (no row content ever reaches stdout/stderr/logs/DB), raise-only
(seeding never touches ``policies.yaml``, the mode, or the ``policy_changes`` ledger), and a
seeded baseline is read by the SAME ``surprise_blended`` the live proxy scores with.
"""

import asyncio
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

import pytest
from typer.testing import CliRunner

from doberman.cli.main import app
from doberman.config import load_mode
from doberman.models import (
    ActionType,
    Algebra,
    BlastRadius,
    Capability,
    DestinationClass,
    Provenance,
    SecurityObject,
    TargetClass,
)
from doberman.policy.drift import read_policy_changes
from doberman.storage.db import open_db
from doberman.subjective.baseline import entity_id, total_observations
from doberman.subjective.drift import K_OBSERVATIONS, surprise_blended
from doberman.subjective.seed import parse_traces, seed_baseline

runner = CliRunner()

_NOW = datetime(2026, 6, 9, tzinfo=timezone.utc)

_FAMILIAR_ALGEBRA = {
    "capability": "mutate",
    "target_class": "internal",
    "destination_class": "none",
    "blast_radius": "single",
    "provenance": "trusted_instruction",
    "classification_confidence": 0.8,
}


def _row(**overrides):
    row = {
        "verdict": "PASS",
        "agent_role": "frontend",
        "action_type": "file_write",
        "tool_name": "fs_write",
        "target": "src/app.py",
    }
    row.update(overrides)
    return row


def _write(path: Path, rows) -> None:
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")


# --- N valid rows raises total_observations by exactly N ------------------------------


async def test_seed_raises_total_observations_by_exactly_n(tmp_path):
    root = str(tmp_path)
    trace_file = tmp_path / "traces.jsonl"
    rows = [_row(target=f"src/file_{i}.py") for i in range(5)]
    _write(trace_file, rows)

    summary = await seed_baseline(str(trace_file), repo_root=root, now=_NOW)
    assert not summary.errors
    assert summary.seeded == 5
    eid = entity_id("frontend", root)
    assert await total_observations(entity_id=eid, repo_root=root) == 5

    summary2 = await seed_baseline(str(trace_file), repo_root=root, now=_NOW)
    assert not summary2.errors
    assert await total_observations(entity_id=eid, repo_root=root) == 10


# --- one BLOCK row among valid ones refuses the whole file -----------------------------


def test_cli_refuses_whole_file_on_one_blocked_row(tmp_path):
    root = str(tmp_path)
    trace_file = tmp_path / "traces.jsonl"
    rows = [
        _row(target="src/a.py"),
        _row(verdict="BLOCK", target="src/b.py"),
        _row(target="src/c.py"),
    ]
    _write(trace_file, rows)

    result = runner.invoke(
        app,
        [
            "memory",
            "seed",
            "--from",
            str(trace_file),
            "--path",
            root,
            "--now",
            _NOW.isoformat(),
        ],
    )

    assert result.exit_code == 1
    # Names the (1-based) line number of the bad row, never the row content.
    assert "2" in result.output
    assert "src/b.py" not in result.output
    eid = entity_id("frontend", root)
    assert asyncio.run(total_observations(entity_id=eid, repo_root=root)) == 0


# --- a malformed row refuses the whole file too -----------------------------------------


def test_seed_refuses_whole_file_on_unknown_key(tmp_path):
    root = str(tmp_path)
    trace_file = tmp_path / "traces.jsonl"
    lines = [
        json.dumps(_row(target="src/a.py")),
        json.dumps(_row(target="src/b.py", typo_field=True)),
    ]
    trace_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    summary = asyncio.run(seed_baseline(str(trace_file), repo_root=root, now=_NOW))
    assert [e.line_no for e in summary.errors] == [2]
    eid = entity_id("frontend", root)
    assert asyncio.run(total_observations(entity_id=eid, repo_root=root)) == 0


def test_seed_refuses_whole_file_on_bad_action_type(tmp_path):
    root = str(tmp_path)
    trace_file = tmp_path / "traces.jsonl"
    lines = [
        json.dumps(_row()),
        json.dumps(_row(action_type="teleport")),
    ]
    trace_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    summary = asyncio.run(seed_baseline(str(trace_file), repo_root=root, now=_NOW))
    assert [e.line_no for e in summary.errors] == [2]


def test_parse_traces_raises_on_non_json_line():
    text = json.dumps(_row()) + "\nnot json at all\n"
    with pytest.raises(Exception) as exc_info:
        parse_traces(text)
    assert [e.line_no for e in exc_info.value.errors] == [2]


# --- redaction: a secret in target/external_destination never leaks --------------------


def test_seed_redacts_secret_target_and_destination(tmp_path, caplog):
    root = str(tmp_path)
    trace_file = tmp_path / "traces.jsonl"
    secret_target = "secrets/AKIA0000000000SEEDSECRET.txt"  # noqa: S105 — test fixture, not a real secret
    secret_dest = "tok-SEEDSECRET.evil.example"  # noqa: S105 — test fixture, not a real secret
    row = _row(
        action_type="file_read",
        target=secret_target,
        external_destination=secret_dest,
    )
    trace_file.write_text(json.dumps(row) + "\n", encoding="utf-8")

    caplog.set_level(logging.DEBUG)
    result = runner.invoke(
        app,
        [
            "memory",
            "seed",
            "--from",
            str(trace_file),
            "--path",
            root,
            "--now",
            _NOW.isoformat(),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "SEEDSECRET" not in result.output
    for record in caplog.records:
        assert "SEEDSECRET" not in record.getMessage()

    eid = entity_id("frontend", root)

    async def _feature_keys():
        async with open_db(root) as conn:
            async with conn.execute(
                "SELECT feature_key FROM baseline_counts WHERE entity_id = ?", (eid,)
            ) as cur:
                return [r[0] for r in await cur.fetchall()]

    keys = asyncio.run(_feature_keys())
    assert keys, "expected the seeded row to land in baseline_counts"
    assert all("SEEDSECRET" not in k for k in keys)


# --- seed-then-score round trip: familiar scores lower than novel ----------------------


async def test_seed_then_score_round_trip(tmp_path):
    root = str(tmp_path)
    trace_file = tmp_path / "traces.jsonl"
    rows = [
        _row(target=f"src/file_{i}.py", algebra=_FAMILIAR_ALGEBRA) for i in range(K_OBSERVATIONS)
    ]
    _write(trace_file, rows)

    summary = await seed_baseline(str(trace_file), repo_root=root, now=_NOW)
    assert not summary.errors

    eid = entity_id("frontend", root)
    familiar_action = SecurityObject(
        id="q-1",
        ts=_NOW,
        agent_role="frontend",
        action_type=ActionType.file_write,
        tool_name="fs_write",
        target="src/query.py",
        algebra=Algebra(**_FAMILIAR_ALGEBRA),
    )
    novel_action = SecurityObject(
        id="q-2",
        ts=_NOW,
        agent_role="frontend",
        action_type=ActionType.network_request,
        tool_name="net_post",
        target="https://x.test",
        external_destination="attacker.example",
        algebra=Algebra(
            capability=Capability.send,
            target_class=TargetClass.secret,
            destination_class=DestinationClass.unknown_external,
            blast_radius=BlastRadius.many,
            provenance=Provenance.untrusted_data,
            classification_confidence=0.9,
        ),
    )

    familiar_score = await surprise_blended(familiar_action, entity_id=eid, repo_root=root)
    novel_score = await surprise_blended(novel_action, entity_id=eid, repo_root=root)
    assert familiar_score < novel_score


# --- --now determinism -------------------------------------------------------------------


def test_seed_now_yields_identical_last_touched_across_roots(tmp_path):
    root1 = tmp_path / "root1"
    root1.mkdir()
    root2 = tmp_path / "root2"
    root2.mkdir()
    trace_file = tmp_path / "traces.jsonl"
    trace_file.write_text(json.dumps(_row()) + "\n", encoding="utf-8")
    stamp = "2026-06-09T00:00:00+00:00"

    for root in (root1, root2):
        result = runner.invoke(
            app,
            ["memory", "seed", "--from", str(trace_file), "--path", str(root), "--now", stamp],
        )
        assert result.exit_code == 0, result.output

    async def _last_touched(root):
        eid = entity_id("frontend", str(root))
        async with open_db(str(root)) as conn:
            async with conn.execute(
                "SELECT last_touched FROM baseline_counts "
                "WHERE entity_id = ? AND feature_key = '__total__'",
                (eid,),
            ) as cur:
                row = await cur.fetchone()
                return row[0]

    t1 = asyncio.run(_last_touched(root1))
    t2 = asyncio.run(_last_touched(root2))
    assert t1 == t2 == stamp


# --- raise-only smoke: policy/mode/ledger are untouched ---------------------------------


def test_seed_never_touches_policy_mode_or_ledger(tmp_path):
    root = str(tmp_path)
    trace_file = tmp_path / "traces.jsonl"
    trace_file.write_text(json.dumps(_row()) + "\n", encoding="utf-8")

    policy_path = Path(root) / ".doberman" / "policies.yaml"
    assert not policy_path.exists()
    mode_before = load_mode(root)
    changes_before = asyncio.run(read_policy_changes(root))

    summary = asyncio.run(seed_baseline(str(trace_file), repo_root=root, now=_NOW))
    assert not summary.errors

    assert not policy_path.exists()
    assert load_mode(root) == mode_before
    changes_after = asyncio.run(read_policy_changes(root))
    assert changes_after == changes_before
