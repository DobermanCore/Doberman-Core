"""Tests for the ambient monitor daemon (FM.2, issue #237).

Proves the hard rules from the issue:

1. Observe-only, structurally: this module never imports doberman.auth or
   doberman.proxy - no prompter, no executor, no challenge.
2. Per-collector AND per-event isolation: a raising collector, a bad yielded
   value, and a scoring failure each cost only their own events - never the
   tick, never a silently dropped event.
3. A scoring failure records a conservative alert row (ReasonCode
   .ambient_scoring_error), never silence.
4. Cursor-based resume: a second tick never replays an already-drained event.
5. The heartbeat + single-instance guard: a fresh sibling heartbeat means
   run_forever refuses to start a second daemon.
6. `doberman monitor status`/`run` CLI wiring.

Ambient-aware rendering (the "observed (not enforced)" prefix and the ban on
"blocked"-sounding output) is doberman.explain's own contract and is tested in
test_explain.py, not here.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest
from typer.testing import CliRunner

from doberman.cli.main import app
from doberman.models import ActionType, ActivityEvent
from doberman.storage.activity import emit_activity_event, load_cursor
from doberman.storage.heartbeat import MONITOR_HEARTBEAT_FILE, heartbeat_path, touch_heartbeat
from doberman.storage.log import read_decisions

runner = CliRunner()

_NOW = datetime(2026, 9, 10, 12, 0, 0, tzinfo=timezone.utc)


def _make_event(
    *,
    action_id: str = "act-001",
    ts: datetime = _NOW,
    agent_role: str = "backend",
    action_type: str = "file_read",
    target_path_class: str | None = "backend/auth/*.ts",
    collector_id: str = "stub.collector",
    entity_fingerprint: str = "hmac:aabbccdd",
    session_fingerprint: str = "hmac:eeff0011",
) -> ActivityEvent:
    """Build a minimal, valid ActivityEvent for testing (mirrors test_activity_bus.py)."""
    return ActivityEvent(
        action_id=action_id,
        ts=ts,
        agent_role=agent_role,
        action_type=action_type,
        target_path_class=target_path_class,
        collector_id=collector_id,
        entity_fingerprint=entity_fingerprint,
        session_fingerprint=session_fingerprint,
    )


class _StubCollector:
    """A minimal collector that yields one or more preset events."""

    def __init__(self, events: list[ActivityEvent]) -> None:
        self._events = events

    def collect(self):
        yield from self._events


class _RaisingCollector:
    """A collector whose collect() always raises."""

    def collect(self):
        raise RuntimeError("collector boom")


# ---------------------------------------------------------------------------
# 1. Observe-only, structurally: no static import of auth or proxy
# ---------------------------------------------------------------------------


def test_monitor_daemon_never_imports_auth_or_proxy():
    """FM.2 hard rule: 'no prompter, no executor, no challenge is imported or
    constructed'. This module must never statically import doberman.auth or
    doberman.proxy - the live gate's own machinery."""
    import ast
    import importlib.util
    import pathlib

    spec = importlib.util.find_spec("doberman.monitor.daemon")
    assert spec is not None and spec.origin is not None
    source = pathlib.Path(spec.origin).read_text()

    forbidden_prefixes = ("doberman.auth", "doberman.proxy")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert not alias.name.startswith(forbidden_prefixes), (
                    f"Static import of {alias.name!r} found in monitor.daemon"
                )
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            assert not mod.startswith(forbidden_prefixes), (
                f"'from {mod} import ...' found in monitor.daemon"
            )


def test_build_engine_stack_returns_a_guardrail_pair():
    from doberman.engine.decision_engine import Guardrail
    from doberman.monitor.daemon import build_engine_stack

    objective, subjective = build_engine_stack()
    assert isinstance(objective, Guardrail)
    assert isinstance(subjective, Guardrail)


# ---------------------------------------------------------------------------
# 2. Collector polling: per-collector and per-event isolation
# ---------------------------------------------------------------------------


def test_poll_collectors_isolates_a_raising_collector(monkeypatch):
    from doberman.monitor import daemon

    stub = _StubCollector(
        [
            _make_event(action_id="e1", collector_id="stub.collector"),
            _make_event(action_id="e2", collector_id="stub.collector"),
        ]
    )
    monkeypatch.setattr(daemon, "discover_collectors", lambda: [_RaisingCollector(), stub])

    events = daemon._poll_collectors()
    assert len(events) == 2
    assert all(e.collector_id == "stub.collector" for e in events)


def test_poll_collectors_skips_a_non_activity_event_yield(monkeypatch):
    from doberman.monitor import daemon

    class _Bad:
        def collect(self):
            yield {"not": "an ActivityEvent"}
            yield _make_event(action_id="ok-1", collector_id="bad.collector")

    monkeypatch.setattr(daemon, "discover_collectors", lambda: [_Bad()])

    events = daemon._poll_collectors()
    assert len(events) == 1
    assert events[0].action_id == "ok-1"


# ---------------------------------------------------------------------------
# 3. SecurityObject reconstruction from a redacted event
# ---------------------------------------------------------------------------


def test_security_object_from_event_falls_back_to_other_for_unknown_action_type():
    from doberman.monitor.daemon import _security_object_from_event

    event = _make_event(action_type="some_future_action_type_not_in_enum")
    action = _security_object_from_event(event)
    assert action.action_type is ActionType.other


def test_security_object_from_event_preserves_target_path_class():
    from doberman.monitor.daemon import _security_object_from_event

    event = _make_event(target_path_class=".env")
    action = _security_object_from_event(event)
    assert action.target_path_class == ".env"
    assert action.tool_name == "ambient:stub.collector"


# ---------------------------------------------------------------------------
# 4. One full tick: poll -> emit -> drain -> score -> record -> save cursor
# ---------------------------------------------------------------------------


async def test_run_tick_emits_scores_and_records_an_ambient_row(tmp_path, monkeypatch):
    from doberman.monitor import daemon

    stub = _StubCollector(
        [_make_event(action_id="tick-1", action_type="file_read", target_path_class="src/*.py")]
    )
    monkeypatch.setattr(daemon, "discover_collectors", lambda: [stub])

    objective, subjective = daemon.build_engine_stack()
    result = await daemon.run_tick(str(tmp_path), objective, subjective, mode="balanced")

    assert result.collected == 1
    assert result.emitted == 1
    assert result.drained == 1
    assert result.scored == 1
    assert result.fallback == 0

    rows = await read_decisions(str(tmp_path))
    assert len(rows) == 1
    assert rows[0]["source_context"] == "ambient:stub.collector"
    assert rows[0]["action_id"] == "tick-1"

    cursor = await load_cursor(str(tmp_path), reader_id=daemon.DEFAULT_READER_ID)
    assert cursor == result.cursor
    assert cursor > 0


async def test_run_tick_does_not_replay_an_already_drained_event(tmp_path, monkeypatch):
    from doberman.monitor import daemon

    monkeypatch.setattr(
        daemon, "discover_collectors", lambda: [_StubCollector([_make_event(action_id="once-1")])]
    )
    objective, subjective = daemon.build_engine_stack()
    first = await daemon.run_tick(str(tmp_path), objective, subjective)
    assert first.drained == 1

    # A second tick's collector emits a NEW event; the cursor must mean the
    # daemon never re-scores "once-1" again.
    monkeypatch.setattr(
        daemon, "discover_collectors", lambda: [_StubCollector([_make_event(action_id="once-2")])]
    )
    second = await daemon.run_tick(str(tmp_path), objective, subjective)
    assert second.drained == 1

    rows = await read_decisions(str(tmp_path))
    assert {row["action_id"] for row in rows} == {"once-1", "once-2"}


async def test_run_tick_isolates_one_poisoned_event_among_clean_ones(tmp_path, monkeypatch):
    from doberman.monitor import daemon

    stub = _StubCollector(
        [
            _make_event(action_id="good-1"),
            _make_event(action_id="poison-1"),
            _make_event(action_id="good-2"),
        ]
    )
    monkeypatch.setattr(daemon, "discover_collectors", lambda: [stub])

    real_builder = daemon._security_object_from_event

    def _sometimes_boom(event):
        if event.action_id == "poison-1":
            raise RuntimeError("boom")
        return real_builder(event)

    monkeypatch.setattr(daemon, "_security_object_from_event", _sometimes_boom)

    objective, subjective = daemon.build_engine_stack()
    result = await daemon.run_tick(str(tmp_path), objective, subjective)

    assert result.drained == 3
    assert result.scored == 2
    assert result.fallback == 1

    rows = await read_decisions(str(tmp_path))
    assert len(rows) == 3
    poisoned = next(row for row in rows if row["action_id"] == "poison-1")
    assert "ambient_scoring_error" in poisoned["reason_codes_json"]
    assert poisoned["final_verdict"] == "BLOCK"
    for good_id in ("good-1", "good-2"):
        good = next(row for row in rows if row["action_id"] == good_id)
        assert "ambient_scoring_error" not in good["reason_codes_json"]


async def test_run_tick_never_raises_even_when_discover_collectors_itself_raises(
    tmp_path, monkeypatch
):
    """The tick-level failure boundary: even a bug in discovery itself (not
    just one collector) must not escape run_tick."""
    from doberman.monitor import daemon

    def _boom():
        raise RuntimeError("registry boom")

    monkeypatch.setattr(daemon, "discover_collectors", _boom)

    objective, subjective = daemon.build_engine_stack()
    result = await daemon.run_tick(str(tmp_path), objective, subjective)

    assert result.collected == 0
    assert result.cursor == -1


# ---------------------------------------------------------------------------
# 4b. No learning from ambient input - baseline stores stay byte-identical
# ---------------------------------------------------------------------------


def _baseline_snapshot(repo_root: str) -> dict[str, list[tuple]]:
    """Raw content of every baseline/revealed-preference learning table FM.2
    must never write to (doberman.subjective.baseline/drift/martingale/revealed)."""
    import sqlite3

    from doberman.storage.db import db_path

    tables = (
        "baseline_counts",
        "baseline_transitions",
        "baseline_state",
        "score_history",
        "preference_feedback",
    )
    conn = sqlite3.connect(str(db_path(repo_root)))
    try:
        return {
            table: conn.execute(
                f"SELECT * FROM {table} ORDER BY rowid"  # noqa: S608 — fixed names
            ).fetchall()
            for table in tables
        }
    finally:
        conn.close()


async def test_ambient_scoring_never_writes_to_any_baseline_learning_table(tmp_path, monkeypatch):
    """FM.2 hard rule: 'baselines update only on engine-allowed actions... Baseline
    stores must be byte-identical after a daemon run.'

    Baseline learning (doberman.subjective.baseline.observe / drift.note_allowed /
    martingale.note_belief / revealed.record_feedback) is only ever called from
    doberman.proxy.executor, AFTER a real forward - never from decide() itself
    (engine/subjective.py imports nothing from doberman.subjective). Since this
    daemon never imports doberman.proxy (see the import-boundary test above), it
    structurally cannot reach that code. This test proves the outcome directly:
    every baseline-shaped table is byte-for-byte unchanged after several real
    ticks - including events that score PASS (the "allowed" case a live proxy
    WOULD learn from).
    """
    from doberman.monitor import daemon
    from doberman.storage.db import open_db

    # Force schema creation before the "before" snapshot (tables are created
    # lazily on first open_db() call - load_cursor short-circuits to 0 and
    # never opens the DB at all when the file doesn't exist yet).
    async with open_db(str(tmp_path)):
        pass
    before = _baseline_snapshot(str(tmp_path))
    assert all(rows == [] for rows in before.values())  # sanity: starts empty

    events = [
        _make_event(action_id="a1", action_type="file_read", target_path_class="src/*.py"),
        _make_event(action_id="a2", action_type="shell_exec", target_path_class=None),
        _make_event(
            action_id="a3", action_type="network_request", target_path_class="api.example.com"
        ),
    ]
    monkeypatch.setattr(daemon, "discover_collectors", lambda: [_StubCollector(events)])

    objective, subjective = daemon.build_engine_stack()
    for _ in range(3):  # several ticks, not just one
        await daemon.run_tick(str(tmp_path), objective, subjective, mode="balanced")

    after = _baseline_snapshot(str(tmp_path))
    assert after == before


def test_monitor_daemon_never_imports_subjective_baseline_or_revealed():
    """Belt-and-suspenders alongside the byte-identical test above: no static
    import of the learning modules at all, so there is no code path in this
    file that could ever call them, now or after a future edit."""
    import ast
    import importlib.util
    import pathlib

    spec = importlib.util.find_spec("doberman.monitor.daemon")
    assert spec is not None and spec.origin is not None
    source = pathlib.Path(spec.origin).read_text()

    forbidden_prefixes = (
        "doberman.subjective.baseline",
        "doberman.subjective.drift",
        "doberman.subjective.martingale",
        "doberman.subjective.revealed",
    )
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            assert not mod.startswith(forbidden_prefixes), (
                f"'from {mod} import ...' found in monitor.daemon"
            )


# ---------------------------------------------------------------------------
# 5. Scoring failure -> conservative alert row, never silence
# ---------------------------------------------------------------------------


async def test_score_event_records_conservative_fallback_on_scoring_failure(tmp_path, monkeypatch):
    from doberman.monitor import daemon

    event = _make_event(action_id="poison-solo", collector_id="stub.collector")

    def _boom(_event):
        raise RuntimeError("boom")

    monkeypatch.setattr(daemon, "_security_object_from_event", _boom)

    objective, subjective = daemon.build_engine_stack()
    clean = await daemon._score_event(
        event, objective, subjective, mode="balanced", repo_root=str(tmp_path)
    )
    assert clean is False

    rows = await read_decisions(str(tmp_path))
    assert len(rows) == 1
    row = rows[0]
    assert row["source_context"] == "ambient:stub.collector"
    assert row["final_verdict"] == "BLOCK"
    assert json.loads(row["reason_codes_json"]) == ["ambient_scoring_error"]


# ---------------------------------------------------------------------------
# 6. Heartbeat + single-instance guard
# ---------------------------------------------------------------------------


def test_is_already_running_true_right_after_touch(tmp_path):
    from doberman.monitor import daemon

    touch_heartbeat(str(tmp_path), filename=MONITOR_HEARTBEAT_FILE)
    assert daemon.is_already_running(str(tmp_path)) is True


def test_is_already_running_false_when_stale(tmp_path):
    from doberman.monitor import daemon

    stale = datetime.now(timezone.utc) - timedelta(seconds=30)
    touch_heartbeat(str(tmp_path), filename=MONITOR_HEARTBEAT_FILE, now=stale)
    assert daemon.is_already_running(str(tmp_path)) is False


def test_is_already_running_false_when_missing(tmp_path):
    from doberman.monitor import daemon

    assert daemon.is_already_running(str(tmp_path)) is False


def test_monitor_heartbeat_is_independent_of_dash_heartbeat(tmp_path):
    """storage.heartbeat's generalization (per-filename) must not let the
    dash and monitor heartbeats be mistaken for one another."""
    from doberman.storage.heartbeat import HEARTBEAT_FILE, heartbeat_is_fresh

    touch_heartbeat(str(tmp_path), filename=HEARTBEAT_FILE)  # dash's own heartbeat
    assert heartbeat_is_fresh(str(tmp_path), filename=HEARTBEAT_FILE) is True
    assert heartbeat_is_fresh(str(tmp_path), filename=MONITOR_HEARTBEAT_FILE) is False


def test_run_forever_refuses_a_second_instance(tmp_path):
    from doberman.monitor import daemon

    touch_heartbeat(str(tmp_path), filename=MONITOR_HEARTBEAT_FILE)
    with pytest.raises(daemon.MonitorAlreadyRunning):
        daemon.run_forever(str(tmp_path), max_ticks=1)


def test_run_forever_runs_bounded_ticks_and_touches_its_own_heartbeat(tmp_path, monkeypatch):
    from doberman.monitor import daemon

    monkeypatch.setattr(daemon, "discover_collectors", lambda: [])

    seen = []
    daemon.run_forever(
        str(tmp_path),
        interval_s=0.01,
        max_ticks=2,
        on_tick=seen.append,
    )

    assert len(seen) == 2
    assert heartbeat_path(str(tmp_path), filename=MONITOR_HEARTBEAT_FILE).exists()


# ---------------------------------------------------------------------------
# 7. doberman monitor status
# ---------------------------------------------------------------------------


async def test_monitor_status_on_a_fresh_repo(tmp_path):
    from doberman.monitor.daemon import monitor_status

    status = await monitor_status(str(tmp_path))
    assert status["running"] is False
    assert status["heartbeat_age_s"] is None
    assert status["cursor"] == 0
    assert status["pending_events"] == 0


async def test_monitor_status_counts_a_pending_backlog_before_any_drain(tmp_path):
    from doberman.monitor.daemon import monitor_status

    await emit_activity_event(_make_event(action_id="p1"), repo_root=str(tmp_path))
    status = await monitor_status(str(tmp_path))
    assert status["cursor"] == 0
    assert status["pending_events"] == 1


async def test_monitor_status_backlog_drops_to_zero_after_a_tick(tmp_path, monkeypatch):
    from doberman.monitor import daemon

    monkeypatch.setattr(
        daemon, "discover_collectors", lambda: [_StubCollector([_make_event(action_id="p2")])]
    )
    objective, subjective = daemon.build_engine_stack()
    await daemon.run_tick(str(tmp_path), objective, subjective)

    status = await daemon.monitor_status(str(tmp_path))
    assert status["pending_events"] == 0


def test_monitor_status_reports_running_when_heartbeat_is_fresh(tmp_path):
    from doberman.monitor.daemon import monitor_status

    touch_heartbeat(str(tmp_path), filename=MONITOR_HEARTBEAT_FILE)

    import asyncio

    status = asyncio.run(monitor_status(str(tmp_path)))
    assert status["running"] is True
    assert status["heartbeat_age_s"] is not None
    assert status["heartbeat_age_s"] < 5.0


# ---------------------------------------------------------------------------
# 8. CLI wiring
# ---------------------------------------------------------------------------


def test_cli_monitor_status_on_an_empty_repo(tmp_path):
    result = runner.invoke(app, ["monitor", "status", "--path", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "NOT RUNNING" in result.output
    assert "cursor: 0" in result.output
    assert "pending events: 0" in result.output


def test_cli_monitor_run_refuses_a_second_instance(tmp_path):
    touch_heartbeat(str(tmp_path), filename=MONITOR_HEARTBEAT_FILE)

    result = runner.invoke(app, ["monitor", "run", "--path", str(tmp_path)])
    assert result.exit_code == 1
    assert "already appears to be running" in result.output


def test_cli_monitor_run_rejects_an_invalid_mode(tmp_path):
    result = runner.invoke(
        app, ["monitor", "run", "--path", str(tmp_path), "--mode", "not-a-real-mode"]
    )
    assert result.exit_code == 1
    assert "error" in result.output.lower()
