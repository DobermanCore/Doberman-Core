"""Tests for the ambient monitor daemon (FM.2, issue #237).

Proves the hard rules from the issue, plus fu351's PR #699 review findings:

1. Observe-only, structurally: this module never imports doberman.auth or
   doberman.proxy - no prompter, no executor, no challenge.
2. Per-collector AND per-event isolation: a raising collector, a bad yielded
   value, and a scoring failure each cost only their own events - never the
   tick, never a silently dropped event.
3. A scoring failure records a conservative alert row (ReasonCode
   .ambient_scoring_error), never silence.
4. Cursor-based resume: a second tick never replays an already-drained event.
5. A failed write holds the cursor back rather than losing the alert, and is
   retried whole on the next tick (fu351: "keep failed alert writes
   retryable" - reproduced as lost alerts after a failed insert).
6. Collector instances are discovered once and retained across ticks, so
   collector-side state survives (fu351: "retain collector instances across
   ticks").
7. No exception payload (message/traceback) ever reaches a log line - only
   the error class name (fu351: "remove exception payloads from logs").
8. The heartbeat + an ATOMIC single-instance lock file: two admissions
   racing at the same instant can never both win (fu351: "make
   single-instance admission atomic" - reproduced as duplicate admission
   during simultaneous starts), and a stale lock from a crashed process is
   reclaimed rather than blocking forever.
9. `doberman monitor status`/`run` CLI wiring.

Ambient-aware rendering (the "observed (not enforced)" prefix and the ban on
"blocked"-sounding output, across doberman.explain/render/tui/dash) is each
of those modules' own contract and is tested in their own test files, not
here.
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


def test_poll_collectors_isolates_a_raising_collector():
    from doberman.monitor import daemon

    stub = _StubCollector(
        [
            _make_event(action_id="e1", collector_id="stub.collector"),
            _make_event(action_id="e2", collector_id="stub.collector"),
        ]
    )
    events = daemon._poll_collectors([_RaisingCollector(), stub])
    assert len(events) == 2
    assert all(e.collector_id == "stub.collector" for e in events)


def test_poll_collectors_skips_a_non_activity_event_yield():
    from doberman.monitor import daemon

    class _Bad:
        def collect(self):
            yield {"not": "an ActivityEvent"}
            yield _make_event(action_id="ok-1", collector_id="bad.collector")

    events = daemon._poll_collectors([_Bad()])
    assert len(events) == 1
    assert events[0].action_id == "ok-1"


def test_poll_collectors_retains_state_on_the_same_instance_across_calls():
    """FM.2 review: collector instances are discovered ONCE (by run_forever)
    and the SAME objects are handed to every tick - a collector that tracks
    internal state (call count, a "last scanned" position) must see that
    state persist across calls, not get reset because a fresh instance was
    built each tick."""
    from doberman.monitor import daemon

    class _StatefulCollector:
        def __init__(self):
            self.calls = 0

        def collect(self):
            self.calls += 1
            yield _make_event(action_id=f"stateful-{self.calls}", collector_id="stateful")

    stateful = _StatefulCollector()
    collectors = [stateful]

    first = daemon._poll_collectors(collectors)
    second = daemon._poll_collectors(collectors)

    assert stateful.calls == 2
    assert first[0].action_id == "stateful-1"
    assert second[0].action_id == "stateful-2"


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


async def test_run_tick_emits_scores_and_records_an_ambient_row(tmp_path):
    from doberman.monitor import daemon

    stub = _StubCollector(
        [_make_event(action_id="tick-1", action_type="file_read", target_path_class="src/*.py")]
    )

    objective, subjective = daemon.build_engine_stack()
    result = await daemon.run_tick(str(tmp_path), objective, subjective, [stub], mode="balanced")

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


async def test_run_tick_does_not_replay_an_already_drained_event(tmp_path):
    from doberman.monitor import daemon

    objective, subjective = daemon.build_engine_stack()
    first_collectors = [_StubCollector([_make_event(action_id="once-1")])]
    first = await daemon.run_tick(str(tmp_path), objective, subjective, first_collectors)
    assert first.drained == 1

    # A second tick's collector emits a NEW event; the cursor must mean the
    # daemon never re-scores "once-1" again.
    second_collectors = [_StubCollector([_make_event(action_id="once-2")])]
    second = await daemon.run_tick(str(tmp_path), objective, subjective, second_collectors)
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

    real_builder = daemon._security_object_from_event

    def _sometimes_boom(event):
        if event.action_id == "poison-1":
            raise RuntimeError("boom")
        return real_builder(event)

    monkeypatch.setattr(daemon, "_security_object_from_event", _sometimes_boom)

    objective, subjective = daemon.build_engine_stack()
    result = await daemon.run_tick(str(tmp_path), objective, subjective, [stub])

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


def test_run_forever_tolerates_discover_collectors_raising_at_startup(tmp_path, monkeypatch):
    """FM.2 review follow-up: run_tick no longer calls discover_collectors()
    at all (collectors are discovered once by run_forever) - so the daemon's
    resilience to a discovery bug is now run_forever's concern: it must
    start with an empty collector list rather than fail to start at all."""
    from doberman.monitor import daemon

    def _boom():
        raise RuntimeError("registry boom")

    monkeypatch.setattr(daemon, "discover_collectors", _boom)

    seen = []
    daemon.run_forever(str(tmp_path), interval_s=0.01, max_ticks=1, on_tick=seen.append)

    assert len(seen) == 1
    assert seen[0].collected == 0


async def test_run_tick_never_raises_on_an_unexpected_internal_bug(tmp_path, monkeypatch):
    """The tick-level failure boundary: a bug ANYWHERE inside run_tick's own
    body (not just a collector) must not escape it — the daemon hard rule is
    that nothing here may ever reach run_forever's loop and stop it."""
    from doberman.monitor import daemon

    async def _boom(*_a, **_k):
        raise RuntimeError("bus read boom")

    monkeypatch.setattr(daemon, "load_cursor", _boom)

    objective, subjective = daemon.build_engine_stack()
    result = await daemon.run_tick(str(tmp_path), objective, subjective, [])

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


async def test_ambient_scoring_never_writes_to_any_baseline_learning_table(tmp_path):
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
    collectors = [_StubCollector(events)]

    objective, subjective = daemon.build_engine_stack()
    for _ in range(3):  # several ticks, not just one
        await daemon.run_tick(str(tmp_path), objective, subjective, collectors, mode="balanced")

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
    clean, written = await daemon._score_event(
        event, objective, subjective, mode="balanced", repo_root=str(tmp_path)
    )
    assert clean is False
    assert written is True  # the fallback row itself still landed durably

    rows = await read_decisions(str(tmp_path))
    assert len(rows) == 1
    row = rows[0]
    assert row["source_context"] == "ambient:stub.collector"
    assert row["final_verdict"] == "BLOCK"
    assert json.loads(row["reason_codes_json"]) == ["ambient_scoring_error"]


# ---------------------------------------------------------------------------
# 5b. A failed write is retryable, never lost (fu351's review: "keep failed
#     alert writes retryable" - reproduced as lost alerts after a failed insert)
# ---------------------------------------------------------------------------


async def test_run_tick_holds_the_cursor_back_when_a_write_fails(tmp_path, monkeypatch):
    """The cursor is a claim of durability: it must never advance past an
    event whose row did not actually land, or that event is gone forever
    (the bus is only ever drained forward, never re-read from an earlier
    point on purpose)."""
    from doberman.monitor import daemon

    await emit_activity_event(_make_event(action_id="will-fail"), repo_root=str(tmp_path))

    async def _failing_record_decision(*_a, **_k):
        return False

    monkeypatch.setattr(daemon, "record_decision", _failing_record_decision)

    objective, subjective = daemon.build_engine_stack()
    result = await daemon.run_tick(str(tmp_path), objective, subjective, [])

    assert result.drained == 1  # it WAS read off the bus and scored...
    assert result.cursor == 0  # ...but the cursor must not have moved
    cursor = await load_cursor(str(tmp_path), reader_id=daemon.DEFAULT_READER_ID)
    assert cursor == 0
    assert (await read_decisions(str(tmp_path))) == []  # and nothing was recorded either


async def test_run_tick_retries_and_records_after_a_transient_write_failure(tmp_path, monkeypatch):
    """The other half: once writes start succeeding again, the SAME event
    (never lost, because the cursor held back) is durably recorded on a
    later tick."""
    from doberman.monitor import daemon
    from doberman.storage import log as log_module

    await emit_activity_event(_make_event(action_id="retry-me"), repo_root=str(tmp_path))

    real_record_decision = log_module.record_decision
    attempts = {"n": 0}

    async def _fail_once_then_succeed(*args, **kwargs):
        attempts["n"] += 1
        if attempts["n"] == 1:
            return False
        return await real_record_decision(*args, **kwargs)

    monkeypatch.setattr(daemon, "record_decision", _fail_once_then_succeed)

    objective, subjective = daemon.build_engine_stack()
    first = await daemon.run_tick(str(tmp_path), objective, subjective, [])
    assert first.cursor == 0
    assert (await read_decisions(str(tmp_path))) == []

    second = await daemon.run_tick(str(tmp_path), objective, subjective, [])
    assert second.drained == 1
    assert second.cursor > 0

    rows = await read_decisions(str(tmp_path))
    assert len(rows) == 1
    assert rows[0]["action_id"] == "retry-me"


async def test_run_tick_stops_the_batch_at_the_first_write_failure(tmp_path, monkeypatch):
    """Once one event's write fails, the REST of the batch isn't attempted
    this tick either - continuing would just add more work to redo, since
    the whole batch is retried together next tick regardless."""
    from doberman.monitor import daemon

    for action_id in ("e1", "e2", "e3"):
        await emit_activity_event(_make_event(action_id=action_id), repo_root=str(tmp_path))

    async def _always_fail(*_a, **_k):
        return False

    monkeypatch.setattr(daemon, "record_decision", _always_fail)

    objective, subjective = daemon.build_engine_stack()
    result = await daemon.run_tick(str(tmp_path), objective, subjective, [])

    assert result.drained == 3  # all three were read off the bus...
    assert result.scored + result.fallback == 1  # ...but only the first was attempted
    assert result.cursor == 0


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

    daemon._acquire_lock(str(tmp_path))  # simulates a sibling daemon's own startup claim
    with pytest.raises(daemon.MonitorAlreadyRunning):
        daemon.run_forever(str(tmp_path), max_ticks=1)


# ---------------------------------------------------------------------------
# 6b. Single-instance admission is atomic (fu351's review: "make single-
#     instance admission atomic" - reproduced as duplicate admission during
#     simultaneous starts)
# ---------------------------------------------------------------------------


def test_try_create_lock_wins_once_and_fails_the_second_time(tmp_path):
    from doberman.monitor import daemon

    assert daemon._try_create_lock(str(tmp_path)) is True
    assert daemon._try_create_lock(str(tmp_path)) is False  # already claimed


def test_try_create_lock_touches_the_heartbeat_immediately_on_winning(tmp_path):
    """Claiming the lock and becoming visibly "running" happen in the SAME
    call, not as two separate steps with a gap between them - otherwise a
    rival racing a moment behind the winner could see the lock exist but the
    heartbeat not yet fresh, and wrongly treat a legitimate brand-new winner
    as a stale, stealable lock."""
    from doberman.monitor import daemon

    assert daemon._try_create_lock(str(tmp_path)) is True
    assert daemon.is_already_running(str(tmp_path)) is True


def test_acquire_lock_steals_a_stale_lock_left_by_a_crashed_process(tmp_path):
    """A lock file with no corresponding fresh heartbeat means its owner
    crashed without cleaning up - the next start must recover, not be
    blocked forever by a dead process's leftover file."""
    from doberman.monitor import daemon

    daemon._lock_path(str(tmp_path)).parent.mkdir(parents=True, exist_ok=True)
    daemon._lock_path(str(tmp_path)).touch()
    stale = datetime.now(timezone.utc) - timedelta(seconds=30)
    touch_heartbeat(str(tmp_path), filename=MONITOR_HEARTBEAT_FILE, now=stale)

    daemon._acquire_lock(str(tmp_path))  # must not raise - the stale lock is reclaimed
    assert daemon.is_already_running(str(tmp_path)) is True  # our own fresh claim, now


def test_acquire_lock_refuses_when_a_live_sibling_holds_it(tmp_path):
    from doberman.monitor import daemon

    daemon._acquire_lock(str(tmp_path))
    with pytest.raises(daemon.MonitorAlreadyRunning):
        daemon._acquire_lock(str(tmp_path))


def test_release_lock_lets_a_fresh_start_succeed_immediately(tmp_path):
    from doberman.monitor import daemon

    daemon._acquire_lock(str(tmp_path))
    daemon._release_lock(str(tmp_path))
    daemon._acquire_lock(str(tmp_path))  # must not raise - no leftover lock in the way


def test_run_forever_releases_the_lock_on_a_clean_stop(tmp_path, monkeypatch):
    from doberman.monitor import daemon

    monkeypatch.setattr(daemon, "discover_collectors", lambda: [])
    daemon.run_forever(str(tmp_path), interval_s=0.01, max_ticks=1)
    assert not daemon._lock_path(str(tmp_path)).exists()


def test_try_create_lock_is_atomic_under_real_concurrent_threads(tmp_path):
    """The actual guarantee fu351 asked for: two admissions racing at the
    same instant must never both win. Real OS threads racing the SAME
    repo_root (not a mocked check-then-touch sequence) - a Barrier lines
    every thread up so they all call os.open() as close together as
    possible, which is what actually exercises the O_CREAT|O_EXCL guarantee
    rather than just the Python-level code wrapped around it."""
    import threading

    from doberman.monitor import daemon

    thread_count = 8
    results: list[bool] = []
    results_lock = threading.Lock()
    barrier = threading.Barrier(thread_count)

    def _attempt() -> None:
        barrier.wait()
        won = daemon._try_create_lock(str(tmp_path))
        with results_lock:
            results.append(won)

    threads = [threading.Thread(target=_attempt) for _ in range(thread_count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert results.count(True) == 1
    assert results.count(False) == thread_count - 1


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


async def test_monitor_status_backlog_drops_to_zero_after_a_tick(tmp_path):
    from doberman.monitor import daemon

    collectors = [_StubCollector([_make_event(action_id="p2")])]
    objective, subjective = daemon.build_engine_stack()
    await daemon.run_tick(str(tmp_path), objective, subjective, collectors)

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
# 7b. No exception payloads in logs (fu351's review: "remove exception
#     payloads from logs" - a raw message/traceback could carry data a
#     collector or the storage layer never meant to leak)
# ---------------------------------------------------------------------------


async def test_tick_failure_log_never_contains_the_exceptions_own_message(tmp_path, caplog):
    """The tick-level failure boundary logs that SOMETHING went wrong and
    which error CLASS it was, never the exception's own message or
    traceback - exc_info=True (or interpolating str(exc)) would attach
    exactly the kind of raw, unredacted content this module exists to keep
    out of its logs."""
    import logging

    from doberman.monitor import daemon

    marker = "super-secret-path/should-never-appear-in-a-log-C7F1A9"

    async def _boom(*_a, **_k):
        raise RuntimeError(marker)

    with caplog.at_level(logging.WARNING, logger="doberman.monitor.daemon"):
        import unittest.mock as mock

        with mock.patch.object(daemon, "load_cursor", _boom):
            objective, subjective = daemon.build_engine_stack()
            await daemon.run_tick(str(tmp_path), objective, subjective, [])

    assert marker not in caplog.text
    assert "RuntimeError" in caplog.text  # the error CLASS is still surfaced
    for record in caplog.records:
        assert record.exc_info is None  # exc_info=True would attach the traceback (and marker)


def test_poll_collectors_failure_log_never_contains_the_exceptions_own_message(caplog):
    import logging

    from doberman.monitor import daemon

    marker = "super-secret-token-should-never-appear-in-a-log-D2E8B4"

    class _Raising:
        def collect(self):
            raise RuntimeError(marker)

    with caplog.at_level(logging.WARNING, logger="doberman.monitor.daemon"):
        daemon._poll_collectors([_Raising()])

    assert marker not in caplog.text
    assert "RuntimeError" in caplog.text


async def test_score_event_failure_log_never_contains_the_exceptions_own_message(
    tmp_path, monkeypatch, caplog
):
    import logging

    from doberman.monitor import daemon

    marker = "super-secret-arg-should-never-appear-in-a-log-A1B2C3"

    def _boom(_event):
        raise RuntimeError(marker)

    monkeypatch.setattr(daemon, "_security_object_from_event", _boom)

    with caplog.at_level(logging.WARNING, logger="doberman.monitor.daemon"):
        objective, subjective = daemon.build_engine_stack()
        await daemon._score_event(
            _make_event(action_id="poison"),
            objective,
            subjective,
            mode="balanced",
            repo_root=str(tmp_path),
        )

    assert marker not in caplog.text
    assert "RuntimeError" in caplog.text


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
    from doberman.monitor import daemon

    daemon._acquire_lock(str(tmp_path))  # simulates a sibling daemon's own startup claim

    result = runner.invoke(app, ["monitor", "run", "--path", str(tmp_path)])
    assert result.exit_code == 1
    assert "already appears to be running" in result.output


def test_cli_monitor_run_rejects_an_invalid_mode(tmp_path):
    result = runner.invoke(
        app, ["monitor", "run", "--path", str(tmp_path), "--mode", "not-a-real-mode"]
    )
    assert result.exit_code == 1
    assert "error" in result.output.lower()
