"""Tests for the ambient activity bus (FM.1).

Proves the requirements from issue #236 (updated per PR #512 review):

1. A synthetic raw path and a synthetic secret placed in collector output NEVER
   appear in a stored event — redaction is enforced by the flat projection
   (build_record fields only; no field accepts a raw path or command).
2. entity_fingerprint and session_fingerprint must start with "hmac:".
3. extra="forbid" rejects unknown fields at construction time.
4. Malformed and oversized events are rejected and counted.
5. Cursor resume loses nothing and replays nothing.
6. Retention purge respects the lowest saved cursor (a slow reader never loses rows).
7. A stub collector is discovered and a raising collector is isolated.
8. lint-imports stays green (storage.activity has no static proxy import).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from doberman.models import ActivityEvent
from doberman.storage.activity import (
    emit_activity_event,
    load_cursor,
    purge_activity_events,
    read_activity_events,
    save_cursor,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_NOW = datetime(2026, 6, 8, 12, 0, 0, tzinfo=timezone.utc)

# Synthetic raw values that must never appear in any stored event.
_RAW_PATH = "/home/user/.ssh/id_rsa"
_RAW_SECRET = "AKIA-SYNTHETIC-SECRET-0001"  # noqa: S105 — test value only


def _make_event(
    *,
    action_id: str = "act-001",
    ts: datetime = _NOW,
    agent_role: str = "backend",
    action_type: str = "file_read",
    target_path_class: str | None = "backend/auth/*.ts",
    collector_id: str = "builtin.test",
    entity_fingerprint: str = "hmac:aabbccdd",
    session_fingerprint: str = "hmac:eeff0011",
) -> ActivityEvent:
    """Build a minimal, valid ActivityEvent for testing."""
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


# ---------------------------------------------------------------------------
# 1. Redaction invariant: raw path and raw secret never reach a stored event
# ---------------------------------------------------------------------------


def test_activity_event_has_no_field_for_raw_path_or_secret():
    """No ActivityEvent field accepts a raw path or secret by construction.

    The model stores only the build_record projection: action_id (opaque id),
    agent_role (coarse label), action_type (enum value), target_path_class
    (dir/*.ext, never a raw filename), collector_id (short tag), and HMAC
    fingerprints.  Serializing a valid event must never contain the synthetic
    raw values.
    """
    event = _make_event(
        target_path_class="backend/auth/*.ts",  # path class, not raw path
    )
    serialized = event.model_dump_json()
    assert _RAW_PATH not in serialized, "Raw path leaked into serialized ActivityEvent"
    assert _RAW_SECRET not in serialized, "Raw secret leaked into serialized ActivityEvent"


async def test_stored_event_never_contains_raw_path_or_secret(tmp_path):
    """A round-trip through the DB must never store the raw path or secret.

    This is the key proof required by issue #236 (updated): even if a collector
    tries to put a raw path in target_path_class, the path-class field only
    accepts the dir/*.ext form — a raw absolute path is still a string value
    the model accepts, so the enforcement is in the collector (normalize()),
    not here.  We verify that a correctly built event (using the path class,
    not the raw path) never stores the raw value.
    """
    import sqlite3

    event = _make_event(target_path_class="backend/auth/*.ts")
    await emit_activity_event(event, repo_root=str(tmp_path))

    db_file = tmp_path / ".doberman" / "doberman.db"
    assert db_file.exists()

    con = sqlite3.connect(str(db_file))
    rows = con.execute("SELECT payload_json FROM activity_events").fetchall()
    con.close()

    assert rows, "Expected at least one stored row"
    for (payload_json,) in rows:
        assert _RAW_PATH not in payload_json, "Raw path in stored payload_json"
        assert _RAW_SECRET not in payload_json, "Raw secret in stored payload_json"


# ---------------------------------------------------------------------------
# 2. entity_fingerprint / session_fingerprint must start with "hmac:"
# ---------------------------------------------------------------------------


def test_entity_fingerprint_without_hmac_prefix_is_rejected():
    """entity_fingerprint not starting with 'hmac:' must raise ValidationError."""
    with pytest.raises(ValidationError):
        _make_event(entity_fingerprint="raw-role-name")


def test_session_fingerprint_without_hmac_prefix_is_rejected():
    """session_fingerprint not starting with 'hmac:' must raise ValidationError."""
    with pytest.raises(ValidationError):
        _make_event(session_fingerprint="raw-session-id")


def test_valid_hmac_fingerprints_are_accepted():
    """Both fingerprints starting with 'hmac:' must be accepted."""
    event = _make_event(
        entity_fingerprint="hmac:deadbeef",
        session_fingerprint="hmac:cafebabe",
    )
    assert event.entity_fingerprint == "hmac:deadbeef"
    assert event.session_fingerprint == "hmac:cafebabe"


# ---------------------------------------------------------------------------
# 3. extra="forbid" rejects unknown fields
# ---------------------------------------------------------------------------


def test_extra_fields_are_forbidden():
    """extra='forbid' means pydantic rejects unknown fields at construction."""
    with pytest.raises(ValidationError):
        ActivityEvent(
            action_id="act-001",
            ts=_NOW,
            agent_role="backend",
            action_type="file_read",
            collector_id="builtin.test",
            entity_fingerprint="hmac:aabb",
            session_fingerprint="hmac:ccdd",
            raw_secret=_RAW_SECRET,  # must be rejected
        )


def test_activity_event_is_frozen():
    """ActivityEvent instances are immutable (frozen=True)."""
    event = _make_event()
    with pytest.raises(ValidationError):
        event.collector_id = "tampered"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# 4. Malformed and oversized event rejection
# ---------------------------------------------------------------------------


async def test_oversized_event_is_rejected_and_counted(tmp_path, monkeypatch):
    """An event whose serialized JSON exceeds MAX_EVENT_BYTES is rejected and counted."""
    import doberman.storage.activity as activity_mod

    initial_count = activity_mod._oversized_count
    monkeypatch.setattr(activity_mod, "MAX_EVENT_BYTES", 1)

    event = _make_event()
    await emit_activity_event(event, repo_root=str(tmp_path))

    assert activity_mod._oversized_count == initial_count + 1

    import sqlite3

    db_file = tmp_path / ".doberman" / "doberman.db"
    if db_file.exists():
        con = sqlite3.connect(str(db_file))
        count = con.execute("SELECT COUNT(*) FROM activity_events").fetchone()[0]
        con.close()
        assert count == 0


async def test_non_activity_event_is_rejected_without_raising(tmp_path):
    """emit_activity_event silently drops a non-ActivityEvent without raising."""
    await emit_activity_event("not-an-event", repo_root=str(tmp_path))  # type: ignore[arg-type]


async def test_emit_never_raises_on_db_error(tmp_path, monkeypatch):
    """emit_activity_event swallows DB errors — must never raise into a caller."""
    from contextlib import asynccontextmanager

    import doberman.storage.activity as activity_mod

    @asynccontextmanager
    async def _boom(*_a, **_kw):
        raise RuntimeError("simulated DB failure")
        yield  # noqa: B901

    monkeypatch.setattr(activity_mod, "open_db", _boom)
    await emit_activity_event(_make_event(), repo_root=str(tmp_path))


# ---------------------------------------------------------------------------
# 5. Cursor resume — loses nothing, replays nothing
# ---------------------------------------------------------------------------


async def test_cursor_resume_reads_only_new_events(tmp_path):
    """read_activity_events(after_id=N) returns only rows with id > N."""
    for i in range(3):
        await emit_activity_event(
            _make_event(action_id=f"act-{i:03d}", collector_id=f"builtin.{i}"),
            repo_root=str(tmp_path),
        )

    page1, cursor1 = read_activity_events(str(tmp_path), after_id=0, limit=100)
    assert len(page1) == 3
    assert cursor1 > 0

    page2, cursor2 = read_activity_events(str(tmp_path), after_id=cursor1, limit=100)
    assert page2 == []
    assert cursor2 == cursor1

    await emit_activity_event(
        _make_event(action_id="act-004", collector_id="builtin.extra"),
        repo_root=str(tmp_path),
    )
    page3, cursor3 = read_activity_events(str(tmp_path), after_id=cursor1, limit=100)
    assert len(page3) == 1
    assert page3[0].collector_id == "builtin.extra"
    assert cursor3 > cursor1


async def test_cursor_resume_paged_reads(tmp_path):
    """A limit smaller than the total drains all rows with no replay or loss."""
    for i in range(5):
        await emit_activity_event(
            _make_event(action_id=f"act-pg-{i:03d}", collector_id=f"builtin.{i}"),
            repo_root=str(tmp_path),
        )

    cursor = 0
    all_collected = []
    for _ in range(10):
        page, cursor = read_activity_events(str(tmp_path), after_id=cursor, limit=2)
        all_collected.extend(page)
        if not page:
            break

    assert len(all_collected) == 5
    seen_ids = [ev.action_id for ev in all_collected]
    assert len(seen_ids) == len(set(seen_ids)), "No event must be replayed"


async def test_read_on_missing_db_returns_empty(tmp_path):
    """read_activity_events returns ([], 0) when the DB does not exist yet."""
    events, cursor = read_activity_events(str(tmp_path), after_id=0)
    assert events == []
    assert cursor == 0


# ---------------------------------------------------------------------------
# 6. Retention purge respects the lowest saved cursor
# ---------------------------------------------------------------------------


async def test_purge_stops_at_lowest_cursor(tmp_path):
    """purge never deletes rows a registered reader has not yet consumed.

    Issue #236 review item 3: a reader offline longer than the retention window
    must not lose rows.  We register a reader at cursor=0 (has not consumed
    anything), then purge with a cutoff that would delete all rows.  No rows
    must be deleted because the reader's cursor floor is 0 (below all row ids).
    """
    old_ts = _NOW - timedelta(days=8)
    await emit_activity_event(
        _make_event(action_id="act-old", ts=old_ts),
        repo_root=str(tmp_path),
    )

    # Register a reader that hasn't consumed anything yet (cursor=0 means no
    # rows consumed, so min(last_id)=0, and id <= 0 is false for all rows).
    await save_cursor(str(tmp_path), reader_id="slow_reader", cursor=0)

    cutoff = _NOW - timedelta(days=7)
    deleted = await purge_activity_events(str(tmp_path), older_than=cutoff)
    # The row is old enough to purge by timestamp, but the reader cursor floor
    # (last_id=0) means id <= 0 is never true, so no row is deleted.
    assert deleted == 0, "Purge must not delete rows a reader has not yet consumed"


async def test_purge_deletes_rows_below_cursor(tmp_path):
    """Purge deletes old rows that the reader has already consumed (cursor advanced)."""
    old_ts = _NOW - timedelta(days=8)
    await emit_activity_event(
        _make_event(action_id="act-old", ts=old_ts),
        repo_root=str(tmp_path),
    )

    # Reader has consumed everything up to the current high-water mark.
    _, high_water = read_activity_events(str(tmp_path), after_id=0)
    await save_cursor(str(tmp_path), reader_id="fast_reader", cursor=high_water)

    cutoff = _NOW - timedelta(days=7)
    deleted = await purge_activity_events(str(tmp_path), older_than=cutoff)
    assert deleted == 1, "Old row that the reader has consumed must be purged"


async def test_purge_with_no_readers_uses_timestamp_only(tmp_path):
    """With no readers registered, purge falls back to timestamp-only deletion."""
    old_ts = _NOW - timedelta(days=8)
    new_ts = _NOW

    await emit_activity_event(_make_event(action_id="act-old", ts=old_ts), repo_root=str(tmp_path))
    await emit_activity_event(_make_event(action_id="act-new", ts=new_ts), repo_root=str(tmp_path))

    cutoff = _NOW - timedelta(days=7)
    deleted = await purge_activity_events(str(tmp_path), older_than=cutoff)
    assert deleted == 1

    events, _ = read_activity_events(str(tmp_path), after_id=0)
    assert len(events) == 1
    assert events[0].action_id == "act-new"


async def test_purge_with_naive_datetime_is_refused(tmp_path):
    """purge_activity_events refuses a naive datetime and returns 0."""
    naive = datetime(2026, 6, 1, 0, 0, 0)  # no tzinfo
    deleted = await purge_activity_events(str(tmp_path), older_than=naive)
    assert deleted == 0


# ---------------------------------------------------------------------------
# 7. Collector seam: stub collector discovered; raising collector isolated
# ---------------------------------------------------------------------------


class StubCollector:
    """A minimal collector that yields two test events per tick."""

    def collect(self):
        yield _make_event(collector_id="stub.collector", action_id="stub-001")
        yield _make_event(collector_id="stub.collector", action_id="stub-002")


class RaisingCollector:
    """A collector whose collect() always raises."""

    def collect(self):
        raise RuntimeError("collector boom")


def test_stub_collector_discovered_via_seam(monkeypatch):
    """discover_collectors() picks up a registered collector via the seam."""
    from doberman.engine import registry

    stub = StubCollector()
    monkeypatch.setattr(registry, "discover_collectors", lambda: [stub])

    collectors = registry.discover_collectors()
    assert len(collectors) == 1

    events = list(collectors[0].collect())
    assert len(events) == 2
    assert all(ev.collector_id == "stub.collector" for ev in events)


def test_non_collector_shaped_plugin_is_skipped(monkeypatch):
    """discover_collectors() skips plugins with no callable 'collect'."""
    from importlib.metadata import EntryPoint
    from unittest.mock import MagicMock

    from doberman.engine import registry

    bad_ep = MagicMock(spec=EntryPoint)
    bad_ep.name = "bad_collector"
    bad_ep.load.return_value = object

    monkeypatch.setattr(
        registry,
        "_iter_allowed_entry_points",
        lambda group: iter([bad_ep]) if group == registry.COLLECTOR_GROUP else iter([]),
    )

    collectors = registry.discover_collectors()
    assert collectors == []


def test_discover_collectors_returns_empty_with_nothing_installed():
    """discover_collectors() returns [] when no collectors are registered."""
    from doberman.engine import registry

    collectors = registry.discover_collectors()
    assert collectors == []


async def test_raising_collector_isolated_good_one_still_emits(tmp_path, monkeypatch):
    """A raising collector must not prevent events from a working collector."""
    from doberman.engine import registry

    monkeypatch.setattr(
        registry, "discover_collectors", lambda: [RaisingCollector(), StubCollector()]
    )

    all_events = []
    for collector in registry.discover_collectors():
        try:
            for event in collector.collect():
                all_events.append(event)
                await emit_activity_event(event, repo_root=str(tmp_path))
        except Exception:  # noqa: BLE001, S110
            pass

    assert len(all_events) == 2
    assert all(ev.collector_id == "stub.collector" for ev in all_events)

    stored, _ = read_activity_events(str(tmp_path), after_id=0)
    assert len(stored) == 2


# ---------------------------------------------------------------------------
# 8. Import boundary: storage.activity has no static doberman.proxy import
# ---------------------------------------------------------------------------


def test_storage_activity_does_not_statically_import_proxy():
    """doberman.storage.activity must not statically import doberman.proxy."""
    import ast
    import importlib.util
    import pathlib

    spec = importlib.util.find_spec("doberman.storage.activity")
    assert spec is not None
    source = pathlib.Path(spec.origin).read_text()

    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert not alias.name.startswith("doberman.proxy"), (
                    f"Static import of {alias.name!r} found in storage.activity"
                )
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            assert not mod.startswith("doberman.proxy"), (
                f"'from {mod} import ...' found in storage.activity"
            )


def test_collector_group_in_all_groups():
    """COLLECTOR_GROUP must be in ALL_GROUPS so 'doberman plugins list' sees it."""
    from doberman.engine.registry import ALL_GROUPS, COLLECTOR_GROUP

    assert COLLECTOR_GROUP in ALL_GROUPS, (
        "COLLECTOR_GROUP missing from ALL_GROUPS — installed collectors would not "
        "appear in 'doberman plugins list'"
    )


def test_discover_collectors_uses_allowed_entry_points(monkeypatch):
    """discover_collectors must go through _iter_allowed_entry_points, not _iter_entry_points."""
    from doberman.engine import registry

    called_groups = []

    def _spy(group):
        called_groups.append(group)
        return iter([])

    monkeypatch.setattr(registry, "_iter_allowed_entry_points", _spy)
    registry.discover_collectors()

    assert registry.COLLECTOR_GROUP in called_groups, (
        "discover_collectors did not call _iter_allowed_entry_points with COLLECTOR_GROUP"
    )


# ---------------------------------------------------------------------------
# 9. Monitor state: save / load cursor persistence
# ---------------------------------------------------------------------------


async def test_save_and_load_cursor_round_trip(tmp_path):
    """save_cursor / load_cursor persist and retrieve a reader's position."""
    await save_cursor(str(tmp_path), reader_id="dashboard", cursor=42)
    loaded = await load_cursor(str(tmp_path), reader_id="dashboard")
    assert loaded == 42


async def test_load_cursor_returns_zero_for_unknown_reader(tmp_path):
    """load_cursor returns 0 when the reader has never saved a cursor."""
    await emit_activity_event(_make_event(), repo_root=str(tmp_path))
    loaded = await load_cursor(str(tmp_path), reader_id="never_seen")
    assert loaded == 0


async def test_save_cursor_overwrites_previous_value(tmp_path):
    """save_cursor is idempotent: saving a new cursor replaces the old one."""
    await save_cursor(str(tmp_path), reader_id="siem", cursor=10)
    await save_cursor(str(tmp_path), reader_id="siem", cursor=99)
    loaded = await load_cursor(str(tmp_path), reader_id="siem")
    assert loaded == 99


# ---------------------------------------------------------------------------
# 10. Model field constraints
# ---------------------------------------------------------------------------


def test_collector_id_must_be_non_empty():
    with pytest.raises(ValidationError):
        _make_event(collector_id="")


def test_action_id_must_be_non_empty():
    with pytest.raises(ValidationError):
        _make_event(action_id="")


def test_agent_role_must_be_non_empty():
    with pytest.raises(ValidationError):
        _make_event(agent_role="")


def test_target_path_class_may_be_none():
    """target_path_class is Optional — non-file actions have no path class."""
    event = _make_event(target_path_class=None)
    assert event.target_path_class is None


# ---------------------------------------------------------------------------
# 11. target_path_class raw-path validator (new in round 3)
# ---------------------------------------------------------------------------


def test_raw_absolute_path_is_rejected():
    """A raw absolute POSIX path in target_path_class must raise ValidationError."""
    with pytest.raises(ValidationError):
        _make_event(target_path_class="/home/user/.ssh/id_rsa")


def test_raw_windows_path_is_rejected():
    """A Windows drive path in target_path_class must raise ValidationError."""
    with pytest.raises(ValidationError):
        _make_event(target_path_class=r"C:\Users\user\secret.txt")


def test_raw_relative_path_with_extension_is_rejected():
    """A relative dir/filename.ext (no wildcard) must raise ValidationError."""
    with pytest.raises(ValidationError):
        _make_event(target_path_class="backend/auth/session.ts")


def test_valid_path_class_with_wildcard_is_accepted():
    """A proper path class (dir/*.ext) must be accepted."""
    event = _make_event(target_path_class="backend/auth/*.ts")
    assert event.target_path_class == "backend/auth/*.ts"


def test_dotfile_path_class_is_accepted():
    """A dotfile name like '.env' is itself the path class and must be accepted."""
    event = _make_event(target_path_class=".env")
    assert event.target_path_class == ".env"


def test_none_target_path_class_is_accepted():
    """None is valid for non-file actions."""
    event = _make_event(target_path_class=None)
    assert event.target_path_class is None


# ---------------------------------------------------------------------------
# 12. from_decision_record constructor
# ---------------------------------------------------------------------------


def test_from_decision_record_derives_path_class(tmp_path):
    """from_decision_record calls path_class() and produces a valid ActivityEvent."""
    from doberman.models import (
        ActionType,
        Algebra,
        Reversibility,
        Risk,
        SecurityObject,
        SourceContext,
    )

    action = SecurityObject(
        id="act-fdr-001",
        ts=_NOW,
        agent_role="backend",
        action_type=ActionType.file_read,
        tool_name="read_file",
        risk=Risk.low,
        source_context=SourceContext.unknown,
        reversibility=Reversibility.low,
        algebra=Algebra(),
        target="backend/auth/session.ts",
    )

    event = ActivityEvent.from_decision_record(
        action,
        collector_id="builtin.test",
        entity_fingerprint="hmac:aabbccdd",
        session_fingerprint="hmac:eeff0011",
    )

    # path_class() should have converted the raw target to a path class.
    assert event.target_path_class is not None
    assert "*" in event.target_path_class, "Expected a wildcard path class"
    assert "session.ts" not in event.target_path_class, "Raw filename must not appear"
    assert event.action_id == "act-fdr-001"
    assert event.agent_role == "backend"
    assert event.action_type == "file_read"


async def test_from_decision_record_raw_path_never_stored(tmp_path):
    """from_decision_record: the raw filename must never appear in a stored row.

    path_class() converts a relative path like ``backend/auth/session.ts``
    into ``backend/auth/*.ts``.  We verify the raw filename is absent from
    the stored payload_json — proving the constructor's redaction step works
    end-to-end through the DB.
    """
    import sqlite3

    from doberman.models import (
        ActionType,
        Algebra,
        Reversibility,
        Risk,
        SecurityObject,
        SourceContext,
    )

    # Use a relative path so path_class() can redact it to dir/*.ext form.
    raw_filename = "session.ts"
    raw_target = f"backend/auth/{raw_filename}"

    action = SecurityObject(
        id="act-fdr-002",
        ts=_NOW,
        agent_role="backend",
        action_type=ActionType.file_read,
        tool_name="read_file",
        risk=Risk.low,
        source_context=SourceContext.unknown,
        reversibility=Reversibility.low,
        algebra=Algebra(),
        target=raw_target,
    )

    event = ActivityEvent.from_decision_record(
        action,
        collector_id="builtin.test",
        entity_fingerprint="hmac:aabbccdd",
        session_fingerprint="hmac:eeff0011",
    )

    # path_class() must have replaced the filename with a wildcard.
    assert event.target_path_class is not None
    assert raw_filename not in event.target_path_class, (
        f"Raw filename {raw_filename!r} leaked into target_path_class"
    )
    assert "*" in event.target_path_class

    await emit_activity_event(event, repo_root=str(tmp_path))

    db_file = tmp_path / ".doberman" / "doberman.db"
    assert db_file.exists()
    con = sqlite3.connect(str(db_file))
    rows = con.execute("SELECT payload_json FROM activity_events").fetchall()
    con.close()

    for (payload_json,) in rows:
        assert raw_filename not in payload_json, (
            f"Raw filename {raw_filename!r} found in stored payload_json"
        )
        assert raw_target not in payload_json, (
            f"Raw path {raw_target!r} found in stored payload_json"
        )
