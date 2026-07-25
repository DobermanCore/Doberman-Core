"""RB.6 — ``EgressVelocityTracker`` unit tests: burst/volume/fan-out signal
thresholds, window filtering, and the two memory bounds (per-entity deque,
tracked-entity map).
"""

from datetime import datetime, timedelta, timezone

from doberman.egress.broker import ConnectionEvent
from doberman.egress.velocity import (
    _BURST_THRESHOLD,
    _FANOUT_THRESHOLD,
    _MAX_EVENTS_PER_ENTITY,
    _MAX_TRACKED_ENTITIES,
    _VOLUME_THRESHOLD_BYTES,
    EgressVelocityTracker,
)

_NOW = datetime(2026, 7, 24, 12, 0, 0, tzinfo=timezone.utc)
_WINDOW = (_NOW - timedelta(minutes=15), _NOW)


def _events(n: int, *, host: str = "a.example.com", bytes_sent: int = 1, entity: str = "e1"):
    return [
        ConnectionEvent(entity_id=entity, ts=_NOW, host=host, bytes_sent=bytes_sent)
        for _ in range(n)
    ]


def test_burst_trips_above_threshold_not_below():
    tracker = EgressVelocityTracker()
    at_threshold = tracker.assess("e1", _events(_BURST_THRESHOLD), _WINDOW)
    assert at_threshold is None

    tracker = EgressVelocityTracker()
    above_threshold = tracker.assess("e1", _events(_BURST_THRESHOLD + 1), _WINDOW)
    assert above_threshold is not None
    assert "burst" in above_threshold.signals


def test_volume_trips_above_threshold_not_below():
    tracker = EgressVelocityTracker()
    at_threshold = tracker.assess("e1", _events(1, bytes_sent=_VOLUME_THRESHOLD_BYTES), _WINDOW)
    assert at_threshold is None

    tracker = EgressVelocityTracker()
    above_threshold = tracker.assess(
        "e1", _events(1, bytes_sent=_VOLUME_THRESHOLD_BYTES + 1), _WINDOW
    )
    assert above_threshold is not None
    assert "volume" in above_threshold.signals


def test_fanout_trips_on_many_distinct_hosts_not_one_host():
    tracker = EgressVelocityTracker()
    many_hosts = [
        ConnectionEvent(entity_id="e1", ts=_NOW, host=f"host{i}.example.com", bytes_sent=1)
        for i in range(_FANOUT_THRESHOLD + 1)
    ]
    finding = tracker.assess("e1", many_hosts, _WINDOW)
    assert finding is not None
    assert "fan_out" in finding.signals

    tracker = EgressVelocityTracker()
    one_host = _events(_FANOUT_THRESHOLD + 1, host="single.example.com")
    finding = tracker.assess("e1", one_host, _WINDOW)
    assert finding is None


def test_events_outside_the_window_are_ignored():
    tracker = EgressVelocityTracker()
    stale = [
        ConnectionEvent(
            entity_id="e1",
            ts=_WINDOW[0] - timedelta(hours=1),
            host="a.example.com",
            bytes_sent=1,
        )
        for _ in range(_BURST_THRESHOLD + 5)
    ]
    finding = tracker.assess("e1", stale, _WINDOW)
    assert finding is None


def test_per_entity_deque_is_bounded():
    tracker = EgressVelocityTracker()
    tracker.assess("e1", _events(_MAX_EVENTS_PER_ENTITY + 50), _WINDOW)
    assert len(tracker._by_entity["e1"]) == _MAX_EVENTS_PER_ENTITY


def test_tracked_entity_map_is_bounded_and_evicts_oldest():
    tracker = EgressVelocityTracker()
    for i in range(_MAX_TRACKED_ENTITIES + 1):
        tracker.assess(f"entity-{i}", _events(1, entity=f"entity-{i}"), _WINDOW)
    assert len(tracker._by_entity) == _MAX_TRACKED_ENTITIES
    assert "entity-0" not in tracker._by_entity
    assert f"entity-{_MAX_TRACKED_ENTITIES}" in tracker._by_entity
