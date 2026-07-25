"""``EgressVelocityTracker`` (Feature RB, slice RB.6) — a bounded, in-memory,
per-entity anomalous-egress-velocity detector over observed
:class:`~doberman.egress.broker.ConnectionEvent`\\ s.

Runs entirely off events an :class:`~doberman.egress.broker.EgressBroker`
already observed and handed back via ``connection_events()`` — this module
adds no I/O, no persistence, and no new dependency (explicitly NOT SQLite).
Memory is bounded two ways so an attacker-controlled ``entity_id`` can never
turn this into a memory-exhaustion vector: each entity's own history is a
``collections.deque(maxlen=_MAX_EVENTS_PER_ENTITY)``, and the number of
distinct tracked entities is capped at ``_MAX_TRACKED_ENTITIES`` (the
least-recently-assessed entity is evicted once the cap is hit).

Three signals, each gated by a module-constant threshold, computed over the
bounded recent window handed to :meth:`EgressVelocityTracker.assess`:

- **burst**   -- too many connection attempts in the window
- **volume**  -- too many bytes sent in the window
- **fan-out** -- too many distinct destination hosts in the window

Not wired into any decision by this module — :mod:`doberman.engine.rules.
destinations` (RB.6) owns when/whether to consult it and what a trip does to
a verdict (raise-only).
"""

from __future__ import annotations

from collections import OrderedDict, deque
from collections.abc import Sequence
from dataclasses import dataclass

from pydantic import AwareDatetime

from doberman.egress.broker import ConnectionEvent

# ponytail: fixed module constants, not policy-configurable -- revisit if a
# real deployment needs per-mode/per-policy tuning (see RB.5's mode gating
# for the shape that would take).
_MAX_EVENTS_PER_ENTITY = 256
_MAX_TRACKED_ENTITIES = 1024
_BURST_THRESHOLD = 20
_VOLUME_THRESHOLD_BYTES = 50 * 1024 * 1024
_FANOUT_THRESHOLD = 10


@dataclass(frozen=True)
class VelocityFinding:
    """Which velocity signal(s) tripped for one entity's recent window."""

    entity: str
    signals: tuple[str, ...]


class EgressVelocityTracker:
    """Bounded, in-memory per-entity egress-velocity detector.

    Stateful across calls on purpose: one long-lived instance (owned by the
    long-lived proxy's ``ExternalDestinationRule``) accumulates each entity's
    observed connections call over call, bounded by the two caps above, so a
    burst spread across several tool calls is still caught.
    """

    def __init__(self) -> None:
        self._by_entity: OrderedDict[str, deque[ConnectionEvent]] = OrderedDict()

    def assess(
        self,
        entity: str,
        events: Sequence[ConnectionEvent],
        window: tuple[AwareDatetime, AwareDatetime],
    ) -> VelocityFinding | None:
        """Fold ``events`` into ``entity``'s bounded history, then check
        whether the portion still inside ``window`` trips burst/volume/
        fan-out.

        Events outside ``window`` are never folded in and never counted --
        defense in depth against a broker that doesn't honor the window it
        was asked for. Previously-tracked events that have since aged out of
        ``window`` are likewise excluded from this call's signal computation
        (they stay in the deque only until ``maxlen`` evicts them).
        """
        start, end = window
        in_window = [event for event in events if start <= event.ts <= end]
        tracked = self._track(entity)
        for event in in_window:
            tracked.append(event)
        recent = [event for event in tracked if start <= event.ts <= end]

        signals: list[str] = []
        if len(recent) > _BURST_THRESHOLD:
            signals.append("burst")
        if sum(event.bytes_sent for event in recent) > _VOLUME_THRESHOLD_BYTES:
            signals.append("volume")
        if len({event.host for event in recent}) > _FANOUT_THRESHOLD:
            signals.append("fan_out")
        if not signals:
            return None
        return VelocityFinding(entity=entity, signals=tuple(signals))

    def _track(self, entity: str) -> deque[ConnectionEvent]:
        """Get-or-create ``entity``'s bounded deque, evicting the
        least-recently-assessed entity once ``_MAX_TRACKED_ENTITIES`` is hit.
        """
        if entity in self._by_entity:
            self._by_entity.move_to_end(entity)
            return self._by_entity[entity]
        if len(self._by_entity) >= _MAX_TRACKED_ENTITIES:
            self._by_entity.popitem(last=False)
        tracked: deque[ConnectionEvent] = deque(maxlen=_MAX_EVENTS_PER_ENTITY)
        self._by_entity[entity] = tracked
        return tracked


def demo() -> None:  # ponytail: smallest runnable self-check, no framework
    """``python -m doberman.egress.velocity`` -- exercise each signal once."""
    from datetime import datetime, timedelta, timezone

    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    window = (now - timedelta(minutes=15), now)
    tracker = EgressVelocityTracker()

    burst = [
        ConnectionEvent(entity_id="e1", ts=now, host="a.example.com", bytes_sent=1)
        for _ in range(_BURST_THRESHOLD + 1)
    ]
    finding = tracker.assess("e1", burst, window)
    assert finding is not None and "burst" in finding.signals  # noqa: S101

    quiet = [ConnectionEvent(entity_id="e2", ts=now, host="a.example.com", bytes_sent=1)]
    assert tracker.assess("e2", quiet, window) is None  # noqa: S101

    print("ok")


if __name__ == "__main__":
    demo()
