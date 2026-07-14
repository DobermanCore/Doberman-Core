"""Feature CB.2 — CostObserver plugin seam.

Covers:
* Protocol shape and structural check
* notify_cost_observers fan-out, isolation, and copy semantics
* discover_cost_observers returns [] with nothing installed
* Wire: record_cost_event notifies registered observers
* Isolation: a raising observer never prevents the ledger write or raises
"""

from datetime import datetime, timezone
from unittest.mock import patch

from doberman.models import CostEvent, CostKind
from doberman.storage.cost import (
    CostObserver,
    _looks_like_cost_observer,
    notify_cost_observers,
    record_cost_event,
)

_NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def _event(units: int = 100, *, kind: CostKind = CostKind.tokens_in) -> CostEvent:
    return CostEvent(action_id="a1", ts=_NOW, kind=kind, units=units, entity_id="e1")


# --- Protocol shape and structural check ------------------------------------


def test_looks_like_cost_observer_passes_with_on_cost():
    class Good:
        def on_cost(self, event: CostEvent) -> None:
            pass

    assert _looks_like_cost_observer(Good())


def test_looks_like_cost_observer_fails_without_on_cost():
    class Bad:
        def emit(self, event: CostEvent) -> None:
            pass

    assert not _looks_like_cost_observer(Bad())


def test_looks_like_cost_observer_fails_when_on_cost_not_callable():
    class NotCallable:
        on_cost = "not a method"

    assert not _looks_like_cost_observer(NotCallable())


def test_cost_observer_protocol_isinstance():
    class Good:
        def on_cost(self, event: CostEvent) -> None:
            pass

    assert isinstance(Good(), CostObserver)


# --- notify_cost_observers fan-out ------------------------------------------


def test_notify_calls_observer_with_event():
    received = []

    class Obs:
        def on_cost(self, event: CostEvent) -> None:
            received.append(event)

    obs = Obs()
    ev = _event()
    with patch("doberman.engine.registry.discover_cost_observers", return_value=[obs]):
        notify_cost_observers(ev)

    assert received == [ev]


def test_notify_passes_copy_not_original():
    """Each observer gets the same frozen CostEvent object — immutability is the
    redaction guarantee, not a defensive copy (CostEvent is frozen by Pydantic)."""
    received = []

    class Obs:
        def on_cost(self, event: CostEvent) -> None:
            received.append(id(event))

    obs = Obs()
    ev = _event()
    with patch("doberman.engine.registry.discover_cost_observers", return_value=[obs]):
        notify_cost_observers(ev)

    assert received == [id(ev)]


def test_notify_skips_non_observer_shaped():
    class Bad:
        pass

    with patch("doberman.engine.registry.discover_cost_observers", return_value=[Bad()]):
        notify_cost_observers(_event())  # must not raise


def test_notify_isolates_raising_observer_and_continues():
    called = []

    class Raiser:
        def on_cost(self, event: CostEvent) -> None:
            raise RuntimeError("boom")

    class Good:
        def on_cost(self, event: CostEvent) -> None:
            called.append(event)

    with patch("doberman.engine.registry.discover_cost_observers", return_value=[Raiser(), Good()]):
        notify_cost_observers(_event())  # must not raise

    assert len(called) == 1


def test_notify_with_no_observers_is_noop():
    with patch("doberman.engine.registry.discover_cost_observers", return_value=[]):
        notify_cost_observers(_event())  # must not raise


# --- discover_cost_observers (registry) -------------------------------------


def test_discover_cost_observers_returns_empty_with_nothing_installed():
    from doberman.engine.registry import discover_cost_observers

    result = discover_cost_observers()
    assert result == []


# --- Wire: record_cost_event notifies observer ------------------------------


async def test_record_cost_event_notifies_observer(tmp_path):
    received: list[CostEvent] = []

    class Obs:
        def on_cost(self, event: CostEvent) -> None:
            received.append(event)

    ev = _event()
    with patch("doberman.engine.registry.discover_cost_observers", return_value=[Obs()]):
        await record_cost_event(ev, repo_root=str(tmp_path))

    assert received == [ev]


async def test_record_cost_event_observer_does_not_prevent_ledger_write(tmp_path):
    """A raising observer must not prevent the cost row from being persisted."""
    from doberman.storage.cost import read_total

    class Raiser:
        def on_cost(self, event: CostEvent) -> None:
            raise RuntimeError("observer boom")

    ev = _event(50)
    with patch("doberman.engine.registry.discover_cost_observers", return_value=[Raiser()]):
        await record_cost_event(ev, repo_root=str(tmp_path))

    # Row was written despite the observer raising.
    assert await read_total(str(tmp_path)) == 50


async def test_record_cost_event_never_raises_when_observer_raises(tmp_path):
    class Raiser:
        def on_cost(self, event: CostEvent) -> None:
            raise RuntimeError("observer boom")

    ev = _event()
    with patch("doberman.engine.registry.discover_cost_observers", return_value=[Raiser()]):
        await record_cost_event(ev, repo_root=str(tmp_path))  # must not raise


async def test_record_cost_event_notifies_after_successful_write_only(tmp_path):
    """Observer must NOT be called when the DB write itself fails (bad root)."""
    called = []

    class Obs:
        def on_cost(self, event: CostEvent) -> None:
            called.append(True)

    bad = tmp_path / "not_a_dir"
    bad.write_text("x")

    with patch("doberman.engine.registry.discover_cost_observers", return_value=[Obs()]):
        await record_cost_event(_event(), repo_root=str(bad))

    assert called == []
