"""Issue #143 — wire the CB.3 loop-anomaly detector into the CB.2 CostObserver seam.

Covers the crossing path that ``test_cost_observer.py`` and
``test_cost_loop_anomaly.py`` never exercise together:

* a call-burst crosses the threshold -> the subscribed observer's optional
  ``on_loop_anomaly`` receives exactly one redaction-safe ``LoopAnomaly``
* an observer exposing only ``on_cost`` keeps receiving ``on_cost``; nothing
  errors even though it has no ``on_loop_anomaly``
* with no observer installed, the detector is never even invoked (no extra
  DB read on the hot path)
* a raising ``on_loop_anomaly`` is logged and swallowed; the record path
  still returns normally
"""

from datetime import datetime, timezone
from unittest.mock import patch

from doberman.models import CostEvent, CostKind
from doberman.storage.cost import LoopAnomaly, record_cost_event


def _call_event(i: int, *, entity_id: str = "e1") -> CostEvent:
    # The wiring under test calls detect_loop_anomaly() without an explicit
    # ``now``, so it defaults to the real current time — event timestamps must
    # be real "now" too, or they fall outside the detector's rolling window.
    ts = datetime.now(timezone.utc)
    return CostEvent(
        action_id=f"a{i}", ts=ts, kind=CostKind.tool_call, units=1, entity_id=entity_id
    )


# --- (a) crossing: call burst reaches the observer ---------------------------


async def test_loop_anomaly_crosses_to_observer_on_call_burst(tmp_path):
    received: list[LoopAnomaly] = []

    class Obs:
        def on_cost(self, event: CostEvent) -> None:
            pass

        def on_loop_anomaly(self, anomaly: LoopAnomaly) -> None:
            received.append(anomaly)

    root = str(tmp_path)
    # Default threshold is 40 calls in a 60s window; 41 tool-call events (same
    # entity, "now") cross it on the last write.
    with patch("doberman.engine.registry.discover_cost_observers", return_value=[Obs()]):
        for i in range(41):
            await record_cost_event(_call_event(i), repo_root=root)

    assert len(received) == 1
    anomaly = received[0]
    assert anomaly.is_anomaly is True
    assert anomaly.signal == "call_burst"
    # Redaction-safe: the entity id never appears in the human explanation.
    assert "e1" not in anomaly.explanation


# --- (b) on_cost-only observer keeps working, no error -----------------------


async def test_on_cost_only_observer_unaffected_by_loop_anomaly_hook(tmp_path):
    received: list[CostEvent] = []

    class OnCostOnly:
        def on_cost(self, event: CostEvent) -> None:
            received.append(event)

    root = str(tmp_path)
    ev = _call_event(0)
    with patch("doberman.engine.registry.discover_cost_observers", return_value=[OnCostOnly()]):
        await record_cost_event(ev, repo_root=root)  # must not raise

    assert received == [ev]


# --- (c) no observers -> detector never runs ----------------------------------


async def test_no_observers_skips_detector_entirely(tmp_path):
    root = str(tmp_path)
    with (
        patch("doberman.engine.registry.discover_cost_observers", return_value=[]),
        patch("doberman.storage.cost.detect_loop_anomaly") as spy,
    ):
        await record_cost_event(_call_event(0), repo_root=root)

    spy.assert_not_called()


# --- (d) raising on_loop_anomaly is logged, record path still returns --------


async def test_raising_on_loop_anomaly_is_logged_and_swallowed(tmp_path):
    class Raiser:
        def on_cost(self, event: CostEvent) -> None:
            pass

        def on_loop_anomaly(self, anomaly: LoopAnomaly) -> None:
            raise RuntimeError("observer boom")

    fake_anomaly = LoopAnomaly(
        is_anomaly=True,
        signal="call_burst",
        window_seconds=60,
        calls=41,
        units=0,
        explanation="41 tool calls in 60s exceed the advisory limit of 40.",
    )

    root = str(tmp_path)
    with (
        patch("doberman.engine.registry.discover_cost_observers", return_value=[Raiser()]),
        patch("doberman.storage.cost.detect_loop_anomaly", return_value=fake_anomaly),
    ):
        await record_cost_event(_call_event(0), repo_root=root)  # must not raise
