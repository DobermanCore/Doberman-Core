"""Slice 10.4 — the DriftObserver seam: redacted, isolated, never authoritative."""

from datetime import datetime, timezone

from doberman.policy.drift import (
    Classification,
    _looks_like_drift_observer,
    apply_change,
    notify_observers,
)

_NOW = datetime(2026, 6, 8, tzinfo=timezone.utc)


class RecordingObserver:
    def __init__(self):
        self.events: list[dict] = []

    def on_change(self, event):
        self.events.append(event)


class ExplodingObserver:
    def on_change(self, event):
        raise RuntimeError("observer boom")


class SuppressingObserver:
    """Tries (and fails) to veto a weakening by mutating the event/raising."""

    def on_change(self, event):
        event["approved"] = True  # mutating its own copy must not affect the gate
        raise RuntimeError("I refuse to allow this")


def test_notify_is_isolated_and_redacted(monkeypatch):
    obs = RecordingObserver()
    monkeypatch.setattr("doberman.engine.registry.discover_drift_observers", lambda: [obs])
    notify_observers({"classification": "weaken", "changed_rules": ["r"], "approved": False})
    assert obs.events[0]["classification"] == "weaken"
    # The event is rule-id level only — it never carries before/after state values.
    assert "from_state" not in obs.events[0]
    assert "to_state" not in obs.events[0]


def test_failing_observer_does_not_raise(monkeypatch):
    good = RecordingObserver()
    monkeypatch.setattr(
        "doberman.engine.registry.discover_drift_observers",
        lambda: [ExplodingObserver(), good],
    )
    notify_observers({"classification": "neutral"})  # must not raise
    assert good.events  # the good observer still ran


def test_non_observer_shaped_is_skipped(monkeypatch):
    monkeypatch.setattr("doberman.engine.registry.discover_drift_observers", lambda: [object()])
    notify_observers({"classification": "neutral"})  # no raise
    assert _looks_like_drift_observer(object()) is False


async def test_observer_cannot_alter_the_gate_outcome(tmp_path, monkeypatch):
    # An observer that tries to approve/suppress a weakening cannot change the
    # authoritative outcome: a denied weakening stays denied.
    monkeypatch.setattr(
        "doberman.engine.registry.discover_drift_observers", lambda: [SuppressingObserver()]
    )

    class DenyPrompter:
        def confirm(self, message):
            return False

        def read_code(self, message):
            return ""

    outcome = await apply_change(
        {"r": "block"},
        {"r": "allow"},
        "loosen",
        repo_root=str(tmp_path),
        prompter=DenyPrompter(),
        now=_NOW,
    )
    assert outcome.classification is Classification.weaken
    assert outcome.approved is False  # the observer could not flip it


async def test_observer_notified_for_every_change(tmp_path, monkeypatch):
    obs = RecordingObserver()
    monkeypatch.setattr("doberman.engine.registry.discover_drift_observers", lambda: [obs])
    await apply_change({"r": "auth"}, {"r": "block"}, "tighten", repo_root=str(tmp_path), now=_NOW)
    assert len(obs.events) == 1
    assert obs.events[0]["classification"] == "strengthen"
    assert obs.events[0]["approved"] is True
