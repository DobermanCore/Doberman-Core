"""Slice 3.8 — entry-point plugin registry (the enterprise seam).

Tested WITHOUT installing any package: we monkeypatch the entry-point lookup to
return fake entry points whose ``.load()`` yields in-test rule classes. Covers:
a fixture plugin runs alongside built-ins; raise-only still holds with plugins
(a plugin can only raise risk); an erroring/garbage plugin is isolated and never
crashes core or lowers a verdict; a plugin import failure is skipped; and with
zero plugins only built-ins run (the standalone behavior).
"""

from datetime import datetime, timezone

import pytest

from doberman.engine import registry
from doberman.engine.objective import ObjectiveGuardrail
from doberman.models import (
    ActionType,
    EvalContext,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    Verdict,
)


# --- In-test plugin rule classes (would normally live in a separate package) --
class AlwaysAuthPlugin:
    def evaluate(self, action, ctx):
        return GuardrailResult(
            verdict=Verdict.AUTH,
            risk=Risk.high,
            reason_codes=[ReasonCode.unknown_external_destination],
            explanation="plugin says auth",
        )


class TryToLowerPlugin:
    # A hostile plugin that returns PASS to try to "lower" a verdict — the
    # engine's combine() must make this impossible.
    def evaluate(self, action, ctx):
        return GuardrailResult(verdict=Verdict.PASS, risk=Risk.low)


class ExplodingPlugin:
    def evaluate(self, action, ctx):
        raise RuntimeError("plugin exploded")


class _FakeEntryPoint:
    def __init__(self, name, loader):
        self.name = name
        self._loader = loader

    def load(self):
        return self._loader()


class _FakeEntryPoints:
    """Mimics importlib.metadata.entry_points() with a .select(group=...)."""

    def __init__(self, by_group):
        self._by_group = by_group

    def select(self, *, group):
        return list(self._by_group.get(group, []))


@pytest.fixture
def patch_entry_points(monkeypatch, enable_plugins):
    """Install a fake entry-points table for the duration of a test, and opt
    every fake entry point's name into the plugins allowlist — discovery is
    now opt-in by name, so a fake entry point the test never enables would
    silently vanish rather than exercise the behavior under test."""

    def _install(rule_group=(), detector_group=()):
        rule_group = list(rule_group)
        detector_group = list(detector_group)
        table = _FakeEntryPoints(
            {
                registry.RULE_GROUP: rule_group,
                registry.DETECTOR_GROUP: detector_group,
            }
        )
        monkeypatch.setattr(registry, "entry_points", lambda: table)
        names = [ep.name for ep in (*rule_group, *detector_group)]
        if names:
            enable_plugins(*names)

    return _install


def _action():
    return SecurityObject(
        id="reg-1",
        ts=datetime(2026, 6, 7, tzinfo=timezone.utc),
        agent_role="unknown",
        action_type=ActionType.file_write,
        tool_name="t",
        target="frontend/Button.tsx",
    )


def _ctx():
    return EvalContext(metadata={"raw_arguments": {"path": "frontend/Button.tsx"}})


def test_no_plugins_installed_discovers_nothing(patch_entry_points):
    patch_entry_points()  # both groups empty
    assert registry.discover_rules() == []


def test_fixture_plugin_is_discovered(patch_entry_points):
    patch_entry_points(rule_group=[_FakeEntryPoint("p", AlwaysAuthPlugin)])
    rules = registry.discover_rules()
    assert len(rules) == 1
    assert isinstance(rules[0], AlwaysAuthPlugin)


def test_detectors_attach_to_the_subjective_seam_not_objective(patch_entry_points):
    # Detectors are the behavioral/subjective seam (Feature 9): discover_rules
    # (objective) ignores them, and discover_detectors picks them up. This keeps
    # a detector plugin running in exactly one place (no double-run).
    patch_entry_points(detector_group=[_FakeEntryPoint("d", AlwaysAuthPlugin)])
    assert registry.discover_rules() == []
    detectors = registry.discover_detectors()
    assert len(detectors) == 1
    assert isinstance(detectors[0], AlwaysAuthPlugin)


def test_plugin_runs_alongside_builtins(patch_entry_points):
    patch_entry_points(rule_group=[_FakeEntryPoint("p", AlwaysAuthPlugin)])
    g = ObjectiveGuardrail()  # load_plugins=True (default) → discovers the fake
    # A benign edit would PASS on built-ins; the plugin raises it to AUTH.
    assert g.evaluate(_action(), _ctx()).verdict is Verdict.AUTH


def test_raise_only_holds_with_a_hostile_lowering_plugin(patch_entry_points):
    # A plugin returning PASS cannot lower a built-in BLOCK.
    patch_entry_points(rule_group=[_FakeEntryPoint("p", TryToLowerPlugin)])
    g = ObjectiveGuardrail()
    action = SecurityObject(
        id="reg-2",
        ts=datetime(2026, 6, 7, tzinfo=timezone.utc),
        agent_role="unknown",
        action_type=ActionType.file_write,
        tool_name="t",
        target=".env",  # built-in path rule BLOCKs this
    )
    ctx = EvalContext(metadata={"raw_arguments": {"path": ".env"}})
    assert g.evaluate(action, ctx).verdict is Verdict.BLOCK


def test_erroring_plugin_is_isolated(patch_entry_points):
    patch_entry_points(rule_group=[_FakeEntryPoint("boom", ExplodingPlugin)])
    g = ObjectiveGuardrail()
    # The benign edit passes built-ins; the plugin raises → isolated as AUTH,
    # never crashes, never PASSes silently below what built-ins said.
    result = g.evaluate(_action(), _ctx())
    assert result.verdict is Verdict.AUTH
    assert ReasonCode.rule_error in result.reason_codes


def test_plugin_import_failure_is_skipped(patch_entry_points):
    def _bad_loader():
        raise ImportError("cannot import plugin")

    patch_entry_points(
        rule_group=[_FakeEntryPoint("good", AlwaysAuthPlugin), _FakeEntryPoint("bad", _bad_loader)]
    )
    rules = registry.discover_rules()
    # The good plugin loads; the bad one is skipped (not raised).
    assert len(rules) == 1
    assert isinstance(rules[0], AlwaysAuthPlugin)


def test_non_guardrail_plugin_is_skipped(patch_entry_points):
    patch_entry_points(rule_group=[_FakeEntryPoint("notrule", lambda: 42)])
    assert registry.discover_rules() == []


def test_plugin_class_with_bad_constructor_is_skipped(patch_entry_points):
    class BadConstructor:
        def __init__(self):
            raise RuntimeError("nope")

        def evaluate(self, action, ctx):  # pragma: no cover - never reached
            return GuardrailResult(verdict=Verdict.PASS, risk=Risk.low)

    patch_entry_points(rule_group=[_FakeEntryPoint("bad", lambda: BadConstructor)])
    assert registry.discover_rules() == []


def test_plugin_instance_entry_point_is_accepted(patch_entry_points):
    # An entry point may point at an instance, not a class.
    instance = AlwaysAuthPlugin()
    patch_entry_points(rule_group=[_FakeEntryPoint("inst", lambda: instance)])
    rules = registry.discover_rules()
    assert rules == [instance]


def test_discovery_failure_does_not_crash(monkeypatch, enable_plugins):
    # If entry_points() itself raises, discovery returns [] (no crash). Needs
    # a name enabled — with an empty allowlist entry_points() is never even
    # called, so this wouldn't exercise the failure path at all.
    def _boom():
        raise RuntimeError("metadata broken")

    enable_plugins("whatever")
    monkeypatch.setattr(registry, "entry_points", _boom)
    assert registry.discover_rules() == []


def test_empty_allowlist_never_calls_entry_points(monkeypatch):
    # The opt-in gate itself: with nothing enabled, entry_points() is never
    # called — not just "returns nothing installed".
    def _must_not_be_called():
        raise AssertionError("entry_points() must not be called with an empty allowlist")

    monkeypatch.setattr(registry, "entry_points", _must_not_be_called)
    assert registry.discover_rules() == []


def test_installed_but_unlisted_plugin_is_never_loaded(patch_entry_points, monkeypatch):
    # An entry point can be present in the (fake) installed set without being
    # enabled — patch the table directly (bypassing patch_entry_points' auto-
    # enable) so the plugin stays unlisted, and prove its loader never runs.
    def _must_not_load():
        raise AssertionError("an unlisted entry point must never be loaded")

    table = _FakeEntryPoints({registry.RULE_GROUP: [_FakeEntryPoint("unlisted", _must_not_load)]})
    monkeypatch.setattr(registry, "entry_points", lambda: table)
    assert registry.discover_rules() == []


def test_enabling_after_first_discovery_needs_a_snapshot_reset(
    monkeypatch, tmp_path, enable_plugins
):
    # allowed_plugin_names() is snapshotted once per process; enabling a name
    # AFTER that snapshot was taken loads nothing until reset_snapshot().
    # ``enable_plugins`` is only depended on for its teardown reset here — the
    # test manages the snapshot by hand to prove the non-widening property.
    from doberman.engine import plugin_config

    monkeypatch.setenv(plugin_config.PLUGINS_FILE_ENV, str(tmp_path / "plugins.json"))
    plugin_config.reset_snapshot()
    table = _FakeEntryPoints({registry.RULE_GROUP: [_FakeEntryPoint("late", AlwaysAuthPlugin)]})
    monkeypatch.setattr(registry, "entry_points", lambda: table)

    assert registry.discover_rules() == []  # nothing enabled yet -> snapshot = ()

    plugin_config.enable("late")  # enabled on disk, but the snapshot is already taken
    assert registry.discover_rules() == []  # still nothing — the stale snapshot holds

    plugin_config.reset_snapshot()
    rules = registry.discover_rules()
    assert len(rules) == 1 and isinstance(rules[0], AlwaysAuthPlugin)
