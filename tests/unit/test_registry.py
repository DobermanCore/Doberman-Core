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
def patch_entry_points(monkeypatch):
    """Install a fake entry-points table for the duration of a test."""

    def _install(rule_group=(), detector_group=()):
        table = _FakeEntryPoints(
            {
                registry.RULE_GROUP: list(rule_group),
                registry.DETECTOR_GROUP: list(detector_group),
            }
        )
        monkeypatch.setattr(registry, "entry_points", lambda: table)

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


def test_detectors_group_is_also_discovered(patch_entry_points):
    patch_entry_points(detector_group=[_FakeEntryPoint("d", AlwaysAuthPlugin)])
    assert len(registry.discover_rules()) == 1


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


def test_discovery_failure_does_not_crash(monkeypatch):
    # If entry_points() itself raises, discovery returns [] (no crash).
    def _boom():
        raise RuntimeError("metadata broken")

    monkeypatch.setattr(registry, "entry_points", _boom)
    assert registry.discover_rules() == []
