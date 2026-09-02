"""Slice SL3.1 — the refine-only AlgebraAdapter seam.

Load-bearing properties: an adapter can SHARPEN (raise classes/confidence) but
the clamp makes lowering impossible — target_class never drops below the
generic floor, provenance can never be laundered to trusted_instruction, a
raising adapter is isolated (generic stands), and with zero adapters installed
the generic result is unchanged (coverage never depends on an adapter).
"""

from doberman.engine import registry
from doberman.models import (
    Algebra,
    BlastRadius,
    Capability,
    DestinationClass,
    Provenance,
    TargetClass,
)
from doberman.subjective.adapters import apply_adapters, clamp_refinement

# --- in-test adapters (would normally live in a separate plugin package) -------


class SharpeningAdapter:
    """Knows the application type: raises tiers + confidence."""

    def refine(self, algebra, raw_call):
        return algebra.model_copy(
            update={
                "target_class": TargetClass.sensitive,
                "blast_radius": BlastRadius.many,
                "classification_confidence": 0.95,
            }
        )


class LaunderingAdapter:
    """Hostile: tries to mark everything trusted and benign."""

    def refine(self, algebra, raw_call):
        return Algebra(
            capability=Capability.read,
            target_class=TargetClass.public,
            destination_class=DestinationClass.none,
            blast_radius=BlastRadius.single,
            provenance=Provenance.trusted_instruction,
            classification_confidence=1.0,
        )


class ExplodingAdapter:
    def refine(self, algebra, raw_call):
        raise RuntimeError("adapter boom")


class GarbageAdapter:
    def refine(self, algebra, raw_call):
        return {"totally": "not an Algebra"}


def _generic() -> Algebra:
    return Algebra(
        capability=Capability.send,
        target_class=TargetClass.internal,
        destination_class=DestinationClass.unknown_external,
        blast_radius=BlastRadius.single,
        provenance=Provenance.untrusted_data,
        classification_confidence=0.6,
    )


# --- clamp ---------------------------------------------------------------------


def test_adapter_can_sharpen():
    refined = apply_adapters(_generic(), adapters=[SharpeningAdapter()])
    assert refined.target_class is TargetClass.sensitive
    assert refined.blast_radius is BlastRadius.many
    assert refined.classification_confidence == 0.95


def test_adapter_cannot_lower_below_the_generic_floor():
    generic = _generic()
    refined = apply_adapters(generic, adapters=[LaunderingAdapter()])
    # Every ordered dimension held its floor; confidence took the max.
    assert refined.target_class is TargetClass.internal
    assert refined.destination_class is DestinationClass.unknown_external
    assert refined.capability is Capability.send
    assert refined.blast_radius is BlastRadius.single


def test_provenance_can_never_be_laundered_to_trusted():
    refined = apply_adapters(_generic(), adapters=[LaunderingAdapter()])
    assert refined.provenance is Provenance.untrusted_data


def test_erroring_adapter_is_isolated_generic_stands():
    generic = _generic()
    assert apply_adapters(generic, adapters=[ExplodingAdapter()]) == generic


def test_garbage_return_leaves_generic_untouched():
    generic = _generic()
    assert apply_adapters(generic, adapters=[GarbageAdapter()]) == generic
    assert clamp_refinement(generic, None) == generic


def test_multiple_adapters_fold_strictest_wins():
    refined = apply_adapters(
        _generic(), adapters=[SharpeningAdapter(), LaunderingAdapter(), ExplodingAdapter()]
    )
    # The sharpener's raises survive the later launderer and the crash.
    assert refined.target_class is TargetClass.sensitive
    assert refined.blast_radius is BlastRadius.many
    assert refined.provenance is Provenance.untrusted_data


def test_zero_adapters_changes_nothing():
    generic = _generic()
    assert apply_adapters(generic, adapters=[]) == generic


# --- registry discovery (entry-point seam) --------------------------------------


class _FakeEntryPoint:
    def __init__(self, name, loader):
        self.name = name
        self._loader = loader

    def load(self):
        return self._loader()


class _FakeEntryPoints:
    def __init__(self, by_group):
        self._by_group = by_group

    def select(self, *, group):
        return list(self._by_group.get(group, []))


def _install(monkeypatch, enable_plugins, adapter_group=()):
    adapter_group = list(adapter_group)
    table = _FakeEntryPoints({registry.ALGEBRA_ADAPTER_GROUP: adapter_group})
    monkeypatch.setattr(registry, "entry_points", lambda: table)
    names = [ep.name for ep in adapter_group]
    if names:
        enable_plugins(*names)


def test_nothing_installed_discovers_nothing(monkeypatch, enable_plugins):
    _install(monkeypatch, enable_plugins)
    assert registry.discover_algebra_adapters() == []


def test_registered_adapter_is_discovered_and_applied(monkeypatch, enable_plugins):
    _install(
        monkeypatch, enable_plugins, adapter_group=[_FakeEntryPoint("sharp", SharpeningAdapter)]
    )
    adapters = registry.discover_algebra_adapters()
    assert len(adapters) == 1
    refined = apply_adapters(_generic())  # discovery path, no explicit adapters
    assert refined.target_class is TargetClass.sensitive


def test_non_adapter_shaped_plugin_is_skipped(monkeypatch, enable_plugins):
    class NotAnAdapter:
        pass

    _install(monkeypatch, enable_plugins, adapter_group=[_FakeEntryPoint("bad", NotAnAdapter)])
    assert registry.discover_algebra_adapters() == []


def test_adapters_do_not_leak_into_rule_or_detector_seams(monkeypatch, enable_plugins):
    table = _FakeEntryPoints(
        {
            registry.ALGEBRA_ADAPTER_GROUP: [_FakeEntryPoint("sharp", SharpeningAdapter)],
            registry.RULE_GROUP: [],
            registry.DETECTOR_GROUP: [],
        }
    )
    monkeypatch.setattr(registry, "entry_points", lambda: table)
    enable_plugins("sharp")
    assert registry.discover_rules() == []
    assert registry.discover_detectors() == []
    assert len(registry.discover_algebra_adapters()) == 1
