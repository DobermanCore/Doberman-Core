"""Entry-point plugin registry (Feature 3, slice 3.8) — the enterprise seam.

Core ships only the basic rules. Premium rule packs and proprietary detectors
live in separately-installed packages (the enterprise edition) that advertise
themselves through Python **entry points** in the groups ``doberman.rules`` and
``doberman.detectors``. This registry discovers and loads them at runtime so
the :class:`~doberman.engine.objective.ObjectiveGuardrail` can run built-ins
**plus** whatever is installed — and **core never imports any plugin by name**
(the hard repo-boundary rule).

SECURITY:

* Loading is **defensive**. A plugin that fails to import, instantiate, or that
  does not look like a ``Guardrail`` is logged and **skipped** — a broken or
  hostile plugin can never crash core or stop the built-in rules from running.
* Plugins are still bound by the engine's raise-only discipline: the objective
  guardrail reduces every result (built-in and plugin) with ``combine()``, so a
  plugin can only ever *add* risk, never lower a verdict. The registry does not
  grant plugins any privileged path around that.
* With nothing installed, discovery returns an empty list and behavior is
  identical to core-only. The standalone test asserts no enterprise plugin is
  present by default.
"""

import logging
from collections.abc import Iterator
from importlib.metadata import EntryPoint, entry_points

from doberman.engine.decision_engine import Guardrail

logger = logging.getLogger("doberman.engine.registry")

#: Entry-point groups core discovers. ``rules`` and ``detectors`` are treated
#: identically here (both contribute ``Guardrail``-shaped objects to the
#: objective guardrail); later features add ``auth_providers``/``audit_sinks``/
#: ``policy_sources``/``drift_observers`` against this same mechanism.
RULE_GROUP = "doberman.rules"
DETECTOR_GROUP = "doberman.detectors"
#: Policy sources (Feature 4.4) register here; resolved by the policy layer.
POLICY_SOURCE_GROUP = "doberman.policy_sources"
#: Auth providers (Feature 7.6) register here; resolved by the auth layer.
AUTH_PROVIDER_GROUP = "doberman.auth_providers"
#: Audit sinks (Feature 8.4) register here; resolved by the storage layer.
AUDIT_SINK_GROUP = "doberman.audit_sinks"
#: Drift observers (Feature 10.4) register here; resolved by the policy layer.
DRIFT_OBSERVER_GROUP = "doberman.drift_observers"
#: Algebra adapters (SL3.1) register here; resolved by the subjective layer.
#: Distinct from ``doberman.detectors``: adapters REFINE the action algebra
#: (clamped raise-only) and never score or verdict anything.
ALGEBRA_ADAPTER_GROUP = "doberman.algebra_adapters"
#: Shadow adjudicators (adaptive-precision Phase 0) register here; resolved by
#: the decision engine. Shadow-only: they observe a decision on REDACTED features
#: and can never change the live verdict.
ADJUDICATOR_GROUP = "doberman.adjudicators"


def _iter_entry_points(group: str) -> Iterator[EntryPoint]:
    """Yield entry points for ``group`` across importlib.metadata versions.

    Wrapped so a failure in discovery itself (not just one plugin) is contained
    — discovery problems must not crash the engine.
    """
    try:
        eps = entry_points()
        # Python 3.12 returns a SelectableGroups; .select is the stable API.
        selected = eps.select(group=group)
    except Exception:  # noqa: BLE001 — discovery must never crash core
        logger.warning("plugin discovery failed for group %s; continuing with built-ins", group)
        return
    yield from selected


def _load_and_construct(entry_point: EntryPoint) -> object | None:
    """Load an entry point and instantiate it if it is a class, or skip it.

    Returns ``None`` (after logging) on any import or constructor error. The
    caller applies its own structural check. We never let a plugin's failure
    propagate — isolation is the whole contract.
    """
    try:
        loaded = entry_point.load()
    except Exception:  # noqa: BLE001 — a plugin import error must not crash core
        logger.warning("skipping plugin %r: failed to import", getattr(entry_point, "name", "?"))
        return None

    candidate = loaded
    if isinstance(loaded, type):
        try:
            candidate = loaded()
        except Exception:  # noqa: BLE001 — bad constructor → skip, never crash
            logger.warning(
                "skipping plugin %r: constructor raised", getattr(entry_point, "name", "?")
            )
            return None
    return candidate


def _instantiate(entry_point: EntryPoint) -> Guardrail | None:
    """Load + instantiate one entry point into a Guardrail, or skip it.

    Returns ``None`` (after logging) on any import/instantiation error or if the
    loaded object is not Guardrail-shaped.
    """
    candidate = _load_and_construct(entry_point)
    if candidate is None:
        return None
    # Structural check only (runtime_checkable can't verify the signature) — the
    # real safety gate is that the objective guardrail validates every returned
    # value as a GuardrailResult and isolates exceptions.
    if not isinstance(candidate, Guardrail):
        logger.warning(
            "skipping plugin %r: does not implement the Guardrail protocol",
            getattr(entry_point, "name", "?"),
        )
        return None
    return candidate


def _discover_guardrails(groups: tuple[str, ...]) -> list[Guardrail]:
    """Discover + instantiate Guardrail-shaped plugins across ``groups``.

    Always returns a list (empty when nothing is installed). Each plugin is
    loaded defensively; failures are logged and skipped. Duplicate name+group
    registrations are de-duplicated.
    """
    plugins: list[Guardrail] = []
    seen: set[str] = set()
    for group in groups:
        for entry_point in _iter_entry_points(group):
            key = f"{group}:{getattr(entry_point, 'name', id(entry_point))}"
            if key in seen:
                continue
            seen.add(key)
            instance = _instantiate(entry_point)
            if instance is not None:
                plugins.append(instance)
    return plugins


def discover_rules() -> list[Guardrail]:
    """Discover registered **rule** plugins (group ``doberman.rules``).

    These run alongside the built-in basic rules in the **objective** guardrail.
    ``doberman.detectors`` is intentionally NOT loaded here — behavioral
    detectors are the **subjective** seam and are discovered by
    :func:`discover_detectors` (their single home, so they never double-run).
    Returns ``[]`` with nothing installed.
    """
    return _discover_guardrails((RULE_GROUP,))


def discover_detectors() -> list[Guardrail]:
    """Discover registered **detector** plugins (group ``doberman.detectors``).

    These run in the **subjective** guardrail (Feature 9) — the home for
    advanced/behavioral (UEBA-style) detection — bound by the same raise-only
    discipline (a detector can only add risk). Returns ``[]`` with nothing
    installed.
    """
    return _discover_guardrails((DETECTOR_GROUP,))


def discover_policy_sources() -> list[object]:
    """Discover registered policy sources (Feature 4.4, group ``doberman.policy_sources``).

    Loaded defensively like rules: an import/constructor failure, or an object
    that is not policy-source-shaped (no ``snapshot``/``authority``), is logged
    and skipped. Returns ``[]`` when nothing is installed. Core never imports a
    source by name — the policy resolver merges whatever is registered.
    """
    # Local import avoids an engine<->policy import cycle at module load.
    from doberman.policy.sources import _looks_like_policy_source

    sources: list[object] = []
    seen: set[str] = set()
    for entry_point in _iter_entry_points(POLICY_SOURCE_GROUP):
        key = f"{POLICY_SOURCE_GROUP}:{getattr(entry_point, 'name', id(entry_point))}"
        if key in seen:
            continue
        seen.add(key)
        candidate = _load_and_construct(entry_point)
        if candidate is None:
            continue
        if not _looks_like_policy_source(candidate):
            logger.warning(
                "skipping policy source %r: not policy-source-shaped",
                getattr(entry_point, "name", "?"),
            )
            continue
        sources.append(candidate)
    return sources


def discover_auth_providers() -> list[object]:
    """Discover registered auth providers (Feature 7.6, group ``doberman.auth_providers``).

    Loaded defensively like rules/sources: an import/constructor failure, or an
    object that is not auth-provider-shaped (no callable ``authenticate``), is
    logged and skipped. Returns ``[]`` when nothing is installed — the auth
    layer then falls back to the built-in local provider. Core never imports a
    provider by name.
    """
    # Local import avoids an engine<->auth import cycle at module load.
    from doberman.auth.provider import _looks_like_auth_provider

    providers: list[object] = []
    seen: set[str] = set()
    for entry_point in _iter_entry_points(AUTH_PROVIDER_GROUP):
        key = f"{AUTH_PROVIDER_GROUP}:{getattr(entry_point, 'name', id(entry_point))}"
        if key in seen:
            continue
        seen.add(key)
        candidate = _load_and_construct(entry_point)
        if candidate is None:
            continue
        if not _looks_like_auth_provider(candidate):
            logger.warning(
                "skipping auth provider %r: not auth-provider-shaped",
                getattr(entry_point, "name", "?"),
            )
            continue
        providers.append(candidate)
    return providers


def discover_audit_sinks() -> list[object]:
    """Discover registered audit sinks (Feature 8.4, group ``doberman.audit_sinks``).

    Loaded defensively like rules/providers: an import/constructor failure, or an
    object that is not sink-shaped (no callable ``emit``), is logged and skipped.
    Returns ``[]`` when nothing is installed — only the local decision log runs.
    Core never imports a sink by name.
    """
    # Local import avoids an engine<->storage import cycle at module load.
    from doberman.storage.sinks import _looks_like_audit_sink

    sinks: list[object] = []
    seen: set[str] = set()
    for entry_point in _iter_entry_points(AUDIT_SINK_GROUP):
        key = f"{AUDIT_SINK_GROUP}:{getattr(entry_point, 'name', id(entry_point))}"
        if key in seen:
            continue
        seen.add(key)
        candidate = _load_and_construct(entry_point)
        if candidate is None:
            continue
        if not _looks_like_audit_sink(candidate):
            logger.warning(
                "skipping audit sink %r: not sink-shaped",
                getattr(entry_point, "name", "?"),
            )
            continue
        sinks.append(candidate)
    return sinks


def discover_algebra_adapters() -> list[object]:
    """Discover registered algebra adapters (SL3.1, group ``doberman.algebra_adapters``).

    Loaded defensively like every other seam: an import/constructor failure, or
    an object that is not adapter-shaped (no callable ``refine``), is logged and
    skipped. Returns ``[]`` when nothing is installed — the generic inference
    layer (SL2) then stands alone, so coverage never depends on an adapter.
    Core never imports an adapter by name; the subjective layer clamps every
    adapter's output raise-only.
    """
    # Local import avoids an engine<->subjective import cycle at module load.
    from doberman.subjective.adapters import _looks_like_algebra_adapter

    adapters: list[object] = []
    seen: set[str] = set()
    for entry_point in _iter_entry_points(ALGEBRA_ADAPTER_GROUP):
        key = f"{ALGEBRA_ADAPTER_GROUP}:{getattr(entry_point, 'name', id(entry_point))}"
        if key in seen:
            continue
        seen.add(key)
        candidate = _load_and_construct(entry_point)
        if candidate is None:
            continue
        if not _looks_like_algebra_adapter(candidate):
            logger.warning(
                "skipping algebra adapter %r: not adapter-shaped",
                getattr(entry_point, "name", "?"),
            )
            continue
        adapters.append(candidate)
    return adapters


def discover_adjudicators() -> list[object]:
    """Discover registered shadow adjudicators (group ``doberman.adjudicators``).

    Loaded defensively like every other seam: an import/constructor failure, or
    an object that is not adjudicator-shaped (no ``adjudicate`` attribute), is
    logged and skipped. Returns ``[]`` when nothing is installed — the engine
    then simply records no shadow annotation. Core never imports an adjudicator
    by name, and the seam is shadow-only: a discovered adjudicator can never
    change the live verdict (:mod:`doberman.engine.adjudicator`).
    """
    # Local import mirrors the other seams and keeps discovery self-contained.
    from doberman.engine.adjudicator import Adjudicator

    adjudicators: list[object] = []
    seen: set[str] = set()
    for entry_point in _iter_entry_points(ADJUDICATOR_GROUP):
        key = f"{ADJUDICATOR_GROUP}:{getattr(entry_point, 'name', id(entry_point))}"
        if key in seen:
            continue
        seen.add(key)
        candidate = _load_and_construct(entry_point)
        if candidate is None:
            continue
        # Structural check only (runtime_checkable verifies the ``adjudicate``
        # attribute, not its signature) — the real gate is that the engine
        # validates every return value and isolates exceptions.
        if not isinstance(candidate, Adjudicator):
            logger.warning(
                "skipping adjudicator %r: does not implement the Adjudicator protocol",
                getattr(entry_point, "name", "?"),
            )
            continue
        adjudicators.append(candidate)
    return adjudicators


def discover_drift_observers() -> list[object]:
    """Discover registered drift observers (Feature 10.4, group ``doberman.drift_observers``).

    Loaded defensively like rules/sinks: an import/constructor failure, or an
    object that is not observer-shaped (no callable ``on_change``), is logged and
    skipped. Returns ``[]`` when nothing is installed — the 2FA gate + local
    ledger are unaffected. Core never imports an observer by name.
    """
    # Local import avoids an engine<->policy import cycle at module load.
    from doberman.policy.drift import _looks_like_drift_observer

    observers: list[object] = []
    seen: set[str] = set()
    for entry_point in _iter_entry_points(DRIFT_OBSERVER_GROUP):
        key = f"{DRIFT_OBSERVER_GROUP}:{getattr(entry_point, 'name', id(entry_point))}"
        if key in seen:
            continue
        seen.add(key)
        candidate = _load_and_construct(entry_point)
        if candidate is None:
            continue
        if not _looks_like_drift_observer(candidate):
            logger.warning(
                "skipping drift observer %r: not observer-shaped",
                getattr(entry_point, "name", "?"),
            )
            continue
        observers.append(candidate)
    return observers
