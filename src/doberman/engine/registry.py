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


def discover_rules() -> list[Guardrail]:
    """Discover and instantiate all registered rule/detector plugins.

    Always returns a list (empty when nothing is installed). Each plugin is
    loaded defensively; failures are logged and skipped. The result is the set
    of EXTRA guardrails to run alongside core's built-ins.
    """
    plugins: list[Guardrail] = []
    seen: set[str] = set()
    for group in (RULE_GROUP, DETECTOR_GROUP):
        for entry_point in _iter_entry_points(group):
            # Guard against duplicate registration of the same name+group.
            key = f"{group}:{getattr(entry_point, 'name', id(entry_point))}"
            if key in seen:
                continue
            seen.add(key)
            instance = _instantiate(entry_point)
            if instance is not None:
                plugins.append(instance)
    return plugins


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
