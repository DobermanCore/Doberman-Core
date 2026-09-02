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
from collections.abc import Collection, Iterator
from functools import lru_cache
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
#: Approval methods (2FA push/biometric) register here; resolved by the auth layer.
APPROVAL_METHOD_GROUP = "doberman.approval_methods"
#: Drift observers (Feature 10.4) register here; resolved by the policy layer.
DRIFT_OBSERVER_GROUP = "doberman.drift_observers"
#: Cost observers (CB.2) register here; resolved by the storage layer.
COST_OBSERVER_GROUP = "doberman.cost_observers"
#: Algebra adapters (SL3.1) register here; resolved by the subjective layer.
#: Distinct from ``doberman.detectors``: adapters REFINE the action algebra
#: (clamped raise-only) and never score or verdict anything.
ALGEBRA_ADAPTER_GROUP = "doberman.algebra_adapters"
#: Shadow adjudicators (adaptive-precision Phase 0) register here; resolved by
#: the decision engine. Shadow-only: they observe a decision on REDACTED features
#: and can never change the live verdict.
ADJUDICATOR_GROUP = "doberman.adjudicators"
#: Runtime egress brokers (Feature RB) register here; resolved by
#: :class:`~doberman.engine.rules.destinations.ExternalDestinationRule`. RB.1
#: wires consultation in but keeps it dormant — no broker verdict can raise or
#: lower a decision until RB.4. Discovery defaults OFF on
#: ``ExternalDestinationRule`` (``load_broker=False``): that rule is rebuilt on
#: every ``ObjectiveGuardrail()`` construction, and the host-hook path builds
#: one per tool call in a cold-start process, so a default-on scan there would
#: add real per-call cost for a verdict RB.1 discards anyway. Only the
#: long-lived proxy singleton opts in — see :func:`discover_egress_brokers`
#: for the memoization that also keeps a repeated opted-in construction cheap.
EGRESS_BROKER_GROUP = "doberman.egress_brokers"
#: Async challenge backends (issue #144) register here; resolved by the auth layer.
#: Lets hosted/push-based approval channels (Slack, e-mail, etc.) supply a custom
#: backend without importing core's synchronous prompter chain.
ASYNC_CHALLENGE_BACKEND_GROUP = "doberman.async_challenge_backends"


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


def discover_auth_providers(allowed: Collection[str]) -> list[object]:
    """Discover OPTED-IN auth providers (Feature 7.6, group ``doberman.auth_providers``).

    Opt-in only: an entry point is loaded (imported and constructed) only if its
    ``.name`` is in ``allowed`` — a package merely being installed is never
    enough to make it an authenticator. Non-allowed entry points are skipped
    before any import/construction happens, so THIS seam never imports an
    unlisted package (the other entry-point groups still auto-load theirs, so
    an installed package can still run code in-process — the allowlist is a
    seam-level control, not a sandbox). Allowed candidates are still loaded defensively like rules/sources: an
    import/constructor failure, or an object that is not auth-provider-shaped
    (no callable ``authenticate``), is logged and skipped. ``allowed`` empty
    returns ``[]`` without iterating entry points at all — the auth layer then
    falls back to the built-in local provider. Core never imports a provider by
    name.
    """
    if not allowed:
        return []

    # Local import avoids an engine<->auth import cycle at module load.
    from doberman.auth.provider import _looks_like_auth_provider

    providers: list[object] = []
    seen: set[str] = set()
    for entry_point in _iter_entry_points(AUTH_PROVIDER_GROUP):
        name = getattr(entry_point, "name", None)
        if name not in allowed:
            continue
        key = f"{AUTH_PROVIDER_GROUP}:{name if name is not None else id(entry_point)}"
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


def discover_approval_methods() -> list[object]:
    """Discover approval methods (2FA push/biometric, group ``doberman.approval_methods``).

    Returns the built-in methods (Windows Hello, ...) followed by any registered
    plugins, loaded defensively: an import/constructor failure, or an object that is
    not approval-method-shaped (no callable ``is_available`` / ``request``), is
    logged and skipped. A plugin whose ``name`` shadows a built-in is skipped so a
    third party cannot silently replace a core factor. Core never imports a plugin
    by name.
    """
    # Local imports avoid an engine<->auth import cycle at module load.
    from doberman.auth.approval import ApprovalMethod
    from doberman.auth.methods import builtin_methods

    methods: list[object] = list(builtin_methods())
    seen_names: set[str | None] = {getattr(m, "name", None) for m in methods}
    for entry_point in _iter_entry_points(APPROVAL_METHOD_GROUP):
        candidate = _load_and_construct(entry_point)
        if candidate is None:
            continue
        if not isinstance(candidate, ApprovalMethod):
            logger.warning(
                "skipping approval method %r: not approval-method-shaped",
                getattr(entry_point, "name", "?"),
            )
            continue
        name = getattr(candidate, "name", None)
        if name in seen_names:
            logger.warning("skipping approval method %r: duplicate name", name)
            continue
        seen_names.add(name)
        methods.append(candidate)
    return methods


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


@lru_cache(maxsize=1)
def discover_egress_brokers() -> list[object]:
    """Discover registered runtime egress brokers (Feature RB, group ``doberman.egress_brokers``).

    Loaded defensively like every other seam: an import/constructor failure, or
    an object that is not broker-shaped (no ``enforcement_status``/``classify``/
    ``connection_events`` attributes), is logged and skipped. Returns ``[]``
    when nothing is installed — the same as core-only. Core never imports a
    broker by name, and the seam is fail-closed: RB.1 wires consultation in but
    a broker verdict cannot yet raise or lower a decision (that starts RB.4).

    Memoized (``lru_cache``): the entry-point scan runs at most once per
    process, however many ``ExternalDestinationRule(load_broker=True)``
    instances are built. Tests that monkeypatch ``entry_points`` must call
    ``discover_egress_brokers.cache_clear()`` first (see
    ``tests/unit/test_egress_broker_seam.py``).
    """
    # Local import mirrors the other seams and keeps discovery self-contained.
    from doberman.egress.broker import EgressBroker

    brokers: list[object] = []
    seen: set[str] = set()
    for entry_point in _iter_entry_points(EGRESS_BROKER_GROUP):
        key = f"{EGRESS_BROKER_GROUP}:{getattr(entry_point, 'name', id(entry_point))}"
        if key in seen:
            continue
        seen.add(key)
        candidate = _load_and_construct(entry_point)
        if candidate is None:
            continue
        # Structural check only (runtime_checkable can't verify signatures) —
        # the real safety gate is that consult_broker() validates every return
        # value and isolates exceptions.
        if not isinstance(candidate, EgressBroker):
            logger.warning(
                "skipping egress broker %r: does not implement the EgressBroker protocol",
                getattr(entry_point, "name", "?"),
            )
            continue
        brokers.append(candidate)
    return brokers


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


def discover_cost_observers() -> list[object]:
    """Discover registered cost observers (CB.2, group ``doberman.cost_observers``).

    Loaded defensively like every other seam: an import/constructor failure, or
    an object that is not observer-shaped (no callable ``on_cost``), is logged
    and skipped. Returns ``[]`` when nothing is installed — the local ledger
    write is unaffected. Core never imports an observer by name.
    """
    # Local import avoids an engine<->storage import cycle at module load.
    from doberman.storage.cost import _looks_like_cost_observer

    observers: list[object] = []
    seen: set[str] = set()
    for entry_point in _iter_entry_points(COST_OBSERVER_GROUP):
        key = f"{COST_OBSERVER_GROUP}:{getattr(entry_point, 'name', id(entry_point))}"
        if key in seen:
            continue
        seen.add(key)
        candidate = _load_and_construct(entry_point)
        if candidate is None:
            continue
        if not _looks_like_cost_observer(candidate):
            logger.warning(
                "skipping cost observer %r: not observer-shaped",
                getattr(entry_point, "name", "?"),
            )
            continue
        observers.append(candidate)
    return observers
