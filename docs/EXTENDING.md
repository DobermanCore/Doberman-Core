# Extending Doberman: the entry-point plugin catalogue

Doberman discovers third-party code through Python entry points (a name-to-code
mapping a package registers, read from `src/doberman/engine/registry.py`).
Core never imports a plugin package by name.

This page catalogues every seam: twelve entry-point groups as of this writing
(`ALL_GROUPS` in `registry.py`). The count was eleven when this page was first
written; `doberman.approval_methods` was added afterward. Two seams have a
runnable worked example, so start there. For the rest, this page plus the
group's `discover_*()` docstring in `registry.py` is the contract.

## Opt in by name first

Installing a plugin package is **never enough on its own**. Every group below
is gated by the same rule (`doberman.engine.plugin_config`): an entry point is
loaded only if its `.name` is listed in the per-user plugins allowlist:

```bash
doberman plugins list             # enabled names, and every installed-but-maybe-not-enabled entry point
doberman plugins enable <name>    # e.g. `doberman plugins enable example_rule`
doberman plugins disable <name>
```

The allowlist is snapshotted once per process, before discovery starts.
Nothing loaded later in the process, such as an already-enabled plugin's own
imports, or an env var or file change made after startup, can widen it.

## The defensive-loading guarantee

Every group below shares one loading discipline (`registry.py`'s module
docstring):

- **Loading is defensive.** A plugin that fails to import, fails to
  instantiate, or does not look like the required shape is logged and
  skipped. A broken or hostile plugin can never crash core or stop the
  built-ins from running.
- **Raise-only.** Rule and detector plugins follow the same discipline as
  built-ins: results are reduced with `combine()`, so a plugin can only add
  risk, never lower a verdict. Other seams (observers, sinks, adapters,
  adjudicators, egress brokers) are limited the same way, each to its own
  advisory, clamped, or shadow role. See each group below for specifics.
- **Nothing installed means core-only.** With no plugin installed, or none
  enabled, discovery returns an empty list or the built-in default. Behavior
  is identical to core with no plugins at all.

Do not read a stronger contract into this than the code provides. The
guarantee above is exactly what `registry.py` documents, no more.

## The twelve groups

### `doberman.rules`

**Shape:** implements the `Guardrail` protocol: one method,
`evaluate(self, action: SecurityObject, ctx: EvalContext) -> GuardrailResult`.
**Resolves via:** `discover_rules()`, consumed by `ObjectiveGuardrail`
(built-in rules + plugins, reduced with `combine()`).
**Worked example:** [`examples/plugin-guardrail/`](../examples/plugin-guardrail/),
full walkthrough at [PLUGINS.md](PLUGINS.md).

### `doberman.detectors`

**Shape:** the same `Guardrail` protocol as `doberman.rules`, structurally
identical per `discover_detectors()`'s own docstring.
**Resolves via:** `discover_detectors()`, consumed by `SubjectiveGuardrail`
(built-in detectors + the three-axis scoring signal + plugins, reduced with
`combine()`). This is the behavioral (UEBA-style) seam, distinct from the
rule-based objective guardrail.
**Worked example:** [`examples/plugin-detector/`](../examples/plugin-detector/).

### `doberman.policy_sources`

**Shape:** duck-typed policy source: an `authority` attribute, a callable
`snapshot`, and a string `name` (`_looks_like_policy_source`).
**Resolves via:** `discover_policy_sources()`, merged by the policy resolver
(`doberman.policy.sources.resolve_policy`) alongside any local sources.
**Worked example:** none yet.

### `doberman.auth_providers`

**Shape:** duck-typed auth provider: a callable `authenticate`
(`_looks_like_auth_provider`).
**Resolves via:** `discover_auth_providers()`, consumed by
`active_provider()` (`doberman.auth.provider`). The first opted-in, correctly
shaped provider (allowlist order, not entry-point iteration order) is wrapped
in `CoGatedProvider`. The built-in local provider is **always** also
consulted, for every tier: a plugin's approval is necessary but never
sufficient. If no opted-in provider is found, the local provider runs
unchanged.
**Worked example:** none yet.

### `doberman.audit_sinks`

**Shape:** duck-typed audit sink: a callable `emit` (`_looks_like_audit_sink`).
**Resolves via:** `discover_audit_sinks()`, consumed by `emit_to_sinks()`
(`doberman.storage.sinks`), which runs every enabled plugin sink first, then
the built-in webhook and OpenTelemetry sinks. A sink that isn't shaped right,
or whose `emit` raises, is logged and skipped. Sink failures never affect the
decision itself.
**Worked example:** [`examples/plugin-audit-sink/`](../examples/plugin-audit-sink/).
See also [PLUGINS.md](PLUGINS.md#forward-the-audit-log-webhook-sink) for the
built-in webhook sink.

### `doberman.approval_methods`

**Shape:** implements `ApprovalMethod`: a callable `is_available` and a
callable `request(prompt, *, action_id, timeout_s)`.
**Resolves via:** `discover_approval_methods()`, which returns the built-in
methods (for example, Windows Hello) followed by any registered plugins. A
plugin whose `name` shadows a built-in is skipped, so a third party can't
silently replace a core factor.
**Worked example:** none yet.

### `doberman.drift_observers`

**Shape:** duck-typed observer: a callable `on_change`
(`_looks_like_drift_observer`).
**Resolves via:** `discover_drift_observers()`, sends a redacted drift event
(drift meaning a change to the policy over time) to every observer via
`notify_observers()` (`doberman.policy.drift`), after the authoritative
decision is made and the ledger is written. A raising observer never affects
the gate.
**Worked example:** none yet.

### `doberman.cost_observers`

**Shape:** duck-typed observer: a callable `on_cost`
(`_looks_like_cost_observer`). It may also expose
`on_loop_anomaly(anomaly)` (duck-typed, not required) to receive the
loop-anomaly detector's readout.
**Resolves via:** `discover_cost_observers()`, sends a redacted `CostEvent`
to every observer via `notify_cost_observers()` (`doberman.storage.cost`),
after a successful ledger write. Advisory only, off the decision path.
**Worked example:** none yet.

### `doberman.algebra_adapters`

**Shape:** duck-typed adapter: a callable `refine`
(`_looks_like_algebra_adapter`). Distinct from `doberman.detectors`: an
adapter *refines* the generic action algebra, it never scores or verdicts
anything.
**Resolves via:** `discover_algebra_adapters()`, consumed by the subjective
layer's `clamp_refinement()` (`doberman.subjective.adapters`). Every ordered
dimension takes the MORE severe of the generic-vs-refined class, so a hostile
or buggy adapter can only raise, never lower, the resulting algebra.
**Worked example:** none yet.

### `doberman.adjudicators`

**Shape:** implements the `Adjudicator` protocol: an `adjudicate` attribute
(a structural `isinstance` check only; the real safety gate is that the
engine validates every return value and isolates exceptions).
**Resolves via:** `discover_adjudicators()`, consumed by
`doberman.engine.adjudicator`. **Shadow-only**: a discovered adjudicator
observes a decision on REDACTED features and can never change the live
verdict.
**Worked example:** none yet.

### `doberman.egress_brokers`

**Shape:** implements the `EgressBroker` protocol:
`enforcement_status`, `classify`, and `connection_events` attributes.
**Resolves via:** `discover_egress_brokers()` (memoized with `lru_cache`, so
the entry-point scan runs at most once per process), consulted by
`ExternalDestinationRule`. Fail-closed by design: a broker verdict cannot yet
raise or lower a decision. That capability lands in a later slice; for now,
consultation is wired in but stays dormant.
**Worked example:** none yet.

### `doberman.async_challenge_backends`

**Shape:** duck-typed backend: a callable `issue` and a callable `resolve`
(`_looks_like_async_backend`).
**Resolves via (the one exception to `discover_*()`):**
`active_async_backend()` (`doberman.auth.async_challenge`), which returns the
first registered, correctly-shaped backend, else the built-in
`IN_MEMORY_BACKEND` singleton. This lets hosted or push-based approval
channels (Slack, email, etc.) supply a custom backend without importing
core's synchronous prompter chain.
**Worked example:** none yet.

## Adding a worked example for an undocumented seam

Copy [`examples/plugin-guardrail/`](../examples/plugin-guardrail/) or
[`examples/plugin-detector/`](../examples/plugin-detector/) as a starting
point: a `pyproject.toml` entry-points block, a minimal implementation of the
group's shape above, and a `tests/` package proving real (non-monkeypatched)
discovery after `pip install -e` + `doberman plugins enable <name>`. Do not add
a new example to the root `pyproject.toml`'s pytest `testpaths`. It stays
self-contained under `examples/`, installed only by its own instructions.
