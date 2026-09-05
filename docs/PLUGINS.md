# Write a guardrail plugin

This page covers Doberman's plugin seams: registering your own rule, and forwarding the redacted
audit log to your own pipeline. Both work the same way, a Python entry-point group core discovers
at runtime, so core never imports a plugin package by name. For the full catalogue of every
entry-point group (rules, detectors, audit sinks, and the rest), see [EXTENDING.md](EXTENDING.md).

## Opt in by name first

Installing a plugin package is never enough on its own. Every entry-point seam (rules,
detectors, audit sinks, auth providers, and the rest) only imports an entry point whose name you've
explicitly trusted:

```bash
doberman plugins list             # enabled names, and every installed-but-maybe-not-enabled entry point
doberman plugins enable <name>    # e.g. `doberman plugins enable example_rule`
doberman plugins disable <name>
```

This closes a gap where a plugin that is merely installed, not enabled, could influence discovery of
another seam before your own code ever runs it (an auto-loaded rule plugin, say, setting an env var
at import time that a different seam reads later). The allowlist is snapshotted once per process
before discovery starts, so enabling a plugin mid-run has no effect until the next run. A rule or
detector plugin also runs against its own copy of the evaluation context. See "Rule and detector
plugins get their own context" below.

## Write a custom guardrail

Third-party rules register through the **`doberman.rules`** entry-point group
(`RULE_GROUP` in `src/doberman/engine/registry.py`). Install a package that declares one, then run
`doberman plugins enable <name>`. Only then does `discover_rules()` pick it up. The objective
guardrail runs built-in rules and every enabled plugin together, reduced with the same raise-only
`combine()` used everywhere else, so a plugin can only add risk, never lower a verdict. A plugin
that fails to import, fails to construct, or isn't shaped like a `Guardrail` is logged and skipped.
It never crashes core.

A five-minute worked example lives at [`examples/plugin-guardrail/`](../examples/plugin-guardrail/)
(from a git checkout):

```bash
pip install -e ".[dev]"
pip install -e examples/plugin-guardrail
doberman plugins enable example_rule
pytest examples/plugin-guardrail/tests -q
doberman plugins disable example_rule   # optional: restore core-only discovery
pip uninstall -y doberman-example-plugin-guardrail
```

The tutorial rule, `ExampleRule`, steps up a write to `SECRETS_TODO.md` to `AUTH`, and never puts
the path or file contents into its explanation. Registration is entirely in the plugin's own
`pyproject.toml`:

```toml
[project.entry-points."doberman.rules"]
example_rule = "example_plugin.rules:ExampleRule"
```

Copy that package as the starting point for a real rule of your own. A few rules keep a plugin
well-behaved:

- Implement `evaluate(self, action, ctx) -> GuardrailResult`, the same contract as the built-ins.
- Prefer `ReasonCode` values from `doberman.models` instead of inventing free-form codes.
- Canonicalize paths (resolve `.`/`..`/symlinks and confine them to the repo root) with
  `doberman.canonical.canonicalize` before matching.
- Only return a result that raises risk for your signal, abstaining (`PASS`) otherwise.

> While the example plugin is installed and enabled, core's "no plugins registered" checks will see
> it. That's expected. Disable or uninstall it before re-running the full core suite if you want a
> clean standalone environment.

### Rule and detector plugins get their own context

`EvalContext.metadata` is a plain mutable dict shared with the built-in rules and the subjective
layer. A rule or detector plugin never sees that shared dict directly: the objective or subjective
guardrail hands it a copy (`ctx.metadata` deep-copied) before calling the plugin. A plugin that
deletes `raw_arguments` or sets `scope_token=True` on its own copy has no effect on what a later
built-in, a later plugin, or the caller sees after evaluation. Only a plugin's *returned*
`GuardrailResult` can move risk, and only upward (`combine()`).

## Forward the audit log (webhook sink)

Drop a `.doberman/audit_webhook.yaml` next to your policy file and every redacted decision record is
also POSTed to your own log pipeline:

```yaml
url: https://logs.example.com/doberman   # HTTPS required off-loopback
auth_env: DOBERMAN_WEBHOOK_TOKEN         # optional: env var read at POST time, sent in the Authorization header
timeout_s: 3                             # optional, per-request
```

No file, no sink: the forwarder (`WebhookAuditSink` in `src/doberman/storage/sinks.py`) is inert by
default. Delivery never touches the decision path. `emit()` hands the record to a bounded background
queue and returns before any I/O, so a wedged endpoint can't delay a decision. On overflow, the
oldest queued record is dropped and the drop count goes up. Records carry the same already-redacted
fields as the local log: path classes, reason codes, verdicts, and HMAC fingerprints (a keyed hash
standing in for a secret, never the secret itself), but never raw secrets. The auth token value is
read from the named env var at POST time, never stored on the sink or logged. This is a bridge to
your pipeline, not a delivery guarantee.

Additional sinks register the same way, through the **`doberman.audit_sinks`** entry-point group:
register the entry point, then `doberman plugins enable <name>`. `emit_to_sinks()` in `sinks.py` runs
every enabled plugin-registered sink first, then the built-in webhook sink and the built-in
OpenTelemetry sink (config-gated via `.doberman/audit_otel.yaml`; see [the OTel guide](audit_otel.md)).
A sink that isn't shaped like an `AuditSink` (no callable `emit`), or whose `emit` raises, is logged
and skipped. It never affects the decision itself.

## Cost observers

Cost and budget monitoring packages register through the **`doberman.cost_observers`** entry-point
group (`CostObserver` in `src/doberman/storage/cost.py`), opted in the same way: `doberman plugins
enable <name>`. Every registered observer's `on_cost` is called with a copy of each redacted
`CostEvent` after a successful ledger write. This is advisory only, off the decision path, and never
raises into or delays the record.

An observer may also expose `on_loop_anomaly(anomaly)` to receive the loop-anomaly detector's
readout. After a tool-call event, if at least one observer is installed, Doberman checks the recent
ledger for a runaway or looping burn. When it flags one, it sends the advisory `LoopAnomaly` to every
observer exposing that hook (`notify_loop_anomaly()`). The hook is duck-typed, not a required
Protocol member, so an observer with only `on_cost` keeps working unchanged. With no observer
installed, the detector never runs, so there's no extra ledger read on the hot path.

## Policy sources (org authority layering + the repo-committed file)

A `PolicySource` (`doberman.policy.sources`) contributes `blocked` and `sensitive` globs that are
resolved into every action decision alongside the local role. This was previously a dormant seam:
nothing in core ever set `EvalContext.metadata["resolved_policy"]`, so a registered source had no
effect until now. There are two ways to add one, both raise-only (a source can only add constraints,
never remove one another source already set):

- **The repo-committed file.** `doberman.policy.yaml` at the repo root (not `.doberman/`, which is
  gitignored). No plugin, no entry point: just commit the file. For the schema, the raise-only pin
  across file edits, and `doberman policy-file --accept`, see
  [README's "Policy as code"](../README.md).
- **A registered plugin.** Third-party sources (for example, an org or enterprise hard policy)
  register through the **`doberman.policy_sources`** entry-point group (`POLICY_SOURCE_GROUP` in
  `src/doberman/engine/registry.py`), opted in the same way as every other seam:
  `doberman plugins enable <name>`. A source that fails to import, fails to construct, or isn't
  policy-source-shaped (no `snapshot`/`authority`) is logged and skipped. It never crashes core.

Both merge via `resolve_policy()`'s raise-only UNION: `blocked` always wins over `sensitive` on a
tie, and a lower-authority source can never remove what a higher-authority one set. Authority only
orders the audit-trail `contributors` list; it never decides which constraints apply.

## Auth providers

Alternative backends (SSO/RBAC, hosted or push approvals) register through the
**`doberman.auth_providers`** entry-point group, opted in the same way as every other seam:
`doberman plugins enable <name>`. If nothing is opted in, or no opted-in provider is found, the
built-in local (CLI plus TOTP, a time-based one-time passcode from an authenticator app) provider
runs unchanged. Whichever plugin is active, it is wrapped in a co-gate: the built-in local provider
is **always** also consulted, for every tier, not just role elevation. A plugin's approval is
necessary but never sufficient, so a compromised or malicious plugin can never authenticate anything
on its own. The human is always asked too.
