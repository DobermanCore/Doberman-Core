# Write a guardrail plugin

This page covers Doberman's plugin seams: registering your own rule, and forwarding the redacted
audit log to your own pipeline. Both work the same way, a Python entry-point group core discovers
at runtime, so core never imports a plugin package by name.

## Opt in by name first

Installing a plugin package is never enough on its own — **every** entry-point seam (rules,
detectors, audit sinks, auth providers, and the rest) only imports an entry point whose name you've
explicitly trusted:

```bash
doberman plugins list             # enabled names, and every installed-but-maybe-not-enabled entry point
doberman plugins enable <name>    # e.g. `doberman plugins enable example_rule`
doberman plugins disable <name>
```

This closes a gap where a merely-*installed* plugin could influence discovery of another seam before
your own code ever runs it (an auto-loaded rule plugin, say, setting an env var at import time that a
different seam reads later). The allowlist is snapshotted once per process before discovery starts, so
enabling a plugin mid-run has no effect until the next run. A rule/detector plugin also runs against its
**own copy** of the evaluation context — see "Rule and detector plugins get their own context" below.

## Write a custom guardrail

Third-party rules register through the **`doberman.rules`** entry-point group
(`RULE_GROUP` in `src/doberman/engine/registry.py`). Install a package that declares one, then
`doberman plugins enable <name>` — only then does `discover_rules()` pick it up; the objective
guardrail runs built-in rules and every enabled plugin together, reduced with the same raise-only
`combine()` used everywhere else, so a plugin can only ever add risk, never lower a verdict. A plugin
that fails to import, fails to construct, or isn't shaped like a `Guardrail` is logged and skipped,
never crashes core.

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

Copy that package as the starting point for a real rule of your own. A few rules that keep a plugin
well-behaved: implement `evaluate(self, action, ctx) -> GuardrailResult`, the same contract as the
built-ins; prefer `ReasonCode` values from `doberman.models` instead of inventing free-form codes;
canonicalize paths with `doberman.canonical.canonicalize` before matching; and only return a result
that *raises* risk for your signal, abstaining (`PASS`) otherwise.

> While the example plugin is installed AND enabled, core's "no plugins registered" checks will see
> it, that is expected. Disable/uninstall before re-running the full core suite if you want a clean
> standalone environment.

### Rule and detector plugins get their own context

`EvalContext.metadata` is a plain mutable dict shared with the built-in rules and the subjective
layer. A rule or detector plugin never sees that shared dict directly: the objective/subjective
guardrail hands it a **copy** (`ctx.metadata` deep-copied) before calling the plugin. A plugin that
deletes `raw_arguments` or sets `scope_token=True` on its own copy has no effect on what a later
built-in, a later plugin, or the caller sees after evaluation — only a plugin's *returned*
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
default. Delivery never touches the decision path: `emit()` hands the record to a bounded background
queue and returns before any I/O, so a wedged endpoint can't delay a decision; on overflow the oldest
queued record is dropped and the drop count is incremented. Records carry the same already-redacted
fields as the local log (path classes, reason codes, verdicts, HMAC fingerprints, never raw secrets),
and the auth token value is read from the named env var at POST time, never stored on the sink or
logged. This is a bridge to your pipeline, not a delivery guarantee.

Additional sinks register the same way, through the **`doberman.audit_sinks`** entry-point group:
register the entry point, then `doberman plugins enable <name>`. `emit_to_sinks()` in `sinks.py` runs
every enabled plugin-registered sink first, then the built-in webhook sink and the built-in
OpenTelemetry sink (config-gated via `.doberman/audit_otel.yaml`, see [the OTel guide](audit_otel.md));
a sink that isn't shaped like an `AuditSink` (no callable `emit`), or whose `emit` raises, is logged
and skipped, and never affects the decision itself.

## Cost observers

Cost/budget monitoring packages register through the **`doberman.cost_observers`** entry-point
group (`CostObserver` in `src/doberman/storage/cost.py`), opted in the same way: `doberman plugins
enable <name>`. Every registered observer's `on_cost` is called with a copy of each redacted
`CostEvent` after a successful ledger write — advisory only, off the decision path, never raising
into or delaying the record. An observer may **optionally** also expose `on_loop_anomaly(anomaly)`
to receive the loop-anomaly detector's readout: after a tool-call event, if at least one observer is
installed, Doberman checks the recent ledger for a runaway/looping burn and, when it flags one, fans
the advisory `LoopAnomaly` out to every observer exposing that hook (`notify_loop_anomaly()`). The
hook is duck-typed, not a required Protocol member, so an observer with only `on_cost` keeps working
unchanged; with no observer installed the detector never runs, so there's no extra ledger read on the
hot path.

## Auth providers

Alternative backends (SSO/RBAC, hosted/push approvals) register through the **`doberman.auth_providers`**
entry-point group, opted in the same way as every other seam: `doberman plugins enable <name>`.
Nothing opted in, or no opted-in provider found, and the built-in local (CLI + TOTP) provider runs
unchanged. Whichever plugin is active, it wraps in a co-gate: the built-in local provider is **always**
also consulted, for **every** tier, not just role elevation — a plugin's approval is necessary but
never sufficient, so a compromised or malicious plugin can never authenticate anything on its own; the
human is always asked too.
