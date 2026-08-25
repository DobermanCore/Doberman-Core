# Write a guardrail plugin

This page covers Doberman's plugin seams: registering your own rule, and forwarding the redacted
audit log to your own pipeline. Both work the same way, a Python entry-point group core discovers
at runtime, so core never imports a plugin package by name.

## Write a custom guardrail

Third-party rules register through the **`doberman.rules`** entry-point group
(`RULE_GROUP` in `src/doberman/engine/registry.py`). Install a package that declares one, and
`discover_rules()` picks it up automatically; the objective guardrail runs built-in rules and every
discovered plugin together, reduced with the same raise-only `combine()` used everywhere else, so a
plugin can only ever add risk, never lower a verdict. A plugin that fails to import, fails to
construct, or isn't shaped like a `Guardrail` is logged and skipped, never crashes core.

A five-minute worked example lives at [`examples/plugin-guardrail/`](../examples/plugin-guardrail/)
(from a git checkout):

```bash
pip install -e ".[dev]"
pip install -e examples/plugin-guardrail
pytest examples/plugin-guardrail/tests -q
pip uninstall -y doberman-example-plugin-guardrail   # optional: restore core-only discovery
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

> While the example plugin is installed, core's "no plugins registered" checks will see it, that is
> expected. Uninstall before re-running the full core suite if you want a clean standalone
> environment.

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

Additional sinks register the same way, through the **`doberman.audit_sinks`** entry-point group.
`emit_to_sinks()` in `sinks.py` runs every plugin-registered sink first, then the built-in webhook
sink and the built-in OpenTelemetry sink (config-gated via `.doberman/audit_otel.yaml`, see
[the OTel guide](audit_otel.md)); a sink that isn't shaped like an `AuditSink` (no callable `emit`),
or whose `emit` raises, is logged and skipped, and never affects the decision itself.
