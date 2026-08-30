# Tutorial: custom AuditSink plugin

Doberman discovers third-party audit sinks through the **`doberman.audit_sinks`**
Python entry-point group (`AUDIT_SINK_GROUP` in `src/doberman/engine/registry.py`).
Core never imports your package by name — install the package, and
`discover_audit_sinks()` picks it up automatically.

This mini-package is a five-minute copy template.

## What it does

`ExampleAuditSink.emit(record)` appends one JSON line to a local file.  The
output path is controlled by the `DOBERMAN_AUDIT_SINK_FILE` environment variable;
when that is unset it defaults to `doberman_audit.jsonl` in the system temp
directory so the example works with zero configuration.

Deliberately hello-world: **no batching, no retries, no network**.  Those are
the built-in webhook sink's job (`doberman.storage.sinks.WebhookAuditSink`).
This example exists to show the registration seam, not to replace the
production sinks.

Invariants this example preserves:

| Invariant | How |
|-----------|-----|
| **emit never raises** | Every exception is caught and logged at WARNING; the decision path must never be blocked by a sink. |
| **Record is read-only** | `emit` does not mutate, enrich, or re-log any field beyond what the record already contains. |
| **No payload added** | The record arrives already redacted; the sink writes it verbatim and adds nothing. |
| **No core patch** | Registration is entirely via this package's `pyproject.toml`. |

## What this plugin must never log

The record handed to `emit` is **already redacted** by the time it arrives.
The sink must not add back anything the redaction layer removed:

| Never log | Why |
|-----------|-----|
| Raw file paths or target strings | Redacted to a path-class label (`general`, `sensitive`, …) before reaching the sink. |
| Agent inputs, tool arguments, or request payloads | Stripped entirely during redaction. |
| File contents or environment variables | Never present in the record. |
| HMAC entity IDs decoded or reversed | `entity_id` is a keyed HMAC; log it as-is, never attempt to reverse it. |
| Additional telemetry derived from the record | The sink is a dumb forwarder; enrichment belongs in a separate pipeline stage. |

## Round trip (from a Doberman-Core checkout)

```bash
# 1. Install core (dev extras optional for running tests)
pip install -e ".[dev]"

# 2. Install this tutorial plugin (editable)
pip install -e examples/plugin-audit-sink

# 3. Prove discovery + emit works
pytest examples/plugin-audit-sink/tests -q
```

Expected: all tests pass, including `test_entry_point_is_discoverable_after_install`.

### Manual smoke (optional)

```python
from doberman.engine.registry import discover_audit_sinks
from example_audit_sink.sinks import ExampleAuditSink

# Confirm discovery
sinks = discover_audit_sinks()
assert any(isinstance(s, ExampleAuditSink) for s in sinks)

# Emit a sample record
sink = ExampleAuditSink()
sink.emit({
    "ts": "2026-08-21T12:00:00+00:00",
    "action_id": "act-smoke",
    "final_verdict": "PASS",
    "reason_codes": [],
})
# No exception → check the output file (DOBERMAN_AUDIT_SINK_FILE or
# doberman_audit.jsonl in the system temp directory).
```

Uninstall when finished so other local experiments are not affected:

```bash
pip uninstall -y doberman-example-plugin-audit-sink
```

> **Important:** while this package is installed, core's "no sinks installed"
> standalone checks (`discover_audit_sinks() == []`) will fail — that is
> expected.  Uninstall before re-running the full core suite.  Default CI does
> **not** install this package; `tests/unit/test_examples_plugin_audit_sink.py`
> covers it instead by importing the sink class straight from this checkout
> (`sys.path`, no install) for layout/entry-point/protocol/emit/never-raises
> checks, so the standalone guarantee stays intact.

## How registration works

```toml
# examples/plugin-audit-sink/pyproject.toml
[project.entry-points."doberman.audit_sinks"]
example_sink = "example_audit_sink.sinks:ExampleAuditSink"
```

At runtime:

1. `emit_to_sinks()` (called after every decision) calls `discover_audit_sinks()`.
2. `discover_audit_sinks()` selects entry points in group `doberman.audit_sinks`.
3. Each entry point is loaded and checked for a callable `emit` attribute;
   non-sink-shaped objects are skipped.
4. Every discovered sink receives a copy of the already-redacted record dict.

## Layout

```text
examples/plugin-audit-sink/
  pyproject.toml                    # package metadata + doberman.audit_sinks entry point
  README.md                         # this file
  src/example_audit_sink/
    __init__.py
    sinks.py                        # ExampleAuditSink (AuditSink protocol)
  tests/
    test_example_sink.py            # discovery + emit + never-raises + read-only + threads
```

## Copy checklist for your own sink

1. New package with `requires-python = ">=3.11"` and `dependencies = ["doberman-core"]`
   (install against a local editable core checkout, not a stale PyPI wheel, while
   developing).
2. Implement `emit(self, record: dict) -> None` — one method, no return value.
3. **`emit` must never raise** — wrap all I/O in a broad `except Exception` and
   log at WARNING.  A sink that throws can break the decision path.
4. **Treat the record as read-only** — do not mutate, copy-and-enrich, or
   re-log fields beyond what the record already contains.
5. Register under `[project.entry-points."doberman.audit_sinks"]`.
6. Never add payload back — the record is already redacted; the sink is a
   forwarder, not an enrichment stage.
7. If your sink is stateful (e.g. holds a queue or a network connection),
   implement `close() -> None` so callers can drain cleanly on shutdown.
   The built-in `WebhookAuditSink` is a reference implementation.

Use `src/doberman/storage/sinks.py` as the reference built-in template.
