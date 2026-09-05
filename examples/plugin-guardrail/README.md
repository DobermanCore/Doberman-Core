# Tutorial: custom Guardrail plugin

Doberman discovers third-party rules through the **`doberman.rules`** Python
entry-point group (an entry point is a name a package lists in its `pyproject.toml`
so other code can find and load it; `RULE_GROUP` in `src/doberman/engine/registry.py`).
Core never imports your package by name. Install the package, and
`discover_rules()` / `ObjectiveGuardrail()` pick it up automatically.

This mini-package is a five-minute copy template.

## What it does

`ExampleRule` steps up a **file write** whose canonical basename is
`SECRETS_TODO.md` to **AUTH** (reason code `sensitive_path_access`). Everything
else abstains (`PASS`).

Invariants this example preserves:

| Invariant | How |
|-----------|-----|
| **Raise-only** | Returns only PASS or AUTH; never lowers another rule's verdict (`combine()` is max-severity). |
| **No payload in logs/explanations** | `explanation` names the *rule*, never the raw path or file contents. |
| **Fail-closed core unchanged** | A broken plugin is isolated by core; this package does not catch-and-swallow errors to PASS. |
| **No core patch** | Registration is entirely via this package's `pyproject.toml`. |

## Round trip (from a Doberman-Core checkout)

```bash
# 1. Install core (dev extras optional for running tests)
pip install -e ".[dev]"

# 2. Install this tutorial plugin (editable)
pip install -e examples/plugin-guardrail

# 3. Prove discovery + the rule fires
pytest examples/plugin-guardrail/tests -q
```

Expected: all tests pass, including `test_entry_point_is_discoverable_after_install`
and `test_plugin_fires_inside_objective_guardrail`.

### Manual smoke (optional)

```python
from doberman.engine.registry import discover_rules
from doberman.engine.objective import ObjectiveGuardrail
from doberman.models import (
    ActionType, EvalContext, SecurityObject, Verdict,
)
from datetime import datetime, timezone
from example_plugin.rules import ExampleRule

assert any(isinstance(r, ExampleRule) for r in discover_rules())

g = ObjectiveGuardrail()
action = SecurityObject(
    id="demo",
    ts=datetime.now(timezone.utc),
    agent_role="unknown",
    action_type=ActionType.file_write,
    tool_name="write_file",
    target="notes/SECRETS_TODO.md",
)
ctx = EvalContext(metadata={"raw_arguments": {"path": "notes/SECRETS_TODO.md"}})
assert g.evaluate(action, ctx).verdict is Verdict.AUTH
```

Uninstall when finished so other local experiments are not affected:

```bash
pip uninstall -y doberman-example-plugin-guardrail
```

> **Important:** while this package is installed, core's "no plugins installed"
> standalone checks (`discover_rules() == []`) will fail. That is expected.
> Uninstall before re-running the full core suite. Default CI does **not**
> install this package; it only path-imports the rule class for evaluate/raise-only
> checks.

## How registration works

```toml
# examples/plugin-guardrail/pyproject.toml
[project.entry-points."doberman.rules"]
example_rule = "example_plugin.rules:ExampleRule"
```

At runtime:

1. `ObjectiveGuardrail(load_plugins=True)` calls `discover_rules()`.
2. `discover_rules()` selects entry points in group `doberman.rules`.
3. Each entry point is loaded and instantiated; non-`Guardrail`-shaped objects are skipped.
4. Built-in rules **and** plugins are reduced with raise-only `combine()`.

## Layout

```text
examples/plugin-guardrail/
  pyproject.toml          # package metadata + doberman.rules entry point
  README.md               # this file
  src/example_plugin/
    __init__.py
    rules.py              # ExampleRule (Guardrail protocol)
  tests/
    test_example_rule.py  # discovery + evaluation + raise-only + redaction
```

## Copy checklist for your own rule

1. New package with `requires-python = ">=3.11"` and `dependencies = ["doberman-core"]` (install against a local editable core checkout, not a stale PyPI wheel, while developing).
2. Implement `evaluate(self, action, ctx) -> GuardrailResult` (same contract as built-ins).
3. Register under `[project.entry-points."doberman.rules"]`.
4. Prefer `ReasonCode` values from `doberman.models` (do not invent free-form codes).
5. Canonicalize paths (reduce a path to one standard, absolute form, so `./a/../b` and `b` are recognized as the same path) with `doberman.canonical.canonicalize` before matching; normalize `\\` → `/` if you accept agent-supplied path strings.
6. Prefer `ctx.metadata["raw_arguments"]` for path matching when present (redacted `action.target` can hide the real path).
7. Never put secrets, full paths, or request payloads into `explanation` or logs.
8. Only return PASS / AUTH / BLOCK results that *raise* risk for your signal; abstain otherwise.
9. Do **not** re-implement repo-root confinement unless you mean to: escapes should stay the built-in path rule's job, so a solo plugin does not invent a weaker story.

Use `src/doberman/engine/rules/paths.py` as the reference built-in template.

This tutorial only steps up **writes** (not deletes/reads) of the marker file. Keep demo scope minimal.
