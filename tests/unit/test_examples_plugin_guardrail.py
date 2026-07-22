"""CI-visible checks for the tutorial plugin under examples/plugin-guardrail (#91).

The example package is **opt-in** (``pip install -e examples/plugin-guardrail``).
These tests never install its entry point into the active environment — that would
pollute every ``ObjectiveGuardrail(load_plugins=True)`` call in the suite.

They do prove:

* the package layout and ``doberman.rules`` entry-point declaration are correct;
* ``ExampleRule`` evaluates as documented (AUTH on SECRETS_TODO.md write);
* explanations never echo the path/payload;
* when injected like a discovered plugin, raise-only still holds with built-ins.

Full entry-point discovery after a real install is covered by the example's own
tests (``examples/plugin-guardrail/tests/``) and documented in its README.
"""

from __future__ import annotations

import importlib
import sys
import tomllib
from datetime import datetime, timezone
from pathlib import Path

import pytest

from doberman.engine import registry
from doberman.engine.objective import ObjectiveGuardrail
from doberman.models import (
    ActionType,
    EvalContext,
    ReasonCode,
    Risk,
    SecurityObject,
    Verdict,
)

_REPO_ROOT = Path(__file__).resolve().parents[2]
_EXAMPLE_ROOT = _REPO_ROOT / "examples" / "plugin-guardrail"
_EXAMPLE_SRC = _EXAMPLE_ROOT / "src"
_EXAMPLE_PYPROJECT = _EXAMPLE_ROOT / "pyproject.toml"


@pytest.fixture(scope="module")
def example_rule_cls():
    """Import ExampleRule from the checkout without installing the package."""
    assert _EXAMPLE_SRC.is_dir(), f"missing tutorial package at {_EXAMPLE_SRC}"
    inserted = str(_EXAMPLE_SRC)
    sys.path.insert(0, inserted)
    try:
        # Fresh import in case a prior test left a stub.
        sys.modules.pop("example_plugin", None)
        sys.modules.pop("example_plugin.rules", None)
        module = importlib.import_module("example_plugin.rules")
        return module.ExampleRule
    finally:
        # Leave the module importable for the rest of this module's tests, but
        # drop the path entry so we do not permanently shadow site-packages.
        if sys.path and sys.path[0] == inserted:
            sys.path.pop(0)


def _write(target: str) -> SecurityObject:
    return SecurityObject(
        id="ex-plugin-ci-1",
        ts=datetime(2026, 7, 19, tzinfo=timezone.utc),
        agent_role="unknown",
        action_type=ActionType.file_write,
        tool_name="write_file",
        target=target,
    )


def _ctx(path: str) -> EvalContext:
    return EvalContext(metadata={"raw_arguments": {"path": path}})


def test_example_package_layout_exists():
    assert (_EXAMPLE_ROOT / "README.md").is_file()
    assert (_EXAMPLE_SRC / "example_plugin" / "rules.py").is_file()
    assert (_EXAMPLE_ROOT / "tests" / "test_example_rule.py").is_file()
    assert _EXAMPLE_PYPROJECT.is_file()


def test_example_pyproject_declares_doberman_rules_entry_point():
    data = tomllib.loads(_EXAMPLE_PYPROJECT.read_text(encoding="utf-8"))
    eps = data["project"]["entry-points"]["doberman.rules"]
    assert eps["example_rule"] == "example_plugin.rules:ExampleRule"
    # Mirror the core package name so ``pip install -e`` resolves against this repo.
    assert "doberman-core" in data["project"]["dependencies"]


def test_example_rule_steps_up_marker_write(example_rule_cls):
    result = example_rule_cls().evaluate(
        _write("docs/SECRETS_TODO.md"),
        _ctx("docs/SECRETS_TODO.md"),
    )
    assert result.verdict is Verdict.AUTH
    assert result.risk is Risk.medium
    assert ReasonCode.sensitive_path_access in result.reason_codes


def test_example_rule_prefers_raw_arguments_over_redacted_target(example_rule_cls):
    """Redacted action.target must not hide a marker write (mirrors paths.py)."""
    action = _write("<redacted>")
    ctx = EvalContext(metadata={"raw_arguments": {"path": "docs/SECRETS_TODO.md"}})
    result = example_rule_cls().evaluate(action, ctx)
    assert result.verdict is Verdict.AUTH


def test_example_rule_falls_back_to_action_target(example_rule_cls):
    """With no raw_arguments, the (possibly already-safe) target is still matched."""
    result = example_rule_cls().evaluate(_write("SECRETS_TODO.md"), EvalContext())
    assert result.verdict is Verdict.AUTH


def test_example_rule_case_insensitive_basename(example_rule_cls):
    result = example_rule_cls().evaluate(
        _write("notes/Secrets_Todo.md"),
        _ctx("notes/Secrets_Todo.md"),
    )
    assert result.verdict is Verdict.AUTH


def test_example_rule_normalizes_backslash_separators(example_rule_cls):
    """Windows-style separators must match even when the host is POSIX."""
    result = example_rule_cls().evaluate(
        _write(r"notes\Secrets_Todo.md"),
        _ctx(r"notes\Secrets_Todo.md"),
    )
    assert result.verdict is Verdict.AUTH


def test_example_rule_near_miss_basename_abstains(example_rule_cls):
    for path in (
        "docs/SECRETS_TODO.mdx",
        "docs/not_SECRETS_TODO.md",
        "docs/SECRETS_TODO.md.bak",
    ):
        result = example_rule_cls().evaluate(_write(path), _ctx(path))
        assert result.verdict is Verdict.PASS, path


def test_example_rule_abstains_on_unrelated_write(example_rule_cls):
    result = example_rule_cls().evaluate(
        _write("src/components/Button.tsx"),
        _ctx("src/components/Button.tsx"),
    )
    assert result.verdict is Verdict.PASS


def test_example_rule_explanation_omits_path_payload(example_rule_cls):
    path = "team/private/SECRETS_TODO.md"
    result = example_rule_cls().evaluate(_write(path), _ctx(path))
    assert result.verdict is Verdict.AUTH
    assert path not in result.explanation
    assert "SECRETS_TODO.md" not in result.explanation
    assert "private" not in result.explanation


def test_example_rule_injected_into_objective_guardrail(example_rule_cls):
    """Simulate discovery by injecting the real class as an extra rule."""
    guardrail = ObjectiveGuardrail(load_plugins=False, extra_rules=[example_rule_cls()])
    result = guardrail.evaluate(
        _write("notes/SECRETS_TODO.md"),
        _ctx("notes/SECRETS_TODO.md"),
    )
    assert result.verdict is Verdict.AUTH
    assert ReasonCode.sensitive_path_access in result.reason_codes


def test_example_rule_cannot_lower_builtin_block(example_rule_cls):
    guardrail = ObjectiveGuardrail(load_plugins=False, extra_rules=[example_rule_cls()])
    result = guardrail.evaluate(_write(".env"), _ctx(".env"))
    assert result.verdict is Verdict.BLOCK
    assert ReasonCode.protected_path_blocked in result.reason_codes


def test_example_rule_is_guardrail_shaped(example_rule_cls):
    from doberman.engine.decision_engine import Guardrail

    instance = example_rule_cls()
    assert isinstance(instance, Guardrail)


def test_registry_group_constant_matches_example_declaration():
    """Tutorial pyproject must use the same group name core discovers."""
    assert registry.RULE_GROUP == "doberman.rules"
