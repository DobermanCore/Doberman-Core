"""Prove the tutorial plugin discovers, evaluates, and stays fail-closed/raise-only.

Run after installing core + this package (from the Doberman-Core checkout)::

    pip install -e .
    pip install -e examples/plugin-guardrail
    pytest examples/plugin-guardrail/tests -q
"""

from __future__ import annotations

from datetime import datetime, timezone

from doberman.engine.objective import ObjectiveGuardrail
from doberman.engine.registry import RULE_GROUP, discover_rules
from doberman.models import (
    ActionType,
    EvalContext,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    Verdict,
)

from example_plugin.rules import ExampleRule


def _write(target: str) -> SecurityObject:
    return SecurityObject(
        id="example-plugin-1",
        ts=datetime(2026, 7, 19, tzinfo=timezone.utc),
        agent_role="unknown",
        action_type=ActionType.file_write,
        tool_name="write_file",
        target=target,
    )


def _ctx(path: str, *, root: str = ".") -> EvalContext:
    return EvalContext(metadata={"repo_root": root, "raw_arguments": {"path": path}})


def test_entry_point_is_discoverable_after_install():
    """``pip install -e`` registers the entry point; discover_rules finds it."""
    rules = discover_rules()
    assert any(isinstance(rule, ExampleRule) for rule in rules), (
        f"ExampleRule not discovered via {RULE_GROUP!r}; "
        "install with: pip install -e examples/plugin-guardrail"
    )


def test_write_to_secrets_todo_steps_up_to_auth():
    rule = ExampleRule()
    result = rule.evaluate(_write("docs/SECRETS_TODO.md"), _ctx("docs/SECRETS_TODO.md"))
    assert result.verdict is Verdict.AUTH
    assert result.risk is Risk.medium
    assert ReasonCode.sensitive_path_access in result.reason_codes


def test_case_and_windows_separators_still_match():
    """Canonical matching is case-insensitive; backslashes normalize on any OS."""
    rule = ExampleRule()
    result = rule.evaluate(
        _write(r"notes\Secrets_Todo.md"),
        _ctx(r"notes\Secrets_Todo.md"),
    )
    assert result.verdict is Verdict.AUTH


def test_redacted_target_still_fires_via_raw_arguments():
    """Prefer raw_arguments so a length-redacted target cannot bypass the rule."""
    action = _write("<redacted>")
    ctx = EvalContext(metadata={"raw_arguments": {"path": "docs/SECRETS_TODO.md"}})
    assert ExampleRule().evaluate(action, ctx).verdict is Verdict.AUTH


def test_target_only_fallback_without_raw_arguments():
    assert ExampleRule().evaluate(_write("SECRETS_TODO.md"), EvalContext()).verdict is Verdict.AUTH


def test_unrelated_write_abstains():
    rule = ExampleRule()
    result = rule.evaluate(_write("src/components/Button.tsx"), _ctx("src/components/Button.tsx"))
    assert result.verdict is Verdict.PASS


def test_read_of_marker_abstains():
    """Tutorial scope is write-only; reads are left to other rules."""
    action = SecurityObject(
        id="example-plugin-read",
        ts=datetime(2026, 7, 19, tzinfo=timezone.utc),
        agent_role="unknown",
        action_type=ActionType.file_read,
        tool_name="read_file",
        target="SECRETS_TODO.md",
    )
    result = ExampleRule().evaluate(action, _ctx("SECRETS_TODO.md"))
    assert result.verdict is Verdict.PASS


def test_explanation_never_echoes_path_or_payload():
    """SECURITY: explanation names the rule, never the path or contents."""
    sensitive_path = "team/private/SECRETS_TODO.md"
    result = ExampleRule().evaluate(_write(sensitive_path), _ctx(sensitive_path))
    assert result.verdict is Verdict.AUTH
    assert sensitive_path not in result.explanation
    assert "SECRETS_TODO.md" not in result.explanation
    assert "private" not in result.explanation


def test_plugin_fires_inside_objective_guardrail():
    """With the package installed, ObjectiveGuardrail discovers and runs it."""
    guardrail = ObjectiveGuardrail()  # load_plugins=True (default)
    # Benign-looking path for built-ins; only the tutorial plugin steps up.
    result = guardrail.evaluate(
        _write("notes/SECRETS_TODO.md"),
        _ctx("notes/SECRETS_TODO.md"),
    )
    assert result.verdict is Verdict.AUTH
    assert ReasonCode.sensitive_path_access in result.reason_codes


def test_plugin_cannot_lower_a_builtin_block():
    """Raise-only: PASS from the tutorial rule cannot weaken a built-in BLOCK."""
    guardrail = ObjectiveGuardrail()
    action = _write(".env")  # built-in ProtectedPathRule blocks this
    result = guardrail.evaluate(action, _ctx(".env"))
    assert result.verdict is Verdict.BLOCK
    assert ReasonCode.protected_path_blocked in result.reason_codes


def test_direct_evaluate_never_raises_on_empty_target():
    """No path → abstain (PASS); evaluate itself must not raise."""
    action = SecurityObject(
        id="example-plugin-empty",
        ts=datetime(2026, 7, 19, tzinfo=timezone.utc),
        agent_role="unknown",
        action_type=ActionType.file_write,
        tool_name="write_file",
        target="",
    )
    result = ExampleRule().evaluate(action, EvalContext())
    assert isinstance(result, GuardrailResult)
    assert result.verdict is Verdict.PASS
