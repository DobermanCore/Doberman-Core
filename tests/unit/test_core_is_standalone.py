"""Slice 0 — bootstrap smoke tests and the standalone guarantee."""

import subprocess
import sys


def test_core_imports_with_no_enterprise_installed():
    import doberman  # noqa: F401 — must succeed with zero enterprise deps

    assert "doberman_enterprise" not in sys.modules


def test_version_is_exposed():
    import doberman

    assert doberman.__version__ == "0.3.0"


def test_policy_core_packages_import_cleanly():
    # Run in a fresh interpreter: importing the policy core must not pull in
    # the proxy adapter. (Checking sys.modules in-process would be order-
    # dependent — other tests legitimately import doberman.proxy.)
    code = (
        "import sys; "
        "import doberman.engine, doberman.learning, doberman.policy, "
        "doberman.roles, doberman.storage; "
        "assert 'doberman.proxy' not in sys.modules"
    )
    subprocess.run([sys.executable, "-c", code], check=True, timeout=60)  # noqa: S603


def test_default_plugin_registry_has_no_enterprise_plugins():
    # Slice 3.8 standalone guarantee: with no enterprise package installed, the
    # entry-point registry discovers nothing — only built-in rules run.
    from doberman.engine.registry import discover_rules

    plugins = discover_rules()
    assert plugins == []
    # And none of whatever (if anything) is installed comes from enterprise.
    assert all("enterprise" not in type(p).__module__ for p in plugins)


def test_objective_guardrail_runs_with_only_builtins():
    # The assembled objective guardrail works standalone: no plugins, just the
    # core rules — a benign action passes, a clearly-forbidden one blocks.
    from datetime import datetime, timezone

    from doberman.engine.objective import ObjectiveGuardrail
    from doberman.models import ActionType, EvalContext, SecurityObject, Verdict

    g = ObjectiveGuardrail()

    def _act(target):
        return SecurityObject(
            id="sa-1",
            ts=datetime(2026, 6, 7, tzinfo=timezone.utc),
            agent_role="unknown",
            action_type=ActionType.file_write,
            tool_name="t",
            target=target,
        )

    assert g.evaluate(_act(".env"), EvalContext()).verdict is Verdict.BLOCK
    assert g.evaluate(_act("frontend/Button.tsx"), EvalContext()).verdict is Verdict.PASS
