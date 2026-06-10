"""Slice 0 — bootstrap smoke tests and the standalone guarantee."""

import subprocess
import sys


def test_core_imports_with_no_enterprise_installed():
    import doberman  # noqa: F401 — must succeed with zero enterprise deps

    assert "doberman_enterprise" not in sys.modules


def test_version_is_exposed():
    import doberman

    assert doberman.__version__ == "0.12.0"


def test_policy_core_packages_import_cleanly():
    # Run in a fresh interpreter: importing the policy core must not pull in
    # the proxy adapter. (Checking sys.modules in-process would be order-
    # dependent — other tests legitimately import doberman.proxy.)
    code = (
        "import sys; "
        "import doberman.engine, doberman.subjective, doberman.policy, "
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


def test_default_auth_provider_is_local_with_no_enterprise():
    # Slice 7.6 standalone guarantee: with no enterprise package installed, the
    # auth-provider registry discovers nothing and the local provider is active.
    from doberman.auth.provider import LocalAuthProvider, active_provider
    from doberman.engine.registry import discover_auth_providers

    assert discover_auth_providers() == []
    assert isinstance(active_provider(), LocalAuthProvider)


def test_no_drift_observers_registered_by_default():
    # Slice 10.4 standalone guarantee: with no enterprise package installed, the
    # drift-observer registry discovers nothing — the 2FA gate + local ledger run.
    from doberman.engine.registry import discover_drift_observers

    assert discover_drift_observers() == []


def test_no_detectors_registered_by_default():
    # Slice 9.3 standalone guarantee: with no enterprise package installed, the
    # detector registry discovers nothing — only the baseline signal runs.
    from doberman.engine.registry import discover_detectors

    assert discover_detectors() == []


def test_no_algebra_adapters_registered_by_default():
    # Slice SL3.1 standalone guarantee: with no adapter package installed, the
    # generic inference layer stands alone — coverage never depends on adapters.
    from doberman.engine.registry import discover_algebra_adapters

    assert discover_algebra_adapters() == []


def test_no_audit_sinks_registered_by_default():
    # Slice 8.4 standalone guarantee: with no enterprise package installed, the
    # audit-sink registry discovers nothing — only the local decision log runs.
    from doberman.engine.registry import discover_audit_sinks

    assert discover_audit_sinks() == []


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
