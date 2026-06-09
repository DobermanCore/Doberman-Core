"""Slice 0 — bootstrap smoke tests and the standalone guarantee."""

import subprocess
import sys


def test_core_imports_with_no_enterprise_installed():
    import doberman  # noqa: F401 — must succeed with zero enterprise deps

    assert "doberman_enterprise" not in sys.modules


def test_version_is_exposed():
    import doberman

    assert doberman.__version__ == "0.2.0"


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
