"""Slice 0 — bootstrap smoke tests and the standalone guarantee."""

import sys


def test_core_imports_with_no_enterprise_installed():
    import doberman  # noqa: F401 — must succeed with zero enterprise deps

    assert "doberman_enterprise" not in sys.modules


def test_version_is_exposed():
    import doberman

    assert doberman.__version__ == "0.0.0"


def test_policy_core_packages_import_cleanly():
    import doberman.engine  # noqa: F401
    import doberman.learning  # noqa: F401
    import doberman.policy  # noqa: F401
    import doberman.roles  # noqa: F401
    import doberman.storage  # noqa: F401

    assert "doberman.proxy" not in sys.modules
