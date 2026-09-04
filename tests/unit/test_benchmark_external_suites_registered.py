"""The three external suites register through BUILTIN_ADAPTERS exactly like
AgentDojo/AgentDyn — proves Task 4's __init__.py wiring, independent of any
operator-supplied data (construction only, never .load())."""

from __future__ import annotations

from tests.benchmarks.adapter import SuiteAdapter
from tests.benchmarks.suites import BUILTIN_ADAPTERS


def test_external_suites_are_registered():
    for name in ("redcode", "msb", "llmail_inject"):
        assert name in BUILTIN_ADAPTERS
        assert isinstance(BUILTIN_ADAPTERS[name](), SuiteAdapter)
