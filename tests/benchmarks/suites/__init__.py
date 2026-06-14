"""Concrete suite adapters.

``synthetic`` is the built-in, deterministic, dependency-free suite that gates in
CI. Real external suites (AgentDojo, AgentDyn, AgentSentry) are added as their
own adapter modules here — see ``tests/benchmarks/README.md`` for the recipe.
"""

from .synthetic import SyntheticAdapter

#: Adapters that need no external data, safe to run in CI unconditionally.
BUILTIN_ADAPTERS = {"synthetic": SyntheticAdapter}

__all__ = ["BUILTIN_ADAPTERS", "SyntheticAdapter"]
