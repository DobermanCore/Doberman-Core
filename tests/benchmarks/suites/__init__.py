"""Concrete suite adapters.

``synthetic`` is the built-in, deterministic, dependency-free suite that gates in
CI. Real external suites (AgentDojo, AgentDyn, AgentSentry) are added as their
own adapter modules here — see ``tests/benchmarks/README.md`` for the recipe.
"""

from .agentdojo import AgentDojoAdapter, AgentDynAdapter
from .corpus import CorpusAdapter
from .synthetic import SyntheticAdapter

#: Adapters that need no external data, safe to run in CI unconditionally.
#: ``agentdojo`` / ``agentdyn`` are registered for on-demand CLI use; they import
#: the optional ``agentdojo``-API package lazily (AgentDyn resolves when its
#: checkout is on ``PYTHONPATH``) and are NOT part of the always-on CI gate.
BUILTIN_ADAPTERS = {
    "synthetic": SyntheticAdapter,
    "corpus": CorpusAdapter,
    "agentdojo": AgentDojoAdapter,
    "agentdyn": AgentDynAdapter,
}

__all__ = [
    "BUILTIN_ADAPTERS",
    "AgentDojoAdapter",
    "AgentDynAdapter",
    "CorpusAdapter",
    "SyntheticAdapter",
]
