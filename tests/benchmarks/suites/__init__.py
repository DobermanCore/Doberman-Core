"""Concrete suite adapters.

``synthetic`` is the built-in, deterministic, dependency-free suite that gates in
CI. ``devsession`` is a second built-in, deterministic, dependency-free suite —
a seeded developer-session corpus sized to clear the subjective layer's warm
thresholds (C11). Real external suites (AgentDojo, AgentDyn, AgentSentry, RedCode,
MSB, LLMail-Inject) are added as their own adapter modules here — see
``tests/benchmarks/README.md`` for the recipe.
"""

from .agentdojo import AgentDojoAdapter, AgentDynAdapter
from .corpus import CorpusAdapter
from .devsession import DevSessionAdapter
from .llmail_inject import LlmailInjectAdapter
from .msb_poisoning import MsbPoisoningAdapter
from .redcode import RedCodeAdapter
from .synthetic import SyntheticAdapter

#: Adapters that need no external data, safe to run in CI unconditionally.
#: ``agentdojo``/``agentdyn``/``redcode``/``msb``/``llmail_inject`` are registered
#: for on-demand CLI use; each imports/reads its optional data lazily (a package
#: import for agentdojo/agentdyn, an operator-supplied env-var directory for the
#: other three) and is NOT part of the always-on CI gate.
BUILTIN_ADAPTERS = {
    "synthetic": SyntheticAdapter,
    "corpus": CorpusAdapter,
    "devsession": DevSessionAdapter,
    "agentdojo": AgentDojoAdapter,
    "agentdyn": AgentDynAdapter,
    "redcode": RedCodeAdapter,
    "msb": MsbPoisoningAdapter,
    "llmail_inject": LlmailInjectAdapter,
}

__all__ = [
    "BUILTIN_ADAPTERS",
    "AgentDojoAdapter",
    "AgentDynAdapter",
    "CorpusAdapter",
    "DevSessionAdapter",
    "LlmailInjectAdapter",
    "MsbPoisoningAdapter",
    "RedCodeAdapter",
    "SyntheticAdapter",
]
