"""Suite-agnostic benchmark harness for Doberman.

This package maps **external agent-security task suites** (AgentDojo, AgentDyn,
AgentSentry, …) onto Doberman's core types and measures the engine's verdicts as
a *filter over labeled actions* — reporting per-suite **ASR** (attack bypass
rate) and **FPR** (benign over-block / friction).

It is deliberately scored offline and deterministically: each suite case is a
``BenchmarkCase`` carrying one or more candidate tool-calls plus a ground-truth
label (``"attack"`` / ``"benign"``); the runner builds a ``SecurityObject`` +
``EvalContext`` per action, runs core's public ``decide()``, and classifies the
resulting verdict. **Doberman is not run as the agent** — we replay labeled
actions, so no live model is needed in the gated path.

Profiles (built on core's already-shipped ``load_plugins`` flag):

* ``builtins_only`` — only the built-in rules/detectors run.
* ``with_plugins`` — built-ins **plus** any entry-point plugins installed in the
  environment. With nothing installed the two profiles are identical.

REDACTION: reports hold counts, case ids, verdict names, and reason codes only —
**never** the attack-payload text. See ``tests/benchmarks/README.md`` for how to
wire a real suite in.
"""

from .adapter import BenchmarkCase, CandidateAction, SuiteAdapter
from .corpus import CorpusAdapter, CorpusRow, load_corpus
from .metrics import SuiteReport
from .profiles import Pipeline, build_pipeline
from .runner import run_profiles, run_suite

__all__ = [
    "BenchmarkCase",
    "CandidateAction",
    "CorpusAdapter",
    "CorpusRow",
    "Pipeline",
    "SuiteAdapter",
    "SuiteReport",
    "build_pipeline",
    "load_corpus",
    "run_profiles",
    "run_suite",
]
