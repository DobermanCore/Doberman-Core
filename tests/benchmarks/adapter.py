"""The suite-agnostic adapter contract.

A ``SuiteAdapter`` turns one external task suite into a stream of
``BenchmarkCase``s. Each case carries the ground-truth ``label`` and one or more
``CandidateAction``s — the tool-calls the harness will run through Doberman's
decision engine. Keeping this contract tiny and suite-independent is the whole
point: the runner and metrics never know which suite produced a case, so a new
suite is just a new adapter (see ``tests/benchmarks/README.md``).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol, runtime_checkable

from doberman.models import ActionType, SourceContext

#: Ground-truth label for a case. ``attack`` = an action that, if allowed,
#: advances an attacker goal; ``benign`` = a legitimate user-task action.
CaseLabel = Literal["attack", "benign"]


@dataclass(frozen=True)
class CandidateAction:
    """One tool-call to evaluate, in suite-neutral terms.

    These fields are the minimum needed to build a redacted ``SecurityObject`` +
    ``EvalContext`` (see ``mapping.py``). ``raw_arguments`` is passed to the
    engine via ``EvalContext.metadata['raw_arguments']`` (the real evaluation
    path that content rules read) — it MAY contain attack text, which is why the
    harness never emits it into any report.
    """

    action_type: ActionType
    tool_name: str
    target: str | None = None
    external_destination: str | None = None
    source_context: SourceContext = SourceContext.unknown
    agent_role: str = "unknown"
    mode: str = "balanced"
    raw_arguments: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class BenchmarkCase:
    """One labeled suite case = an id + label + the actions to evaluate.

    ``case_id`` must be unique within a suite and contain **no** payload text
    (it appears in reports). ``attacker_goal_index`` optionally points at the
    single action whose allowance constitutes attack success; when ``None`` (the
    default) every action in an ``attack`` case is treated as attacker-goal.
    ``note`` is a redaction-safe, class-level label only (never the payload).
    """

    case_id: str
    label: CaseLabel
    actions: tuple[CandidateAction, ...]
    attacker_goal_index: int | None = None
    note: str = ""


@runtime_checkable
class SuiteAdapter(Protocol):
    """Map one external suite into ``BenchmarkCase``s.

    Implementations live under ``suites/`` and own that suite's on-disk schema.
    ``load`` must be deterministic for a fixed input so the harness stays
    reproducible (sort, don't rely on dict/set ordering).
    """

    #: Stable, lowercase suite identifier (e.g. ``"agentdojo"``).
    suite_name: str

    def load(self) -> Iterable[BenchmarkCase]:
        """Yield the suite's labeled cases."""
        ...
