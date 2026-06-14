# Doberman benchmark harness — wiring external task suites

A small, **suite-agnostic** harness that scores Doberman as a *filter over
labeled actions* and reports per-suite **ASR** (attack bypass rate) and **FPR**
(benign over-block / friction). It maps any external agent-security task suite —
**[AgentDojo]**, **AgentDyn**, **AgentSentry**, … — onto core's `SecurityObject`
/ `EvalContext`, runs the real `decide()` engine, and classifies the verdict.

It imports **only** core's public API and **registers nothing** — it is a read-
only consumer of the engine. No third-party suite code or data is vendored here;
you point an adapter at a suite you obtain yourself.

[AgentDojo]: https://github.com/ethz-spylab/agentdojo

---

## Mental model: Doberman is the filter, not the agent

These suites are normally used to run an *agent* end-to-end. Doberman is a
**mediator** that judges each candidate tool-call. So we do **not** run the
suite's agent. Instead we take the suite's **labeled candidate actions** —

- **attack** = an action that, if allowed, advances an attacker's injected goal,
- **benign** = a legitimate user-task action —

map each to a `SecurityObject` + `EvalContext`, run `decide()`, and score the
verdict (`PASS` < `AUTH` < `BLOCK`):

| label  | `PASS`         | `AUTH`              | `BLOCK`        |
|--------|----------------|---------------------|----------------|
| attack | **bypassed**   | mitigated           | mitigated      |
| benign | ok             | friction (FPR)      | false block    |

This keeps the gated path **deterministic and offline** (no live model). If a
suite only ships task *definitions* (not recorded agent traces), generating
traces needs an agent + LLM — that is **out of scope** for the gated harness; run
it separately and feed the resulting labeled actions in.

---

## Layout

```
tests/benchmarks/
├── adapter.py     # CandidateAction, BenchmarkCase, SuiteAdapter  (the contract)
├── mapping.py     # CandidateAction -> SecurityObject / EvalContext
├── profiles.py    # build_pipeline(load_plugins=...) -> Pipeline
├── metrics.py     # SuiteReport: ASR, asr_strict, FPR, hard_fpr
├── runner.py      # run_suite(adapter, pipeline), run_profiles(adapter)
├── run.py         # CLI: python -m tests.benchmarks.run --suite <name> --profile both
├── suites/
│   ├── synthetic.py   # built-in, deterministic, dependency-free (the CI gate)
│   ├── agentdojo.py   # AgentDojo + AgentDyn adapters (on-demand; lazy `agentdojo` import)
│   └── <your_suite>.py
└── README.md      # this file
```

Tests: `tests/unit/test_benchmark_harness.py` (metrics/selector/isolation),
`tests/unit/test_benchmark_agentdojo.py` (the AgentDojo/AgentDyn mapping +
redaction, with the `agentdojo` package faked), and
`tests/integration/test_benchmark_synthetic_gate.py` (real-engine gate).

---

## The contract you implement

A suite adapter is any object with a `suite_name` and a `load()` that yields
`BenchmarkCase`s:

```python
from collections.abc import Iterable
from doberman.models import ActionType, SourceContext
from tests.benchmarks.adapter import BenchmarkCase, CandidateAction

class MySuiteAdapter:
    suite_name = "mysuite"

    def __init__(self, root: str) -> None:
        self._root = root  # operator-supplied path to the obtained suite

    def load(self) -> Iterable[BenchmarkCase]:
        for task in _read_tasks(self._root):          # YOUR parsing
            yield BenchmarkCase(
                case_id=task.id,                       # NO payload text in the id
                label="attack" if task.is_injection else "benign",
                note=task.category,                    # class-level label only
                attacker_goal_index=task.goal_step,    # or None = all actions count
                actions=tuple(
                    CandidateAction(
                        action_type=_map_action_type(call.kind),  # -> ActionType.*
                        tool_name=call.tool,
                        target=call.target,                       # path / resource
                        external_destination=call.url_or_host,    # for egress
                        source_context=SourceContext.tool_output, # provenance
                        raw_arguments=call.arguments,             # may hold payload
                    )
                    for call in task.tool_calls
                ),
            )
```

Then run it:

```python
from tests.benchmarks.runner import run_profiles
report = run_profiles(MySuiteAdapter(root="/path/to/suite"))
```

Register it in `suites/__init__.py` (`BUILTIN_ADAPTERS`) **only if** it needs no
external data (the synthetic suite does that); suites that need an operator-
supplied path stay out of the always-on CI gate and run on demand.

### Field-mapping cheatsheet

| suite concept | maps to | notes |
|---|---|---|
| tool call kind (read/write/exec/http/git/install) | `CandidateAction.action_type` (`ActionType.*`) | pick the closest; use `ActionType.other` if unsure |
| tool name | `tool_name` | free text |
| file path / resource | `target` | the canonical rules read this |
| destination URL / host | `external_destination` | drives the egress rule |
| where the instruction came from | `source_context` (`SourceContext.*`) | `tool_output` / `webpage` / `email` for injected content |
| raw tool arguments / body | `raw_arguments` (dict) | reaches `EvalContext.metadata["raw_arguments"]`; **may contain attack text** |
| ground-truth attack vs benign | `BenchmarkCase.label` | the single most important field to get right |
| which step is the attacker's goal | `attacker_goal_index` | `None` ⇒ every action in an attack case is scored |

---

## Profiles (`builtins_only` vs `with_plugins`)

The only difference is core's shipped `load_plugins` flag:

- `builtins_only` — only the built-in rules/detectors run.
- `with_plugins`  — built-ins **plus** any entry-point plugins installed in the
  environment (`doberman.rules` / `doberman.detectors`).

`run_profiles()` runs both and reports the **uplift** (`delta_asr`, `delta_fpr`).
On a standalone core install nothing is registered, so the two profiles are
identical and uplift is 0 — install a plugin package and the delta shows what it
adds. (The harness names no specific plugin package; it just measures whatever is
installed.)

---

## Metrics (read `metrics.py` for the exact math)

- **ASR** — `bypassed / attacks`; mitigation counts `BLOCK` **or** `AUTH`
  (an `AUTH` interrupts an autonomous chain). The headline bypass rate.
- **asr_strict** — mitigation counts `BLOCK` **only**; `AUTH` is treated as not
  stopped (a human might approve). The conservative lower bound on protection.
- **FPR** — `(benign AUTH + benign BLOCK) / benign`; the friction cost.
- **hard_fpr** — `benign BLOCK / benign`; false hard-blocks of legitimate work.

Always report ASR **and** asr_strict together — don't oversell a number.

---

## Redaction (mandatory)

Reports contain **counts, case ids, verdict names, and reason codes only** —
**never** payload text. `raw_arguments` may carry the attack string, but it never
enters a report. Keep payload text out of `case_id` and `note`. The synthetic
suite ships a `PAYLOAD_MARKER` and the gate asserts it never appears in any
serialized report — keep that guarantee for your suite too.

---

## Running

```bash
# from the repo root, in the project venv
python -m tests.benchmarks.run --suite synthetic --profile both     # JSON report
python -m pytest tests/integration/test_benchmark_synthetic_gate.py  # the gate
```

---

## Per-suite linking notes

> **Verify first.** Before writing an adapter, confirm the suite's real
> repository, task/label schema, and **license** for the data you intend to use.
> Do **not** commit third-party fixtures whose license forbids redistribution —
> load them from an operator-supplied path and commit only a tiny synthetic or
> license-clear subset for any gated test.

### AgentDojo (reference, best-documented) — adapter shipped
- Source: `https://github.com/ethz-spylab/agentdojo`. Tasks are organized into
  **suites** (banking, slack, travel, workspace) with **user tasks** (benign) and
  **injection tasks** (attack), each naming the tool calls and the attacker goal.
- Map: each user-task tool-call → a `benign` case; each injection-task tool-call
  whose success = the injected goal → an `attack` case (`attacker_goal_index`
  pointing at the goal call). Put injected content's origin in `source_context`
  (`tool_output` / `webpage`). Pin a commit hash for reproducibility.
- **Implemented** in `suites/agentdojo.py` (`AgentDojoAdapter`), registered in
  `BUILTIN_ADAPTERS` as `agentdojo`. It imports the `agentdojo` package **lazily**
  (so CI never depends on it) and vendors **no** suite data — `pip install
  agentdojo`, then `python -m tests.benchmarks.run --suite agentdojo`.

### AgentDyn — adapter shipped (data is operator-supplied)
- *Dynamic*/multi-step, AgentDojo-derived; reuses the same `agentdojo` package
  API and adds the `shopping`/`github`/`dailylife` suites. Each step is emitted
  as an ordered `CandidateAction` in one `BenchmarkCase` with `attacker_goal_index`
  at the consummating egress step, so multi-step correlation is exercised.
- **Implemented** as `AgentDynAdapter` in `suites/agentdojo.py` (registered as
  `agentdyn`). Put the AgentDyn checkout on the path to resolve its data, e.g.
  `PYTHONPATH=/path/to/AgentDyn/src python -m tests.benchmarks.run --suite agentdyn`.
- **Confirm AgentDyn's license before redistributing any of its data**; the
  adapter loads it from your supplied path and vendors nothing here.

### AgentSentry
- **Confirm the exact project name, schema, and license first** (not yet
  verified here). Map its attack/benign labels onto `BenchmarkCase.label` and its
  tool-calls onto `CandidateAction` exactly as above.

If a named suite turns out not to exist under that name or its license is
incompatible, **stop and report** rather than inventing a mapping.
