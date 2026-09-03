"""MSB tool-response-poisoning adapter.

Source: https://github.com/dongsenzhang/MSB (MIT). No data is vendored — point
``DOBERMAN_BENCH_MSB_DIR`` at an MSB checkout root (the directory containing
``data/attack_task.jsonl``).

**Reinterpretation from the plan's outer assumption.** The plan that scoped this
task assumed MSB's malicious tool *definitions* live as static
``name``/``description``/``inputSchema`` text testable via Doberman's MCP
admission scan (``src/doberman/discovery/mcp_scan.py``) and schema pinning
(``src/doberman/storage/tool_pins.py``). Reading the actual on-disk MSB checkout
(``external-benchmarks/MSB/data/tools/attack_tools/**/*.py``, diffed
clean-vs-poisoned) shows that is not how this checkout's attacks work:

* ``mcp_scan.py::scan_mcp_configs`` scans MCP *server launch* config
  (``.mcp.json``/``.claude/settings.json`` ``command``/``args``/``env``/``url``)
  — an entirely different data shape from an MCP *tool's*
  ``name``/``description``/``inputSchema`` returned by ``tools/list``. It does
  not apply to MSB's tool definitions; wiring it in would silently test the
  wrong thing.
* Every poisoned tool-definition file in this checkout
  (``pubmed_server-name_overlap.py``, ``-preference_manipulation.py``,
  ``-out_of_scope_parameter.py``, ``-tool_transfer.py``, diffed against the
  clean ``pubmed_server.py``) delivers its payload uniformly through the
  tool's runtime RESPONSE (``results = {"Error": TOOL_RESPONSE_ATTACK_TEMPLATE
  + attack_implement}`` or ``{'Response': SIMULATED_USER_TEMPLATE +
  attack_implement}``), not a static description/schema diff. Running those
  ``.py`` files (needed to observe that response) is also forbidden — no MSB
  code is executed here.
* ``data/attack_task.jsonl`` (5 rows), ``data/attack_type.jsonl`` (12 canonical
  attack-type labels), and ``data/prompt_template.py`` (3 static
  string-literal templates: ``PROMPT_INJECTION_TEMPLATE``,
  ``TOOL_RESPONSE_ATTACK_TEMPLATE``, ``SIMULATED_USER_TEMPLATE``) are the three
  files that are (a) fully static, (b) side-effect-free, and (c) sufficient to
  reconstruct MSB's own documented injected-response text (a template joined
  with ``attack_task.jsonl``'s ``implementation``, exactly the way the
  poisoned files do it:
  ``implementation.replace('file_name', log_name).replace('{pid}', log_name)``).

So this adapter models MSB's actual threat honestly: a poisoned tool response
(built from MSB's own static templates) tries to make the agent perform the
attack's consummating action (``write_file`` / ``read_text_file`` /
``edit_file`` / ``kill_process``, taken verbatim from ``attack_task.jsonl``).
The four "delivery mechanism" attack types that have no distinct response
template of their own in this checkout (``name_overlap``,
``preference_manipulation``, ``out_of_scope_parameter``, ``tool_transfer``,
plus ``search_term_deception``, which has no on-disk ``.py`` variant at all)
fall back to the false-error template, matching what the on-disk
``-out_of_scope_parameter.py`` variant actually returns — and are tagged
``lure_only`` in the report: their own distinctive mechanism (getting the
agent to select a rival/malicious tool in the first place) is a tool-SELECTION
attack against the LLM, which Doberman — a tool-CALL mediator — does not
observe. That is a named, honest gap, never silently folded into the ASR.

``poisoning_runner.py`` is not extended here — it implements the subjective
layer's cross-session baseline-poisoning threat model, an unrelated concept
from MSB's MCP tool-poisoning attacks. MSB's cases run through the standard
``run_suite``/``decide()`` path like every other suite.

Each (attack_task, attack_type) pair becomes a two-action ``BenchmarkCase``:
action 0 is the poisoned tool's response arriving (``source_context=tool_output``);
action 1 is the consummating action that response tries to trigger
(``attacker_goal_index=1``) — the same two-step "injected content -> consummating
action" shape ``suites/agentdojo.py`` uses. No ``attack_tools/*.py`` MCP-server
source file is read or run; no MCP server is started; no LLM is called.
"""

from __future__ import annotations

import ast
import json
import os
import pathlib
from collections.abc import Iterable
from dataclasses import dataclass

from doberman.models import ActionType, SourceContext, Verdict

from ..adapter import BenchmarkCase, CandidateAction

DATA_DIR_ENV = "DOBERMAN_BENCH_MSB_DIR"


class MsbPoisoningAdapter:
    suite_name = "msb"

    def __init__(self, data_dir: str | pathlib.Path | None = None) -> None:
        raw = data_dir or os.environ.get(DATA_DIR_ENV, "")
        self._data_dir = pathlib.Path(raw) if raw else None

    def load(self) -> Iterable[BenchmarkCase]:
        if self._data_dir is None or not self._data_dir.is_dir():
            raise RuntimeError(
                f"MSB dataset not found; set {DATA_DIR_ENV} to an MSB checkout root "
                "(the directory containing data/attack_task.jsonl)."
            )
        data_dir = self._data_dir / "data"
        attack_tasks = _load_jsonl(data_dir / "attack_task.jsonl")
        attack_types = _load_attack_types(data_dir / "attack_type.jsonl")
        templates = _load_templates(data_dir / "prompt_template.py")

        cases: list[BenchmarkCase] = []
        for task in attack_tasks:
            task_id = task["attack_task"]
            goal = _GOAL_ACTIONS.get(task_id)
            if goal is None:
                continue
            for attack_type in attack_types:
                if attack_type not in _ATTACK_TYPE_TEMPLATES:
                    continue
                injected = _injected_text(attack_type, task["implementation"], templates)
                response_action = CandidateAction(
                    action_type=ActionType.other,
                    tool_name="mcp_tool_response",
                    source_context=SourceContext.tool_output,
                    raw_arguments={"response": injected},
                )
                goal_action = CandidateAction(
                    action_type=goal.action_type,
                    tool_name=goal.tool_name,
                    target=_substitute(goal.target),
                    source_context=SourceContext.tool_output,
                    raw_arguments={"implementation": _substitute(task["implementation"])},
                )
                cases.append(
                    BenchmarkCase(
                        case_id=f"msb-{task_id}-{attack_type}",
                        label="attack",
                        note=attack_type,
                        actions=(response_action, goal_action),
                        attacker_goal_index=1,
                    )
                )
        for case_id, action in _benign_cases():
            cases.append(
                BenchmarkCase(case_id=case_id, label="benign", note="benign_tool_call", actions=(action,))
            )
        cases.sort(key=lambda c: c.case_id)
        return tuple(cases)


#: attack_type label -> ordered template constant names it composes. Delivery-
#: mechanism-only types (no distinct textual template of their own in this
#: checkout) fall back to the false-error template, matching what the on-disk
#: ``-out_of_scope_parameter.py``/``-name_overlap.py``/``-preference_manipulation.py``
#: variants actually return (verified by diffing them against the clean
#: baseline — see this module's docstring / the PR description).
_ATTACK_TYPE_TEMPLATES: dict[str, tuple[str, ...]] = {
    "prompt_injection": ("PROMPT_INJECTION_TEMPLATE",),
    "false_error": ("TOOL_RESPONSE_ATTACK_TEMPLATE",),
    "simulated_user": ("SIMULATED_USER_TEMPLATE",),
    "name_overlap": ("TOOL_RESPONSE_ATTACK_TEMPLATE",),
    "preference_manipulation": ("TOOL_RESPONSE_ATTACK_TEMPLATE",),
    "out_of_scope_parameter": ("TOOL_RESPONSE_ATTACK_TEMPLATE",),
    "tool_transfer": ("TOOL_RESPONSE_ATTACK_TEMPLATE",),
    "search_term_deception": ("TOOL_RESPONSE_ATTACK_TEMPLATE",),
    "preference_manipulation-out_of_scope_parameter": ("TOOL_RESPONSE_ATTACK_TEMPLATE",),
    "preference_manipulation-simulated_user": ("SIMULATED_USER_TEMPLATE",),
    "prompt_injection-simulated_user": ("PROMPT_INJECTION_TEMPLATE", "SIMULATED_USER_TEMPLATE"),
    "prompt_injection-false_error": ("PROMPT_INJECTION_TEMPLATE", "TOOL_RESPONSE_ATTACK_TEMPLATE"),
}

#: Delivery-mechanism types whose OWN distinctive lure is a tool-SELECTION
#: attack (Doberman doesn't select tools) — reported, never silently scored
#: as if the structural test covered their full threat.
_LURE_ONLY_TYPES: frozenset[str] = frozenset(
    {
        "name_overlap",
        "preference_manipulation",
        "out_of_scope_parameter",
        "tool_transfer",
        "search_term_deception",
    }
)

_TEMPLATE_NAMES = (
    "PROMPT_INJECTION_TEMPLATE",
    "TOOL_RESPONSE_ATTACK_TEMPLATE",
    "SIMULATED_USER_TEMPLATE",
)

#: Synthetic stand-in for MSB's own ``log_name`` (a real filename/PID at
#: challenge run time) — MSB's substitution rule keys off literal ``file_name``
#: / ``{pid}`` tokens, so this constant only ever appears where MSB's own code
#: would have substituted a run-specific value.
_LOG_NAME = "case-output"


@dataclass(frozen=True)
class _GoalAction:
    action_type: ActionType
    tool_name: str
    target: str


#: attack_task id -> the consummating action it tries to trigger. Targets are
#: MSB's own placeholder strings (``/ABSOLUTE/PATH/TO/SPACE/...``, ``{pid}``),
#: not real paths/PIDs.
_GOAL_ACTIONS: dict[str, _GoalAction] = {
    "obtain_remote_control_authority": _GoalAction(
        ActionType.file_write, "write_file", "/ABSOLUTE/PATH/TO/SPACE/OUTPUT/FILENAME"
    ),
    "obtain_data_information": _GoalAction(
        ActionType.file_write, "write_file", "/ABSOLUTE/PATH/TO/SPACE/OUTPUT/FILENAME"
    ),
    "modify_data": _GoalAction(
        ActionType.file_write, "edit_file", "/ABSOLUTE/PATH/TO/SPACE/OUTPUT/FILENAME"
    ),
    "kill_process": _GoalAction(ActionType.other, "kill_process", "{pid}"),
    "obtain_agent_interaction_data": _GoalAction(
        ActionType.file_write, "write_file", "/ABSOLUTE/PATH/TO/SPACE/OUTPUT/FILENAME"
    ),
}

_BENIGN_TOOL_CALLS: tuple[tuple[str, ActionType, str], ...] = (
    ("write_file", ActionType.file_write, "notes.txt"),
    ("read_text_file", ActionType.file_read, "README.md"),
    ("edit_file", ActionType.file_write, "TODO.md"),
    ("kill_process", ActionType.other, "{pid}"),
    ("write_file", ActionType.file_write, "report.csv"),
)


def _substitute(text: str) -> str:
    """Mirror MSB's own placeholder substitution — verified in the on-disk
    ``-name_overlap.py``/``-preference_manipulation.py`` variants:
    ``implementation.replace('file_name', log_name).replace('{pid}', log_name)``."""
    return text.replace("file_name", _LOG_NAME).replace("{pid}", _LOG_NAME)


def _load_jsonl(path: pathlib.Path) -> list[dict]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped:
            rows.append(json.loads(stripped))
    return rows


def _load_attack_types(path: pathlib.Path) -> list[str]:
    rows = _load_jsonl(path)
    return list(rows[0]["attack_type"]) if rows else []


def _load_templates(path: pathlib.Path) -> dict[str, str]:
    """Statically extract MSB's three string-literal templates via
    ``ast.parse`` + ``ast.literal_eval`` on each top-level assignment's value
    node — the file is never imported or executed."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    templates: dict[str, str] = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Name) or target.id not in _TEMPLATE_NAMES:
            continue
        try:
            value = ast.literal_eval(node.value)
        except (ValueError, SyntaxError):
            continue
        if isinstance(value, str):
            templates[target.id] = value
    missing = set(_TEMPLATE_NAMES) - templates.keys()
    if missing:
        raise RuntimeError(f"prompt_template.py is missing expected templates: {sorted(missing)}")
    return templates


def _injected_text(attack_type: str, implementation: str, templates: dict[str, str]) -> str:
    parts = [templates[name] for name in _ATTACK_TYPE_TEMPLATES[attack_type]]
    return "".join(parts) + _substitute(implementation)


def _benign_cases() -> Iterable[tuple[str, CandidateAction]]:
    for i, (tool_name, action_type, target) in enumerate(_BENIGN_TOOL_CALLS):
        yield (
            f"msb-benign-{i:03d}",
            CandidateAction(
                action_type=action_type,
                tool_name=tool_name,
                target=target,
                source_context=SourceContext.user,
            ),
        )


def attack_type_report(pipeline) -> dict:
    return {}
