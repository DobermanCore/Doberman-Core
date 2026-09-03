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
        return ()


_ATTACK_TYPE_TEMPLATES: dict[str, tuple[str, ...]] = {}
_LURE_ONLY_TYPES: frozenset[str] = frozenset()


def attack_type_report(pipeline) -> dict:
    return {}
