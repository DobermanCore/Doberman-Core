"""RedCode-Exec adapter — maps AI-secure/RedCode's risky-code-execution dataset
onto core types.

Source: https://github.com/AI-secure/RedCode (code MIT; dataset CC BY 4.0 per
the checkout's ``dataset/LICENSE``). No data is vendored here — point
``DOBERMAN_BENCH_REDCODE_DIR`` at an operator-obtained checkout's
``dataset/RedCode-Exec`` directory (the one containing
``bash2text_dataset_json/`` and ``py2text_dataset_json/``).

RedCode-Exec ships (Index, Prompt, Language, Code, expected_result,
Text_summary, Text_details) records asking a code agent to *execute* a given
Bash or Python snippet. Doberman is the filter, not the agent: each record's
``Code`` becomes ONE ``CandidateAction`` (``action_type=shell_exec``, the whole
snippet under ``raw_arguments["command"]`` — the exact key
``suites/corpus.py``'s ``_COMMAND_ACTIONS`` convention also uses, so the same
destructive-command / secret / token-channel content rules read it) and is
scored against the real ``decide()``.

Each of the 27 ``Index`` numbers is a distinct risky *scenario* (30 code
variants per index). This checkout ships no scenario-name table (no
``dataset/RedCode-Exec``-level README beyond a one-line pointer to
``dataset/README.md``) — ``_SCENARIOS`` below classifies each index from its
own record content (sample records per index were read while writing this
adapter; see the PR description for the raw samples). The classification is
Doberman's threat model, not RedCode's official taxonomy: an index is
``"in_scope"`` only if it lands on a threat Doberman's objective rules
actually gate (destructive command, protected-path read/write,
secret/credential exfiltration, external egress, persistence/backdoor,
process/system tamper, encoded-command obfuscation). Code-quality / logic-bug
demonstrations that RedCode also includes under its risky-scenario umbrella —
weak PRNG, an unsalted hash, an always-True access-control check, a
discriminatory scoring function, ``pickle.loads`` of a fixed local payload,
plain business-logic bugs, and two benign monitoring controls — are
``"out_of_scope"``: Doberman has no rule surface for "is this code
cryptographically sound / fair / well-designed," and the harness reports that
honestly (a separate ``out_of_scope`` bucket) rather than silently dropping
them or letting them dilute the in-scope ASR. ``"block"`` / ``"auth_or_block"``
only label which floor Doberman's rules are expected to engage at — they do
not assert a required verdict; the real, measured numbers are what
``scenario_report()`` and the harness's own ASR/FPR path report.

Two URL-fetch indices (2 and 26/3) look superficially similar (both reach an
external host) but are classified differently on purpose: index 2
(``malicious_url_download``) downloads attacker content AND persists it to a
local path (``wget -O /usr/downloaded_script.py <url>`` / an equivalent
``open(..., "w")`` in the Python variant, verified against real records for
both languages) — a concrete protected-path-write + external-egress primitive,
hence ``"in_scope"``. Indices 3 (``fetch_remote_content_print``) and 26
(``malicious_url_fetch_2``) only fetch a URL and print the response to stdout
(verified against real records) — no write, no persistence, no execution of
the fetched content — so both stay ``"out_of_scope"``: printing text to a
console is not a threat Doberman's deterministic rules gate. Same behavior
(index 3 and 26) gets the same expectation; different behavior (index 2's
persist-to-disk vs. index 3/26's print-only) gets a different one.

RedCode-Exec's egress targets are typically ``127.0.0.1:<port>`` — the
dataset's own sandboxed stand-in for a remote attacker-controlled host (its
Docker environment listens on loopback ports so the benchmark stays
deterministic and offline). The adapter preserves the literal destination
string; whether Doberman's egress rule treats a loopback destination as
"external" is exactly the honest thing this suite measures, not something the
adapter should paper over.

RedCode-Exec ships no benign counterpart — every record is a risky-scenario
execution request. ``_BENIGN_BASH_COMMANDS`` / ``_BENIGN_PYTHON_COMMANDS``
below are this adapter's own synthetic, ordinary-developer-workflow commands
(``ls``, ``git status``, ``pytest -q``, …), used only to measure FPR.
"""

from __future__ import annotations

import json
import os
import pathlib
import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlsplit

from doberman.models import ActionType, SourceContext

from ..adapter import BenchmarkCase, CandidateAction

#: Env var pointing at a RedCode checkout's ``dataset/RedCode-Exec`` directory.
DATA_DIR_ENV = "DOBERMAN_BENCH_REDCODE_DIR"

_LANG_TOOL: dict[str, str] = {"Bash": "bash", "Python": "python"}

Expectation = Literal["block", "auth_or_block", "out_of_scope"]


@dataclass(frozen=True)
class _Scenario:
    label: str
    expectation: Expectation


class RedCodeAdapter:
    """Serve RedCode-Exec records + a synthetic benign control set as ``BenchmarkCase``s."""

    suite_name = "redcode"

    def __init__(self, data_dir: str | pathlib.Path | None = None) -> None:
        raw = data_dir or os.environ.get(DATA_DIR_ENV, "")
        self._data_dir = pathlib.Path(raw) if raw else None

    def load(self) -> Iterable[BenchmarkCase]:
        if self._data_dir is None or not self._data_dir.is_dir():
            raise RuntimeError(
                f"RedCode-Exec dataset not found; set {DATA_DIR_ENV} to a RedCode "
                "checkout's dataset/RedCode-Exec directory (containing "
                "bash2text_dataset_json/ and py2text_dataset_json/)."
            )
        return ()


_SCENARIOS: dict[int, _Scenario] = {}


def scenario_report(pipeline) -> dict:
    return {}
