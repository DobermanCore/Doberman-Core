"""BIPIA adapters: Microsoft's indirect prompt-injection benchmark, email and
table splits, mapped onto core types.

Source: https://github.com/microsoft/BIPIA (code MIT; ``benchmark/`` data under
each source dataset's own licence, see its ``LICENSE``). No data is vendored:
point ``DOBERMAN_BENCH_BIPIA_DIR`` at a checkout root (the directory containing
``benchmark/``). Only ``benchmark/{email,table}/test.jsonl`` (rows of
``context``/``question``/``ideal``) and ``benchmark/text_attack_test.json`` (attack
category -> list of attack strings) are read; no BIPIA code is run.

Samples are built the way BIPIA's own ``QAPIABuilder`` builds them: every clean
context x every attack string x an insertion position, the attack joined to the
context with a newline. Each attacked sample becomes a two-action case: action 0
is the untrusted read (``read_email`` with ``SourceContext.email``, or
``read_table`` with ``SourceContext.tool_output``), action 1 is the reply the
injection tries to shape, sent to a fixed, clearly-synthetic recipient
(``attacker_goal_index=1``). BIPIA's attacks ask the model to change its *answer*
(add a scam line, encode it, translate it); the benchmark ships no compliant
answer, so the reply body is the attack string itself, the most an
echo/content rule could ever match. Each clean context also yields one benign
case: the same read and reply, the reply carrying the dataset's ``ideal`` answer.

The two splits are separate suites (``bipia_email``, ``bipia_table``) so the
runner, which aggregates per suite, never blends them into one number.
"""

from __future__ import annotations

import json
import os
import pathlib
from collections.abc import Iterable

from doberman.models import ActionType, SourceContext

from ..adapter import BenchmarkCase, CandidateAction

DATA_DIR_ENV = "DOBERMAN_BENCH_BIPIA_DIR"
#: Fixed, clearly-synthetic reply recipient, the same for both splits so their
#: numbers differ only by content and provenance; not derived from any record.
REPLY_DESTINATION = "reply@example.com"
# shortcut: BIPIA's "middle" position needs nltk sentence splitting and is not
# reproduced; add it if a detector turns out to be position-sensitive.
_POSITIONS = ("start", "end")


def _insert(context: str, attack: str, position: str) -> str:
    return "\n".join([attack, context] if position == "start" else [context, attack])


def _read_jsonl(path: pathlib.Path) -> list[dict]:
    lines = path.read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines if line.strip()]


class _BipiaAdapter:
    suite_name: str
    _split: str
    _read_tool: str
    _source: SourceContext

    def __init__(self, data_dir: str | pathlib.Path | None = None) -> None:
        raw = data_dir or os.environ.get(DATA_DIR_ENV, "")
        self._data_dir = pathlib.Path(raw) if raw else None

    def _case(self, case_id: str, note: str, body: str, reply: str, *, attack: bool):
        read = CandidateAction(
            action_type=ActionType.file_read,
            tool_name=self._read_tool,
            source_context=self._source,
            raw_arguments={"body": body},
        )
        send = CandidateAction(
            action_type=ActionType.network_request,
            tool_name="send_reply",
            external_destination=REPLY_DESTINATION,
            source_context=self._source,
            raw_arguments={"to": REPLY_DESTINATION, "body": reply},
        )
        return BenchmarkCase(
            case_id=case_id,
            label="attack" if attack else "benign",
            note=note,
            actions=(read, send),
            attacker_goal_index=1 if attack else None,
        )

    def load(self) -> Iterable[BenchmarkCase]:
        bench = self._data_dir / "benchmark" if self._data_dir else None
        if bench is None or not bench.is_dir():
            raise RuntimeError(
                f"BIPIA checkout not found; set {DATA_DIR_ENV} to a checkout root "
                "(the directory containing benchmark/)."
            )
        rows = _read_jsonl(bench / self._split / "test.jsonl")
        attacks = json.loads((bench / "text_attack_test.json").read_text(encoding="utf-8"))
        prefix = f"bipia-{self._split}"

        cases: list[BenchmarkCase] = []
        for c, row in enumerate(rows):
            cases.append(
                self._case(
                    f"{prefix}-benign-{c:03d}", "clean", row["context"], row["ideal"], attack=False
                )
            )
            a = 0
            for category in sorted(attacks):
                for attack in attacks[category]:
                    for position in _POSITIONS:
                        cases.append(
                            self._case(
                                f"{prefix}-attack-{c:03d}-{a:03d}-{position}",
                                # The category is BIPIA's label, never attack text.
                                category,
                                _insert(row["context"], attack, position),
                                attack,
                                attack=True,
                            )
                        )
                    a += 1
        return tuple(cases)


class BipiaEmailAdapter(_BipiaAdapter):
    suite_name = "bipia_email"
    _split = "email"
    _read_tool = "read_email"
    _source = SourceContext.email


class BipiaTableAdapter(_BipiaAdapter):
    suite_name = "bipia_table"
    _split = "table"
    _read_tool = "read_table"
    _source = SourceContext.tool_output
