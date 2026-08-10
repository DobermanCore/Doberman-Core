"""Load the small, deterministic labelled benchmark corpus.

The corpus format deliberately keeps the payload separate from the structural
fields used in reports.  ``CorpusAdapter`` is the only place that turns a row
into a benchmark action, so adding a row never requires changing the runner.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from doberman.models import ActionType, SourceContext, Verdict

from .adapter import BenchmarkCase, CandidateAction

DEFAULT_CORPUS_PATH = Path(__file__).parents[1] / "corpus" / "benchmark.jsonl"
_KINDS = frozenset({"injection", "exfiltration", "secrets", "benign"})
_REQUIRED_KEYS = frozenset(
    {
        "id",
        "kind",
        "surfaces",
        "payload",
        "is_attack",
        "expected_verdict_at_least",
        "forbidden_verdict_at_least",
        "notes",
    }
)
_VERDICT_ORDER = {Verdict.PASS: 0, Verdict.AUTH: 1, Verdict.BLOCK: 2}


@dataclass(frozen=True)
class CorpusRow:
    """One schema-validated, redaction-aware corpus record."""

    case_id: str
    kind: str
    surfaces: tuple[str, ...]
    payload: str
    is_attack: bool
    expected_verdict_at_least: Verdict
    forbidden_verdict_at_least: Verdict | None
    notes: str

    @property
    def category(self) -> str:
        """Return the attack family used for per-category metrics."""

        if self.is_attack:
            return self.kind
        return next(
            (
                surface
                for surface in self.surfaces
                if surface in {"injection", "exfiltration", "secrets"}
            ),
            "benign",
        )

    @classmethod
    def from_mapping(cls, raw: Any, *, line_number: int) -> CorpusRow:
        if not isinstance(raw, dict):
            raise TypeError(f"line {line_number}: row must be an object")
        missing = _REQUIRED_KEYS - raw.keys()
        extra = raw.keys() - _REQUIRED_KEYS
        if missing or extra:
            raise ValueError(
                f"line {line_number}: schema keys mismatch; missing={sorted(missing)}, "
                f"extra={sorted(extra)}"
            )
        case_id = raw["id"]
        kind = raw["kind"]
        surfaces = raw["surfaces"]
        payload = raw["payload"]
        is_attack = raw["is_attack"]
        notes = raw["notes"]
        if not isinstance(case_id, str) or not case_id.strip():
            raise ValueError(f"line {line_number}: id must be a non-empty string")
        if not isinstance(kind, str) or kind not in _KINDS:
            raise ValueError(f"line {line_number}: kind must be one of {sorted(_KINDS)}")
        if (
            not isinstance(surfaces, list)
            or not surfaces
            or not all(isinstance(surface, str) and surface for surface in surfaces)
        ):
            raise ValueError(f"line {line_number}: surfaces must be a non-empty string list")
        if not isinstance(payload, str) or not payload:
            raise ValueError(f"line {line_number}: payload must be a non-empty string")
        if not isinstance(is_attack, bool) or is_attack != (kind != "benign"):
            raise ValueError(f"line {line_number}: is_attack does not match kind")
        if not isinstance(notes, str) or not notes:
            raise ValueError(f"line {line_number}: notes must be a non-empty string")
        try:
            expected = Verdict(raw["expected_verdict_at_least"])
        except (TypeError, ValueError) as exc:
            raise ValueError(f"line {line_number}: invalid expected verdict") from exc
        forbidden_raw = raw["forbidden_verdict_at_least"]
        if forbidden_raw is None:
            forbidden = None
        else:
            try:
                forbidden = Verdict(forbidden_raw)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"line {line_number}: invalid forbidden verdict") from exc
        if is_attack and _VERDICT_ORDER[expected] < _VERDICT_ORDER[Verdict.AUTH]:
            raise ValueError(f"line {line_number}: attack rows must expect AUTH or BLOCK")
        if not is_attack and forbidden is None:
            raise ValueError(f"line {line_number}: benign rows need a false-positive guard")
        if not is_attack and _VERDICT_ORDER[expected] >= _VERDICT_ORDER[Verdict.AUTH]:
            raise ValueError(f"line {line_number}: benign rows must expect PASS")
        return cls(
            case_id=case_id,
            kind=kind,
            surfaces=tuple(surfaces),
            payload=payload,
            is_attack=is_attack,
            expected_verdict_at_least=expected,
            forbidden_verdict_at_least=forbidden,
            notes=notes,
        )


def load_corpus(path: Path = DEFAULT_CORPUS_PATH) -> tuple[CorpusRow, ...]:
    """Read and validate a UTF-8 JSONL corpus in deterministic file order."""

    rows: list[CorpusRow] = []
    seen: set[str] = set()
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"line {line_number}: invalid JSON") from exc
        row = CorpusRow.from_mapping(raw, line_number=line_number)
        if row.case_id in seen:
            raise ValueError(f"line {line_number}: duplicate id {row.case_id!r}")
        seen.add(row.case_id)
        rows.append(row)
    if not rows:
        raise ValueError(f"corpus is empty: {path}")
    return tuple(rows)


def _action_for(row: CorpusRow) -> CandidateAction:
    source = SourceContext.tool_output if row.is_attack else SourceContext.user
    if row.kind == "exfiltration":
        return CandidateAction(
            action_type=ActionType.network_request,
            tool_name="http_post",
            external_destination="198.51.100.7",
            source_context=source,
            mode="strict",
            raw_arguments={"body": row.payload},
        )
    if row.kind == "secrets":
        return CandidateAction(
            action_type=ActionType.file_read,
            tool_name="read_file",
            target=".env",
            source_context=source,
            raw_arguments={"content": row.payload},
        )
    if row.kind == "injection":
        return CandidateAction(
            action_type=ActionType.shell_exec,
            tool_name="shell",
            target="workspace/README.md",
            source_context=source,
            raw_arguments={"command": row.payload},
        )
    if "network" in row.surfaces:
        return CandidateAction(
            action_type=ActionType.network_request,
            tool_name="http_get",
            external_destination="github.com",
            source_context=source,
            raw_arguments={"note": row.payload},
        )
    return CandidateAction(
        action_type=ActionType.file_read,
        tool_name="read_file",
        target="workspace/README.md",
        source_context=source,
        raw_arguments={"note": row.payload},
    )


class CorpusAdapter:
    """Benchmark adapter backed by the labelled JSONL corpus."""

    suite_name = "corpus"

    def __init__(self, path: Path = DEFAULT_CORPUS_PATH) -> None:
        self._rows = load_corpus(path)

    @property
    def rows(self) -> tuple[CorpusRow, ...]:
        return self._rows

    def load(self) -> tuple[BenchmarkCase, ...]:
        return tuple(
            BenchmarkCase(
                case_id=row.case_id,
                label="attack" if row.is_attack else "benign",
                actions=(_action_for(row),),
                note=row.category,
            )
            for row in self._rows
        )
