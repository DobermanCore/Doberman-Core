"""C8 — the labeled detection corpus + its adapter (issue #241).

A flat, hand-editable **JSONL** corpus of labeled candidate actions that
measures *detection quality* — false-positive rate (the driver of approval
fatigue) and true-positive rate per category — where the rest of the harness
only proves the *harness* is wired correctly against a narrow synthetic suite.

Each row is one line of JSON (schema in :class:`CorpusRow`). The corpus is
**data, not code**: adding a labeled row is a one-line append that needs no
harness change (issue #241's acceptance bar). ``tests/corpus/_generate.py``
(re)builds and *calibrates* the shipped file against the live engine.

Two ways to consume it:

* :class:`CorpusAdapter` yields ``BenchmarkCase``s so the existing
  ``runner``/``metrics`` produce the same aggregate ASR/FPR + redaction
  guarantee as any other suite (it registers as the ``corpus`` suite).
* :func:`evaluate_corpus` keeps the per-row link (row → verdict) that the
  category metrics and the per-row **verdict-floor / forbidden-verdict**
  assertions need — the part the aggregate path can't express.

REDACTION: a row's ``payload`` MAY hold attack text (that is the point of a
detection corpus), so — exactly like ``suites/synthetic.py``'s ``PAYLOAD_MARKER``
and the red-team generator's ``text`` field — it rides only in
``raw_arguments`` and NEVER enters a report. ``id``/``kind``/``notes`` are
class-level labels and must stay payload-free.
"""

from __future__ import annotations

import json
import pathlib
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from doberman.models import ActionType, SourceContext, Verdict

from ..adapter import BenchmarkCase, CandidateAction

#: The shipped, calibrated corpus. Regenerate with ``tests/corpus/_generate.py``.
DEFAULT_CORPUS_PATH = (
    pathlib.Path(__file__).resolve().parents[2] / "corpus" / "detection_corpus.jsonl"
)

#: PASS < AUTH < BLOCK — the raise-only verdict lattice the floors compare against.
_VERDICT_RANK: dict[Verdict, int] = {Verdict.PASS: 0, Verdict.AUTH: 1, Verdict.BLOCK: 2}

#: Categories a row may carry (``kind``). ``benign`` is the FPR bucket; the rest
#: are attack buckets whose detection rate is the TPR.
KINDS = frozenset({"injection", "exfiltration", "secrets", "destructive", "encoded", "benign"})

#: Keys the built-in rules read a payload from (``commands`` reads ``command``;
#: ``secrets``/``token_channels`` scan every string). Shell/git payloads must land
#: on ``command`` to reach the destructive-command rule; everything else on a
#: generic key that the string-scanning rules still see.
_COMMAND_ACTIONS = frozenset({ActionType.shell_exec, ActionType.git_op})


def _payload_key(action_type: ActionType) -> str:
    return "command" if action_type in _COMMAND_ACTIONS else "content"


@dataclass(frozen=True)
class CorpusRow:
    """One labeled corpus row (issue #241's schema).

    Fields
    ------
    id:          unique, payload-free identifier (appears in reports).
    kind:        category label — one of :data:`KINDS`.
    surfaces:    the structural action fields (``action_type`` required; plus
                 ``tool_name``/``target``/``external_destination``/
                 ``source_context``/``agent_role``/``mode``) — what the action
                 touches. Never holds payload text.
    payload:     the attack/benign *content* string, or ``None``. Rides only in
                 ``raw_arguments`` (redaction).
    is_attack:   ground-truth label. ``True`` ⇒ attack bucket (TPR),
                 ``False`` ⇒ benign bucket (FPR).
    expected_verdict_at_least:
                 an attack row's **measured floor** — the verdict the engine
                 must reach *or exceed* (raise-only regression fence). ``None``
                 for a documented gap (an attack the deterministic layer does
                 not catch today) or for a benign row.
    forbidden_verdict_at_least:
                 a benign row's **false-positive guard** — the verdict it must
                 never reach (typically ``AUTH``: a legitimate action must stay
                 ``PASS``). ``None`` for an attack row.
    notes:       redaction-safe, class-level note (gap rationale, technique).
    """

    id: str
    kind: str
    surfaces: dict[str, Any]
    is_attack: bool
    payload: str | None = None
    expected_verdict_at_least: Verdict | None = None
    forbidden_verdict_at_least: Verdict | None = None
    notes: str = ""

    def to_candidate_action(self) -> CandidateAction:
        """Map ``surfaces`` + ``payload`` onto the harness's suite-neutral action."""
        s = self.surfaces
        action_type = ActionType(s["action_type"])
        raw_arguments: dict[str, Any] = {}
        if self.payload is not None:
            raw_arguments[_payload_key(action_type)] = self.payload
        return CandidateAction(
            action_type=action_type,
            tool_name=str(s.get("tool_name", "tool")),
            target=s.get("target"),
            external_destination=s.get("external_destination"),
            source_context=SourceContext(s.get("source_context", "unknown")),
            agent_role=str(s.get("agent_role", "unknown")),
            mode=str(s.get("mode", "balanced")),
            raw_arguments=raw_arguments,
        )


def _parse_verdict(value: Any, field: str, row_id: str) -> Verdict | None:
    if value is None:
        return None
    try:
        return Verdict(value)
    except ValueError as exc:  # noqa: TRY003 — precise message beats a generic one
        raise ValueError(f"row {row_id!r}: {field} {value!r} is not a valid Verdict") from exc


def _row_from_json(obj: dict[str, Any]) -> CorpusRow:
    """Validate one parsed JSON object into a :class:`CorpusRow` (raises on bad schema)."""
    row_id = obj.get("id")
    if not isinstance(row_id, str) or not row_id:
        raise ValueError(f"corpus row missing a string 'id': {obj!r:.80}")
    kind = obj.get("kind")
    if kind not in KINDS:
        raise ValueError(f"row {row_id!r}: kind {kind!r} not in {sorted(KINDS)}")
    surfaces = obj.get("surfaces")
    if not isinstance(surfaces, dict) or "action_type" not in surfaces:
        raise ValueError(f"row {row_id!r}: 'surfaces' must be a dict with 'action_type'")
    try:
        ActionType(surfaces["action_type"])
    except ValueError as exc:
        raise ValueError(
            f"row {row_id!r}: action_type {surfaces['action_type']!r} invalid"
        ) from exc
    is_attack = obj.get("is_attack")
    if not isinstance(is_attack, bool):
        raise ValueError(f"row {row_id!r}: 'is_attack' must be a bool")
    payload = obj.get("payload")
    if payload is not None and not isinstance(payload, str):
        raise ValueError(f"row {row_id!r}: 'payload' must be a string or null")

    expected = _parse_verdict(
        obj.get("expected_verdict_at_least"), "expected_verdict_at_least", row_id
    )
    forbidden = _parse_verdict(
        obj.get("forbidden_verdict_at_least"), "forbidden_verdict_at_least", row_id
    )

    # A benign row asserts a false-positive guard; an attack row asserts a floor
    # (or None = documented gap). Cross-checking the two keeps a mislabeled row
    # from silently landing in the wrong bucket.
    if is_attack and forbidden is not None:
        raise ValueError(
            f"row {row_id!r}: attack rows use expected_verdict_at_least, not forbidden"
        )
    if not is_attack and expected is not None:
        raise ValueError(
            f"row {row_id!r}: benign rows use forbidden_verdict_at_least, not expected"
        )
    if not is_attack and forbidden is None:
        raise ValueError(
            f"row {row_id!r}: benign row needs a forbidden_verdict_at_least (FP guard)"
        )

    return CorpusRow(
        id=row_id,
        kind=kind,
        surfaces=surfaces,
        is_attack=is_attack,
        payload=payload,
        expected_verdict_at_least=expected,
        forbidden_verdict_at_least=forbidden,
        notes=str(obj.get("notes", "")),
    )


def load_corpus(path: str | pathlib.Path = DEFAULT_CORPUS_PATH) -> list[CorpusRow]:
    """Parse + schema-validate every row of a JSONL corpus, sorted by ``id``.

    Blank lines and ``#``-comment lines are ignored. A malformed row raises
    (a corpus is a fixture — a bad row is a bug to fix, not a case to skip);
    this is stricter than ``run_suite``'s per-case isolation on purpose.
    Duplicate ids raise.
    """
    rows: list[CorpusRow] = []
    seen: set[str] = set()
    text = pathlib.Path(path).read_text(encoding="utf-8")
    for lineno, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        try:
            obj = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}:{lineno}: invalid JSON: {exc}") from exc
        row = _row_from_json(obj)
        if row.id in seen:
            raise ValueError(f"{path}:{lineno}: duplicate row id {row.id!r}")
        seen.add(row.id)
        rows.append(row)
    rows.sort(key=lambda r: r.id)
    return rows


@dataclass(frozen=True)
class RowResult:
    """One row's decided verdict, keeping the row link the aggregate path drops."""

    row: CorpusRow
    verdict: Verdict
    reason_codes: tuple[str, ...]

    @property
    def floor_ok(self) -> bool:
        """An attack row met its measured floor (raise-only fence); trivially True
        for a benign row or a documented-gap attack (``expected`` is ``None``)."""
        floor = self.row.expected_verdict_at_least
        if floor is None:
            return True
        return _VERDICT_RANK[self.verdict] >= _VERDICT_RANK[floor]

    @property
    def forbidden_ok(self) -> bool:
        """A benign row stayed below its false-positive guard; trivially True for
        an attack row (``forbidden`` is ``None``)."""
        forbidden = self.row.forbidden_verdict_at_least
        if forbidden is None:
            return True
        return _VERDICT_RANK[self.verdict] < _VERDICT_RANK[forbidden]

    @property
    def mitigated(self) -> bool:
        """Attack was stopped (AUTH or BLOCK interrupts the chain)."""
        return self.verdict is not Verdict.PASS

    @property
    def flagged(self) -> bool:
        """Any non-PASS verdict (a positive, attack or benign)."""
        return self.verdict is not Verdict.PASS


class CorpusAdapter:
    """Serve the labeled corpus as ``BenchmarkCase``s (the aggregate ASR/FPR path).

    Deterministic (rows are sorted by id in :func:`load_corpus`), needs no
    external data, so it is safe in CI and registered as the ``corpus`` suite.
    ``kind`` becomes the redaction-safe ``note``; ``payload`` rides in
    ``raw_arguments`` only.
    """

    suite_name = "corpus"

    def __init__(self, path: str | pathlib.Path = DEFAULT_CORPUS_PATH) -> None:
        self._path = path

    def load(self) -> Iterable[BenchmarkCase]:
        for row in load_corpus(self._path):
            yield BenchmarkCase(
                case_id=row.id,
                label="attack" if row.is_attack else "benign",
                note=row.kind,
                actions=(row.to_candidate_action(),),
            )


def evaluate_corpus(
    rows: Iterable[CorpusRow], pipeline: Any, *, mode: str | None = None
) -> list[RowResult]:
    """Decide each row through ``pipeline``, keeping the per-row verdict link.

    Reuses the harness's own mapping (``to_security_object``/``to_eval_context``)
    so the corpus exercises the exact production classification path. ``mode``
    overrides each row's own ``surfaces.mode`` when set.
    """
    from ..mapping import to_eval_context, to_security_object

    results: list[RowResult] = []
    for row in rows:
        action = row.to_candidate_action()
        security_object = to_security_object(f"corpus:{row.id}", action)
        ctx = to_eval_context(action)
        if mode is not None:
            ctx = ctx.model_copy(update={"mode": mode})
        decision = pipeline.decide(security_object, ctx)
        results.append(
            RowResult(
                row=row,
                verdict=decision.final_verdict,
                reason_codes=tuple(code.value for code in decision.reason_codes),
            )
        )
    return results
