"""Operator-supplied allowed-action trace seeding for the per-entity streaming baseline (#326).

``doberman memory seed --from <file>`` warms one deployment's per-entity baseline (see
:mod:`doberman.subjective.baseline`) from a documented JSONL trace file, through the SAME
:func:`~doberman.subjective.baseline.observe` path the live proxy calls — seeding and live
warming can never diverge because there is only the one learning path. See
``docs/BASELINE_SEEDING.md`` for the trace format and a worked example.

Four hard invariants (issue #326):

* **Allowed-only.** A trace whose verdict is not ``PASS``/``allowed: true`` is refused, and a
  malformed trace is refused too — the WHOLE FILE, not just the bad row (a partially seeded
  baseline is unauditable: the operator can't tell which rows landed). Every line is parsed and
  validated before any row is observed.
* **Raise-only.** Seeding only calls :func:`~doberman.subjective.baseline.observe`; it never
  writes ``policies.yaml``, the mode, or a ``policy_changes`` row — it can only warm the
  cold-start surprise baseline, never move a verdict or a floor.
* **Redaction.** The summary carries an entity-id prefix, counts, and booleans only — never a
  trace's ``target``/``external_destination`` value or any other row content. Row content only
  ever reaches :func:`~doberman.subjective.baseline.observe`, which stores classes and keyed
  fingerprints (see that module's own redaction discipline).
* **Deterministic + local.** No network. The only clock read is the injected ``now`` (default:
  current UTC at call time), and every row in one run shares that single stamp.

This module is policy core: it may import ``doberman.storage``/``doberman.subjective`` but must
never import ``doberman.proxy`` (enforced by the ``lint-imports`` contract).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from pydantic import ValidationError

from doberman.models import ActionType, Algebra, Reversibility, SecurityObject
from doberman.subjective.baseline import entity_id, observe, total_observations
from doberman.subjective.drift import K_OBSERVATIONS
from doberman.subjective.infer import infer_algebra

#: Top-level JSONL row keys the seeder understands. Anything else is a typo, not a feature —
#: reject the row rather than silently ignore it (issue #326's "any other key" rule).
_REQUIRED_KEYS = frozenset({"agent_role", "action_type", "tool_name"})
_VERDICT_KEYS = frozenset({"verdict", "allowed"})
_OPTIONAL_KEYS = frozenset(
    {"target", "external_destination", "reversibility", "target_count", "algebra"}
)
_ALLOWED_KEYS = _REQUIRED_KEYS | _VERDICT_KEYS | _OPTIONAL_KEYS

#: ``Algebra`` fields an operator may set explicitly; any other key in the ``algebra`` object is
#: a typo, same discipline as the row itself (pydantic ignores unknown fields by default, which
#: would otherwise let a misspelled dimension silently fall back to its conservative default).
_ALGEBRA_KEYS = frozenset(
    {
        "capability",
        "target_class",
        "destination_class",
        "blast_radius",
        "provenance",
        "classification_confidence",
    }
)

# The HST (see baseline.py's SL4.2 section) is process-lifetime only — never rehydrated from the
# DB — so a `doberman memory seed` run (a short-lived CLI process) cannot durably warm it; the
# next real proxy process starts its HST cold regardless of what this command did. Reporting a
# live learn count here would tell the operator a number that is discarded at process exit.
# ponytail: no persistence branch, always this literal — building HST persistence is explicitly
# out of scope for this slice.
HST_STATUS = "in-process"


@dataclass(frozen=True)
class Trace:
    """One validated, allowed-action row, ready to replay through ``observe()``."""

    line_no: int
    agent_role: str
    action_type: ActionType
    tool_name: str
    target: str | None = None
    external_destination: str | None = None
    reversibility: Reversibility = Reversibility.medium
    target_count: int | None = None
    algebra: Algebra | None = None  # None => infer_algebra() at replay time


@dataclass(frozen=True)
class TraceError:
    """A row that failed validation. Carries the line number only, never its content."""

    line_no: int
    reason: str


class TraceValidationError(ValueError):
    """Raised by :func:`parse_traces` when any row in the file is invalid.

    Whole-file fail-closed (issue #326): the caller must refuse the entire file, never replay
    the rows that did parse. ``errors`` is every bad line, in file order — never row content.
    """

    def __init__(self, errors: list[TraceError]) -> None:
        super().__init__(f"{len(errors)} invalid trace row(s)")
        self.errors = errors


@dataclass(frozen=True)
class EntitySummary:
    """Redaction-safe per-entity seeding result — never a raw entity id or row content."""

    entity: str
    seeded: int
    total_observations: int
    warm: bool
    hst: str


@dataclass(frozen=True)
class SeedSummary:
    """Result of one :func:`seed_baseline` run. ``entities`` is empty when ``errors`` is not."""

    seeded: int
    entities: tuple[EntitySummary, ...] = ()
    errors: tuple[TraceError, ...] = ()


def _parse_algebra(raw: object, line_no: int, errors: list[TraceError]) -> Algebra | None:
    if raw is None:
        return None
    if not isinstance(raw, dict) or set(raw) - _ALGEBRA_KEYS:
        errors.append(TraceError(line_no, "invalid_algebra"))
        return None
    try:
        return Algebra(**raw)
    except (ValidationError, TypeError):
        errors.append(TraceError(line_no, "invalid_algebra"))
        return None


def _is_pass(row: dict) -> bool:
    return row.get("verdict") == "PASS" or row.get("allowed") is True


def parse_traces(text: str) -> list[Trace]:
    """Parse and validate a JSONL trace file's TEXT into replay-ready :class:`Trace` rows.

    Whole-file fail-closed: every line is checked, and if ANY line is malformed or not an
    allowed trace, this raises :class:`TraceValidationError` naming every bad line (never a
    partial, "the good ones" list) — no caller can accidentally replay a partially-valid file.
    Blank lines are skipped without affecting 1-based line numbering.
    """
    traces: list[Trace] = []
    errors: list[TraceError] = []
    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            errors.append(TraceError(line_no, "invalid_json"))
            continue
        if not isinstance(row, dict):
            errors.append(TraceError(line_no, "not_an_object"))
            continue

        if set(row) - _ALLOWED_KEYS:
            errors.append(TraceError(line_no, "unexpected_key"))
            continue
        if _REQUIRED_KEYS - set(row) or not (_VERDICT_KEYS & set(row)):
            errors.append(TraceError(line_no, "missing_required_field"))
            continue
        if not _is_pass(row):
            errors.append(TraceError(line_no, "verdict_not_pass"))
            continue

        agent_role = row["agent_role"]
        if not isinstance(agent_role, str) or not agent_role.strip():
            errors.append(TraceError(line_no, "invalid_agent_role"))
            continue
        tool_name = row["tool_name"]
        if not isinstance(tool_name, str) or not tool_name.strip():
            errors.append(TraceError(line_no, "invalid_tool_name"))
            continue
        try:
            action_type = ActionType(row["action_type"])
        except ValueError:
            errors.append(TraceError(line_no, "invalid_action_type"))
            continue

        target = row.get("target")
        if target is not None and not isinstance(target, str):
            errors.append(TraceError(line_no, "invalid_target"))
            continue
        destination = row.get("external_destination")
        if destination is not None and not isinstance(destination, str):
            errors.append(TraceError(line_no, "invalid_external_destination"))
            continue

        reversibility = Reversibility.medium
        if "reversibility" in row:
            try:
                reversibility = Reversibility(row["reversibility"])
            except ValueError:
                errors.append(TraceError(line_no, "invalid_reversibility"))
                continue

        target_count = row.get("target_count")
        if target_count is not None and (type(target_count) is not int or target_count < 1):
            errors.append(TraceError(line_no, "invalid_target_count"))
            continue

        before = len(errors)
        algebra = _parse_algebra(row.get("algebra"), line_no, errors)
        if len(errors) != before:
            continue

        traces.append(
            Trace(
                line_no=line_no,
                agent_role=agent_role,
                action_type=action_type,
                tool_name=tool_name,
                target=target,
                external_destination=destination,
                reversibility=reversibility,
                target_count=target_count,
                algebra=algebra,
            )
        )

    if errors:
        raise TraceValidationError(errors)
    return traces


def _to_security_object(trace: Trace, stamp: datetime) -> SecurityObject:
    metadata = {"target_count": trace.target_count} if trace.target_count is not None else {}
    base = SecurityObject(
        id=f"seed:{trace.line_no}",
        ts=stamp,
        agent_role=trace.agent_role,
        action_type=trace.action_type,
        tool_name=trace.tool_name,
        target=trace.target,
        external_destination=trace.external_destination,
        reversibility=trace.reversibility,
        metadata=metadata,
    )
    algebra = trace.algebra if trace.algebra is not None else infer_algebra(base)
    return base.model_copy(update={"algebra": algebra})


async def seed_baseline(path: str, *, repo_root: str, now: datetime | None = None) -> SeedSummary:
    """Warm ``repo_root``'s per-entity baseline from the JSONL trace file at ``path``.

    Whole-file fail-closed (see the module docstring): every line is parsed and validated FIRST;
    if anything is malformed or not an allowed trace, nothing is observed and
    ``SeedSummary.errors`` names every bad line. Only on a fully clean file does this replay each
    row through :func:`~doberman.subjective.baseline.observe`, in file order, entity-scoped the
    same way the live proxy would (``entity_id(row.agent_role, repo_root)``) so the seeded
    baseline is the one live traffic reads.
    """
    text = Path(path).read_text(encoding="utf-8-sig")  # utf-8-sig tolerates a leading BOM
    try:
        traces = parse_traces(text)
    except TraceValidationError as exc:
        return SeedSummary(seeded=0, errors=tuple(exc.errors))

    stamp = now or datetime.now(timezone.utc)
    seeded_by_entity: dict[str, int] = {}
    for trace in traces:
        eid = entity_id(trace.agent_role, repo_root)
        obj = _to_security_object(trace, stamp)
        await observe(obj, entity_id=eid, repo_root=repo_root, now=stamp)
        seeded_by_entity[eid] = seeded_by_entity.get(eid, 0) + 1

    entities = []
    for eid, seeded in seeded_by_entity.items():
        total = await total_observations(entity_id=eid, repo_root=repo_root)
        entities.append(
            EntitySummary(
                entity=eid[:12],
                seeded=seeded,
                total_observations=total,
                warm=total >= K_OBSERVATIONS,
                hst=HST_STATUS,
            )
        )
    return SeedSummary(seeded=len(traces), entities=tuple(entities))
