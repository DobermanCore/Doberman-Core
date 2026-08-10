"""Append-only, redacted decision log (Feature 8, slice 8.2).

One immutable, **redacted** row per engine decision, written to the local
SQLite ``decisions`` table and fanned out to any registered audit sinks
(slice 8.4). This is the substrate explainability, learning, and drift defense
build on.

Redaction is structural and load-bearing:

* The row stores a path **class** (filename dropped), the action type, the
  verdict, reason codes, the decided layer, and ids — **never** the raw target,
  raw arguments, file contents, or a prompt. Secrets are represented only by the
  HMAC fingerprints already on the action, upserted into ``secret_fingerprints``.
* Writing is **append-only**: this module only ever ``INSERT``s into
  ``decisions`` (and upserts ``last_seen`` on fingerprints) — there is no
  ``UPDATE``/``DELETE`` path for a decision row.
* Writing is **best-effort**: any failure is logged to stderr and swallowed —
  it can never raise into the execution path and never flips a verdict. The
  decision has already been made and enforced before this runs.
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import PurePosixPath

from doberman.models import ActionType, Decision, SecurityObject
from doberman.storage.db import open_db
from doberman.storage.device_metrics import record_decision_metric
from doberman.storage.sinks import emit_to_sinks

logger = logging.getLogger("doberman.storage.log")

_PATH_ACTIONS = frozenset({ActionType.file_read, ActionType.file_write, ActionType.file_delete})

_INSERT_DECISION = (
    "INSERT INTO decisions "
    "(ts, action_id, agent_role, action_type, target_path_class, risk, source_context, "
    "final_verdict, decided_layer, reason_codes_json, auth_required, auth_result, elevation_id, "
    "entity_id, session_id) "
    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
)

_INSERT_SHADOW = (
    "INSERT INTO shadow_adjudications "
    "(ts, action_id, live_verdict, shadow_verdict, shadow_reason_codes, entity_id) "
    "VALUES (?, ?, ?, ?, ?, ?)"
)

_UPSERT_FINGERPRINT = (
    "INSERT INTO secret_fingerprints (fingerprint, label, first_seen, last_seen, source_path_class) "
    "VALUES (?, ?, ?, ?, ?) "
    "ON CONFLICT(fingerprint) DO UPDATE SET last_seen = excluded.last_seen"
)

_SELECT_DECISIONS = (
    "SELECT id, ts, action_id, agent_role, action_type, target_path_class, risk, source_context, "
    "final_verdict, decided_layer, reason_codes_json, auth_required, auth_result, elevation_id "
    "FROM decisions ORDER BY id DESC"
)

# Mirrors _SELECT_DECISIONS but ascending + cursor-bounded, for the dash's live
# feed poll (doberman.dash): "give me what's new since the last row I saw".
_SELECT_DECISIONS_SINCE = (
    "SELECT id, ts, action_id, agent_role, action_type, target_path_class, risk, source_context, "
    "final_verdict, decided_layer, reason_codes_json, auth_required, auth_result, elevation_id "
    "FROM decisions WHERE id > ? ORDER BY id ASC"
)

_DECISION_COLUMNS = [
    "id",
    "ts",
    "action_id",
    "agent_role",
    "action_type",
    "target_path_class",
    "risk",
    "source_context",
    "final_verdict",
    "decided_layer",
    "reason_codes_json",
    "auth_required",
    "auth_result",
    "elevation_id",
]


def path_class(action: SecurityObject) -> str | None:
    """A redaction-safe class for a file target: drop the filename, keep dir + ext.

    ``backend/auth/session.ts`` → ``backend/auth/*.ts``; ``.env`` → ``.env``
    (dotfiles/extensionless names are themselves the class). Non-file actions
    have no path class. Never returns the raw filename of an extensioned file.

    Public (renamed from ``_path_class``) so D3's dashboard-approval queue
    (``doberman.auth.dashboard_prompter``) can derive the same redaction-safe
    path class for a pending row without duplicating this logic.
    """
    if action.target_path_class:
        return action.target_path_class
    if action.action_type not in _PATH_ACTIONS or not action.target:
        return None
    pure = PurePosixPath(str(action.target).replace("\\", "/"))
    parent = pure.parent.as_posix()
    parent = "" if parent == "." else parent
    stem_class = f"*{pure.suffix}" if pure.suffix else pure.name
    return f"{parent}/{stem_class}" if parent else stem_class


def _decided_layer(decision: Decision) -> str:
    """Which layer produced the verdict: objective alone, or combined with subjective."""
    return "objective" if decision.subjective is None else "combined"


def build_record(
    decision: Decision,
    action: SecurityObject,
    *,
    auth_result: str | None,
    elevation_id: str | None,
    now: datetime,
    entity_id: str | None = None,
    session_id: str | None = None,
) -> dict:
    """Build the single redacted record persisted and handed to every sink.

    ``entity_id`` is a keyed HMAC fingerprint of role+workspace (SL4) — itself
    redaction-safe — that powers the per-entity step-up budget and
    revealed-preference learning. ``session_id`` is the host harness's opaque
    session identifier (HK.5.1) — a UUID, not a secret — used to correlate the
    calls of one agent session for the multi-step taint floor.
    """
    return {
        "ts": now.isoformat(),
        "action_id": decision.action_id,
        "agent_role": action.agent_role,
        "action_type": action.action_type.value,
        "target_path_class": path_class(action),
        "risk": decision.final_risk.value,
        "source_context": action.source_context.value,
        "final_verdict": decision.final_verdict.value,
        "decided_layer": _decided_layer(decision),
        "reason_codes": [rc.value for rc in decision.reason_codes],
        "auth_required": decision.final_verdict.value == "AUTH",
        "auth_result": auth_result,
        "elevation_id": elevation_id,
        "entity_id": entity_id,
        "session_id": session_id,
    }


async def record_decision(
    decision: Decision,
    action: SecurityObject,
    *,
    repo_root: str,
    auth_result: str | None = None,
    elevation_id: str | None = None,
    now: datetime | None = None,
    entity_id: str | None = None,
    session_id: str | None = None,
) -> None:
    """Persist one redacted decision row and fan it out to sinks (best-effort).

    Never raises: building the record, the storage write, and the sink fan-out
    are all inside the failure boundary, so nothing here can alter or block the
    decision (which has already been enforced).
    """
    try:
        record = build_record(
            decision,
            action,
            auth_result=auth_result,
            elevation_id=elevation_id,
            now=now or datetime.now(timezone.utc),
            entity_id=entity_id,
            session_id=session_id,
        )
    except Exception:  # noqa: BLE001 — the decision log must never break execution
        logger.warning("decision log: could not build record for action %s", decision.action_id)
        return

    try:
        async with open_db(repo_root) as conn:
            await conn.execute(
                _INSERT_DECISION,
                (
                    record["ts"],
                    record["action_id"],
                    record["agent_role"],
                    record["action_type"],
                    record["target_path_class"],
                    record["risk"],
                    record["source_context"],
                    record["final_verdict"],
                    record["decided_layer"],
                    json.dumps(record["reason_codes"]),
                    int(record["auth_required"]),
                    record["auth_result"],
                    record["elevation_id"],
                    record["entity_id"],
                    record["session_id"],
                ),
            )
            for fp in action.payload_fingerprints:
                await conn.execute(
                    _UPSERT_FINGERPRINT,
                    (fp, "secret", record["ts"], record["ts"], record["target_path_class"]),
                )
            await conn.commit()
    except Exception:  # noqa: BLE001 — the decision log must never break execution
        logger.warning("decision log write failed for action %s; continuing", decision.action_id)

    # Fan-out is best-effort and isolated; never let it raise either.
    try:
        emit_to_sinks(record, repo_root=repo_root)
    except Exception:  # noqa: BLE001 — defense in depth (emit_to_sinks already isolates)
        logger.warning("audit sink fan-out failed for action %s; continuing", decision.action_id)

    # Device-global rollup for `doberman dashboard` (best-effort, defense in
    # depth — record_decision_metric already swallows its own failures).
    try:
        record_decision_metric(record["final_verdict"])
    except Exception:  # noqa: BLE001 — the device rollup must never break execution
        logger.warning("device metrics rollup failed for action %s; continuing", decision.action_id)


async def record_shadow(
    decision: Decision,
    action: SecurityObject,
    *,
    repo_root: str,
    entity_id: str | None = None,
) -> None:
    """Persist one redacted shadow-adjudication row (best-effort, shadow-only).

    Writes a row ONLY when ``decision.shadow`` is set. Stores the live verdict and
    the shadow verdict/reason-code **classes** — never a raw value — so this
    ledger is redaction-safe by construction. Like :func:`record_decision` it is
    outside the decision path: any failure is logged and swallowed, so it can
    never raise into execution or alter a verdict (the decision is already made).

    Not yet wired into the executor persist path — this slice provides + unit-tests
    the writer; wiring is a follow-up.
    """
    if decision.shadow is None:
        return
    try:
        shadow = decision.shadow
        ts = datetime.now(timezone.utc).isoformat()
        async with open_db(repo_root) as conn:
            await conn.execute(
                _INSERT_SHADOW,
                (
                    ts,
                    decision.action_id,
                    decision.final_verdict.value,
                    shadow.verdict.value,
                    json.dumps([rc.value for rc in shadow.reason_codes]),
                    entity_id,
                ),
            )
            await conn.commit()
    except Exception:  # noqa: BLE001 — the shadow log must never break execution
        logger.warning("shadow log write failed for action %s; continuing", decision.action_id)


async def read_decisions(repo_root: str, *, limit: int | None = None) -> list[dict]:
    """Read decision rows, newest first (for ``doberman log``). Fails closed to []."""
    from doberman.storage.db import db_path

    if not db_path(repo_root).exists():
        return []
    query = _SELECT_DECISIONS + (f" LIMIT {int(limit)}" if limit else "")
    try:
        async with open_db(repo_root) as conn:
            async with conn.execute(query) as cur:
                rows = await cur.fetchall()
    except Exception:  # noqa: BLE001 — a read failure must never crash the CLI
        return []
    return [dict(zip(_DECISION_COLUMNS, row, strict=True)) for row in rows]


async def read_decisions_since(
    repo_root: str, since_id: int, *, limit: int | None = None
) -> list[dict]:
    """Read decision rows with ``id > since_id``, oldest first (cursor-based poll).

    For the dash's live feed (``doberman.dash``): pass the highest ``id`` already
    seen and get back only what's new. Same shape/columns as :func:`read_decisions`
    and the same fail-closed-to-``[]`` behavior (missing/locked DB, any error).
    """
    from doberman.storage.db import db_path

    if not db_path(repo_root).exists():
        return []
    query = _SELECT_DECISIONS_SINCE + (f" LIMIT {int(limit)}" if limit else "")
    try:
        async with open_db(repo_root) as conn:
            async with conn.execute(query, (since_id,)) as cur:
                rows = await cur.fetchall()
    except Exception:  # noqa: BLE001 — a read failure must never crash the dash
        return []
    return [dict(zip(_DECISION_COLUMNS, row, strict=True)) for row in rows]


async def memory_summary(repo_root: str) -> dict:
    """Plain-language, redaction-safe profile for ``doberman memory``.

    Reports *classes and habits only*: how many decisions, the verdict mix, the
    most-touched path classes, and how many distinct secrets have been seen — as
    a **count**, never a fingerprint value, and never a raw secret.
    """
    from collections import Counter

    from doberman.storage.db import db_path

    summary = {"decisions": 0, "verdicts": {}, "top_path_classes": [], "secrets_seen": 0}
    if not db_path(repo_root).exists():
        return summary
    decisions = await read_decisions(repo_root)
    summary["decisions"] = len(decisions)
    summary["verdicts"] = dict(Counter(d["final_verdict"] for d in decisions))
    classes = Counter(d["target_path_class"] for d in decisions if d["target_path_class"])
    summary["top_path_classes"] = classes.most_common(5)
    try:
        async with open_db(repo_root) as conn:
            async with conn.execute("SELECT COUNT(*) FROM secret_fingerprints") as cur:
                row = await cur.fetchone()
        summary["secrets_seen"] = row[0] if row else 0
    except Exception:  # noqa: BLE001 — best-effort summary
        summary["secrets_seen"] = 0
    return summary
