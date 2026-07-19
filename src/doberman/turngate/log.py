"""Slice TG1.2 — append-only, redacted turn-decision logging.

Turn verdicts are recorded in the **same** local ``decisions`` table as action
verdicts, marked ``action_type='turn'`` (the stage discriminator) so a single
``doberman log`` view covers both invocation points. The :class:`TurnObject`
carries no raw prompt text, so a row can hold only fingerprints/classes/verdicts
— never a prompt. Best-effort: a logging failure never alters or blocks a turn
decision (logging is observational).
"""

import json
import logging

from doberman.models import Decision, TurnObject, Verdict
from doberman.storage.db import open_db

logger = logging.getLogger("doberman.turngate.log")

_INSERT = (
    "INSERT INTO decisions "
    "(ts, action_id, agent_role, action_type, target_path_class, risk, source_context, "
    "final_verdict, decided_layer, reason_codes_json, auth_required, auth_result, "
    "elevation_id, entity_id) "
    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
)


async def record_turn_decision(
    turn: TurnObject,
    decision: Decision,
    *,
    repo_root: str,
    stage: str = "turn",
    auth_result: str | None = None,
) -> None:
    """Append one redacted row for a turn decision (best-effort; never raises)."""
    auth_required = int(decision.final_verdict in (Verdict.AUTH, Verdict.BLOCK))
    try:
        async with open_db(repo_root) as conn:
            await conn.execute(
                _INSERT,
                (
                    decision.decided_at.isoformat(),
                    turn.id,
                    "(turn)",
                    "turn",
                    None,
                    decision.final_risk.value,
                    "turn",
                    decision.final_verdict.value,
                    stage,
                    json.dumps([rc.value for rc in decision.reason_codes]),
                    auth_required,
                    auth_result,
                    None,
                    turn.entity_id,
                ),
            )
            await conn.commit()
    except Exception:  # noqa: BLE001 — logging must never break the turn path
        logger.warning("turn decision log persist failed (turn %s); continuing", turn.id[:12])
