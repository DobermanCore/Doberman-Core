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

from doberman.models import AuthPath, Decision, TurnObject, Verdict
from doberman.storage.db import open_db
from doberman.storage.policy_catalogue import PolicySnapshotV1

logger = logging.getLogger("doberman.turngate.log")

_INSERT = (
    "INSERT INTO decisions "
    "(ts, action_id, agent_role, action_type, target_path_class, risk, source_context, "
    "final_verdict, decided_layer, reason_codes_json, auth_required, auth_result, "
    "auth_path, human_confirmed, elevation_id, entity_id, policy_version) "
    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
)


async def record_turn_decision(
    turn: TurnObject,
    decision: Decision,
    *,
    repo_root: str,
    stage: str = "turn",
    auth_result: str | None = None,
    auth_path: str = AuthPath.none,
    human_confirmed: bool | None = None,
    policy_snapshot: PolicySnapshotV1 | None = None,
) -> None:
    """Append one redacted row for a turn decision (best-effort; never raises).

    ``auth_path``/``human_confirmed`` (#505) record which code path resolved an
    authentication and whether a person approved it. They default to "no auth
    was involved", which is correct for every stage that does not challenge
    (``turn_block``, ``turn_pass``, ``turn_lockout``); the two challenging
    stages pass their own values.

    The caller captures ``policy_snapshot`` during evaluation. Missing snapshots
    and failed catalogue writes leave a NULL stamp, never a reconstructed policy
    or a dropped decision row.
    """
    auth_required = int(decision.final_verdict in (Verdict.AUTH, Verdict.BLOCK))
    policy_version = None
    try:
        from doberman.storage.policy_catalogue import ORIGIN_DECISION, record_version

        if policy_snapshot is not None:
            policy_version = record_version(
                repo_root, policy_snapshot, origin=ORIGIN_DECISION, now=decision.decided_at
            )
    except Exception:  # noqa: BLE001 — stamping must never prevent decision persistence
        logger.warning("turn policy stamping failed (turn %s); continuing", turn.id[:12])
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
                    auth_path,
                    # None stays None: "not recorded" must never collapse into
                    # 0 ("no human"), which would read as a fail-open signal.
                    None if human_confirmed is None else int(human_confirmed),
                    None,
                    turn.entity_id,
                    policy_version,
                ),
            )
            await conn.commit()
    except Exception:  # noqa: BLE001 — logging must never break the turn path
        logger.warning("turn decision log persist failed (turn %s); continuing", turn.id[:12])
