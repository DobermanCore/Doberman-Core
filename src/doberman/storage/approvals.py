"""Pending-approval queue mediating the dashboard and the decision path (D3).

This is the ONLY channel between the two processes: the decision-path process
(proxy/hosthook, via ``doberman.auth.dashboard_prompter.DashboardPrompter``)
writes a row and polls it; the dash server's ``/api/pending`` and
``/api/resolve/{id}`` routes read and resolve it. There is no HTTP call into
the decision path in either direction.

Redaction is structural: a row stores only what the terminal/GUI prompt
itself already shows a human (action type, risk, reason codes, the human
explanation, and a path *class* - never a raw target, argument, or secret).

Single-use and race-safe: resolution is one ``UPDATE ... WHERE
status = 'pending' AND expires_at > ?`` state transition, gated on affected-row
count, so two concurrent resolutions of the same row can never both "win" and
an expired row can never be resolved (it is already dead).
"""

import json
import uuid
from datetime import datetime, timedelta, timezone

from doberman.storage.db import open_db

#: How long a pending row stays resolvable before it's considered dead.
DEFAULT_APPROVAL_TTL_S = 120.0

_INSERT_PENDING = (
    "INSERT INTO pending_approvals "
    "(id, action_id, created_at, expires_at, status, tier, action_type, risk, "
    "reason_codes_json, explanation, target_path_class) "
    "VALUES (?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?, ?)"
)

_COLUMNS = [
    "id",
    "action_id",
    "created_at",
    "expires_at",
    "status",
    "tier",
    "action_type",
    "risk",
    "reason_codes_json",
    "explanation",
    "target_path_class",
    "decision",
    "totp_code",
]

_SELECT_ONE = f"SELECT {', '.join(_COLUMNS)} FROM pending_approvals WHERE id = ?"  # noqa: S608

_SELECT_PENDING_LIST = (
    f"SELECT {', '.join(_COLUMNS)} FROM pending_approvals "  # noqa: S608
    "WHERE status = 'pending' AND expires_at > ? ORDER BY created_at ASC"
)

_RESOLVE = (
    "UPDATE pending_approvals SET status = 'resolved', decision = ?, totp_code = ? "
    "WHERE id = ? AND status = 'pending' AND expires_at > ?"
)


def _row_to_dict(row) -> dict:
    record = dict(zip(_COLUMNS, row, strict=True))
    record["reason_codes"] = json.loads(record["reason_codes_json"] or "[]")
    return record


async def create_pending(
    action_id: str,
    *,
    tier: str,
    action_type: str,
    risk: str,
    reason_codes: list[str],
    explanation: str,
    target_path_class: str | None,
    repo_root: str = ".",
    now: datetime | None = None,
    ttl_s: float = DEFAULT_APPROVAL_TTL_S,
) -> str:
    """Write a new pending row and return its id.

    Every field is already redaction-safe by the time it reaches here (see
    ``doberman.auth.dashboard_prompter`` - it derives these from the same
    ``Decision``/``SecurityObject`` the terminal prompt itself renders).
    """
    when = now or datetime.now(timezone.utc)
    expires = when + timedelta(seconds=ttl_s)
    approval_id = uuid.uuid4().hex
    async with open_db(repo_root) as conn:
        await conn.execute(
            _INSERT_PENDING,
            (
                approval_id,
                action_id,
                when.isoformat(),
                expires.isoformat(),
                tier,
                action_type,
                risk,
                json.dumps(reason_codes),
                explanation,
                target_path_class,
            ),
        )
        await conn.commit()
    return approval_id


async def get_pending(approval_id: str, *, repo_root: str = ".") -> dict | None:
    """Fetch one row by id (used by the prompter's poll loop). None if absent."""
    async with open_db(repo_root) as conn:
        async with conn.execute(_SELECT_ONE, (approval_id,)) as cur:
            row = await cur.fetchone()
    return _row_to_dict(row) if row else None


async def list_pending(*, repo_root: str = ".", now: datetime | None = None) -> list[dict]:
    """List unexpired rows still awaiting a decision (for the dash UI)."""
    when = now or datetime.now(timezone.utc)
    async with open_db(repo_root) as conn:
        async with conn.execute(_SELECT_PENDING_LIST, (when.isoformat(),)) as cur:
            rows = await cur.fetchall()
    return [_row_to_dict(row) for row in rows]


async def resolve(
    approval_id: str,
    *,
    decision: str,
    totp_code: str | None = None,
    repo_root: str = ".",
    now: datetime | None = None,
) -> bool:
    """Race-safe single-use resolution. Returns True iff THIS call won the race.

    A second resolve of the same row, or a resolve after expiry, affects zero
    rows and returns False - the row stays exactly as it was (already-resolved
    stays resolved; expired-pending stays pending-but-dead).
    """
    when = now or datetime.now(timezone.utc)
    async with open_db(repo_root) as conn:
        cur = await conn.execute(_RESOLVE, (decision, totp_code, approval_id, when.isoformat()))
        await conn.commit()
        return cur.rowcount > 0
