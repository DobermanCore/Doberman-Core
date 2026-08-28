"""Bounded exact-action approval memory (keyed fingerprints only)."""

from dataclasses import dataclass
from datetime import datetime, timezone

from doberman.storage.db import open_db


@dataclass(frozen=True)
class ApprovalMemoryEntry:
    fingerprint: str
    session_id: str | None
    required_tier: str
    action_type: str
    method: str
    approved_at: datetime
    expires_at: datetime


_COLUMNS = (
    "fingerprint",
    "session_id",
    "required_tier",
    "action_type",
    "method",
    "approved_at",
    "expires_at",
)
_SELECT = f"SELECT {', '.join(_COLUMNS)} FROM approval_memory WHERE fingerprint = ?"  # noqa: S608


def _parse(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)


def _entry(row) -> ApprovalMemoryEntry:
    return ApprovalMemoryEntry(
        fingerprint=row[0],
        session_id=row[1],
        required_tier=row[2],
        action_type=row[3],
        method=row[4],
        approved_at=_parse(row[5]),
        expires_at=_parse(row[6]),
    )


async def remember(
    fingerprint: str,
    *,
    session_id: str | None,
    required_tier: str,
    action_type: str,
    method: str,
    approved_at: datetime,
    expires_at: datetime,
    repo_root: str = ".",
) -> None:
    """Remember one factor-verified approval, replacing an older exact hit."""
    async with open_db(repo_root) as conn:
        await conn.execute(
            "INSERT INTO approval_memory "
            "(fingerprint, session_id, required_tier, action_type, method, approved_at, expires_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(fingerprint) DO UPDATE SET "
            "session_id=excluded.session_id, required_tier=excluded.required_tier, "
            "action_type=excluded.action_type, method=excluded.method, "
            "approved_at=excluded.approved_at, expires_at=excluded.expires_at",
            (
                fingerprint,
                session_id,
                required_tier,
                action_type,
                method,
                approved_at.isoformat(),
                expires_at.isoformat(),
            ),
        )
        await conn.commit()


async def lookup(
    fingerprint: str,
    *,
    session_id: str | None,
    now: datetime,
    repo_root: str = ".",
) -> ApprovalMemoryEntry | None:
    """Return a live exact hit; two known session ids must agree."""
    async with open_db(repo_root) as conn:
        async with conn.execute(_SELECT, (fingerprint,)) as cur:
            row = await cur.fetchone()
    if row is None:
        return None
    entry = _entry(row)
    if entry.expires_at <= now:
        return None
    if entry.session_id is not None and session_id is not None and entry.session_id != session_id:
        return None
    return entry


async def clear(repo_root: str) -> int:
    """Delete all approval-memory entries for one repository."""
    async with open_db(repo_root) as conn:
        cur = await conn.execute("DELETE FROM approval_memory")
        await conn.commit()
        return cur.rowcount


async def purge_expired(now: datetime, *, repo_root: str = ".") -> int:
    """Delete entries whose bounded lifetime has ended."""
    async with open_db(repo_root) as conn:
        cur = await conn.execute(
            "DELETE FROM approval_memory WHERE expires_at <= ?", (now.isoformat(),)
        )
        await conn.commit()
        return cur.rowcount


async def count_live(now: datetime, *, repo_root: str = ".") -> int:
    """Count live entries without returning their fingerprints."""
    async with open_db(repo_root) as conn:
        async with conn.execute(
            "SELECT COUNT(*) FROM approval_memory WHERE expires_at > ?", (now.isoformat(),)
        ) as cur:
            row = await cur.fetchone()
    return int(row[0]) if row else 0
