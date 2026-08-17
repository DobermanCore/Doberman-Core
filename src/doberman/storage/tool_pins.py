"""Keyed TOFU pins for the MCP tool surface advertised by ``tools/list``.

The first observed schema is trusted. This defends against a tool changing its
advertised contract after first contact; it cannot establish that first contact
was benign. Only keyed HMAC fingerprints are persisted, never raw descriptions
or input schemas.
"""

import json
import logging
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from typing import Any

from doberman.storage.db import open_db
from doberman.storage.fingerprint import fingerprint

logger = logging.getLogger("doberman.storage.tool_pins")

PinStatus = str


def canonicalize_tool(name: str, description: str | None, input_schema: Mapping[str, Any]) -> str:
    """Return a keyed fingerprint of the canonical ``(name, description, schema)`` triple."""
    canonical = json.dumps(
        (name, description, input_schema),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return fingerprint(canonical)


async def reconcile_pins(tools: Iterable[Any], *, repo_root: str) -> None:
    """Reconcile one ``tools/list`` response against trust-on-first-use pins.

    A new name is pinned on first sight. Later changes are recorded as a
    ``last_seen_fp`` mismatch until a human approves them. TOFU protects against
    CHANGE, not a malicious schema on first contact. Failures are logged by
    class only and never escape into the proxy's ``tools/list`` path.
    """
    try:
        now = datetime.now(timezone.utc).isoformat()
        async with open_db(repo_root) as conn:
            for tool in tools:
                current_fp = canonicalize_tool(tool.name, tool.description, tool.inputSchema)
                async with conn.execute(
                    "SELECT pinned_fp FROM tool_pins WHERE tool_name = ?", (tool.name,)
                ) as cursor:
                    row = await cursor.fetchone()
                if row is None:
                    await conn.execute(
                        "INSERT INTO tool_pins "
                        "(tool_name, pinned_fp, last_seen_fp, pinned_at, changed_at) "
                        "VALUES (?, ?, ?, ?, NULL)",
                        (tool.name, current_fp, current_fp, now),
                    )
                elif row[0] == current_fp:
                    await conn.execute(
                        "UPDATE tool_pins SET last_seen_fp = ?, changed_at = NULL "
                        "WHERE tool_name = ?",
                        (current_fp, tool.name),
                    )
                else:
                    await conn.execute(
                        "UPDATE tool_pins SET last_seen_fp = ?, changed_at = ? WHERE tool_name = ?",
                        (current_fp, now, tool.name),
                    )
            await conn.commit()
    except Exception as exc:  # noqa: BLE001 - tools/list must remain available
        logger.warning(
            "tool-pin reconciliation failed; continuing (error class: %s)",
            type(exc).__name__,
        )


async def _read_pin(tool_name: str, repo_root: str) -> tuple[str, str | None, str | None] | None:
    async with open_db(repo_root) as conn:
        async with conn.execute(
            "SELECT pinned_fp, last_seen_fp, changed_at FROM tool_pins WHERE tool_name = ?",
            (tool_name,),
        ) as cursor:
            return await cursor.fetchone()


async def pin_status(tool_name: str, *, repo_root: str) -> PinStatus:
    """Return ``ok``, ``changed``, or ``unknown``; any read error is ``changed``."""
    try:
        row = await _read_pin(tool_name, repo_root)
    except Exception as exc:  # noqa: BLE001 - fail closed on any pin-store read error
        logger.warning("tool-pin read failed (error class: %s)", type(exc).__name__)
        return "changed"
    if row is None:
        return "unknown"
    pinned_fp, last_seen_fp, changed_at = row
    return "ok" if pinned_fp == last_seen_fp and changed_at is None else "changed"


async def approve_pin(tool_name: str, *, repo_root: str) -> str | None:
    """Promote the last-seen fingerprint and clear the changed marker.

    Authentication belongs to the CLI caller; this storage operation contains
    no gate of its own. Returns the promoted fingerprint, or ``None`` when no
    last-seen pin exists.
    """
    async with open_db(repo_root) as conn:
        async with conn.execute(
            "SELECT last_seen_fp FROM tool_pins WHERE tool_name = ?", (tool_name,)
        ) as cursor:
            row = await cursor.fetchone()
        if row is None or row[0] is None:
            return None
        approved_fp = row[0]
        await conn.execute(
            "UPDATE tool_pins SET pinned_fp = ?, changed_at = NULL WHERE tool_name = ?",
            (approved_fp, tool_name),
        )
        await conn.commit()
        return approved_fp
