"""Redaction-safe summary stats for the dashboard (D2).

Aggregates over exactly the rows :func:`doberman.storage.log.read_decisions`
already returns for the CLI (``doberman log`` / ``doberman memory``) and the
TUI - no new query layer, no field this module invents on its own. Every value
here is derived from already-redacted columns (verdict, action type, path
*class*, reason codes) - never a raw target, argument, or secret.
"""

from __future__ import annotations

import json
from collections import Counter

from doberman.config import load_enforcement, load_mode
from doberman.policy.drift import effective_enforcement
from doberman.storage.log import read_decisions

# Reason codes that flag a secret- or taint-related event: the Feature 3
# secret/exfil rules, the HK.5 multi-step read-then-send exfiltration floor,
# and the smuggled-token-channel defense. A dash-presentation grouping (not a
# decision-path constant), so it lives here rather than in doberman.models.
SECRET_TAINT_REASON_CODES = frozenset(
    {
        "secret_exfiltration",
        "sensitive_secret_access",
        "possible_high_entropy_secret",
        "encoded_exfiltration",
        "multi_step_exfil",
        "confirmed_exfil",
        "smuggled_token_channel",
        "anomalous_token_pattern",
    }
)

#: An ambient-monitor row (FM.2, ``doberman.monitor.daemon``) tags its
#: ``source_context`` this way — see ``doberman.render.is_ambient_source_context``,
#: duplicated here (not imported) for the same reason ``doberman.render``
#: duplicates it rather than importing ``doberman.explain``: this module is
#: a presentation-layer leaf and the check is a two-line string test, not
#: worth a cross-module dependency.
_AMBIENT_SOURCE_PREFIX = "ambient:"

_DEFAULT_RECENT_WINDOW = 50


def _is_ambient(row: dict) -> bool:
    source_context = row.get("source_context")
    return isinstance(source_context, str) and source_context.startswith(_AMBIENT_SOURCE_PREFIX)


def reason_codes(row: dict) -> list[str]:
    """Parse a decision row's ``reason_codes_json`` defensively (never raises).

    Mirrors ``doberman.tui._reason_codes_text``'s tolerance for a tampered or
    corrupt row - bad JSON or an unexpected shape yields ``[]``, never a crash.
    """
    try:
        codes = json.loads(row.get("reason_codes_json") or "[]")
    except (TypeError, ValueError):
        return []
    if not isinstance(codes, list):
        return []
    return [str(code) for code in codes]


async def _current_enforcement(repo_root: str) -> str:
    """Ledger-verified effective enforcement, async-safe for a running loop.

    Mirrors ``doberman.config.resolve_enforcement_sync`` but awaits
    :func:`doberman.policy.drift.effective_enforcement` directly instead of
    bridging with ``asyncio.run`` - the dash route already runs inside an
    event loop, where ``resolve_enforcement_sync`` would fail closed to
    "enforce" every time (it refuses to nest ``asyncio.run``).
    """
    enforcement, expires_at, revert = load_enforcement(repo_root)
    if str(enforcement).strip().lower() == "enforce":
        return "enforce"
    try:
        return await effective_enforcement(
            repo_root, enforcement=enforcement, expires_at=expires_at, revert=revert
        )
    except Exception:  # noqa: BLE001 — stats must never crash the dash; fail closed
        return "enforce"


async def build_stats(repo_root: str, *, recent_window: int = _DEFAULT_RECENT_WINDOW) -> dict:
    """Redaction-safe stats for ``GET /api/stats``.

    Verdict counts (all-time + a recent window), the top reason codes, a count
    of secret/taint-related events, and the current mode + effective
    enforcement dial. Fails closed: a missing/empty DB (``read_decisions``
    already returns ``[]``) yields all-zero stats, never an error.

    An ambient-monitor AUTH/BLOCK-grade row (FM.2) is counted separately, under
    ``ambient_alert_counts``/``recent_ambient_alert_count`` — folding it into
    ``verdict_counts``/``recent_verdict_counts`` would make the dashboard's own
    "N BLOCK" badge (and the focal "recent BLOCK" number) read as "N things
    were blocked" when some of them never were, exactly the hard rule issue
    #237 sets for every OTHER surface that renders a verdict. An ambient PASS
    row needs no such split — PASS was never a claim of enforcement — so it
    stays in the ordinary PASS count.
    """
    rows = await read_decisions(repo_root)  # newest first
    live_rows = [row for row in rows if not _is_ambient(row)]
    verdict_counts = Counter(row["final_verdict"] for row in live_rows)
    ambient_alert_counts = Counter(
        row["final_verdict"] for row in rows if _is_ambient(row) and row["final_verdict"] != "PASS"
    )

    recent_rows = rows[:recent_window]
    recent_live_rows = [row for row in recent_rows if not _is_ambient(row)]
    recent_verdict_counts = Counter(row["final_verdict"] for row in recent_live_rows)
    recent_ambient_alert_count = sum(
        1 for row in recent_rows if _is_ambient(row) and row["final_verdict"] != "PASS"
    )

    reason_counts: Counter[str] = Counter()
    secret_taint_events = 0
    for row in rows:
        codes = reason_codes(row)
        reason_counts.update(codes)
        if SECRET_TAINT_REASON_CODES.intersection(codes):
            secret_taint_events += 1

    return {
        "total_decisions": len(rows),
        "verdict_counts": dict(verdict_counts),
        "ambient_alert_counts": dict(ambient_alert_counts),
        "ambient_alert_total": sum(ambient_alert_counts.values()),
        "recent_window": recent_window,
        "recent_verdict_counts": dict(recent_verdict_counts),
        "recent_ambient_alert_count": recent_ambient_alert_count,
        "top_reason_codes": reason_counts.most_common(5),
        "secret_taint_events": secret_taint_events,
        "mode": load_mode(repo_root),
        "enforcement": await _current_enforcement(repo_root),
    }
