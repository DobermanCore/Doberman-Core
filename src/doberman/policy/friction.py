"""Friction telemetry — approval-fatigue report + gated tuning proposals (#243).

Pure aggregation over already-redacted decision-log rows (the shape
``doberman.storage.log.read_decisions`` returns): no DB access, no proxy
import (kept a policy-core leaf so import-linter's contracts hold). Two entry
points:

* :func:`build_friction_report` — how much friction the AUTH gate is
  generating: interventions per session, top AUTH reasons, approval rates,
  weekly trend.
* :func:`generate_proposals` — where an AUTH class has been approved 100% of
  the time, often enough, that a *standing, revocable, time-limited*
  elevation would remove real friction without loosening anything by itself.
  Emitting a proposal is the ceiling of what this module does — actually
  applying one always routes through
  :func:`doberman.policy.drift.apply_standing_elevation`'s
  possession-factor-gated weaken chokepoint; nothing here ever mutates policy
  or storage.
"""

import json
from collections import Counter, defaultdict
from datetime import datetime, timedelta

from doberman.auth.elevation import _WHOLE_TREE
from doberman.models import ReasonCode

#: The literal ``auth_result`` value the executor/host-hooks record for an
#: approved AUTH challenge (verified against the write sites -
#: ``doberman.proxy.executor``'s ``_persist(..., auth_result="approved")``
#: calls - not assumed).
APPROVED = "approved"

#: Action types the standing-elevation mechanism can cover - it is a
#: path-glob grant (``doberman.auth.elevation``), so only path-shaped actions
#: are eligible.
_ELEVATABLE_ACTIONS = frozenset({"file_read", "file_write", "file_delete"})

#: The only reason code(s) a standing elevation may ever be proposed for. A
#: role-out-of-scope AUTH is satisfied purely by "this path is outside the
#: agent's declared role boundary" - a standing elevation genuinely closes
#: that gap (doberman.auth.elevation). Every other AUTH-worthy code (secret
#: access/exfiltration, PII/financial data-class egress, destructive
#: commands, control-plane, tool-schema drift, the lethal trifecta, ...) is a
#: live security signal that must never be proposed away - this allowlist is
#: deliberately a single element, and the "subset of PROPOSABLE" check in
#: generate_proposals() is what enforces that, not any per-code logic.
PROPOSABLE_REASON_CODES = frozenset({ReasonCode.role_out_of_scope.value})

#: Default proposal lifetime, plumbed straight into `apply_standing_elevation`.
_DEFAULT_TTL_DAYS = 7


def _parse_reason_codes(raw: str | None) -> list[str]:
    """Best-effort parse of a row's ``reason_codes_json``; never raises."""
    if not raw:
        return []
    try:
        codes = json.loads(raw)
    except (TypeError, ValueError):
        return []
    return codes if isinstance(codes, list) else []


def _week_start(ts_raw: object) -> str | None:
    """The ISO date of the Monday starting ``ts_raw``'s week, or ``None`` if unparsable."""
    if not isinstance(ts_raw, str):
        return None
    try:
        dt = datetime.fromisoformat(ts_raw)
    except ValueError:
        return None
    monday = dt.date() - timedelta(days=dt.date().weekday())
    return monday.isoformat()


def _rate_table(groups: dict[str, list[object]]) -> dict[str, dict]:
    """``{key: {n, approved, rate}}`` - denominator excludes ``None`` results."""
    out: dict[str, dict] = {}
    for key, results in groups.items():
        decided = [r for r in results if r is not None]
        n = len(decided)
        approved = sum(1 for r in decided if r == APPROVED)
        out[key] = {"n": n, "approved": approved, "rate": (approved / n) if n else None}
    return out


def build_friction_report(rows: list[dict]) -> dict:
    """Aggregate redacted decision rows into a friction report.

    Pure and total: never raises on malformed input (malformed
    ``reason_codes_json`` drops just that row's codes; an unparsable ``ts``
    drops just that row from ``trend``) - matching the redacted-log's own
    fail-closed-to-empty read contract.
    """
    decisions = len(rows)
    session_ids = {r["session_id"] for r in rows if r.get("session_id")}
    sessions = len(session_ids)
    unsessioned_decisions = sum(1 for r in rows if not r.get("session_id"))

    auth_rows = [r for r in rows if r.get("final_verdict") == "AUTH"]
    interventions = len(auth_rows)
    interventions_per_session = (interventions / sessions) if sessions else None

    reason_counts: Counter[str] = Counter()
    by_reason: dict[str, list[object]] = defaultdict(list)
    by_target: dict[str, list[object]] = defaultdict(list)
    for row in auth_rows:
        auth_result = row.get("auth_result")
        for code in _parse_reason_codes(row.get("reason_codes_json")):
            reason_counts[code] += 1
            by_reason[code].append(auth_result)
        target_class = row.get("target_path_class")
        if target_class:
            by_target[f"{row.get('action_type')} {target_class}"].append(auth_result)

    top_auth_reason_codes = [
        [code, n] for code, n in sorted(reason_counts.items(), key=lambda kv: (-kv[1], kv[0]))
    ]

    week_buckets: dict[str, dict[str, int]] = {}
    week_sessions: dict[str, set[str]] = defaultdict(set)
    for row in rows:
        week = _week_start(row.get("ts"))
        if week is None:
            continue
        bucket = week_buckets.setdefault(week, {"decisions": 0, "interventions": 0})
        bucket["decisions"] += 1
        if row.get("final_verdict") == "AUTH":
            bucket["interventions"] += 1
        sid = row.get("session_id")
        if sid:
            week_sessions[week].add(sid)
    trend = {
        week: {
            "decisions": bucket["decisions"],
            "interventions": bucket["interventions"],
            "sessions": len(week_sessions.get(week, ())),
            "interventions_per_session": (
                bucket["interventions"] / len(week_sessions[week])
                if week_sessions.get(week)
                else None
            ),
        }
        for week, bucket in sorted(week_buckets.items())
    }

    return {
        "version": 1,
        "decisions": decisions,
        "sessions": sessions,
        "unsessioned_decisions": unsessioned_decisions,
        "interventions": interventions,
        "interventions_per_session": interventions_per_session,
        "top_auth_reason_codes": top_auth_reason_codes,
        "approval_rate_by_reason": _rate_table(by_reason),
        "approval_rate_by_target": _rate_table(by_target),
        "trend": trend,
    }


def _is_narrow(target_path_class: str) -> bool:
    """A directory-scoped class, or a wildcard-free literal (e.g. a dotfile).

    A bare root-level ``*.ext`` (no directory component, still a wildcard) is
    refused - it is not narrow enough for a standing elevation.
    """
    if "/" in target_path_class:
        return True
    return "*" not in target_path_class


def _proposal_id(action_type: str, target_path_class: str, codes: set[str]) -> str:
    import hashlib

    key = f"{action_type}|{target_path_class}|{','.join(sorted(codes))}"
    return hashlib.sha256(key.encode()).hexdigest()[:10]


def generate_proposals(rows: list[dict], *, min_occurrences: int = 5) -> list[dict]:
    """Standing-elevation proposals for AUTH classes approved every single time.

    Allowlist semantics throughout - anything not affirmatively satisfying
    every condition below fails closed to "no proposal" for that group:

    1. at least ``min_occurrences`` AUTH rows in the group, ALL approved
       (one denied/timeout/unresolved row disqualifies the whole group);
    2. a truthy, non-whole-tree, narrow ``target_path_class`` (see
       :func:`_is_narrow`);
    3. a path-shaped ``action_type`` (the elevation mechanism is path-glob
       based, see ``doberman.auth.elevation``);
    4. the union of the group's reason codes is non-empty and a subset of
       :data:`PROPOSABLE_REASON_CODES` - today that is *only*
       ``role_out_of_scope``: a standing elevation genuinely satisfies just
       that AUTH (see ``doberman.auth.elevation``'s docstring). Every
       security-relevant code (secret_*, *_exfiltration, pii_*,
       destructive_*, control-plane, tool_schema_changed, lethal_trifecta,
       ...) is excluded by construction, never by a per-code carve-out.

    # ponytail: standing-elevation proposals are the only tuning lever today
    # - other friction sources (e.g. subjective cold-start noise, #326) need
    # their own consumable mechanism before they can grow a proposal `kind`
    # here; add one only when that lever exists.
    """
    groups: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for row in rows:
        if row.get("final_verdict") != "AUTH":
            continue
        action_type = row.get("action_type")
        target_class = row.get("target_path_class")
        if action_type not in _ELEVATABLE_ACTIONS or not target_class:
            continue
        groups[(action_type, target_class)].append(row)

    proposals = []
    for (action_type, target_class), group_rows in sorted(groups.items()):
        n = len(group_rows)
        if n < min_occurrences:
            continue
        if any(r.get("auth_result") != APPROVED for r in group_rows):
            continue
        if target_class in _WHOLE_TREE or not _is_narrow(target_class):
            continue
        codes: set[str] = set()
        for r in group_rows:
            codes.update(_parse_reason_codes(r.get("reason_codes_json")))
        if not codes or not codes <= PROPOSABLE_REASON_CODES:
            continue
        sorted_codes = sorted(codes)
        proposals.append(
            {
                "id": _proposal_id(action_type, target_class, codes),
                "kind": "standing_elevation",
                "action_type": action_type,
                "target_path_class": target_class,
                "occurrences": n,
                "approval_rate": 1.0,
                "reason_codes": sorted_codes,
                "ttl_days": _DEFAULT_TTL_DAYS,
                "what_would_loosen": (
                    f"role out-of-scope AUTH prompts for {action_type} on {target_class} "
                    f"become PASS for {_DEFAULT_TTL_DAYS} days"
                ),
                "why": f"approved {n}/{n} times",
            }
        )
    return proposals
