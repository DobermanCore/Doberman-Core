"""Revealed-preference learning (SL6.1) — bounded by the F10 policy gate.

Every approve/deny on a SUBJECTIVE step-up is a labeled example of operator
tolerance on that action's algebra point. This module records those outcomes
per entity and preference dimension, and proposes BOUNDED weight nudges toward
the observed tolerance — the approval-fatigue fix, grounded in revealed rather
than stated preference.

SECURITY — every loosening is gated:

* A nudge that REDUCES a weight (fewer subjective asks) is a **weakening** and
  routes through the core policy-change gate (:func:`doberman.policy.drift.
  apply_change`): rendered diff + 2FA, recorded in the append-only ledger —
  including denied attempts. A weight INCREASE classifies as a strengthening
  and applies automatically (raise-only). The mapping onto the gate's
  protection ranks: decrease ⇒ ``auth → allow``, increase ⇒ ``auth → block``.
* Nudges are bounded (:data:`STEP`), hysteresis-banded (no oscillation), and
  gated on a minimum sample size — approve-spam cannot move weights quickly,
  and counters reset after every attempt so evidence is never reused.
* **Scope tokens** are a session-only nuisance reduction: an approve may grant
  an "approve for this task" token for that exact algebra point, bounded by a
  TTL, held only in process memory (never persisted), and NEVER granted for a
  lethal-trifecta step-up — the floor stays untouchable.

This module is policy core: it must never import ``doberman.proxy``.
"""

import logging
from datetime import datetime, timedelta, timezone

from doberman.auth.challenge import Prompter
from doberman.config import load_preferences, save_preferences
from doberman.models import ReasonCode, SecurityObject
from doberman.policy.drift import ChangeOutcome, apply_change
from doberman.policy.preferences import PreferenceVector, care_contributions
from doberman.storage.db import open_db

logger = logging.getLogger("doberman.subjective.revealed")

#: Decisions per dimension before any nudge is even considered.
MIN_SAMPLES = 20

#: Bounded nudge size per attempt.
STEP = 0.05

#: Hysteresis band around the 50% approve rate: inside it, no nudge (prevents
#: oscillation on an ambivalent operator).
HYSTERESIS = 0.1

#: Scope-token lifetime ("approve for this task"). Session-only: tokens live
#: in process memory and die with the proxy, whatever the TTL.
SCOPE_TOKEN_TTL_SECONDS = 900

#: The preference dimensions revealed learning may touch (interruption
#: tolerance is deliberately excluded — the fatigue dial stays declared-only).
_LEARNABLE_DIMENSIONS = ("confidentiality", "reversibility", "blast_radius")

#: A unit vector: contribution > 0 means the action exercises that dimension.
_PROBE = PreferenceVector(
    confidentiality=1.0, reversibility=1.0, interruption_tolerance=0.5, blast_radius=1.0
)

_UPSERT_FEEDBACK = (
    "INSERT INTO preference_feedback "
    "(entity_id, dimension, approvals, denials, updated_at, last_touched) "
    "VALUES (?, ?, ?, ?, ?, ?) "
    "ON CONFLICT(entity_id, dimension) DO UPDATE SET "
    "approvals = approvals + excluded.approvals, denials = denials + excluded.denials, "
    "updated_at = excluded.updated_at, last_touched = excluded.last_touched"
)

#: In-process scope tokens: (entity_id, algebra_point) → expiry. Never persisted.
_SCOPE_TOKENS: dict[tuple[str, str], datetime] = {}


def _exercised_dimensions(action: SecurityObject) -> list[str]:
    """The learnable dimensions this action actually exercises."""
    contributions = care_contributions(_PROBE, action.algebra, action.reversibility)
    return [d for d in _LEARNABLE_DIMENSIONS if contributions.get(d, 0.0) > 0.0]


async def record_feedback(
    action: SecurityObject,
    approved: bool,
    *,
    entity_id: str,
    repo_root: str,
    now: datetime | None = None,
) -> None:
    """Record one approve/deny outcome against the action's algebra point.

    Best-effort, never raises — feedback is learning data, not a decision.
    """
    stamp = (now or datetime.now(timezone.utc)).isoformat()
    dimensions = _exercised_dimensions(action)
    if not dimensions:
        return
    try:
        async with open_db(repo_root) as conn:
            for dimension in dimensions:
                await conn.execute(
                    _UPSERT_FEEDBACK,
                    (entity_id, dimension, int(approved), int(not approved), stamp, stamp),
                )
            await conn.commit()
    except Exception:  # noqa: BLE001 — learning must never break the execution path
        logger.warning("preference feedback write failed (entity %s); continuing", entity_id[:12])


async def _feedback_rates(entity_id: str, repo_root: str) -> dict[str, tuple[int, int]]:
    try:
        async with open_db(repo_root) as conn:
            async with conn.execute(
                "SELECT dimension, approvals, denials FROM preference_feedback WHERE entity_id = ?",
                (entity_id,),
            ) as cur:
                rows = await cur.fetchall()
    except Exception:  # noqa: BLE001 — a read failure simply means no nudge
        return {}
    return {str(r[0]): (int(r[1]), int(r[2])) for r in rows}


async def _record_guard_block(entity_id: str, repo_root: str, now: datetime | None) -> None:
    """Surface a guard-blocked proposal for review (redacted, best-effort)."""
    stamp = (now or datetime.now(timezone.utc)).isoformat()
    try:
        async with open_db(repo_root) as conn:
            await conn.execute(
                "INSERT INTO score_history (entity_id, ts, kind, value, last_touched) "
                "VALUES (?, ?, ?, ?, ?)",
                (entity_id, stamp, "martingale_review", 1.0, stamp),
            )
            await conn.commit()
    except Exception:  # noqa: BLE001 — best-effort surfacing
        logger.warning("guard-block record failed (entity %s)", entity_id[:12])


async def _reset_feedback(entity_id: str, dimensions: list[str], repo_root: str) -> None:
    """Zero the counters after a nudge attempt — evidence is never reused."""
    try:
        async with open_db(repo_root) as conn:
            for dimension in dimensions:
                await conn.execute(
                    "DELETE FROM preference_feedback WHERE entity_id = ? AND dimension = ?",
                    (entity_id, dimension),
                )
            await conn.commit()
    except Exception:  # noqa: BLE001 — best-effort hygiene
        logger.warning("preference feedback reset failed (entity %s)", entity_id[:12])


def _proposed_changes(
    rates: dict[str, tuple[int, int]], current: PreferenceVector
) -> dict[str, float]:
    """Bounded per-dimension weight proposals from the observed tolerance."""
    proposals: dict[str, float] = {}
    for dimension in _LEARNABLE_DIMENSIONS:
        approvals, denials = rates.get(dimension, (0, 0))
        total = approvals + denials
        if total < MIN_SAMPLES:
            continue
        approve_rate = approvals / total
        weight = getattr(current, dimension)
        if approve_rate >= 0.5 + HYSTERESIS:
            proposals[dimension] = max(0.0, round(weight - STEP, 4))  # comfort: fewer asks
        elif approve_rate <= 0.5 - HYSTERESIS:
            proposals[dimension] = min(1.0, round(weight + STEP, 4))  # pushback: tighten
    return {d: w for d, w in proposals.items() if w != getattr(current, d)}


def _gate_states(
    current: PreferenceVector, proposals: dict[str, float]
) -> tuple[dict[str, str], dict[str, str]]:
    """Map weight changes onto the F10 gate's protection ranks.

    A weight DECREASE reduces subjective ask-propensity ⇒ ``auth → allow``
    (classified weaken, 2FA-gated); an INCREASE ⇒ ``auth → block``
    (strengthen, auto-applied). Documented adapter — the gate's ranker only
    understands protection states, not floats.
    """
    before: dict[str, str] = {}
    after: dict[str, str] = {}
    for dimension, proposed in proposals.items():
        key = f"pref.{dimension}"
        before[key] = "auth"
        after[key] = "allow" if proposed < getattr(current, dimension) else "block"
    return before, after


async def maybe_nudge(
    *,
    entity_id: str,
    repo_root: str,
    prompter: Prompter | None = None,
    now: datetime | None = None,
) -> PreferenceVector | None:
    """Propose and (if approved) apply bounded weight nudges from feedback.

    Returns the new vector when a change was applied, else ``None``. Two
    layers gate every proposal: the SL8.2 **Martingale self-improvement
    guard** blocks updates whose driving belief stream is entrenched or too
    short (regardless of direction), then every weakening goes through
    :func:`apply_change` (diff + 2FA + append-only ledger, denied attempts
    included); strengthenings auto-apply. Counters for the involved dimensions
    reset after the attempt either way.
    """
    from doberman.subjective.martingale import guard_self_update, read_beliefs

    rates = await _feedback_rates(entity_id, repo_root)
    current = load_preferences(repo_root)
    proposals = _proposed_changes(rates, current)
    if not proposals:
        return None

    beliefs = await read_beliefs(entity_id, repo_root=repo_root)
    guard = guard_self_update(beliefs)
    if not guard.allowed:
        logger.warning(
            "preference nudge blocked by the self-improvement guard (entity %s): %s",
            entity_id[:12],
            guard.reason,
        )
        await _record_guard_block(entity_id, repo_root, now)
        await _reset_feedback(entity_id, list(proposals), repo_root)
        return None

    before, after = _gate_states(current, proposals)
    try:
        outcome: ChangeOutcome = await apply_change(
            before,
            after,
            f"revealed-preference nudge from {sum(sum(v) for v in rates.values())} decisions",
            repo_root=repo_root,
            prompter=prompter,
            now=now,
        )
    except Exception:  # noqa: BLE001 — a gate failure means NO change (fail closed)
        logger.warning("preference nudge gate failed (entity %s); keeping weights", entity_id[:12])
        await _reset_feedback(entity_id, list(proposals), repo_root)
        return None

    await _reset_feedback(entity_id, list(proposals), repo_root)
    if not outcome.approved:
        return None
    updated = current
    for dimension, weight in proposals.items():
        updated = updated.with_weight(dimension, weight)
    save_preferences(updated, repo_root, ledger_ts=outcome.ts)
    return updated


# --- scope tokens ("approve for this task") ---------------------------------------


def algebra_point(action: SecurityObject) -> str:
    """The class-level identity a scope token binds to (never a raw value)."""
    algebra = action.algebra
    return (
        f"{action.tool_name}|{algebra.capability}|{algebra.target_class}"
        f"|{algebra.destination_class}|{algebra.blast_radius}"
    )


def grant_scope_token(
    action: SecurityObject,
    decision_reasons: list[ReasonCode],
    *,
    entity_id: str,
    now: datetime | None = None,
) -> bool:
    """Grant a TTL-bounded, session-only token for this exact algebra point.

    REFUSED outright for a lethal-trifecta step-up — the floor is untouchable
    by every comfort mechanism. Returns whether a token was granted.
    """
    if ReasonCode.lethal_trifecta in decision_reasons:
        return False
    when = now or datetime.now(timezone.utc)
    _SCOPE_TOKENS[(entity_id, algebra_point(action))] = when + timedelta(
        seconds=SCOPE_TOKEN_TTL_SECONDS
    )
    return True


def has_scope_token(action: SecurityObject, *, entity_id: str, now: datetime | None = None) -> bool:
    """Whether a live token covers this action's algebra point (expired pruned)."""
    when = now or datetime.now(timezone.utc)
    key = (entity_id, algebra_point(action))
    expiry = _SCOPE_TOKENS.get(key)
    if expiry is None:
        return False
    if expiry <= when:
        _SCOPE_TOKENS.pop(key, None)
        return False
    return True


def clear_scope_tokens() -> None:
    """Drop every in-process token (tests / session teardown)."""
    _SCOPE_TOKENS.clear()


def revoke_tool_scope_tokens(tool_name: str) -> int:
    """Drop every entity's live tokens for one tool (pinned-schema change).

    A token is comfort granted for a tool as it was pinned; once the tool's
    advertised contract changes, that comfort must not mute the step-up on the
    new contract. Revoking only tightens (raise-only), so no gate. Returns the
    number of tokens dropped. Tokens bind to ``tool_name|<algebra>`` keys, so a
    prefix match is exact per tool.
    """
    prefix = f"{tool_name}|"
    doomed = [key for key in _SCOPE_TOKENS if key[1].startswith(prefix)]
    for key in doomed:
        _SCOPE_TOKENS.pop(key, None)
    return len(doomed)
