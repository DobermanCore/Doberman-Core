"""Policy-drift detection & poisoning defense (Feature 10).

The thesis flags **policy poisoning** — the slow erosion of protection over time
— as a top weakness. Learning and edits may *tighten* freely, but any
**weakening** must be deliberate: classified, gated behind strong auth with a
visible diff, and recorded in an append-only ledger. This module is that
mechanism (a core safety invariant):

* :func:`classify_change` — labels a proposed change ``strengthen`` /
  ``weaken`` / ``neutral``. **Ambiguous or mixed → weaken** (fail safe).
* :func:`apply_change` — the **single chokepoint**: a weakening requires a
  ``two_factor`` confirmation against a rendered Before/After diff and is applied
  only on approval; strengthening/neutral changes apply (still logged). Every
  attempt — including denials (the attack signal) — is written to the ledger and
  fanned out to registered :class:`DriftObserver` s.
* :class:`DriftObserver` — the enterprise seam (org-wide drift monitoring /
  compliance). Observers receive **redacted** events and can **never** approve or
  suppress a weakening — the 2FA gate is core and authoritative.

This module is policy core: it may import ``doberman.auth`` / ``doberman.storage``
but never ``doberman.proxy``.
"""

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from typing import Protocol, runtime_checkable

from doberman.auth import totp
from doberman.auth.challenge import Prompter
from doberman.storage.db import db_path, open_db

logger = logging.getLogger("doberman.policy.drift")


class Classification(StrEnum):
    """How a proposed policy change affects protection."""

    strengthen = "strengthen"
    weaken = "weaken"
    neutral = "neutral"


#: Protection rank of a policy state token (higher = stronger protection). A
#: weakening is any move DOWN this scale (or removing a protective entry). Unknown
#: tokens rank as ``auth`` (mid) — conservative, never treated as "no protection".
_RANK: dict[str, int] = {
    "block": 3,
    "hard_block": 3,
    "blocked": 3,
    "protected": 3,
    "deny": 3,
    "auth": 2,
    "sensitive": 2,
    "step_up": 2,
    "unknown": 2,
    "on": 2,
    "enabled": 2,
    "true": 2,
    "allow": 1,
    "normal": 1,
    "trusted": 1,
    "pass": 1,
    # Strictness modes — so a `mode` downgrade (e.g. strict→light) classifies as a
    # weaken rather than silently as neutral. Stricter = higher.
    "paranoid": 4,
    "strict": 3,
    "balanced": 2,
    "light": 1,
    # Orthogonal enforcement states: enforce > monitor > off (off shares the 0 below).
    "enforce": 2,
    "monitor": 1,
    "off": 0,
    "disabled": 0,
    "false": 0,
    "none": 0,
    "absent": 0,
}

#: Rank used when a key is absent from a side of the diff (no entry = no protection).
_ABSENT_RANK = 0
#: Rank for an unrecognized token (treat as needs-auth — never "no protection").
_UNKNOWN_TOKEN_RANK = 2


def _rank(value: object) -> int:
    if value is None:
        return _ABSENT_RANK
    if isinstance(value, bool):
        return 2 if value else 0
    return _RANK.get(str(value).strip().lower(), _UNKNOWN_TOKEN_RANK)


def classify_change(before: dict, after: dict) -> Classification:
    """Classify a policy change as strengthen / weaken / neutral.

    Compares two ``{rule_id: state}`` mappings by protection rank. **Any**
    weakening (a rule moved to a weaker state, or a protective entry removed)
    makes the whole change a ``weaken`` — even if other rules strengthened
    (mixed → weaken, fail safe). Only-strengthening → ``strengthen``; identical →
    ``neutral``.
    """
    weakened = False
    strengthened = False
    for key in set(before) | set(after):
        before_rank = _rank(before[key]) if key in before else _ABSENT_RANK
        after_rank = _rank(after[key]) if key in after else _ABSENT_RANK
        if after_rank < before_rank:
            weakened = True
        elif after_rank > before_rank:
            strengthened = True
    if weakened:
        return Classification.weaken
    if strengthened:
        return Classification.strengthen
    return Classification.neutral


@dataclass(frozen=True)
class ChangeOutcome:
    """The result of routing a change through :func:`apply_change`."""

    classification: Classification
    approved: bool
    method: str


def _changed_keys(before: dict, after: dict) -> list[str]:
    return sorted(k for k in set(before) | set(after) if before.get(k) != after.get(k))


def _render_diff(before: dict, after: dict, reason: str) -> str:
    """A human-readable Before/After diff for the weaken confirmation (no secrets)."""
    lines = ["Doberman policy WEAKENING requested — review carefully:"]
    for key in _changed_keys(before, after):
        lines.append(f"  {key}: {before.get(key, '(absent)')} → {after.get(key, '(absent)')}")
    lines.append(f"Reason: {reason or '(none given)'}")
    return "\n".join(lines)


def _run_weaken_gate(
    before: dict, after: dict, reason: str, prompter: Prompter
) -> tuple[bool, str]:
    """Require presence + a valid TOTP code to approve a weakening. Fails closed."""
    try:
        if not prompter.confirm(_render_diff(before, after, reason)):
            return False, "denied"
        code = prompter.read_code("Enter your 2FA code to authorize this policy weakening")
        if totp.verify(code):
            return True, "two_factor"
        return False, "denied"
    except Exception:  # noqa: BLE001 — any input/timeout error denies the weakening
        return False, "denied"


_INSERT_CHANGE = (
    "INSERT INTO policy_changes "
    "(ts, rule_id, from_state, to_state, classification, reason, approval_method, "
    "approved, approved_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
)


async def _record_change(
    repo_root: str,
    before: dict,
    after: dict,
    classification: Classification,
    reason: str,
    *,
    approved: bool,
    method: str,
    now: datetime,
) -> None:
    """Append one ledger row per changed rule (best-effort; never raises)."""
    approved_by = "local" if approved else None
    ts = now.isoformat()
    try:
        async with open_db(repo_root) as conn:
            for key in _changed_keys(before, after):
                await conn.execute(
                    _INSERT_CHANGE,
                    (
                        ts,
                        key,
                        str(before.get(key, "(absent)")),
                        str(after.get(key, "(absent)")),
                        classification.value,
                        reason,
                        method,
                        int(approved),
                        approved_by,
                    ),
                )
            await conn.commit()
    except Exception:  # noqa: BLE001 — ledger failure must not crash the edit path
        logger.warning("policy-change ledger write failed; continuing")


async def apply_change(
    before: dict,
    after: dict,
    reason: str,
    *,
    repo_root: str,
    prompter: Prompter | None = None,
    now: datetime | None = None,
) -> ChangeOutcome:
    """The single chokepoint for a policy change. Returns the outcome.

    A **weaken** is gated behind a 2FA confirmation of a rendered diff and is
    approved only on success; a **strengthen**/**neutral** applies automatically.
    Every attempt (incl. denials) is written to the append-only ledger and fanned
    out to registered drift observers. The caller persists the new policy **only
    when** ``outcome.approved`` is True — this function decides, records, and
    notifies; it never weakens silently.
    """
    when = now or datetime.now(timezone.utc)
    classification = classify_change(before, after)

    if classification is Classification.weaken:
        from doberman.auth.provider import CliPrompter

        approved, method = _run_weaken_gate(before, after, reason, prompter or CliPrompter())
    else:
        approved, method = True, "auto"

    await _record_change(
        repo_root,
        before,
        after,
        classification,
        reason,
        approved=approved,
        method=method,
        now=when,
    )
    notify_observers(
        {
            "ts": when.isoformat(),
            "classification": classification.value,
            "changed_rules": _changed_keys(before, after),
            "reason": reason,
            "approved": approved,
            "method": method,
        }
    )
    return ChangeOutcome(classification=classification, approved=approved, method=method)


async def log_change(
    before: dict,
    after: dict,
    reason: str,
    *,
    repo_root: str,
    now: datetime | None = None,
) -> ChangeOutcome:
    """Record a user-initiated, **audited but not 2FA-gated** policy change.

    For changes the operator has chosen to make frictionless yet auditable — the
    strictness-mode dial (light↔paranoid). The change is classified and written to
    the append-only ledger (``method="logged"``) and applied by the caller; a
    weakening is recorded as such (never hidden) but is not gated. This is a
    separate, explicitly-chosen audit-only path and does NOT relax the general
    :func:`apply_change` weaken-gate (policy/role weakenings still require 2FA).
    The dramatic enforcement-disable uses :func:`apply_enforcement_change`.
    """
    when = now or datetime.now(timezone.utc)
    classification = classify_change(before, after)
    await _record_change(
        repo_root,
        before,
        after,
        classification,
        reason,
        approved=True,
        method="logged",
        now=when,
    )
    notify_observers(
        {
            "ts": when.isoformat(),
            "classification": classification.value,
            "changed_rules": _changed_keys(before, after),
            "reason": reason,
            "approved": True,
            "method": "logged",
        }
    )
    return ChangeOutcome(classification=classification, approved=True, method="logged")


def _run_enforcement_gate(
    before: dict, after: dict, reason: str, prompter: Prompter
) -> tuple[bool, str]:
    """Gate softening/disabling enforcement: confirm, plus TOTP **only if enrolled**.

    Disabling Doberman is a deliberate operator action that must be confirmed and
    audited — but, unlike a policy-rule weakening, must not be made *impossible* for
    a user who never set up 2FA (that would put the safety valve out of reach). So
    we require a 2FA code when one is enrolled and fall back to an explicit
    confirmation when it is not. Scoped to the enforcement toggle: it does NOT relax
    :func:`_run_weaken_gate` (policy/role weakenings still require 2FA). Fails closed.
    """
    try:
        if not prompter.confirm(_render_diff(before, after, reason)):
            return False, "denied"
        if totp.is_enrolled():
            code = prompter.read_code("Enter your 2FA code to authorize softening enforcement")
            if not totp.verify(code):
                return False, "denied"
            return True, "two_factor"
        return True, "confirmed"
    except Exception:  # noqa: BLE001 — any input/timeout error denies the change
        return False, "denied"


async def apply_enforcement_change(
    before: dict,
    after: dict,
    reason: str,
    *,
    repo_root: str,
    prompter: Prompter | None = None,
    now: datetime | None = None,
) -> ChangeOutcome:
    """Chokepoint for an enforcement-state change (enforce / monitor / off).

    Softening (enforce→monitor/off) is gated by :func:`_run_enforcement_gate`
    (confirm + 2FA-if-enrolled); re-arming (→enforce) is a strengthen and applies
    automatically. Every attempt — including denials — is recorded to the
    append-only ledger and fanned out to observers; the caller persists only when
    ``approved`` is True.
    """
    when = now or datetime.now(timezone.utc)
    classification = classify_change(before, after)
    if classification is Classification.weaken:
        from doberman.auth.provider import CliPrompter

        approved, method = _run_enforcement_gate(before, after, reason, prompter or CliPrompter())
    else:
        approved, method = True, "auto"
    await _record_change(
        repo_root,
        before,
        after,
        classification,
        reason,
        approved=approved,
        method=method,
        now=when,
    )
    notify_observers(
        {
            "ts": when.isoformat(),
            "classification": classification.value,
            "changed_rules": _changed_keys(before, after),
            "reason": reason,
            "approved": approved,
            "method": method,
        }
    )
    return ChangeOutcome(classification=classification, approved=approved, method=method)


async def read_policy_changes(repo_root: str, *, limit: int | None = None) -> list[dict]:
    """Read ledger rows, newest first (for ``doberman policy-history``)."""
    if not db_path(repo_root).exists():
        return []
    query = (
        "SELECT ts, rule_id, from_state, to_state, classification, reason, "
        "approval_method, approved, approved_by FROM policy_changes ORDER BY id DESC"
    )
    if limit:
        query += f" LIMIT {int(limit)}"
    cols = [
        "ts",
        "rule_id",
        "from_state",
        "to_state",
        "classification",
        "reason",
        "approval_method",
        "approved",
        "approved_by",
    ]
    try:
        async with open_db(repo_root) as conn:
            async with conn.execute(query) as cur:
                rows = await cur.fetchall()
    except Exception:  # noqa: BLE001 — a read failure must never crash the CLI
        return []
    return [dict(zip(cols, row, strict=True)) for row in rows]


# --- DriftObserver seam (slice 10.4) -------------------------------------


@runtime_checkable
class DriftObserver(Protocol):
    """Receives **redacted** policy-change events (org-wide monitoring seam).

    Implementations live in installed packages registered via the
    ``doberman.drift_observers`` entry-point group. ``on_change`` is purely
    observational: it can never approve, suppress, or alter a weakening (the 2FA
    gate is core and authoritative) and must not raise into the caller.
    """

    def on_change(self, event: dict) -> None: ...


def _looks_like_drift_observer(obj: object) -> bool:
    """Structural check (the Protocol's isinstance is method-name only)."""
    return callable(getattr(obj, "on_change", None))


def notify_observers(event: dict) -> None:
    """Fan a **redacted** drift event out to every registered observer, isolated.

    Never raises and never affects the gate: observers are notified *after* the
    authoritative decision is made and the ledger written. A non-observer-shaped
    or raising observer is logged and skipped. With none installed this is a
    no-op.
    """
    from doberman.engine.registry import discover_drift_observers

    for observer in discover_drift_observers():
        if not _looks_like_drift_observer(observer):
            logger.warning("skipping drift observer %r: not observer-shaped", observer)
            continue
        try:
            observer.on_change(dict(event))
        except Exception:  # noqa: BLE001 — an observer can never break the gate
            logger.warning("drift observer %r raised; skipping", type(observer).__name__)
