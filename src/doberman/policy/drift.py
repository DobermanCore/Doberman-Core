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
* :func:`apply_enforcement_change` — the same chokepoint for the orthogonal
  enforcement dial (enforce / monitor / off): softening is gated (confirm +
  TOTP-if-enrolled), re-arming applies automatically.
* :func:`effective_enforcement` — the **read-side** clamp: turns the on-disk
  enforcement fields into the state to act on, verifying them against the ledger
  so a hand-edit of ``policies.yaml`` (e.g. ``enforcement: off``) that bypassed the
  gate is caught and clamped back to ``enforce`` (fail closed). Consumers MUST use
  this instead of reading ``PolicyDoc.enforcement`` directly.
* :func:`log_change` — the audited-but-not-gated path, scope-enforced to the
  strictness ``mode`` dial only.
* :class:`DriftObserver` — the enterprise seam (org-wide drift monitoring /
  compliance). Observers receive **redacted** events and can **never** approve or
  suppress a weakening — the 2FA gate is core and authoritative. The free-text
  ``reason`` on every event (and every ledger row) is scrubbed of secret-shaped
  substrings and length-capped by :func:`_redact_reason` before it is ever
  recorded or fanned out — a pasted token in a reason must never reach the
  ledger or an observer.

This module is policy core: it may import ``doberman.auth`` / ``doberman.storage``
/ ``doberman.engine`` (secret-detection reuse only) but never ``doberman.proxy``.
"""

import logging
import re
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
    # "enforce" outranks _UNKNOWN_TOKEN_RANK (2) so enforce → <unrecognized/typo state>
    # classifies as a weaken (gated), never neutral. Consumers must treat an
    # unrecognized enforcement value as "enforce" (fail closed).
    "enforce": 3,
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


#: A `reason` is free text supplied by whatever triggered the policy change — it
#: is never trusted and must never carry a secret into the ledger. Cap length so
#: the ledger (a decision record, not a payload store) can't be used to smuggle a
#: huge blob either.
_REASON_MAX_CHARS = 300
_HIGH_ENTROPY_CANDIDATE = re.compile(r"[A-Za-z0-9+/=_\-]{24,}")


def _redact_reason(reason: str) -> str:
    """Scrub a free-text ``reason`` before it reaches the ledger or an observer.

    Reuses the credential-pattern and high-entropy-token detectors from
    :mod:`doberman.engine.rules.secrets` (imported lazily to avoid a module-load
    cycle, matching the pattern already used by :func:`notify_observers`):
    every known credential shape is replaced outright, and every long
    high-entropy token is replaced if it looks secret-shaped. The result is then
    capped at ``_REASON_MAX_CHARS``. Fails safe: any internal error returns a
    fixed placeholder — never the raw ``reason`` — and never raises.
    """
    if not reason:
        return reason
    try:
        from doberman.engine.rules.secrets import _CREDENTIAL_PATTERNS, _looks_high_entropy_secret

        scrubbed = reason
        for pattern in _CREDENTIAL_PATTERNS:
            scrubbed = pattern.sub("[redacted]", scrubbed)

        def _scrub_candidate(match: re.Match[str]) -> str:
            token = match.group(0)
            return "[redacted]" if _looks_high_entropy_secret(token) else token

        scrubbed = _HIGH_ENTROPY_CANDIDATE.sub(_scrub_candidate, scrubbed)
        if len(scrubbed) > _REASON_MAX_CHARS:
            scrubbed = scrubbed[:_REASON_MAX_CHARS] + "…"
        return scrubbed
    except Exception:  # noqa: BLE001 — never leak the raw reason on any failure
        return "[reason redaction failed]"


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
    reason = _redact_reason(reason)
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

    Scope is enforced, not just documented: any changed key other than ``mode``
    raises ``ValueError`` (fail closed — nothing recorded, nothing approved), so
    this path can never be miswired into rubber-stamping a rule/role weakening.
    """
    reason = _redact_reason(reason)
    extra = set(_changed_keys(before, after)) - {"mode"}
    if extra:
        raise ValueError(
            "log_change is scoped to the strictness-mode dial; route "
            f"{sorted(extra)} through apply_change/apply_enforcement_change instead"
        )
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


def _expiry_extended(before: dict, after: dict) -> bool:
    """True when the auto-revert deadline moved later (both sides numeric)."""
    b = before.get("enforcement_expires_at")
    a = after.get("enforcement_expires_at")
    return isinstance(b, (int, float)) and isinstance(a, (int, float)) and float(a) > float(b)


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
    reason = _redact_reason(reason)
    when = now or datetime.now(timezone.utc)
    classification = classify_change(before, after)
    # Extending a softened state's auto-revert deadline keeps protection down for
    # longer — but rank comparison sees two unknown floats as neutral. Upgrade it
    # to a weaken explicitly so the timer can't be pushed out ungated (fail safe).
    if (
        classification is not Classification.weaken
        and str(after.get("enforcement", "enforce")).strip().lower() != "enforce"
        and _expiry_extended(before, after)
    ):
        classification = Classification.weaken
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


# --- Read-side tamper clamp (#81) ----------------------------------------


def _last_approved_to_state(rows: list[dict], rule_id: str) -> str | None:
    """The ``to_state`` of the most recent APPROVED ledger row for ``rule_id``.

    ``rows`` are newest-first (as :func:`read_policy_changes` returns them), so the
    first approved match is the most recent. ``None`` when no approved row exists.
    ``approved`` is stored as ``int(bool)`` — an approved row is ``1``.
    """
    for row in rows:
        if row.get("rule_id") == rule_id and row.get("approved") == 1:
            return row.get("to_state")
    return None


def _ledger_confirms(rows: list[dict], state: str, expires_at: float | None, revert: str) -> bool:
    """True iff the on-disk enforcement fields match the last ledger-APPROVED values.

    The on-disk soften is legitimate only if the gate approved *this* exact state:
    the most recent approved ``enforcement`` row's ``to_state`` must equal the
    on-disk ``state``, the expiry must match in **both** directions (hand-deleting
    ``enforcement_expires_at`` from the yaml would turn an approved *temporary*
    soften into a permanent one — a weaken), and a non-default ``enforcement_revert``
    must match its approved row. Absent-from-ledger while present-on-disk = mismatch
    (a soften that never went through the gate).

    Comparisons use the exact strings :func:`_record_change` stored: it writes
    ``str(after[key])``, so a float epoch lands as ``str(float)`` (e.g.
    ``"1700000000.0"``) — hence ``str(expires_at)`` here. A cleared / never-set
    expiry appears in the ledger as no row, ``"None"`` (``str(None)``), or
    ``"(absent)"`` (the absent-key sentinel) — all three mean "no expiry approved".
    """
    if _last_approved_to_state(rows, "enforcement") != state:
        return False
    ledger_expiry = _last_approved_to_state(rows, "enforcement_expires_at")
    if ledger_expiry in ("None", "(absent)"):
        ledger_expiry = None
    if ledger_expiry != (None if expires_at is None else str(expires_at)):
        return False
    # revert defaults to "enforce" (the strongest target); only a non-default revert
    # needs a matching approved row — a default one can never weaken the outcome.
    if revert != "enforce" and _last_approved_to_state(rows, "enforcement_revert") != revert:
        return False
    return True


def _emit_tamper_anomaly(on_disk_state: str, now: datetime | None) -> None:
    """Best-effort anomaly for a suspected on-disk enforcement tamper.

    Emits a redacted observer event + a ``logger.warning``. It writes **no ledger
    row**: the ledger records *changes the gate approved*, and this is a read-side
    clamp — recording it would forge a "change" that never happened and pollute the
    append-only history. Must never raise and never influence the caller's return.
    """
    logger.warning(
        "enforcement tamper suspected: on-disk state %r has no matching ledger-approved "
        "row; clamped to enforce",
        on_disk_state,
    )
    try:
        notify_observers(
            {
                "ts": (now or datetime.now(timezone.utc)).isoformat(),
                "event": "enforcement_tamper_suspected",
                "on_disk": on_disk_state,
                "reason": "on-disk enforcement does not match the last ledger-approved "
                "state; clamped to enforce",
            }
        )
    except Exception:  # noqa: BLE001, S110 — anomaly emission can never break the clamp
        pass


async def effective_enforcement(
    repo_root: str,
    *,
    enforcement: str,
    expires_at: float | None = None,
    revert: str = "enforce",
    now: datetime | None = None,
) -> str:
    """The single sanctioned way to turn on-disk enforcement fields into the state to act on.

    This clamp protects the mediated path's gate from **on-disk tampering**: once the
    engine honors ``enforcement``, hand-editing ``.doberman/policies.yaml`` to
    ``enforcement: off`` would silently bypass the whole :func:`apply_enforcement_change`
    gate. So a soften (``monitor``/``off``) is honored **only** when the append-only
    ledger holds a matching APPROVED change for it; anything else is clamped back to
    ``enforce``. It is **raise-only** — it can only ever return a state at least as
    strong (in protection terms) as the on-disk claim, never weaker — so consumers
    MUST call this instead of reading :attr:`PolicyDoc.enforcement` directly.

    Order:
      1. ``enforce`` returns immediately with no I/O (the common case stays free); an
         unrecognized value returns ``enforce`` (consumer contract: unrecognized ⇒
         enforce) plus an anomaly.
      2. Ledger cross-check: the on-disk state (and any expiry/revert) must equal the
         most recent approved ledger values, else it is treated as tampering.
      3. Timer: a verified soften past ``expires_at`` reverts to the verified
         ``revert`` target (clamped to ``enforce`` if that would be weaker).
      4. Any mismatch / missing ledger / unexpected error ⇒ ``enforce`` (fail closed)
         + a best-effort anomaly.
    """
    state = str(enforcement).strip().lower()
    # Common path: on-disk claims full enforcement — nothing to soften, nothing to
    # verify. Return with zero I/O (this runs on every mediated action).
    if state == "enforce":
        return "enforce"
    # Unrecognized/garbage on disk ⇒ enforce (consumer contract from #72) — and a
    # corrupt enforcement value is itself suspicious, so raise an anomaly.
    if state not in {"monitor", "off"}:
        _emit_tamper_anomaly(state, now)
        return "enforce"
    try:
        rows = await read_policy_changes(repo_root)
        if not _ledger_confirms(rows, state, expires_at, revert):
            _emit_tamper_anomaly(state, now)
            return "enforce"
        # The soften is ledger-legitimate. Honor its timer: once past the deadline it
        # has expired and reverts. A revert target weaker than the current state (e.g.
        # "off") would *lower* protection on expiry — clamp any non-{enforce,monitor}
        # revert up to enforce (raise-only).
        when = now or datetime.now(timezone.utc)
        if expires_at is not None and when.timestamp() >= expires_at:
            return revert if revert in {"enforce", "monitor"} else "enforce"
        return state
    except Exception:  # noqa: BLE001 — any unexpected error fails closed to enforce
        _emit_tamper_anomaly(state, now)
        return "enforce"


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
