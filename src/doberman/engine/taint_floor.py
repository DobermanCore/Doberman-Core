"""HK.5.2 / 5.2b — the cross-call, taint-primary multi-step exfiltration floor.

Extracted (H2a, behavior-preserving) from the Claude Code host-hook adapter so
both host-hook adapters and the pure-MCP proxy can share it (the proxy wiring
itself is H2b — not this slice). See :func:`apply_taint_floor` for the
mechanism.
"""

from __future__ import annotations

from typing import Any

from doberman.engine.decision_engine import max_risk, max_verdict
from doberman.models import Decision, ReasonCode, Risk, SecurityObject, Verdict

#: HK.5.2 taint floor: modes where a tainted-session egress is BLOCKed outright
#: rather than AUTH'd. Mirrors the lethal-trifecta hard block (ADR 0021): raise-only,
#: strictest modes only — light/balanced keep the human in the loop.
_STRICT_MODES: frozenset[str] = frozenset({"strict", "paranoid"})
_FLOOR_EXPLANATION = (
    "A secret entered this session's context earlier; this egress is a potential "
    "multi-step exfiltration."
)
_CONFIRMED_EXFIL_EXPLANATION = (
    "An outbound value matches a secret that entered this session's context earlier "
    "— a confirmed read-then-send exfiltration."
)


def apply_taint_floor(
    action: SecurityObject,
    decision: Decision,
    mode: str,
    repo_root: str,
    session_id: str | None,
    args: dict[str, Any],
) -> Decision:
    """HK.5.2 / 5.2b — the taint-primary multi-step exfiltration floor (raise-only).

    The objective floor judges each call in isolation, so a cross-call exfil —
    read a secret in call N (HK.5.1 records ``secret_access`` taint), then send it
    in call M whose own payload looks clean — slips through. When THIS action is an
    egress and the session already holds ``secret_access`` taint, raise the verdict:
    ``AUTH`` in light/balanced (human-in-the-loop) or ``BLOCK`` in strict/paranoid,
    mirroring the single-call lethal-trifecta floor (ADR 0021/0024). **Raise-only** —
    it never lowers a verdict or risk. Best-effort and light: one SQLite taint read,
    only on the egress path, and any failure leaves the objective decision untouched.

    Scope note: the egress signal is ``action.external_destination`` (what
    ``normalize`` recognises — WebFetch, network requests, domain/MCP egress tools).
    Deep Bash-command egress parsing is HK.5.6; entropy-on-egress and the read-vs-send
    fingerprint match (→ confirmatory BLOCK) are HK.5.2b.
    """
    if action.external_destination is None:
        return decision  # not an egress — nothing can leave through this action
    if decision.final_verdict is Verdict.BLOCK:
        return decision  # already maximally raised; skip the reads

    # HK.5.2b — confirmatory read-vs-send match: an outbound token whose keyed-HMAC
    # fingerprint was recorded when a secret entered this session is the SAME secret
    # leaving. A CONFIRMED exfil → hard BLOCK in EVERY mode (highest confidence; not
    # mode-gated like the taint floor below).
    if _outbound_matches_recorded_secret(args, action.external_destination, repo_root, session_id):
        reasons = list(dict.fromkeys([*decision.reason_codes, ReasonCode.confirmed_exfil]))
        explanation = " ".join(
            part for part in (decision.explanation.strip(), _CONFIRMED_EXFIL_EXPLANATION) if part
        )
        return decision.model_copy(
            update={
                "final_verdict": Verdict.BLOCK,
                "final_risk": Risk.critical,
                "reason_codes": reasons,
                "explanation": explanation,
            }
        )

    if not _session_holds_secret(repo_root, session_id):
        return decision

    floor_verdict = Verdict.BLOCK if mode in _STRICT_MODES else Verdict.AUTH
    floor_risk = Risk.critical if floor_verdict is Verdict.BLOCK else Risk.high
    reasons = list(dict.fromkeys([*decision.reason_codes, ReasonCode.multi_step_exfil]))
    explanation = " ".join(
        part for part in (decision.explanation.strip(), _FLOOR_EXPLANATION) if part
    )
    return decision.model_copy(
        update={
            "final_verdict": max_verdict(decision.final_verdict, floor_verdict),
            "final_risk": max_risk(decision.final_risk, floor_risk),
            "reason_codes": reasons,
            "explanation": explanation,
        }
    )


def _session_holds_secret(repo_root: str, session_id: str | None) -> bool:
    """True iff this session has accumulated ``secret_access`` taint (a secret
    entered its context) under the session or entity scope.

    A light SQLite read on the egress path only. On any error it returns ``False`` —
    it never *fabricates* taint (which would AUTH/BLOCK every egress). A degraded
    taint store is the alarm-not-downgrade concern of HK.5.0c, not a place to
    silently escalate here.
    """
    import asyncio  # lazy: keep this module's import light

    from doberman.storage.taint import (  # lazy: light (no numpy/scipy/river)
        TAINT_SECRET_ACCESS,
        entity_scope,
        read_taint,
    )

    scopes: list[str] = [session_id] if session_id else []
    try:
        scopes.append(entity_scope(repo_root))
    except Exception:  # noqa: BLE001,S110 — keep the session scope even if entity scope fails
        pass
    if not scopes:
        return False

    async def _any_secret() -> bool:
        for scope in scopes:
            counts = await read_taint(repo_root, scope)
            if counts.get(TAINT_SECRET_ACCESS, 0) > 0:
                return True
        return False

    try:
        return asyncio.run(_any_secret())
    except Exception:  # noqa: BLE001 — a failed taint read never fabricates a verdict
        return False


def _outbound_secret_fingerprints(args: dict[str, Any], dest: str | None) -> set[str]:
    """Keyed-HMAC fingerprints of secret-candidate tokens anywhere in the outbound
    payload (the call's arguments + its external destination). Light + best-effort;
    the plaintext is never stored or logged."""
    from doberman.engine.rules.secrets import candidate_secret_fingerprints

    fps: set[str] = set()

    def _walk(value: Any) -> None:
        if isinstance(value, str):
            fps.update(candidate_secret_fingerprints(value))
        elif isinstance(value, dict):
            for item in value.values():
                _walk(item)
        elif isinstance(value, (list, tuple)):
            for item in value:
                _walk(item)

    _walk(args)
    if dest:
        fps.update(candidate_secret_fingerprints(dest))
    return fps


def _outbound_matches_recorded_secret(
    args: dict[str, Any], dest: str | None, repo_root: str, session_id: str | None
) -> bool:
    """True iff an outbound token matches a secret fingerprint recorded earlier in
    this session/entity scope (a confirmed read-then-send). One light SQLite read on
    the egress path only — and only when something secret-shaped is actually going
    out. Fails closed to False (never fabricates a match)."""
    fps = _outbound_secret_fingerprints(args, dest)
    if not fps:
        return False  # nothing secret-shaped outbound — skip the DB read

    import asyncio

    from doberman.storage.taint import entity_scope, match_secret_fingerprint

    scopes: list[str] = [session_id] if session_id else []
    try:
        scopes.append(entity_scope(repo_root))
    except Exception:  # noqa: BLE001,S110 — keep the session scope even if entity scope fails
        pass
    if not scopes:
        return False

    fp_list = list(fps)

    async def _any_match() -> bool:
        for scope in scopes:
            if await match_secret_fingerprint(repo_root, scope, fp_list):
                return True
        return False

    try:
        return asyncio.run(_any_match())
    except Exception:  # noqa: BLE001 — a failed match read never fabricates a verdict
        return False
