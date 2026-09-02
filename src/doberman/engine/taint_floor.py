"""HK.5.2 / 5.2b — the cross-call, taint-primary multi-step exfiltration floor.

Extracted (H2a, behavior-preserving) from the Claude Code host-hook adapter so
both host-hook adapters and the pure-MCP proxy (H2b) can share it. The proxy
already runs inside a live event loop, so it awaits :func:`apply_taint_floor_async`
directly; :func:`apply_taint_floor` is a thin sync wrapper (``asyncio.run``)
kept for the sync host-hook call site — calling the sync wrapper from the
async proxy would raise ``RuntimeError: asyncio.run() cannot be called from a
running event loop``, so the two are deliberately not interchangeable.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
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

#: Tools that pull untrusted external content into the agent's context — the
#: "untrusted provenance" leg of the multi-step trifecta AND the C1 echo
#: tripwire's source classification. Lives here (not in hosthooks/) so both the
#: proxy's record_output_taint and every host-hook adapter share one constant;
#: hosthooks/claude_code.py imports it FROM here (engine must never import
#: hosthooks — the reverse direction is fine and already used throughout).
UNTRUSTED_READ_TOOLS: frozenset[str] = frozenset({"WebFetch", "WebSearch"})

_ECHO_EXPLANATION_TEMPLATE = (
    "A destination in this call first appeared in untrusted {source_class} content "
    "read earlier in this session ({when})."
)


async def apply_taint_floor_async(
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

    Async so the MCP proxy — already inside a running event loop — can ``await``
    this directly. See :func:`apply_taint_floor` for the sync host-hook wrapper.
    """
    if action.external_destination is None:
        return decision  # not an egress — nothing can leave through this action
    if decision.final_verdict is Verdict.BLOCK:
        return decision  # already maximally raised; skip the reads

    # HK.5.2b — confirmatory read-vs-send match: an outbound token whose keyed-HMAC
    # fingerprint was recorded when a secret entered this session is the SAME secret
    # leaving. A CONFIRMED exfil → hard BLOCK in EVERY mode (highest confidence; not
    # mode-gated like the taint floor below).
    if await _outbound_matches_recorded_secret(
        args, action.external_destination, repo_root, session_id
    ):
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

    if not await _session_holds_secret(repo_root, session_id):
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


def apply_taint_floor(
    action: SecurityObject,
    decision: Decision,
    mode: str,
    repo_root: str,
    session_id: str | None,
    args: dict[str, Any],
) -> Decision:
    """Sync wrapper around :func:`apply_taint_floor_async` for the host-hook adapter.

    The Claude Code host-hook's ``evaluate_pre``/``evaluate_post`` run outside any
    event loop, so wrapping in ``asyncio.run`` here is safe and keeps that call site
    unchanged. The MCP proxy runs INSIDE a live event loop and must await
    ``apply_taint_floor_async`` directly — calling this sync wrapper there would
    raise ``RuntimeError: asyncio.run() cannot be called from a running event loop``.
    Signature and behavior are otherwise identical.
    """
    return asyncio.run(apply_taint_floor_async(action, decision, mode, repo_root, session_id, args))


async def _session_holds_secret(repo_root: str, session_id: str | None) -> bool:
    """True iff this session has accumulated ``secret_access`` taint (a secret
    entered its context) under the session or entity scope.

    A light SQLite read on the egress path only. On any error it returns ``False`` —
    it never *fabricates* taint (which would AUTH/BLOCK every egress). A degraded
    taint store is the alarm-not-downgrade concern of HK.5.0c, not a place to
    silently escalate here.
    """
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

    try:
        for scope in scopes:
            counts = await read_taint(repo_root, scope)
            if counts.get(TAINT_SECRET_ACCESS, 0) > 0:
                return True
        return False
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


async def _outbound_matches_recorded_secret(
    args: dict[str, Any], dest: str | None, repo_root: str, session_id: str | None
) -> bool:
    """True iff an outbound token matches a secret fingerprint recorded earlier in
    this session/entity scope (a confirmed read-then-send). One light SQLite read on
    the egress path only — and only when something secret-shaped is actually going
    out. Fails closed to False (never fabricates a match)."""
    fps = _outbound_secret_fingerprints(args, dest)
    if not fps:
        return False  # nothing secret-shaped outbound — skip the DB read

    from doberman.storage.taint import entity_scope, match_secret_fingerprint

    scopes: list[str] = [session_id] if session_id else []
    try:
        scopes.append(entity_scope(repo_root))
    except Exception:  # noqa: BLE001,S110 — keep the session scope even if entity scope fails
        pass
    if not scopes:
        return False

    fp_list = list(fps)

    try:
        for scope in scopes:
            if await match_secret_fingerprint(repo_root, scope, fp_list):
                return True
        return False
    except Exception:  # noqa: BLE001 — a failed match read never fabricates a verdict
        return False


def _outbound_untrusted_value_fingerprints(args: dict[str, Any], dest: str | None) -> set[str]:
    """Keyed-HMAC fingerprints of untrusted-value-candidate tokens anywhere in
    the outbound payload (the call's arguments + its external destination).
    Mirrors ``_outbound_secret_fingerprints``'s walk exactly, swapping in the
    C1 host/URL/email extractor."""
    from doberman.engine.rules.provenance_values import untrusted_value_fingerprints

    fps: set[str] = set()

    def _walk(value: Any) -> None:
        if isinstance(value, str):
            fps.update(untrusted_value_fingerprints(value))
        elif isinstance(value, dict):
            for item in value.values():
                _walk(item)
        elif isinstance(value, (list, tuple)):
            for item in value:
                _walk(item)

    _walk(args)
    if dest:
        fps.update(untrusted_value_fingerprints(dest))
    return fps


async def apply_echo_tripwire_async(
    action: SecurityObject,
    decision: Decision,
    mode: str,  # noqa: ARG001 — accepted for call-site symmetry with apply_taint_floor_async;
    # v1 is AUTH-capped in EVERY mode (no mode-gated BLOCK tier — out of scope,
    # see the slice plan's "Out of scope").
    repo_root: str,
    session_id: str | None,
    args: dict[str, Any],
) -> Decision:
    """C1 — the untrusted-value echo tripwire (raise-only, AUTH-capped in v1).

    A host/URL/email that entered this session's context from an untrusted read
    (WebFetch/WebSearch result, issue/PR body — see UNTRUSTED_READ_TOOLS above
    and hosthooks/claude_code.py's PostToolUse recording) and then reappears as
    THIS call's egress destination is a tripwire on EXACT value reuse, not flow
    analysis — no n-gram shingling, no partial match. Whole-value keyed-HMAC
    only. Raise-only: never lowers a verdict/risk, and a storage failure leaves
    the decision untouched (fails closed to no-match, never fabricates one).
    """
    if action.external_destination is None:
        return decision  # not an egress — nothing can leave through this action
    if decision.final_verdict is Verdict.BLOCK:
        return decision  # already maximally raised; skip the read

    fps = _outbound_untrusted_value_fingerprints(args, action.external_destination)
    if not fps:
        return decision  # nothing host/URL/email-shaped outbound — skip the DB read

    from doberman.storage.taint import entity_scope, match_untrusted_value

    scopes: list[str] = [session_id] if session_id else []
    try:
        scopes.append(entity_scope(repo_root))
    except Exception:  # noqa: BLE001,S110 — keep the session scope even if entity scope fails
        pass
    if not scopes:
        return decision

    fp_list = list(fps)
    source_class: str | None = None
    try:
        for scope in scopes:
            source_class = await match_untrusted_value(repo_root, scope, fp_list)
            if source_class:
                break
    except Exception:  # noqa: BLE001 — a failed match read never fabricates a verdict
        return decision
    if not source_class:
        return decision

    reasons = list(dict.fromkeys([*decision.reason_codes, ReasonCode.untrusted_value_echo]))
    when = datetime.now(timezone.utc).strftime("%H:%M UTC")
    explanation_line = _ECHO_EXPLANATION_TEMPLATE.format(source_class=source_class, when=when)
    explanation = " ".join(
        part for part in (decision.explanation.strip(), explanation_line) if part
    )
    return decision.model_copy(
        update={
            "final_verdict": max_verdict(decision.final_verdict, Verdict.AUTH),
            "final_risk": max_risk(decision.final_risk, Risk.high),
            "reason_codes": reasons,
            "explanation": explanation,
        }
    )


def apply_echo_tripwire(
    action: SecurityObject,
    decision: Decision,
    mode: str,
    repo_root: str,
    session_id: str | None,
    args: dict[str, Any],
) -> Decision:
    """Sync wrapper around :func:`apply_echo_tripwire_async` for the host-hook
    spine (``hosthooks/spine.py``) — exactly mirrors :func:`apply_taint_floor`'s
    sync/async split and its same "don't call this from a running event loop"
    hazard. See that function's docstring for why the two are not
    interchangeable.
    """
    return asyncio.run(
        apply_echo_tripwire_async(action, decision, mode, repo_root, session_id, args)
    )


async def record_output_taint(
    output_text: str,
    repo_root: str,
    session_id: str | None = None,
    *,
    tool_name: str | None = None,
) -> None:
    """Best-effort: record taint from a forwarded tool result's output text, for
    the pure-MCP proxy. Mirrors the host-hook's PostToolUse recording
    (``_record_taint`` / ``_record_secret_fingerprints`` /
    ``_record_untrusted_value_fingerprints`` in ``hosthooks/claude_code.py``) so
    a secret OR an untrusted value read through the proxy taints the session
    exactly like one read through the host-hook.

    C1 widening: ``tool_name`` now lets this classify the untrusted-provenance
    leg (``TAINT_UNTRUSTED_READ`` + the host/URL/email VALUE fingerprints) —
    previously this function dropped ``tool_name`` entirely, so the proxy path
    recorded ZERO untrusted-read taint no matter what it fetched. Both legs are
    independent (a clean-of-secrets WebFetch result still records the untrusted
    leg; a secret found via a trusted tool still records the secret leg) and
    each is judged from the text directly (the proxy has no PostToolUse reason-
    code signal the host-hook gates on). Never raises — a recording failure
    must never break the forward/return path — and never fabricates taint
    beyond what was actually found in the text.
    """
    try:
        from doberman.engine.rules.provenance_values import untrusted_value_fingerprints
        from doberman.engine.rules.secrets import candidate_secret_fingerprints
        from doberman.storage.taint import (
            TAINT_SECRET_ACCESS,
            TAINT_UNTRUSTED_READ,
            entity_scope,
            record_secret_fingerprints,
            record_taints,
            record_untrusted_values,
        )

        scopes: list[str] = [session_id] if session_id else []
        try:
            scopes.append(entity_scope(repo_root))
        except Exception:  # noqa: BLE001,S110
            pass
        if not scopes:
            return

        fps = candidate_secret_fingerprints(output_text)
        if fps:
            await record_taints(repo_root, scopes, [TAINT_SECRET_ACCESS])
            await record_secret_fingerprints(repo_root, scopes, list(fps))

        if tool_name in UNTRUSTED_READ_TOOLS:
            await record_taints(repo_root, scopes, [TAINT_UNTRUSTED_READ])
            values = untrusted_value_fingerprints(output_text)
            if values:
                await record_untrusted_values(repo_root, scopes, list(values), tool_name)
    except Exception:  # noqa: BLE001 — recording must never break the execution path
        return
