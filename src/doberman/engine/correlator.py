"""C3.1 — the session correlator: a cross-call, pattern-based exfiltration floor.

Catches individually-safe actions that combine into exfiltration across a
session — a sequence the per-action objective/subjective rules miss, because
each of those judges exactly one action.

:func:`correlate` itself is a PURE function, deliberately **not** wired into
:func:`doberman.engine.decision_engine.decide`. ``decide()`` short-circuits on
the first non-PASS objective verdict (an AUTH/BLOCK leg of a multi-step
attack), so a correlator called from inside it would never see the later legs
that complete the pattern. Like the taint floor
(:mod:`doberman.engine.taint_floor`), it is meant to run AFTER ``decide()``
returns, over the session's persisted decision history —
:func:`apply_correlator_async`/:func:`apply_correlator` below do exactly that
(read the history, run :func:`correlate`, raise the decision), mirroring the
taint floor's own async/sync split so both the async proxy executor and the
sync host-hook spine can share one implementation without either importing
the other's (heavier) module.

It also deliberately does **not** touch
:data:`doberman.engine.decision_engine.SUBJECTIVE_HARD_BLOCK_ALLOWLIST` — the
apply wrapper raises the final ``Decision`` directly via
``max_verdict``/``max_risk`` (mirroring the taint floor's own call site),
bypassing the subjective clamp by construction rather than smuggling a new
code onto that allowlist.
"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from dataclasses import dataclass

from doberman.engine.decision_engine import max_risk, max_verdict
from doberman.models import (
    ActionType,
    Decision,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    SourceContext,
    Verdict,
)

#: Modes where a firing pattern hard-BLOCKs outright rather than AUTH'ing.
#: Mirrors the taint floor's own strict/paranoid gate (ADR 0021): raise-only,
#: strictest modes only — light/balanced keep the human in the loop.
_STRICT_MODES: frozenset[str] = frozenset({"strict", "paranoid"})

#: Reason codes on a PRIOR row that mark it as a sensitive/secret read — the
#: "sensitive data" leg of the trifecta, and the read leg of the destructive-
#: flow pattern.
#:
#: Deliberately SECRET-CLASS ONLY (content/secret-store evidence from
#: ``SecretLeakageRule``) — ``sensitive_path_access`` (a bare glob-policy hit
#: from ``ProtectedPathRule``, e.g. ``infra/**``/``backend/auth/**``) is
#: excluded. Measured on a hand-built benign/attack sequence corpus
#: (2026-08-13): a benign "read untrusted web content -> read a policy-
#: sensitive config that legitimately holds an API token -> call a real but
#: non-allowlisted external API" chain and an attack "read untrusted content
#: -> read an actual secret-store file (``.npmrc``/``credentials``-shaped) ->
#: send to an unknown destination" chain are cleanly distinguishable at the
#: read step: the benign config read fires ONLY ``sensitive_path_access``
#: (glob-policy, not secret-content evidence), while the attack's read of a
#: real credential store fires ``sensitive_secret_access`` (secret-class) —
#: the two rules key off different, non-overlapping path/content signals
#: (``ProtectedPathRule``'s ``DEFAULT_SENSITIVE_GLOBS`` vs
#: ``SecretLeakageRule``'s ``_SECRET_PATH``/content patterns). Keeping only
#: secret-class codes here dropped ``correlated_trifecta``'s own false-fire
#: rate on the benign chain from 100% to 0% in EVERY mode, with zero loss on
#: the attack corpus (``correlated_trifecta`` still fires 100% of the time).
#: Strict mode's benign session still ends up AUTH overall — but that is
#: ``ExternalDestinationRule``'s own "unknown destination" policy in strict
#: mode (unrelated to, and unaffected by, this narrowing), not the
#: correlator misfiring — see ``doberman-vault/Sessions`` for the benchmark.
#: Residual, NOT fixed by this narrowing: a benign session whose "sensitive"
#: read genuinely touches real secret-shaped content (not just a
#: policy-sensitive path) is still structurally identical to an attack read
#: and will still fire — the correlator has no task/intent signal (the
#: deferred D2 task-match leg) to tell "legitimately needs this credential"
#: from "is exfiltrating it".
_SENSITIVE_READ_REASONS: frozenset[ReasonCode] = frozenset(
    {
        ReasonCode.sensitive_secret_access,
        ReasonCode.possible_high_entropy_secret,
        ReasonCode.secret_exfiltration,
    }
)

#: Reason codes marking a PRIOR row as an egress *attempt* — used only by the
#: weak budget clause below, never as the primary egress signal (that is
#: always the CURRENT action's live ``external_destination``, exactly like
#: ``taint_floor.py``'s own egress scope note).
_EGRESS_ATTEMPT_REASONS: frozenset[ReasonCode] = frozenset(
    {
        ReasonCode.unknown_external_destination,
        ReasonCode.egress_requires_auth,
        ReasonCode.confidentiality_sensitive_destination,
        ReasonCode.egress_route_divergence,
        ReasonCode.anomalous_egress_velocity,
        ReasonCode.multi_step_exfil,
        ReasonCode.confirmed_exfil,
    }
)

# ponytail: a round threshold, not a fit against real traffic — the budget
# clause is a weak co-factor by design (it can never fire alone; see
# `correlate` below), so a wrong constant here only ever shifts risk between
# high/critical on an already-firing pattern, never PASS vs. AUTH/BLOCK.
# Upgrade path: calibrate against real session logs if this proves loose.
_BUDGET_VOLUME_THRESHOLD = 3

_TRIFECTA_EXPLANATION = (
    "This session read sensitive or secret data, carried untrusted-provenance "
    "content, and is now sending data to an external destination — a cross-call "
    "lethal trifecta."
)
_DESTRUCTIVE_FLOW_EXPLANATION = (
    "This session enumerated or read data, ran a shell command, and is now "
    "sending data to an external destination — a possible archive-and-exfiltrate flow."
)
_BUDGET_NOTE = " Session also shows elevated sensitive-read/egress-attempt volume."


@dataclass(frozen=True)
class DecisionRow:
    """One session-scoped decision, as returned by
    :func:`doberman.storage.log.recent_session_decisions` — the same redacted
    slice already persisted for a decision row. Never carries a raw target or
    argument; only the classes/reason-codes vocabulary the decision log itself
    is redacted to.
    """

    action_type: ActionType
    target_path_class: str | None
    source_context: SourceContext
    risk: Risk
    reason_codes: tuple[ReasonCode, ...]
    final_verdict: Verdict

    @classmethod
    def from_storage(cls, row: dict) -> DecisionRow | None:
        """Build one row from a ``recent_session_decisions`` dict.

        Returns ``None`` on any malformed/unrecognized value — a bad historic
        row (a schema drift, a stale enum value from an old version) must
        never crash the correlator; the caller simply loses that one row from
        its window instead of failing the whole read.
        """
        try:
            return cls(
                action_type=ActionType(row["action_type"]),
                target_path_class=row.get("target_path_class"),
                source_context=SourceContext(row["source_context"]),
                risk=Risk(row["risk"]),
                reason_codes=tuple(ReasonCode(rc) for rc in row.get("reason_codes") or ()),
                final_verdict=Verdict(row["final_verdict"]),
            )
        except (KeyError, ValueError, TypeError):
            return None


def _is_untrusted_ingress(row: DecisionRow) -> bool:
    """Everything but a directly-typed user instruction is at least mixed/
    untrusted provenance — mirrors ``subjective/infer.py``'s
    ``SourceContext`` → ``Provenance`` map (``SourceContext.user`` is the only
    member mapped to ``trusted_instruction``)."""
    return row.source_context is not SourceContext.user


def _is_sensitive_read(row: DecisionRow) -> bool:
    return bool(_SENSITIVE_READ_REASONS.intersection(row.reason_codes))


def _is_command(row: DecisionRow) -> bool:
    return row.action_type is ActionType.shell_exec


def _is_broad_read(row: DecisionRow) -> bool:
    return row.action_type is ActionType.file_read


def _is_egress_attempt(row: DecisionRow) -> bool:
    return bool(_EGRESS_ATTEMPT_REASONS.intersection(row.reason_codes))


def _current_is_egress(action: SecurityObject) -> bool:
    """Mirrors ``taint_floor.py``: the egress signal is ``external_destination``."""
    return action.external_destination is not None


def _trifecta_fires(recent: Sequence[DecisionRow], action: SecurityObject) -> bool:
    """Untrusted-provenance ingress + a sensitive/secret read, anywhere earlier
    this session, followed by the CURRENT action being an external egress."""
    if not _current_is_egress(action):
        return False
    has_untrusted_ingress = any(_is_untrusted_ingress(row) for row in recent)
    has_sensitive_read = any(_is_sensitive_read(row) for row in recent)
    return has_untrusted_ingress and has_sensitive_read


def _destructive_flow_fires(recent: Sequence[DecisionRow], action: SecurityObject) -> bool:
    """A broad read/list + a shell command, anywhere earlier this session,
    followed by the CURRENT action being an external egress.

    ponytail: the redacted decision log never carries raw command text (by
    design — see ``models.py``'s ``SecurityObject.raw_args_redacted`` note), so
    "archive/compress shape" cannot be distinguished from any other shell
    command once it is only a persisted ``DecisionRow`` — any prior
    ``shell_exec`` is treated as the archive-leg proxy. Upgrade path: if a
    future objective rule fingerprints archive-shaped commands (tar/zip/gzip
    verbs) into a dedicated reason code, key off that instead of the bare
    action type.
    """
    if not _current_is_egress(action):
        return False
    has_broad_read = any(_is_broad_read(row) for row in recent)
    has_command = any(_is_command(row) for row in recent)
    return has_broad_read and has_command


def correlate(
    recent: Sequence[DecisionRow],
    current: Decision,  # noqa: ARG001 — part of the documented contract; not yet consulted
    action: SecurityObject,
    mode: str,
) -> GuardrailResult | None:
    """Pure cross-call pattern check over a session's recent decisions.

    Returns the strongest applicable raise as a :class:`GuardrailResult`, or
    ``None`` when no pattern fires. Never raises — any internal failure
    (malformed input, an unexpected type) is swallowed and treated as "no
    match"; the caller is responsible for failing closed by leaving the
    existing objective/subjective decision untouched, never by escalating on
    a correlator bug.

    ``current`` (the Decision already reached for THIS action) is accepted for
    the documented interface / future patterns that need it, but the two
    patterns implemented here only need the live ``action`` (for the egress
    signal) and the redacted ``recent`` history.
    """
    try:
        return _correlate(recent, action, mode)
    except Exception:  # noqa: BLE001 — pure helper; caller treats a failure as None
        return None


def _correlate(
    recent: Sequence[DecisionRow], action: SecurityObject, mode: str
) -> GuardrailResult | None:
    fired_trifecta = _trifecta_fires(recent, action)
    fired_destructive = _destructive_flow_fires(recent, action)
    if not fired_trifecta and not fired_destructive:
        return None

    hard_block = mode in _STRICT_MODES
    verdict = Verdict.BLOCK if hard_block else Verdict.AUTH
    risk = Risk.critical if hard_block else Risk.high

    reasons: list[ReasonCode] = []
    explanations: list[str] = []
    if fired_trifecta:
        reasons.append(ReasonCode.correlated_trifecta)
        explanations.append(_TRIFECTA_EXPLANATION)
    if fired_destructive:
        reasons.append(ReasonCode.correlated_destructive_flow)
        explanations.append(_DESTRUCTIVE_FLOW_EXPLANATION)
    explanation = " ".join(explanations)

    # Budget clause: a weak, COMBINABLE-ONLY co-factor — it can never be the
    # sole trigger (guarded by the fired_trifecta/fired_destructive check
    # above, which runs first and returns None on volume alone). High session
    # sensitive-read/egress-attempt volume alongside an already-firing pattern
    # pushes risk to critical even outside strict/paranoid; per ADR 0059 this
    # never fires standalone (no blind gameable threshold).
    volume = sum(1 for row in recent if _is_sensitive_read(row) or _is_egress_attempt(row))
    if volume >= _BUDGET_VOLUME_THRESHOLD:
        risk = Risk.critical
        explanation += _BUDGET_NOTE

    return GuardrailResult(
        verdict=verdict,
        risk=risk,
        reason_codes=reasons,
        explanation=explanation,
    )


#: How many of the session's most-recent decisions to read as pattern-check
#: history. Bounded so the read stays a cheap, single indexed query
#: regardless of session length. Matches the proxy executor's own
#: ``_CORRELATOR_WINDOW`` (kept here as the shared default so a caller that
#: doesn't override it gets the same window either way).
_DEFAULT_WINDOW = 20


async def apply_correlator_async(
    action: SecurityObject,
    decision: Decision,
    mode: str,
    repo_root: str,
    session_id: str | None,
    *,
    window: int = _DEFAULT_WINDOW,
) -> Decision:
    """C3.1 — read this session's recent decision history and raise-only
    apply :func:`correlate` to ``decision``.

    Mirrors ``taint_floor.py``'s own shape: read a bounded slice of session
    history, run the pure pattern check, and apply any raise directly via
    ``max_verdict``/``max_risk`` — bypassing the subjective clamp by
    construction, rather than adding a new code to
    ``SUBJECTIVE_HARD_BLOCK_ALLOWLIST``.

    Fails closed to the untouched ``decision``: a DB read failure or a
    correlator bug must never crash the caller or silently escalate —
    ``recent_session_decisions`` and :func:`correlate` are already
    individually fail-closed/fail-quiet, and this wrapper adds one more layer
    of defense-in-depth around the two calls. With ``session_id=None`` (no
    session concept at the call site) ``recent_session_decisions`` returns an
    empty history and this never fires — the same documented gap as the
    taint floor's own ``session_id=None`` callers.
    """
    try:
        from doberman.storage.log import recent_session_decisions  # lazy: keeps this module light

        raw_rows = await recent_session_decisions(repo_root, session_id, window)
        rows = [
            row for row in (DecisionRow.from_storage(raw) for raw in raw_rows) if row is not None
        ]
        raise_result = correlate(rows, decision, action, mode)
    except Exception:  # noqa: BLE001 — the correlator must never break the caller's path
        return decision
    if raise_result is None:
        return decision
    reasons = list(dict.fromkeys([*decision.reason_codes, *raise_result.reason_codes]))
    explanation = " ".join(
        part for part in (decision.explanation.strip(), raise_result.explanation.strip()) if part
    )
    return decision.model_copy(
        update={
            "final_verdict": max_verdict(decision.final_verdict, raise_result.verdict),
            "final_risk": max_risk(decision.final_risk, raise_result.risk),
            "reason_codes": reasons,
            "explanation": explanation,
        }
    )


def apply_correlator(
    action: SecurityObject,
    decision: Decision,
    mode: str,
    repo_root: str,
    session_id: str | None,
    *,
    window: int = _DEFAULT_WINDOW,
) -> Decision:
    """Sync wrapper around :func:`apply_correlator_async` for the host-hook
    spine (:mod:`doberman.hosthooks.spine`), which runs outside any event
    loop — same split, and the same reason, as ``taint_floor.py``'s own
    ``apply_taint_floor``/``apply_taint_floor_async`` pair: the async proxy
    executor already runs inside a live event loop and must await
    :func:`apply_correlator_async` directly (calling this sync wrapper there
    would raise ``RuntimeError: asyncio.run() cannot be called from a running
    event loop``).

    ponytail: ``doberman.proxy.executor._apply_correlator`` still carries its
    own copy of this read-correlate-raise sequence rather than calling
    :func:`apply_correlator_async` directly — its tests monkeypatch
    ``executor.recent_session_decisions`` (a module-level name), which a
    delegating call would silently stop honoring. Not worth widening this
    slice's diff (and risk) to touch already-green proxy tests for a ~15-line
    dedup; upgrade path: fold it in when that test's monkeypatch target moves
    to ``doberman.storage.log`` directly.
    """
    return asyncio.run(
        apply_correlator_async(action, decision, mode, repo_root, session_id, window=window)
    )
