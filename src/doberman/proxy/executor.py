"""The single execution chokepoint between the agent and downstream tools.

Every tool call intercepted by the proxy MUST flow through
:func:`decide_and_execute` — there is no other route to a downstream tool. The
decision engine (Feature 2) judges every normalized action; Feature 7 turns an
``AUTH`` into a real, action-specific challenge:

* ``PASS`` forwards the call.
* ``AUTH`` runs a tiered challenge (confirm / 2FA / role elevation). On approval
  the action is **re-decided** (TOCTOU guard) and, unless it now ``BLOCK``s,
  forwarded; a satisfied ``role_elevation`` grants a narrow, temporary, (for
  destructive scopes) single-use elevation first. Denial/timeout forwards
  nothing.
* ``BLOCK`` returns a policy error and is NEVER forwarded.

Any engine failure is itself a ``BLOCK`` (fail closed). The approval is bound to
exactly one action id (no replay onto a different call).
"""

import logging
from datetime import datetime, timezone

from mcp.client.session import ClientSession
from mcp.types import CallToolResult, TextContent

from doberman.auth.challenge import AuthTier, Prompter, run_auth_challenge
from doberman.auth.elevation import find_cover, scope_for_target
from doberman.config import load_active_role, load_mode
from doberman.engine.decision_engine import PASS_STUB, Guardrail, decide
from doberman.engine.objective import ObjectiveGuardrail
from doberman.models import (
    ActionType,
    Decision,
    EvalContext,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    Verdict,
)
from doberman.proxy.interception_log import log_action
from doberman.proxy.normalize import normalize
from doberman.storage.db import active_elevations, grant_elevation, mark_used
from doberman.storage.log import record_decision

_engine_logger = logging.getLogger("doberman.proxy.engine")

#: Repo root used for config + the elevation store. Module-level so tests can
#: point it at an isolated temp dir (the DB/config must never touch the repo).
REPO_ROOT = "."

#: Prompter for AUTH challenges. None ⇒ the provider's default CLI prompter
#: (stdin/stdout). The stdio ``serve`` path sets this to a controlling-terminal
#: prompter so a challenge never reads/writes the agent's MCP stream. Module-level
#: so tests can inject a headless fake.
AUTH_PROMPTER: Prompter | None = None

# Guardrail implementations used by the proxy. The objective guardrail is the
# real Feature 3 rule set; the subjective guardrail stays a PASS stub until
# Feature 9 lands. Module-level so tests can monkeypatch the policy without
# touching the routing.
DEFAULT_OBJECTIVE: Guardrail = ObjectiveGuardrail()
DEFAULT_SUBJECTIVE: Guardrail = PASS_STUB

#: Action types whose elevations are single-use (a destructive op should not be
#: silently repeatable on one approval).
_DESTRUCTIVE_ACTIONS = frozenset({ActionType.file_delete})

_DENIED_TEMPLATE = (
    "doberman: downstream call failed; action denied "
    "(reason: {reason}; error class: {error_class}; action id: {action_id})"
)

_VERDICT_TEMPLATES = {
    Verdict.AUTH: (
        "doberman: authentication required "
        "(reasons: {reasons}; {explanation}; action id: {action_id})"
    ),
    Verdict.BLOCK: (
        "doberman: blocked by policy (reasons: {reasons}; {explanation}; action id: {action_id})"
    ),
}


def _denied_result(reason: ReasonCode, error_class: str, action_id: str) -> CallToolResult:
    """Build a fail-closed error result (no payload or argument echo)."""
    return CallToolResult(
        content=[
            TextContent(
                type="text",
                text=_DENIED_TEMPLATE.format(
                    reason=reason, error_class=error_class, action_id=action_id
                ),
            )
        ],
        isError=True,
    )


def _verdict_result(decision: Decision) -> CallToolResult:
    """Agent-visible explanatory error for an AUTH/BLOCK decision."""
    template = _VERDICT_TEMPLATES[decision.final_verdict]
    return CallToolResult(
        content=[
            TextContent(
                type="text",
                text=template.format(
                    reasons=", ".join(decision.reason_codes) or "unspecified",
                    explanation=decision.explanation.strip() or "no further detail",
                    action_id=decision.action_id,
                ),
            )
        ],
        isError=True,
    )


def _engine_failure_decision(action: SecurityObject) -> Decision:
    """A synthetic fail-closed BLOCK used when the engine itself fails."""
    blocked = GuardrailResult(
        verdict=Verdict.BLOCK,
        risk=Risk.high,
        reason_codes=[ReasonCode.objective_guardrail_error],
        explanation="Decision engine failed; failing closed.",
    )
    return Decision(
        action_id=action.id,
        final_verdict=Verdict.BLOCK,
        final_risk=Risk.high,
        objective=blocked,
        subjective=None,
        reason_codes=list(blocked.reason_codes),
        explanation=blocked.explanation,
        decided_at=datetime.now(timezone.utc),
    )


def _build_ctx(arguments: dict | None, grants: tuple) -> EvalContext:
    """Assemble the EvalContext for one decision.

    The objective rules (Feature 3) inspect the UN-redacted call content via
    ``metadata['raw_arguments']`` (in-memory only, never logged/persisted). The
    active role (F4), mode (F6), and active elevations (F7) ride along too.
    """
    return EvalContext(
        role=load_active_role(REPO_ROOT),
        mode=load_mode(REPO_ROOT),
        metadata={
            "raw_arguments": dict(arguments or {}),
            "repo_root": REPO_ROOT,
            "elevations": grants,
        },
    )


def _safe_decide(action: SecurityObject, ctx: EvalContext) -> Decision:
    """Run the engine; any failure becomes a fail-closed BLOCK (never crashes)."""
    try:
        return decide(action, DEFAULT_OBJECTIVE, DEFAULT_SUBJECTIVE, ctx)
    except Exception:  # noqa: BLE001 — engine failure must fail closed, not crash
        # BaseException (CancelledError, SystemExit) propagates on purpose — an
        # unwind is fail-closed by construction (no forward is reached).
        _engine_logger.exception("decision engine raised; failing closed (action %s)", action.id)
        return _engine_failure_decision(action)


def _is_destructive(action: SecurityObject) -> bool:
    return action.action_type in _DESTRUCTIVE_ACTIONS


async def _forward(
    downstream: ClientSession,
    tool_name: str,
    arguments: dict | None,
    action: SecurityObject,
) -> CallToolResult:
    """Forward an approved call downstream, failing closed on any error."""
    try:
        return await downstream.call_tool(tool_name, arguments or {})
    except Exception as exc:  # noqa: BLE001 — fail closed on ANY failure mode
        # Never re-raise into the serving path and never echo arguments.
        # Deliberately `Exception`, not `BaseException`: cancellation and
        # interpreter shutdown must propagate (they carry no payload to leak).
        return _denied_result(ReasonCode.downstream_error, type(exc).__name__, action.id)


async def _consume_single_use(action: SecurityObject, grants: tuple, now: datetime) -> None:
    """Mark a single-use elevation spent after it released a forward (best-effort)."""
    grant = find_cover(action.target, grants, root=REPO_ROOT)
    if grant is not None and grant.single_use:
        await mark_used(REPO_ROOT, grant.id)


async def _persist(
    decision: Decision,
    action: SecurityObject,
    *,
    auth_result: str | None = None,
    elevation_id: str | None = None,
) -> None:
    """Append one redacted row to the local decision log (best-effort).

    Wrapped so that even a catastrophic logging failure can never alter, block,
    or crash a decision that has already been enforced (logging is observational).
    """
    try:
        await record_decision(
            decision,
            action,
            repo_root=REPO_ROOT,
            auth_result=auth_result,
            elevation_id=elevation_id,
        )
    except Exception:  # noqa: BLE001 — logging must never break the execution path
        _engine_logger.warning("decision log persist failed (action %s); continuing", action.id)


async def _handle_auth(
    downstream: ClientSession,
    tool_name: str,
    arguments: dict | None,
    action: SecurityObject,
    decision: Decision,
    now: datetime,
) -> CallToolResult:
    """Run the tiered challenge for an AUTH decision and act on the outcome."""
    auth_result = run_auth_challenge(decision, action, prompter=AUTH_PROMPTER)
    # Approval is bound to THIS action id — never honor a result for another call.
    if not auth_result.approved or auth_result.action_id != action.id:
        await _persist(decision, action, auth_result="denied")
        return _verdict_result(decision)

    # A satisfied role elevation grants a narrow, temporary permission first.
    elevation_id: str | None = None
    if auth_result.tier is AuthTier.role_elevation:
        scope = scope_for_target(action.target, root=REPO_ROOT)
        if scope is None:
            # No narrow scope can be formed (non-path / escapes root): refuse.
            await _persist(decision, action, auth_result="denied")
            return _verdict_result(decision)
        try:
            grant = await grant_elevation(
                REPO_ROOT,
                scope,
                action.id,
                now=now,
                single_use=_is_destructive(action),
            )
            elevation_id = grant.id
        except Exception:  # noqa: BLE001 — a failed grant must fail closed
            _engine_logger.warning("elevation grant failed (action %s); denying", action.id)
            await _persist(decision, action, auth_result="denied")
            return _verdict_result(decision)

    # TOCTOU guard: re-decide with refreshed elevations. A change to BLOCK must
    # block even post-approval; otherwise the human-approved action is released.
    grants = tuple(await active_elevations(REPO_ROOT, now))
    redecision = _safe_decide(action, _build_ctx(arguments, grants))
    if redecision.final_verdict is Verdict.BLOCK:
        log_action(action, redecision.final_verdict)
        await _persist(redecision, action, auth_result="approved")
        return _verdict_result(redecision)

    result = await _forward(downstream, tool_name, arguments, action)
    if not result.isError:
        await _consume_single_use(action, grants, now)
    await _persist(decision, action, auth_result="approved", elevation_id=elevation_id)
    return result


async def decide_and_execute(
    downstream: ClientSession,
    tool_name: str,
    arguments: dict | None,
) -> CallToolResult:
    """Decide whether to execute a tool call, then act on the verdict.

    This is THE chokepoint: normalize → decide → enforce. The downstream forward
    happens only on a PASS decision or a successfully-authenticated AUTH.
    """
    action: SecurityObject = normalize(tool_name, arguments)
    now = datetime.now(timezone.utc)

    # Active elevations (F7) may satisfy a role-boundary AUTH for the exact
    # covered target, so they are loaded BEFORE the first decision.
    grants = tuple(await active_elevations(REPO_ROOT, now))
    decision = _safe_decide(action, _build_ctx(arguments, grants))

    # Record every intercepted action with its REAL verdict. Logged before the
    # gate — safe because log_action swallows its own failures and forwards
    # nothing.
    log_action(action, decision.final_verdict)

    if decision.final_verdict is Verdict.BLOCK:
        await _persist(decision, action)
        return _verdict_result(decision)

    if decision.final_verdict is Verdict.AUTH:
        return await _handle_auth(downstream, tool_name, arguments, action, decision, now)

    # PASS — forward, then consume any single-use elevation that released it.
    result = await _forward(downstream, tool_name, arguments, action)
    if not result.isError:
        await _consume_single_use(action, grants, now)
    await _persist(decision, action)
    return result
