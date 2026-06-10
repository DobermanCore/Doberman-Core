"""The single execution chokepoint between the agent and downstream tools.

Every tool call intercepted by the proxy MUST flow through
:func:`decide_and_execute` — there is no other route to a downstream tool.
The decision engine (Feature 2) judges every normalized action: ``PASS``
forwards, ``AUTH`` returns an authentication-required error (real auth
arrives with Feature 7), ``BLOCK`` returns a policy error and the call is
NEVER forwarded. Any engine failure is itself a ``BLOCK`` (fail closed).
"""

import logging
from datetime import datetime, timezone

from mcp.client.session import ClientSession
from mcp.types import CallToolResult, TextContent

from doberman.config import load_active_role
from doberman.engine.decision_engine import PASS_STUB, Guardrail, decide
from doberman.engine.objective import ObjectiveGuardrail
from doberman.models import (
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

_engine_logger = logging.getLogger("doberman.proxy.engine")

# Guardrail implementations used by the proxy. The objective guardrail is now
# the real Feature 3 rule set; the subjective guardrail stays a PASS stub until
# Feature 9 lands. Module-level so tests can monkeypatch the policy without
# touching the routing.
DEFAULT_OBJECTIVE: Guardrail = ObjectiveGuardrail()
DEFAULT_SUBJECTIVE: Guardrail = PASS_STUB

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


async def decide_and_execute(
    downstream: ClientSession,
    tool_name: str,
    arguments: dict | None,
) -> CallToolResult:
    """Decide whether to execute a tool call, then act on the verdict.

    This is THE chokepoint: normalize → decide → enforce. The downstream
    forward happens in exactly one place, reachable only on a PASS decision.
    """
    action: SecurityObject = normalize(tool_name, arguments)

    # The objective rules (Feature 3) need to inspect the UN-redacted call
    # content to detect secrets / parse commands. We hand it to them through
    # EvalContext.metadata, which is in-memory only and never logged or
    # persisted — the SecurityObject itself stays redacted for the audit log.
    # The active agent role (Feature 4) is loaded from .doberman/role.yaml; it
    # is None when no role is configured, in which case the role rule abstains.
    ctx = EvalContext(
        role=load_active_role("."),
        metadata={"raw_arguments": dict(arguments or {})},
    )

    try:
        decision = decide(action, DEFAULT_OBJECTIVE, DEFAULT_SUBJECTIVE, ctx)
    except Exception:  # noqa: BLE001 — engine failure must fail closed, not crash
        # BaseException (CancelledError, SystemExit) propagates on purpose —
        # an unwind is fail-closed by construction (the forward below is
        # never reached). Log the failure server-side for forensics; the
        # exception text never reaches the agent.
        _engine_logger.exception("decision engine raised; failing closed (action %s)", action.id)
        decision = _engine_failure_decision(action)

    # Record every intercepted action with its REAL verdict. Logged BEFORE
    # the verdict gate — safe because log_action can never bypass the gate
    # (it swallows its own failures and forwards nothing).
    log_action(action, decision.final_verdict)

    if decision.final_verdict is not Verdict.PASS:
        # AUTH (F7 adds the real challenge) and BLOCK both stop here:
        # the downstream call below is never reached.
        return _verdict_result(decision)

    try:
        return await downstream.call_tool(tool_name, arguments or {})
    except Exception as exc:  # noqa: BLE001 — fail closed on ANY failure mode
        # Never re-raise into the serving path and never echo arguments:
        # the agent gets a generic denial carrying a stable reason code and
        # the action id for correlation with the interception log.
        # Deliberately `Exception`, not `BaseException`: cancellation
        # (asyncio.CancelledError) and interpreter shutdown must propagate —
        # swallowing them would break structured concurrency, and they carry
        # no payload to leak.
        return _denied_result(ReasonCode.downstream_error, type(exc).__name__, action.id)
