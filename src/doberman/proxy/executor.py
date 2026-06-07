"""The single execution chokepoint between the agent and downstream tools.

Every tool call intercepted by the proxy MUST flow through
:func:`decide_and_execute` — there is no other route to a downstream tool.
For now the decision hook is a pass-through (observation only); Feature 2
replaces it with the real decision engine. The fail-closed contract is
already in force: any error on the way to the downstream tool yields an
error result, never a silent success or a bypass.
"""

from mcp.client.session import ClientSession
from mcp.types import CallToolResult, TextContent

from doberman.models import ReasonCode, SecurityObject, Verdict
from doberman.proxy.interception_log import log_action
from doberman.proxy.normalize import normalize

_DENIED_TEMPLATE = (
    "doberman: downstream call failed; action denied "
    "(reason: {reason}; error class: {error_class}; action id: {action_id})"
)


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


async def decide_and_execute(
    downstream: ClientSession,
    tool_name: str,
    arguments: dict | None,
) -> CallToolResult:
    """Decide whether to execute a tool call, then (if allowed) forward it.

    This is THE chokepoint. The decision hook is currently a pass-through
    stub — every call is forwarded — but the routing invariant (exactly one
    path, through this function) and the fail-closed error handling are real.
    """
    action: SecurityObject = normalize(tool_name, arguments)
    # --- decision hook (Feature 2 wires the engine in here) -----------------
    # verdict = PASS (pass-through stub); `action` is what the engine judges.
    # ------------------------------------------------------------------------
    # Record every intercepted action (best-effort; never blocks execution).
    log_action(action, Verdict.PASS)
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
