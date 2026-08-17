"""Doberman's MCP proxy: an MCP server to the agent, an MCP client downstream.

The proxy re-exposes the downstream server's tools unchanged and routes every
``tools/call`` through :func:`doberman.proxy.executor.decide_and_execute` —
the single chokepoint. The agent's MCP config points at Doberman instead of
the real tool server, which puts Doberman physically on the execution path.
"""

import logging

from mcp.client.session import ClientSession
from mcp.server.lowlevel import Server
from mcp.shared.exceptions import McpError
from mcp.types import INTERNAL_ERROR, CallToolResult, ErrorData, Tool

from doberman.proxy import executor
from doberman.storage import tool_pins

PROXY_NAME = "doberman"
logger = logging.getLogger("doberman.proxy.mcp_proxy")


def build_proxy_server(downstream: ClientSession, *, name: str = PROXY_NAME) -> Server:
    """Build the proxy MCP server in front of one downstream tool server.

    ``tools/list`` is forwarded so the agent sees exactly the downstream
    tool surface; ``tools/call`` goes through the chokepoint. If the
    downstream is unreachable, both fail with an error — never a bypass.
    """
    server: Server = Server(name)

    @server.list_tools()
    async def _list_tools() -> list[Tool]:
        try:
            result = await downstream.list_tools()
        except Exception as exc:
            # Sanitize: never forward a raw downstream error message to the
            # agent — it could carry paths, credentials, or internals. The
            # agent only learns the error class.
            raise McpError(
                ErrorData(
                    code=INTERNAL_ERROR,
                    message=(
                        "doberman: downstream tool listing failed "
                        f"(error class: {type(exc).__name__})"
                    ),
                )
            ) from None
        try:
            # Keep this module-attribute call patchable: schema reconciliation
            # is observable in tests and must never make tools/list unavailable.
            await tool_pins.reconcile_pins(result.tools, repo_root=executor.REPO_ROOT)
        except Exception as exc:  # noqa: BLE001 - tools/list must remain available
            # Defense in depth around the storage API's own never-raise contract.
            # Never include the exception message: it could contain raw schema.
            logger.warning(
                "tool-pin reconciliation escaped its boundary; continuing (error class: %s)",
                type(exc).__name__,
            )
        return result.tools

    @server.call_tool()
    async def _call_tool(tool_name: str, arguments: dict) -> CallToolResult:
        # The ONLY route from an agent-visible tool call to a downstream tool.
        # NOTE: tests monkeypatch `executor.decide_and_execute`; keep this a
        # module-attribute call (not a `from`-import) so the routing invariant
        # stays observable.
        try:
            return await executor.decide_and_execute(downstream, tool_name, arguments)
        except Exception as exc:  # noqa: BLE001 — H1: the chokepoint must never
            # leak a raw exception (and its message, which could carry argument
            # fragments) past this point. Deliberately `Exception`, not
            # `BaseException`: cancellation/interpreter shutdown still propagate.
            return executor.handler_failure_result(exc)

    return server
