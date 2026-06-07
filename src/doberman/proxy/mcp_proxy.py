"""Doberman's MCP proxy: an MCP server to the agent, an MCP client downstream.

The proxy re-exposes the downstream server's tools unchanged and routes every
``tools/call`` through :func:`doberman.proxy.executor.decide_and_execute` —
the single chokepoint. The agent's MCP config points at Doberman instead of
the real tool server, which puts Doberman physically on the execution path.
"""

from mcp.client.session import ClientSession
from mcp.server.lowlevel import Server
from mcp.types import CallToolResult, Tool

from doberman.proxy import executor

PROXY_NAME = "doberman"


def build_proxy_server(downstream: ClientSession, *, name: str = PROXY_NAME) -> Server:
    """Build the proxy MCP server in front of one downstream tool server.

    ``tools/list`` is forwarded so the agent sees exactly the downstream
    tool surface; ``tools/call`` goes through the chokepoint. If the
    downstream is unreachable, both fail with an error — never a bypass.
    """
    server: Server = Server(name)

    @server.list_tools()
    async def _list_tools() -> list[Tool]:
        result = await downstream.list_tools()
        return result.tools

    @server.call_tool()
    async def _call_tool(tool_name: str, arguments: dict) -> CallToolResult:
        # The ONLY route from an agent-visible tool call to a downstream tool.
        return await executor.decide_and_execute(downstream, tool_name, arguments)

    return server
