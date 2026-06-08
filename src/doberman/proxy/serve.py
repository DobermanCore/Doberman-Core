"""Run Doberman as a real MCP proxy over stdio in front of one downstream tool server.

Doberman is an MCP *server* to the agent (over this process's stdin/stdout) and an MCP
*client* to the downstream server (which it spawns). Every ``tools/call`` flows through the
single chokepoint (:func:`doberman.proxy.executor.decide_and_execute`) — there is no path
around it. This is the deployable counterpart to :func:`doberman.proxy.mcp_proxy.build_proxy_server`,
which builds the proxy object; this module gives it a transport.

SECURITY: nothing here writes this process's stdout (that is the agent's MCP channel). AUTH
challenges are routed to the controlling terminal via :class:`~doberman.auth.tty_prompter.TtyPrompter`
so a prompt never touches the agent stream; with no terminal the challenge denies (fail closed).
"""

import logging

from mcp import ClientSession, StdioServerParameters, stdio_client
from mcp.server.stdio import stdio_server

from doberman.auth.tty_prompter import TtyPrompter
from doberman.proxy import executor
from doberman.proxy.mcp_proxy import build_proxy_server

logger = logging.getLogger("doberman.proxy.serve")


async def serve_stdio(downstream: StdioServerParameters, *, repo_root: str = ".") -> None:
    """Spawn ``downstream``, then serve the Doberman proxy to the agent over stdio.

    Points the engine at ``repo_root`` (its ``.doberman/`` holds the active role, policy,
    decision log, and elevation store) and installs the controlling-terminal prompter so an
    ``AUTH`` challenge never reads/writes the agent's stdin/stdout. Returns when the agent
    disconnects; any transport failure propagates (the caller exits non-zero, forwarding nothing).
    """
    executor.REPO_ROOT = repo_root
    executor.AUTH_PROMPTER = TtyPrompter()
    logger.info("starting downstream: %s", downstream.command)
    async with stdio_client(downstream) as (downstream_read, downstream_write):
        async with ClientSession(downstream_read, downstream_write) as session:
            await session.initialize()
            proxy = build_proxy_server(session)
            async with stdio_server() as (agent_read, agent_write):
                logger.info("ready — proxying tool calls to the agent over stdio")
                await proxy.run(agent_read, agent_write, proxy.create_initialization_options())
