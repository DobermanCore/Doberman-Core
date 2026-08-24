"""Run Doberman as a real MCP proxy over stdio in front of one downstream tool server.

Doberman is an MCP *server* to the agent (over this process's stdin/stdout) and an MCP
*client* to the downstream server (which it spawns). Every ``tools/call`` flows through the
single chokepoint (:func:`doberman.proxy.executor.decide_and_execute`) — there is no path
around it. This is the deployable counterpart to :func:`doberman.proxy.mcp_proxy.build_proxy_server`,
which builds the proxy object; this module gives it a transport.

SECURITY: nothing here writes this process's stdout (that is the agent's MCP channel). AUTH
challenges try four channels in order: the **dashboard** first
(:class:`~doberman.auth.dashboard_prompter.DashboardPrompter` — engages only when a dash
server's heartbeat is fresh, D3; falls back with zero added latency if no dashboard is running,
and falls back on its own poll timeout too — a live-but-unwatched dashboard must not deny a
human who can still answer elsewhere), then MCP **elicitation**
(:class:`~doberman.auth.elicitation_prompter.ElicitationPrompter` — rendered natively inside
the agent client, for clients that support it; never used for 2FA codes), then a topmost GUI
dialog (:class:`~doberman.auth.gui_prompter.GuiPrompter` — when an agent's TUI owns the
console, a terminal prompt opens "successfully" but is invisible, so the dialog is the channel
the human can actually see), then the controlling terminal
(:class:`~doberman.auth.tty_prompter.TtyPrompter`) for headless/SSH sessions. With no channel
available the challenge denies (fail closed). A prompt never touches the agent stream.
"""

import asyncio
import logging

from mcp import ClientSession, StdioServerParameters, stdio_client
from mcp.server.stdio import stdio_server

from doberman.auth.dashboard_prompter import DashboardPrompter
from doberman.auth.elicitation_prompter import ElicitationPrompter
from doberman.auth.gui_prompter import FallbackPrompter, GuiPrompter
from doberman.auth.tty_prompter import TtyPrompter
from doberman.config import load_policy
from doberman.engine.objective import ObjectiveGuardrail
from doberman.proxy import executor
from doberman.proxy.mcp_proxy import build_proxy_server

logger = logging.getLogger("doberman.proxy.serve")


async def serve_stdio(downstream: StdioServerParameters, *, repo_root: str = ".") -> None:
    """Spawn ``downstream``, then serve the Doberman proxy to the agent over stdio.

    Points the engine at ``repo_root`` (its ``.doberman/`` holds the active role, policy,
    decision log, and elevation store) and installs the dashboard→elicitation→GUI→terminal
    prompter chain so an ``AUTH`` challenge never reads/writes the agent's stdin/stdout — and is
    actually *visible* when the agent's TUI owns the console. Returns when the agent
    disconnects; any transport failure propagates (the caller exits non-zero, forwarding
    nothing).
    """
    executor.REPO_ROOT = repo_root

    # Rebuild DEFAULT_OBJECTIVE now that REPO_ROOT is known, so any
    # policy-stored egress-velocity thresholds (RB.6) take effect in the
    # long-lived proxy singleton's ExternalDestinationRule.  The module-level
    # DEFAULT_OBJECTIVE was constructed at import time with no REPO_ROOT, so
    # it always used the built-in defaults.  A missing/corrupt policy falls
    # back to None (built-in defaults apply — identical to pre-RB.6 behaviour).
    _policy = load_policy(repo_root)
    _velocity_thresholds = _policy.egress_velocity_thresholds if _policy is not None else None
    executor.DEFAULT_OBJECTIVE = ObjectiveGuardrail(
        rules=executor._default_objective_rules(velocity_thresholds=_velocity_thresholds)
    )

    logger.info("starting downstream: %s", downstream.command)
    async with stdio_client(downstream) as (downstream_read, downstream_write):
        async with ClientSession(downstream_read, downstream_write) as session:
            await session.initialize()
            proxy = build_proxy_server(session)
            # The elicitation channel needs the proxy (to resolve the per-request agent
            # session) and this loop (challenges run in a worker thread and bridge back).
            executor.AUTH_PROMPTER = FallbackPrompter(
                [
                    DashboardPrompter(executor.REPO_ROOT),
                    ElicitationPrompter(proxy, asyncio.get_running_loop()),
                    GuiPrompter(),
                    TtyPrompter(),
                ]
            )
            async with stdio_server() as (agent_read, agent_write):
                # ASCII only: this line lands in whatever stderr the client gave us, and a
                # non-UTF-8 capture turns the em-dash into a replacement char in their log.
                logger.info("ready - proxying tool calls to the agent over stdio")
                await proxy.run(agent_read, agent_write, proxy.create_initialization_options())
