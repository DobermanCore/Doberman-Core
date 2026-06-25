"""End-to-end test of `doberman serve`: a real agent ⇄ doberman ⇄ downstream chain.

Spawns `python -m doberman.cli.main serve -- python <stdio_tool_server> <calllog>` as a subprocess and
connects to it with a real MCP client (the "agent"). Proves the deployable wiring works over stdio AND
the chokepoint property end-to-end: a PASS reaches the tool (a line in the call-log); a BLOCK does not.

This is the heavier test (it launches processes); a short timeout guards against a hung child.
"""

import asyncio
import json
import os
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from mcp import ClientSession, StdioServerParameters, stdio_client

_FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "stdio_tool_server.py"
# Generous bound for a *real* two-subprocess (proxy + downstream) MCP/stdio
# round-trip: process spawn + handshake is slow on Windows/CI and saturates under
# parallel load. This guards against a genuine hang, not slowness — the behavioral
# assertions below are what the test actually checks.
_TIMEOUT_S = 90.0


@asynccontextmanager
async def _agent_through_doberman(repo_root: Path, call_log: Path) -> AsyncIterator[ClientSession]:
    """An MCP client connected to `doberman serve`, which fronts the stdio fixture downstream."""
    params = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "doberman.cli.main",
            "serve",
            "--path",
            str(repo_root),
            "--",
            sys.executable,
            str(_FIXTURE),
            str(call_log),
        ],
        # Full env so the child can import doberman (venv) and find the interpreter.
        env={**os.environ},
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as agent:
            await agent.initialize()
            yield agent


def _logged_tools(call_log: Path) -> list[str]:
    if not call_log.exists():
        return []
    return [
        json.loads(line)[0] for line in call_log.read_text(encoding="utf-8").splitlines() if line
    ]


async def test_downstream_tools_are_re_exposed(tmp_path):
    call_log = tmp_path / "calls.log"
    async with asyncio.timeout(_TIMEOUT_S):
        async with _agent_through_doberman(tmp_path, call_log) as agent:
            result = await agent.list_tools()
    names = {tool.name for tool in result.tools}
    assert {"fs_write", "fs_delete", "shell_exec", "net_get"} <= names


async def test_pass_decision_reaches_the_tool(tmp_path):
    call_log = tmp_path / "calls.log"
    async with asyncio.timeout(_TIMEOUT_S):
        async with _agent_through_doberman(tmp_path, call_log) as agent:
            # A fetch to a trusted host PASSes (mirrors test_proxy_passthrough.py).
            result = await agent.call_tool("net_get", {"url": "https://github.com/owner/repo"})
    assert not result.isError
    assert "net_get" in _logged_tools(call_log)


async def test_block_decision_reaches_no_tool(tmp_path):
    call_log = tmp_path / "calls.log"
    async with asyncio.timeout(_TIMEOUT_S):
        async with _agent_through_doberman(tmp_path, call_log) as agent:
            # A catastrophic command is BLOCKed by the objective guardrail.
            result = await agent.call_tool("shell_exec", {"command": "rm -rf /"})
    assert result.isError
    # The chokepoint property: the blocked call never reached the downstream tool.
    assert "shell_exec" not in _logged_tools(call_log)
