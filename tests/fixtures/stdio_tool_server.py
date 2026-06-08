"""A runnable downstream MCP tool server over stdio, for the serve end-to-end test.

Mirrors the tool surface of :mod:`tests.fixtures.fake_tool_server` (fs_write / fs_delete /
shell_exec / net_get) but runs as a real subprocess so ``doberman serve`` can spawn it. Every
*executed* call is appended as one JSON line ``[tool_name, arguments]`` to the file named by the
``DOBERMAN_TEST_CALLLOG`` environment variable, so the test can assert exactly what reached a tool
(the chokepoint property: a blocked call must leave no line behind).

Run as: ``python tests/fixtures/stdio_tool_server.py``  (stdout is its MCP channel — never printed to).
"""

import asyncio
import json
import os
import sys

from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

SERVER_NAME = "stdio-downstream"

_TOOLS: list[Tool] = [
    Tool(
        name="fs_write",
        description="Write content to a file.",
        inputSchema={
            "type": "object",
            "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
            "required": ["path", "content"],
        },
    ),
    Tool(
        name="fs_delete",
        description="Delete a file.",
        inputSchema={
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    ),
    Tool(
        name="shell_exec",
        description="Run a shell command.",
        inputSchema={
            "type": "object",
            "properties": {"command": {"type": "string"}},
            "required": ["command"],
        },
    ),
    Tool(
        name="net_get",
        description="HTTP GET a URL.",
        inputSchema={
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
    ),
]

KNOWN_TOOL_NAMES = {tool.name for tool in _TOOLS}


def _call_log_path() -> str | None:
    """Where to record executed calls: argv[1] (robust — flows through `serve --`) or the
    DOBERMAN_TEST_CALLLOG env var as a fallback."""
    if len(sys.argv) > 1 and sys.argv[1]:
        return sys.argv[1]
    return os.environ.get("DOBERMAN_TEST_CALLLOG")


def _record(tool_name: str, arguments: dict) -> None:
    """Append one executed call to the call-log file (never to stdout)."""
    call_log = _call_log_path()
    if not call_log:
        return
    with open(call_log, "a", encoding="utf-8") as handle:
        handle.write(json.dumps([tool_name, arguments]) + "\n")


def build() -> Server:
    server: Server = Server(SERVER_NAME)

    @server.list_tools()
    async def _list_tools() -> list[Tool]:
        return _TOOLS

    @server.call_tool()
    async def _call_tool(tool_name: str, arguments: dict) -> list[TextContent]:
        if tool_name not in KNOWN_TOOL_NAMES:
            raise ValueError(f"unknown tool: {tool_name}")  # error before recording
        _record(tool_name, arguments)
        return [TextContent(type="text", text=f"ok: {tool_name} executed")]

    return server


async def main() -> None:
    server = build()
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":  # pragma: no cover — exercised as a subprocess by the e2e test
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, EOFError):
        sys.exit(0)
