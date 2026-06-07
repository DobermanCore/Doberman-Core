"""A fake downstream MCP tool server that records every executed call.

Used by integration tests to prove the chokepoint property: if Doberman
returns an error (or, from Feature 2 on, a BLOCK), the fake server must have
recorded nothing — the call never reached a tool.
"""

from typing import Any

from mcp.server.lowlevel import Server
from mcp.types import TextContent, Tool

FAKE_SERVER_NAME = "fake-downstream"

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


class FakeToolServer:
    """In-process downstream MCP server; records (tool_name, arguments) calls."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        # When True the server errors on every call BEFORE recording —
        # simulates the downstream dying/failing mid-session.
        self.fail_mode = False

    def build(self) -> Server:
        server: Server = Server(FAKE_SERVER_NAME)

        @server.list_tools()
        async def _list_tools() -> list[Tool]:
            return _TOOLS

        @server.call_tool()
        async def _call_tool(tool_name: str, arguments: dict[str, Any]) -> list[TextContent]:
            if self.fail_mode:
                raise RuntimeError("downstream failure (simulated)")
            if tool_name not in KNOWN_TOOL_NAMES:
                # Unknown tool: error BEFORE recording — nothing executed.
                raise ValueError(f"unknown tool: {tool_name}")
            self.calls.append((tool_name, arguments))
            return [TextContent(type="text", text=f"ok: {tool_name} executed")]

        return server
