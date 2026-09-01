"""A fake downstream MCP tool server that records every executed call.

Used by integration tests to prove the chokepoint property: if Doberman
returns an error (or, from Feature 2 on, a BLOCK), the fake server must have
recorded nothing — the call never reached a tool.
"""

import asyncio
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
    # A mail-like tool (SL9): proves the ONE subjective engine covers a second
    # synthetic application type with zero adapters installed.
    Tool(
        name="send_email",
        description="Send an email through the corporate relay.",
        inputSchema={
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "to": {"type": "array", "items": {"type": "string"}},
                "body": {"type": "string"},
            },
            "required": ["url", "to", "body"],
        },
    ),
    # A pure domain-tool (egress-coverage tests): carries a recipient via 'to'
    # with NO 'url' arg so it normalises to ActionType.other. Used to prove that
    # benign sends PASS and secret-exfil sends BLOCK via the trifecta / secret
    # floors without ExternalDestinationRule AUTHing on every recipient.
    Tool(
        name="send_message",
        description="Send a direct message to a recipient.",
        inputSchema={
            "type": "object",
            "properties": {
                "to": {"type": "string"},
                "body": {"type": "string"},
            },
            "required": ["to", "body"],
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
        # Concurrency tests: yield the event loop once before recording, so two
        # racing calls can both be in flight downstream at the same time.
        self.yield_before_call = False

    def build(self) -> Server:
        server: Server = Server(FAKE_SERVER_NAME)

        @server.list_tools()
        async def _list_tools() -> list[Tool]:
            return _TOOLS

        @server.call_tool()
        async def _call_tool(tool_name: str, arguments: dict[str, Any]) -> list[TextContent]:
            if self.yield_before_call:
                await asyncio.sleep(0)
            if self.fail_mode:
                raise RuntimeError("downstream failure (simulated)")
            if tool_name not in KNOWN_TOOL_NAMES:
                # Unknown tool: error BEFORE recording — nothing executed.
                raise ValueError(f"unknown tool: {tool_name}")
            self.calls.append((tool_name, arguments))
            return [TextContent(type="text", text=f"ok: {tool_name} executed")]

        return server
