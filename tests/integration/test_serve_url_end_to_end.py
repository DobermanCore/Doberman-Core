"""End-to-end test of `doberman serve --url`: a real agent <-> doberman <-> remote-HTTP chain.

The HTTP twin of :mod:`test_serve_end_to_end` — same real agent/proxy/downstream round trip
and the same chokepoint assertions, but the downstream server is a `FastMCP` app served over
Streamable HTTP by a real `uvicorn` server in a background thread instead of a spawned stdio
subprocess. Proves `--url` wires the deployable proxy exactly like the stdio path: a PASS
reaches the tool (a line in the call-log); a BLOCK does not.

``uvicorn`` is a ``dev``-extra-only dependency (never a runtime one), hence the importorskip.
"""

import asyncio
import json
import os
import socket
import sys
import threading
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters, stdio_client

uvicorn = pytest.importorskip("uvicorn")

from mcp.server.fastmcp import FastMCP  # noqa: E402 - after importorskip

# Generous bound for a *real* two-process (proxy + uvicorn) MCP/HTTP round-trip: process
# spawn + handshake is slow on Windows/CI and saturates under parallel load. This guards
# against a genuine hang, not slowness — the behavioral assertions below are what the test
# actually checks. Mirrors test_serve_end_to_end.py's stdio twin.
_TIMEOUT_S = 90.0


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _build_downstream_app(call_log: Path) -> FastMCP:
    """A FastMCP app mirroring tests/fixtures/stdio_tool_server.py's tool surface: every
    executed call is appended as one JSON line ``[tool_name, arguments]`` to ``call_log``, so
    the test can assert exactly what reached a tool (the chokepoint property)."""
    app = FastMCP("http-downstream")

    def _record(tool_name: str, arguments: dict) -> None:
        with open(call_log, "a", encoding="utf-8") as handle:
            handle.write(json.dumps([tool_name, arguments]) + "\n")

    @app.tool()
    def fs_write(path: str, content: str) -> str:
        """Write content to a file."""
        _record("fs_write", {"path": path, "content": content})
        return "ok: fs_write executed"

    @app.tool()
    def fs_delete(path: str) -> str:
        """Delete a file."""
        _record("fs_delete", {"path": path})
        return "ok: fs_delete executed"

    @app.tool()
    def shell_exec(command: str) -> str:
        """Run a shell command."""
        _record("shell_exec", {"command": command})
        return "ok: shell_exec executed"

    @app.tool()
    def net_get(url: str) -> str:
        """HTTP GET a URL."""
        _record("net_get", {"url": url})
        return "ok: net_get executed"

    return app


@pytest.fixture
def http_downstream(tmp_path):
    """Serve a FastMCP app over Streamable HTTP in a background thread; yields
    ``(url, call_log)``. Streamable HTTP is mounted at ``/mcp`` (FastMCP's
    ``streamable_http_path`` default — verified against the installed SDK, not assumed)."""
    call_log = tmp_path / "calls.log"
    app = _build_downstream_app(call_log)
    port = _free_port()
    config = uvicorn.Config(
        app.streamable_http_app(),
        host="127.0.0.1",
        port=port,
        log_level="warning",
        # Streamable HTTP/SSE run over plain HTTP, not websockets; skip loading uvicorn's
        # "auto" websocket protocol (which imports the deprecated `websockets.legacy` and
        # trips this repo's warnings-as-errors pytest config from the background thread).
        ws="none",
    )
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                break
        except OSError:
            time.sleep(0.05)
    else:
        raise RuntimeError("http_downstream fixture: uvicorn server did not start in time")
    try:
        yield f"http://127.0.0.1:{port}/mcp", call_log
    finally:
        server.should_exit = True
        thread.join(timeout=10.0)


@asynccontextmanager
async def _agent_through_doberman(repo_root: Path, url: str) -> AsyncIterator[ClientSession]:
    """An MCP client connected to `doberman serve --url`, which fronts the FastMCP downstream."""
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "doberman.cli.main", "serve", "--path", str(repo_root), "--url", url],
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


async def test_downstream_tools_are_re_exposed_over_http(tmp_path, http_downstream):
    url, _call_log = http_downstream
    async with asyncio.timeout(_TIMEOUT_S):
        async with _agent_through_doberman(tmp_path, url) as agent:
            result = await agent.list_tools()
    names = {tool.name for tool in result.tools}
    assert {"fs_write", "fs_delete", "shell_exec", "net_get"} <= names


async def test_pass_decision_reaches_the_http_tool(tmp_path, http_downstream):
    url, call_log = http_downstream
    async with asyncio.timeout(_TIMEOUT_S):
        async with _agent_through_doberman(tmp_path, url) as agent:
            # A fetch to a trusted host PASSes (mirrors test_proxy_passthrough.py).
            result = await agent.call_tool("net_get", {"url": "https://github.com/owner/repo"})
    assert not result.isError
    assert "net_get" in _logged_tools(call_log)


async def test_block_decision_reaches_no_http_tool(tmp_path, http_downstream):
    url, call_log = http_downstream
    async with asyncio.timeout(_TIMEOUT_S):
        async with _agent_through_doberman(tmp_path, url) as agent:
            # A catastrophic command is BLOCKed by the objective guardrail.
            result = await agent.call_tool("shell_exec", {"command": "rm -rf /"})
    assert result.isError
    # The chokepoint property: the blocked call never reached the downstream tool.
    assert "shell_exec" not in _logged_tools(call_log)
