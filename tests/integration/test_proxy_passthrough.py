"""Slice 1.2 — integration tests for the pass-through MCP proxy chokepoint."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import NoReturn

import pytest
from mcp.client.session import ClientSession
from mcp.shared.exceptions import McpError
from mcp.shared.memory import create_connected_server_and_client_session
from mcp.types import CallToolResult

from doberman.proxy import executor
from doberman.proxy.mcp_proxy import build_proxy_server
from tests.fixtures.fake_tool_server import KNOWN_TOOL_NAMES, FakeToolServer


@asynccontextmanager
async def proxied_session() -> AsyncIterator[tuple[FakeToolServer, ClientSession]]:
    """fake downstream <- doberman proxy <- agent-side client session."""
    fake = FakeToolServer()
    async with create_connected_server_and_client_session(fake.build()) as downstream:
        proxy = build_proxy_server(downstream)
        async with create_connected_server_and_client_session(proxy) as agent:
            yield fake, agent


class DeadSession:
    """Stands in for an unreachable downstream (every operation fails)."""

    async def list_tools(self, *args: object, **kwargs: object) -> NoReturn:
        raise ConnectionError("downstream unreachable")

    async def call_tool(self, *args: object, **kwargs: object) -> NoReturn:
        raise ConnectionError("downstream unreachable")


async def test_downstream_tools_are_re_exposed():
    async with proxied_session() as (_, agent):
        result = await agent.list_tools()
        assert {tool.name for tool in result.tools} == KNOWN_TOOL_NAMES


async def test_call_is_forwarded_and_recorded():
    async with proxied_session() as (fake, agent):
        result = await agent.call_tool("fs_write", {"path": "a.txt", "content": "hello"})
        assert not result.isError
        assert result.content[0].text == "ok: fs_write executed"
        assert fake.calls == [("fs_write", {"path": "a.txt", "content": "hello"})]


async def test_unknown_tool_errors_and_nothing_recorded():
    async with proxied_session() as (fake, agent):
        result = await agent.call_tool("rm_rf_root", {})
        # The downstream refuses the unknown tool; its error result is passed
        # through (Doberman-side blocking of unknown tools is F2/F3 decision
        # logic). The chokepoint property holds: nothing was executed.
        assert result.isError
        assert fake.calls == []


async def test_downstream_unreachable_fails_closed_and_sanitized():
    proxy = build_proxy_server(DeadSession())  # type: ignore[arg-type]
    async with create_connected_server_and_client_session(proxy) as agent:
        # tools/list before the downstream is ready/reachable -> error, no hang.
        with pytest.raises(McpError) as excinfo:
            await agent.list_tools()
        # Raw downstream error text must not reach the agent — class name only.
        assert "downstream unreachable" not in str(excinfo.value)
        assert "ConnectionError" in str(excinfo.value)


async def test_downstream_fails_mid_session_fails_closed():
    async with proxied_session() as (fake, agent):
        ok = await agent.call_tool("fs_write", {"path": "a.txt", "content": "x"})
        assert not ok.isError
        # Downstream starts failing mid-session.
        fake.fail_mode = True
        result = await agent.call_tool("fs_delete", {"path": "a.txt"})
        assert result.isError
        # The failed call executed nothing — only the first call was recorded.
        assert fake.calls == [("fs_write", {"path": "a.txt", "content": "x"})]


async def test_transport_error_yields_denied_result_with_reason_code():
    result = await executor.decide_and_execute(
        DeadSession(),  # type: ignore[arg-type]
        "fs_delete",
        {"path": "a.txt"},
    )
    assert result.isError
    assert "downstream_error" in result.content[0].text


async def test_error_result_never_echoes_arguments():
    secret = "AKIA-FAKE-SECRET-VALUE-12345"  # noqa: S105 — synthetic test value
    result = await executor.decide_and_execute(
        DeadSession(),  # type: ignore[arg-type]
        "fs_write",
        {"path": "x", "content": secret},
    )
    assert result.isError
    assert secret not in result.content[0].text


async def test_end_to_end_error_never_echoes_arguments():
    # Full agent->proxy->downstream path: a failing call carrying a synthetic
    # secret must yield an agent-visible error that never contains it.
    secret = "AKIA-FAKE-SECRET-VALUE-67890"  # noqa: S105 — synthetic test value
    async with proxied_session() as (fake, agent):
        fake.fail_mode = True
        result = await agent.call_tool("fs_write", {"path": "x", "content": secret})
        assert result.isError
        assert all(secret not in block.text for block in result.content)
        assert fake.calls == []


async def test_every_call_is_normalized_before_execution(monkeypatch):
    """Slice 1.3 wiring proof: the chokepoint normalizes each call."""
    from doberman.proxy import normalize as normalize_mod

    seen: list[str] = []
    original = normalize_mod.normalize

    def spy(tool_name, arguments, context=None):
        seen.append(tool_name)
        return original(tool_name, arguments, context)

    monkeypatch.setattr("doberman.proxy.executor.normalize", spy)
    async with proxied_session() as (_, agent):
        await agent.call_tool("fs_write", {"path": "a.txt", "content": "x"})
        await agent.call_tool("net_get", {"url": "https://example.com"})
    assert seen == ["fs_write", "net_get"]


async def test_every_call_routes_through_decide_and_execute(monkeypatch):
    routed: list[str] = []
    original = executor.decide_and_execute

    async def spy(downstream, tool_name, arguments) -> CallToolResult:
        routed.append(tool_name)
        return await original(downstream, tool_name, arguments)

    monkeypatch.setattr(executor, "decide_and_execute", spy)
    async with proxied_session() as (fake, agent):
        # Benign actions that the real objective guardrail (F3) lets PASS so the
        # forward still happens: a trivial echo and a fetch to a trusted host.
        await agent.call_tool("shell_exec", {"command": "echo hi"})
        await agent.call_tool("net_get", {"url": "https://github.com/owner/repo"})
    assert routed == ["shell_exec", "net_get"]
    assert [name for name, _ in fake.calls] == ["shell_exec", "net_get"]
