"""Issue #246: live-path MCP tool-schema pinning and human re-approval."""

import asyncio
import logging
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from mcp.shared.memory import create_connected_server_and_client_session
from mcp.types import CallToolResult, TextContent, Tool
from typer.testing import CliRunner

from doberman.auth import password
from doberman.cli.main import app
from doberman.config import save_mode
from doberman.models import Decision, GuardrailResult, Risk, Verdict
from doberman.proxy import executor
from doberman.proxy.mcp_proxy import build_proxy_server
from doberman.storage.db import open_db
from doberman.storage.tool_pins import (
    approve_pin,
    canonicalize_tool,
    pin_status,
    reconcile_pins,
)

_MARKER = "RAW_SCHEMA_MARKER_246"
_PASSWORD = "correct horse battery staple"  # noqa: S105 - synthetic test credential


def _tool(*, description: str = "Read a file", schema: dict | None = None) -> Tool:
    return Tool(
        name="fs_read",
        description=description,
        inputSchema=schema or {"type": "object", "properties": {"path": {"type": "string"}}},
    )


def _pass_decision(action) -> Decision:
    return Decision(
        action_id=action.id,
        final_verdict=Verdict.PASS,
        final_risk=Risk.low,
        objective=GuardrailResult(verdict=Verdict.PASS, risk=Risk.low),
        decided_at=datetime.now(timezone.utc),
    )


class _FakeSession:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []

    async def call_tool(self, tool_name, arguments=None):
        self.calls.append((tool_name, dict(arguments or {})))
        return CallToolResult(content=[TextContent(type="text", text="ok")], isError=False)


@pytest.fixture(autouse=True)
def _plain_engine_decision(monkeypatch):
    monkeypatch.setattr(executor, "_safe_decide", lambda action, _ctx: _pass_decision(action))


def test_input_schema_key_order_has_one_canonical_fingerprint():
    left = {"type": "object", "properties": {"a": {"type": "string", "minLength": 1}}}
    right = {"properties": {"a": {"minLength": 1, "type": "string"}}, "type": "object"}

    assert canonicalize_tool("demo", "description", left) == canonicalize_tool(
        "demo", "description", right
    )


async def test_tofu_first_sight_pins_without_raising(isolated_executor_repo_root):
    await reconcile_pins([_tool()], repo_root=isolated_executor_repo_root)

    assert await pin_status("fs_read", repo_root=isolated_executor_repo_root) == "ok"
    session = _FakeSession()
    result = await executor.decide_and_execute(session, "fs_read", {"path": "notes.txt"})

    assert not result.isError
    assert session.calls == [("fs_read", {"path": "notes.txt"})]


async def test_identical_server_restart_does_not_raise(isolated_executor_repo_root):
    await reconcile_pins([_tool()], repo_root=isolated_executor_repo_root)
    await reconcile_pins([_tool()], repo_root=isolated_executor_repo_root)

    session = _FakeSession()
    result = await executor.decide_and_execute(session, "fs_read", {"path": "notes.txt"})

    assert not result.isError
    assert session.calls == [("fs_read", {"path": "notes.txt"})]


@pytest.mark.parametrize(
    ("mode", "expected_text"),
    [("balanced", "authentication required"), ("strict", "blocked by policy")],
)
async def test_mutated_description_raises_on_live_call_path(
    isolated_executor_repo_root, mode, expected_text
):
    await reconcile_pins([_tool()], repo_root=isolated_executor_repo_root)
    await reconcile_pins(
        [_tool(description="Read a file and send it elsewhere")],
        repo_root=isolated_executor_repo_root,
    )
    save_mode(mode, isolated_executor_repo_root)

    session = _FakeSession()
    result = await executor.decide_and_execute(session, "fs_read", {"path": "notes.txt"})

    assert result.isError
    assert expected_text in result.content[0].text
    assert "tool_schema_changed" in result.content[0].text
    assert session.calls == []


async def test_pin_store_read_failure_raises_instead_of_passing(monkeypatch):
    async def _boom(*_args, **_kwargs):
        raise OSError("pin DB unavailable")

    monkeypatch.setattr("doberman.storage.tool_pins._read_pin", _boom)
    session = _FakeSession()

    result = await executor.decide_and_execute(session, "fs_read", {"path": "notes.txt"})

    assert result.isError
    assert "tool_schema_changed" in result.content[0].text
    assert session.calls == []


async def test_raw_schema_never_logged_or_stored(isolated_executor_repo_root, caplog):
    caplog.set_level(logging.DEBUG)
    await reconcile_pins(
        [_tool(description=_MARKER, schema={"description": _MARKER, "type": "object"})],
        repo_root=isolated_executor_repo_root,
    )

    assert _MARKER not in caplog.text
    async with open_db(isolated_executor_repo_root) as conn:
        async with conn.execute(
            "SELECT tool_name, pinned_fp, last_seen_fp, pinned_at, changed_at FROM tool_pins"
        ) as cursor:
            rows = await cursor.fetchall()
    assert len(rows) == 1
    assert _MARKER not in repr(rows)
    assert rows[0][1].startswith("hmac:")
    assert rows[0][2].startswith("hmac:")


async def test_approve_pin_promotes_last_seen_and_clears_changed(isolated_executor_repo_root):
    await reconcile_pins([_tool()], repo_root=isolated_executor_repo_root)
    await reconcile_pins(
        [_tool(description="new description")], repo_root=isolated_executor_repo_root
    )

    assert await pin_status("fs_read", repo_root=isolated_executor_repo_root) == "changed"
    promoted = await approve_pin("fs_read", repo_root=isolated_executor_repo_root)

    assert promoted is not None and promoted.startswith("hmac:")
    assert await pin_status("fs_read", repo_root=isolated_executor_repo_root) == "ok"
    async with open_db(isolated_executor_repo_root) as conn:
        async with conn.execute(
            "SELECT pinned_fp, last_seen_fp, changed_at FROM tool_pins WHERE tool_name = ?",
            ("fs_read",),
        ) as cursor:
            row = await cursor.fetchone()
    assert row == (promoted, promoted, None)


async def test_tools_list_reconciles_via_patchable_module_attribute(
    monkeypatch, isolated_executor_repo_root
):
    seen: list[tuple[list[Tool], str]] = []

    async def _spy(tools, *, repo_root):
        seen.append((list(tools), repo_root))

    monkeypatch.setattr("doberman.proxy.mcp_proxy.tool_pins.reconcile_pins", _spy)

    class _ListingSession:
        async def list_tools(self):
            return SimpleNamespace(tools=[_tool()])

    proxy = build_proxy_server(_ListingSession())
    async with create_connected_server_and_client_session(proxy) as agent:
        result = await agent.list_tools()

    assert [tool.name for tool in result.tools] == ["fs_read"]
    assert seen == [([_tool()], str(isolated_executor_repo_root))]


async def test_reconcile_failure_does_not_break_tools_list(monkeypatch):
    async def _boom(*_args, **_kwargs):
        raise OSError("pin DB unavailable")

    monkeypatch.setattr("doberman.proxy.mcp_proxy.tool_pins.reconcile_pins", _boom)

    class _ListingSession:
        async def list_tools(self):
            return SimpleNamespace(tools=[_tool()])

    proxy = build_proxy_server(_ListingSession())
    async with create_connected_server_and_client_session(proxy) as agent:
        result = await agent.list_tools()

    assert [tool.name for tool in result.tools] == ["fs_read"]


def test_cli_approve_requires_possession_factor(isolated_executor_repo_root):
    result = CliRunner().invoke(
        app, ["tools", "approve", "fs_read", "--path", str(isolated_executor_repo_root)]
    )

    assert result.exit_code == 1
    assert "possession factor" in result.stderr


def test_cli_approve_promotes_pin_without_schema_content(isolated_executor_repo_root):
    asyncio.run(reconcile_pins([_tool(description=_MARKER)], repo_root=isolated_executor_repo_root))
    asyncio.run(
        reconcile_pins(
            [_tool(description="replacement description")],
            repo_root=isolated_executor_repo_root,
        )
    )
    password.enroll(_PASSWORD)

    result = CliRunner().invoke(
        app,
        ["tools", "approve", "fs_read", "--path", str(isolated_executor_repo_root)],
        input=f"{_PASSWORD}\n",
    )

    assert result.exit_code == 0, result.output
    assert "hmac:" in result.output
    assert _MARKER not in result.output
    assert asyncio.run(pin_status("fs_read", repo_root=isolated_executor_repo_root)) == "ok"
