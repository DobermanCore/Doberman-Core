"""Slice 1.4 — tests for the structured, redacted interception log."""

import json
import logging
import re

import pytest

from doberman.proxy import interception_log
from doberman.proxy.interception_log import LOGGER_NAME

from .test_proxy_passthrough import proxied_session


def _log_records(caplog: pytest.LogCaptureFixture) -> list[dict]:
    lines = [r.message for r in caplog.records if r.name == LOGGER_NAME]
    return [json.loads(line) for line in lines]


async def test_one_valid_json_line_per_call_with_action_id(caplog):
    caplog.set_level(logging.INFO, logger=LOGGER_NAME)
    async with proxied_session() as (_, agent):
        await agent.call_tool("fs_write", {"path": "a.txt", "content": "hello"})
        await agent.call_tool("shell_exec", {"command": "echo hi"})

    records = _log_records(caplog)
    assert len(records) == 2
    for record in records:
        assert record["event"] == "tool_call_intercepted"
        assert record["verdict"] == "PASS"
        assert record["action"]["id"]  # stable id for correlation
    assert records[0]["action"]["tool_name"] == "fs_write"
    assert records[0]["action"]["action_type"] == "file_write"
    assert records[1]["action"]["target"] == "echo hi"


async def test_synthetic_secret_never_appears_in_log(caplog):
    caplog.set_level(logging.DEBUG)  # capture everything from every logger
    secret = "AKIAFAKEFAKEFAKEFAKE"  # noqa: S105 — synthetic test value
    async with proxied_session() as (_, agent):
        await agent.call_tool("fs_write", {"path": "a.txt", "content": secret})
        await agent.call_tool("net_get", {"url": "https://x.test", "api_key": secret})
    assert secret not in caplog.text


async def test_logging_failure_never_blocks_execution(caplog, monkeypatch):
    caplog.set_level(logging.INFO, logger=LOGGER_NAME)

    def boom(*args, **kwargs):
        raise RuntimeError("log serialization broke")

    monkeypatch.setattr(interception_log.json, "dumps", boom)
    async with proxied_session() as (fake, agent):
        result = await agent.call_tool("fs_write", {"path": "a.txt", "content": "x"})
    # The call still executed and succeeded despite the logging failure.
    assert not result.isError
    assert fake.calls == [("fs_write", {"path": "a.txt", "content": "x"})]
    # And the failure itself was noted (best-effort fallback line).
    assert any("interception_log_failed" in r.message for r in caplog.records)


def test_log_action_survives_total_logging_failure(monkeypatch):
    # Even the last-ditch fallback failing must not raise into execution.
    class ExplodingLogger:
        def info(self, *args, **kwargs):
            raise RuntimeError("logger broken")

        def warning(self, *args, **kwargs):
            raise RuntimeError("logger broken harder")

    from doberman.models import Verdict
    from doberman.proxy.normalize import normalize

    monkeypatch.setattr(interception_log, "logger", ExplodingLogger())
    action = normalize("fs_write", {"path": "x"})
    interception_log.log_action(action, Verdict.PASS)  # must not raise


async def test_failed_calls_are_still_logged_and_ids_correlate(caplog):
    caplog.set_level(logging.INFO, logger=LOGGER_NAME)
    from doberman.proxy import executor

    from .test_proxy_passthrough import DeadSession

    result = await executor.decide_and_execute(
        DeadSession(),  # type: ignore[arg-type]
        "fs_delete",
        {"path": "a.txt"},
    )
    assert result.isError
    records = _log_records(caplog)
    assert len(records) == 1
    logged_id = records[0]["action"]["id"]
    # The denial the agent sees carries the same action id as the log line.
    match = re.search(r"action id: ([0-9a-f]+)", result.content[0].text)
    assert match is not None
    assert match.group(1) == logged_id
