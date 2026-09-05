"""Slice 1.4 — tests for the structured, redacted interception log."""

import json
import logging
import re
from datetime import datetime, timezone

import pytest

from doberman.models import ActionType, SecurityObject, Verdict
from doberman.proxy import executor, interception_log
from doberman.proxy.interception_log import LOGGER_NAME
from doberman.proxy.normalize import normalize
from doberman.storage.log import path_class

from .test_proxy_passthrough import DeadSession, proxied_session


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
        assert record["id"]  # stable id for correlation
    assert records[0]["tool_name"] == "fs_write"
    assert records[0]["action_type"] == "file_write"
    assert records[0]["target_path_class"] == "*.txt"
    # shell_exec has no path class, and the raw command text is never logged
    # (the sink only ever emits the redaction-safe field set — see log_action).
    assert records[1]["target_path_class"] is None
    assert "echo hi" not in caplog.text


async def test_synthetic_secret_never_appears_in_log(caplog):
    caplog.set_level(logging.DEBUG)  # capture everything from every logger
    secret = "AKIAFAKEFAKEFAKEFAKE"  # noqa: S105 — synthetic test value
    async with proxied_session() as (_, agent):
        await agent.call_tool("fs_write", {"path": "a.txt", "content": secret})
        await agent.call_tool("net_get", {"url": "https://x.test", "api_key": secret})
    # The redaction guarantee must actually have been exercised: both calls
    # produced a log line, and neither contains the secret.
    assert len(_log_records(caplog)) == 2
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

    monkeypatch.setattr(interception_log, "logger", ExplodingLogger())
    action = normalize("fs_write", {"path": "x"})
    interception_log.log_action(action, Verdict.PASS)  # must not raise


async def test_failed_calls_are_still_logged_and_ids_correlate(caplog):
    caplog.set_level(logging.INFO, logger=LOGGER_NAME)
    result = await executor.decide_and_execute(
        DeadSession(),  # type: ignore[arg-type]
        "fs_delete",
        {"path": "a.txt"},
    )
    assert result.isError
    records = _log_records(caplog)
    assert len(records) == 1
    logged_id = records[0]["id"]
    # The denial the agent sees carries the same action id as the log line.
    match = re.search(r"action id: ([0-9a-f]+)", result.content[0].text)
    assert match is not None
    assert match.group(1) == logged_id


def test_short_unshaped_secret_under_non_sensitive_key_never_logged(caplog):
    """The critical proof: log_action must not depend on normalize()'s redactor.

    normalize()'s ``_redact_value`` is a length/shape heuristic stopgap (H1
    hardening layered the canonical shared detector on top, but it too is
    shape-based) — a short, unshaped secret under a non-sensitive argument key
    and an env-assignment-style key name the shared detector's keyword list
    doesn't recognize (e.g. ``content="db_config=..."``, not "db_password=...";
    see the shared detector's ``_ENV_ASSIGNMENT`` keyword list) passes through
    ``raw_args_redacted`` completely unredacted. Before this fix, ``log_action``
    logged ``action.model_dump()`` (which includes ``raw_args_redacted``), so a
    routine PASS could write that secret to the interception log in cleartext.
    This test fails on the old code and passes on the new.
    """
    caplog.set_level(logging.INFO, logger=LOGGER_NAME)
    secret_value = "db_config=Tr0ub4dor&3"  # noqa: S105 — synthetic test value
    action = normalize("write_file", {"content": secret_value, "path": "config.env"})
    # Sanity-check the premise: the heuristic redactor really did let this
    # secret through unredacted (otherwise this test would prove nothing).
    assert action.raw_args_redacted["content"] == secret_value

    interception_log.log_action(action, Verdict.PASS)

    assert "db_config" not in caplog.text
    assert "Tr0ub4dor" not in caplog.text

    records = _log_records(caplog)
    assert len(records) == 1
    record = records[0]
    assert record["event"] == "tool_call_intercepted"
    assert record["verdict"] == "PASS"
    assert record["action_type"] == "file_write"
    assert record["tool_name"] == "write_file"
    assert record["target_path_class"] == "*.env"
    assert "raw_args_redacted" not in record
    assert "target" not in record


def test_secret_shaped_value_never_logged(caplog):
    """Regression guard: a secret-SHAPED value is also absent from the log."""
    caplog.set_level(logging.INFO, logger=LOGGER_NAME)
    secret_value = "AKIA" + "1234567890ABCDEF"  # noqa: S105 — synthetic test value
    action = normalize("write_file", {"token": secret_value, "path": "a.txt"})

    interception_log.log_action(action, Verdict.PASS)

    assert secret_value not in caplog.text


def _file_action(target: str) -> SecurityObject:
    return SecurityObject(
        id="act-path-class",
        ts=datetime(2026, 6, 8, tzinfo=timezone.utc),
        agent_role="r",
        action_type=ActionType.file_read,
        tool_name="fs_read",
        target=target,
    )


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        # Relative path, directory + extensionless filename: the raw filename
        # used to be returned verbatim instead of being classed like any
        # other filename. See BUILD-LOG / path-class-report for the finding.
        (".ssh/id_rsa", ".ssh/*"),
        ("config/credentials", "config/*"),
        ("secrets/prod", "secrets/*"),
        # Absolute POSIX path, same extensionless-under-a-directory shape.
        ("/etc/passwd", "/etc/*"),
        # Windows drive path, same shape.
        ("C:/Users/x/.aws/credentials", "C:/Users/x/.aws/*"),
    ],
)
def test_extensionless_name_under_a_directory_is_wildcarded_not_verbatim(target, expected):
    result = path_class(_file_action(target))
    assert result == expected
    # The raw filename component must never survive verbatim in the class.
    raw_name = target.rsplit("/", 1)[-1]
    assert raw_name not in result


def test_bare_dotfile_with_no_directory_is_still_its_own_class():
    """The documented legitimate shape is preserved: a top-level dotfile
    (no directory component) is itself the class — see path_class()'s
    docstring (`.env` -> `.env`)."""
    assert path_class(_file_action(".env")) == ".env"


def test_extensioned_name_under_a_directory_is_still_wildcarded():
    """Pinned baseline, unaffected by the extensionless fix."""
    assert path_class(_file_action("backend/auth/session.ts")) == "backend/auth/*.ts"
