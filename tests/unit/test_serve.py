"""Unit tests for the `doberman serve` command and the `serve_stdio` launcher.

Covers CLI argument parsing (downstream command after `--`, `--path`, the missing-command error)
and that `serve_stdio` sets the executor's repo root + a non-stdio AUTH prompter and runs the proxy
over stdio. The real stdio transports are faked so these stay headless and deterministic; the full
agent⇄serve⇄downstream chain is covered by the integration test.
"""

import logging
import sys
from contextlib import asynccontextmanager

import pytest
from mcp import StdioServerParameters
from typer.testing import CliRunner

import doberman.cli.main as cli
from doberman.auth.tty_prompter import TtyPrompter
from doberman.proxy import executor
from doberman.proxy import serve as serve_mod

runner = CliRunner()


@pytest.fixture(autouse=True)
def _restore_executor_globals():
    """The serve path mutates module-level executor globals — restore them after each test."""
    repo_root, prompter = executor.REPO_ROOT, executor.AUTH_PROMPTER
    try:
        yield
    finally:
        executor.REPO_ROOT = repo_root
        executor.AUTH_PROMPTER = prompter


@pytest.fixture
def _no_logging_mutation(monkeypatch):
    """Stub out stderr-logging setup so CLI-parse tests don't reconfigure global logging."""
    monkeypatch.setattr(cli, "_configure_stderr_logging", lambda *a, **k: None)


# --- CLI parsing -----------------------------------------------------------------


def test_missing_downstream_command_exits_2(monkeypatch):
    called = False

    async def _spy(*_a, **_k):
        nonlocal called
        called = True

    monkeypatch.setattr(cli, "serve_stdio", _spy)
    result = runner.invoke(cli.app, ["serve"])
    assert result.exit_code == 2
    assert not called


def test_builds_stdio_params_from_argv(monkeypatch, _no_logging_mutation):
    seen: dict = {}

    async def _spy(params, *, repo_root):
        seen["params"] = params
        seen["repo_root"] = repo_root

    monkeypatch.setattr(cli, "serve_stdio", _spy)
    result = runner.invoke(cli.app, ["serve", "--", "mytool", "a", "b"])
    assert result.exit_code == 0
    assert result.output == ""  # nothing on stdout — that is the agent's MCP channel
    assert seen["params"].command == "mytool"
    assert seen["params"].args == ["a", "b"]
    assert seen["repo_root"] == "."


def test_path_option_threads_repo_root(monkeypatch, _no_logging_mutation):
    seen: dict = {}

    async def _spy(params, *, repo_root):
        seen["repo_root"] = repo_root

    monkeypatch.setattr(cli, "serve_stdio", _spy)
    result = runner.invoke(cli.app, ["serve", "-p", "/repo", "--", "mytool"])
    assert result.exit_code == 0
    assert seen["repo_root"] == "/repo"


def test_serve_reports_downstream_failure_cleanly(monkeypatch, _no_logging_mutation):
    """A failure to start/serve becomes a clean stderr error + exit 1, never a raw traceback."""

    async def _boom(*_a, **_k):
        raise RuntimeError("downstream boom")

    monkeypatch.setattr(cli, "serve_stdio", _boom)
    result = runner.invoke(cli.app, ["serve", "--", "mytool"])
    assert result.exit_code == 1
    assert "doberman serve failed" in result.output
    assert result.exception is None or isinstance(result.exception, SystemExit)


def test_stderr_logging_keeps_stdout_clean():
    """_configure_stderr_logging pins doberman logs to stderr and scrubs stdout from root."""
    root = logging.getLogger()
    doberman_logger = logging.getLogger("doberman")
    saved_root, saved_dob = root.handlers[:], doberman_logger.handlers[:]
    saved_prop = doberman_logger.propagate
    hostile = logging.StreamHandler(sys.stdout)  # pretend a host config logs to stdout
    root.addHandler(hostile)
    try:
        cli._configure_stderr_logging()
        assert doberman_logger.propagate is False
        assert doberman_logger.handlers
        assert all(getattr(h, "stream", None) is sys.stderr for h in doberman_logger.handlers)
        assert not any(
            isinstance(h, logging.StreamHandler) and getattr(h, "stream", None) is sys.stdout
            for h in root.handlers
        )
    finally:
        root.handlers[:] = saved_root
        doberman_logger.handlers[:] = saved_dob
        doberman_logger.propagate = saved_prop


# --- serve_stdio wiring ----------------------------------------------------------


async def test_serve_stdio_sets_repo_root_and_tty_prompter(monkeypatch):
    """serve_stdio points the engine at repo_root and installs a non-stdio prompter, then runs."""
    ran: dict = {}

    @asynccontextmanager
    async def _fake_stdio_client(_params):
        yield ("d_read", "d_write")

    class _FakeSession:
        def __init__(self, read, write):
            ran["session_args"] = (read, write)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_a):
            return False

        async def initialize(self):
            ran["initialized"] = True

    @asynccontextmanager
    async def _fake_stdio_server():
        yield ("a_read", "a_write")

    class _FakeProxy:
        def create_initialization_options(self):
            return "init-opts"

        async def run(self, read, write, opts):
            ran["run"] = (read, write, opts)

    monkeypatch.setattr(serve_mod, "stdio_client", _fake_stdio_client)
    monkeypatch.setattr(serve_mod, "ClientSession", _FakeSession)
    monkeypatch.setattr(serve_mod, "stdio_server", _fake_stdio_server)
    monkeypatch.setattr(serve_mod, "build_proxy_server", lambda _session: _FakeProxy())

    params = StdioServerParameters(command="mytool", args=[])
    await serve_mod.serve_stdio(params, repo_root="/some/repo")

    assert executor.REPO_ROOT == "/some/repo"
    assert isinstance(executor.AUTH_PROMPTER, TtyPrompter)
    assert ran["session_args"] == ("d_read", "d_write")  # downstream streams wired into the session
    assert ran["initialized"] is True
    assert ran["run"] == ("a_read", "a_write", "init-opts")
