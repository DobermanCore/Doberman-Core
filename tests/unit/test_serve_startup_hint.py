"""`doberman serve` must not look like a hang, and must never say so on stdout.

Run bare in a terminal the proxy blocks on stdin waiting for a client and prints
nothing further, which reads as a hang - or as "serve was supposed to start my
agent". One stderr line fixes that, but stdout is the MCP channel, so the fix
must be provably invisible to a client that spawned the process on a pipe.
"""

import pytest
from typer.testing import CliRunner

import doberman.cli.main as cli
from doberman.proxy import serve as serve_mod

runner = CliRunner()


@pytest.fixture
def _stub_serve(monkeypatch):
    """Keep `serve` from actually spawning a downstream or touching global logging."""
    monkeypatch.setattr(cli, "_configure_stderr_logging", lambda *a, **k: None)

    async def _spy(*_a, **_k):
        return None

    monkeypatch.setattr(serve_mod, "serve_stdio", _spy)


def test_hint_says_it_starts_nothing_and_names_both_wiring_paths():
    hint = cli._SERVE_WAITING_HINT
    assert "does not start your agent" in hint
    assert "claude mcp add doberman" in hint  # the MCP-proxy path
    assert "doberman setup" in hint  # the hooks path, recommended for Claude Code
    assert "stdin" in hint  # names what it is actually waiting for


def test_hint_is_ascii_only():
    """It goes to whatever stderr the caller gave us; a non-UTF-8 capture would
    mangle an em-dash into a replacement character in their log."""
    cli._SERVE_WAITING_HINT.encode("ascii")


def test_piped_stderr_gets_no_hint_and_stdout_stays_empty(_stub_serve):
    """A client-spawned process gets pipes, not a tty: the hint is for humans, and
    stdout must carry nothing but MCP frames."""
    result = runner.invoke(cli.app, ["serve", "--", "mytool"])

    assert result.exit_code == 0
    assert result.stdout == ""
    assert "does not start your agent" not in result.stderr


def test_a_terminal_gets_the_hint_on_stderr(monkeypatch, _stub_serve):
    written: list[str] = []
    monkeypatch.setattr(cli, "_stderr_is_tty", lambda: True)
    monkeypatch.setattr(cli.typer, "echo", lambda msg, **kw: written.append(f"{kw}:{msg}"))

    runner.invoke(cli.app, ["serve", "--", "mytool"])

    hinted = [line for line in written if "does not start your agent" in line]
    assert hinted, written
    assert "'err': True" in hinted[0]  # stderr only - never the MCP channel
