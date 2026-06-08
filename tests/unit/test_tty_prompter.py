"""Unit tests for the controlling-terminal prompter (serve-mode AUTH channel).

The prompter must (a) collect a confirm/code from the terminal, (b) raise on EOF/no-terminal so
the provider denies (fail closed), and (c) NEVER touch sys.stdin/sys.stdout (the agent's MCP stream).
``_open_tty`` is monkeypatched so these stay headless and deterministic.

Note on fakes: a real ``/dev/tty`` opened ``r+`` does NOT share a buffer between read and write
(write goes to the screen, read comes from the keyboard). ``io.StringIO`` does share one, so the
fakes below keep the input and the captured output separate.
"""

import io

import pytest

from doberman.auth import tty_prompter
from doberman.auth.tty_prompter import TtyPrompter


class _FakeWrite:
    """A terminal-output handle: records what was written; close() is a no-op so the test
    can still inspect it after the prompter closes its handles."""

    def __init__(self) -> None:
        self.text = ""

    def write(self, s: str) -> int:
        self.text += s
        return len(s)

    def flush(self) -> None:  # pragma: no cover — trivial
        pass

    def close(self) -> None:
        pass


def _fake_tty(input_text: str) -> tuple[io.StringIO, _FakeWrite]:
    """Distinct (read, write) handles, mirroring a real bidirectional tty."""
    return io.StringIO(input_text), _FakeWrite()


@pytest.mark.parametrize(
    ("reply", "expected"),
    [("y\n", True), ("yes\n", True), ("Y\n", True), ("YES\n", True), ("n\n", False), ("\n", False)],
)
def test_confirm_maps_reply_to_bool(monkeypatch, reply, expected):
    monkeypatch.setattr(tty_prompter, "_open_tty", lambda: _fake_tty(reply))
    assert TtyPrompter().confirm("Approve THIS exact action?") is expected


def test_confirm_writes_prompt_to_terminal(monkeypatch):
    captured = _fake_tty("y\n")
    monkeypatch.setattr(tty_prompter, "_open_tty", lambda: captured)
    TtyPrompter().confirm("Approve THIS exact action?")
    assert "Approve THIS exact action?" in captured[1].text


def test_read_code_returns_stripped_code(monkeypatch):
    monkeypatch.setattr(tty_prompter, "_open_tty", lambda: _fake_tty("123456\n"))
    assert TtyPrompter().read_code("Enter your 2FA code") == "123456"


def test_confirm_raises_on_eof_so_provider_denies(monkeypatch):
    # Empty string = EOF / closed terminal. Must raise (never silently approve).
    monkeypatch.setattr(tty_prompter, "_open_tty", lambda: _fake_tty(""))
    with pytest.raises(EOFError):
        TtyPrompter().confirm("Approve?")


def test_read_code_raises_on_eof(monkeypatch):
    monkeypatch.setattr(tty_prompter, "_open_tty", lambda: _fake_tty(""))
    with pytest.raises(EOFError):
        TtyPrompter().read_code("Enter your 2FA code")


def test_read_code_raises_on_blank_line(monkeypatch):
    # A blank line (Enter with no code) must NOT return "" to the TOTP verifier — it denies.
    monkeypatch.setattr(tty_prompter, "_open_tty", lambda: _fake_tty("\n"))
    with pytest.raises(EOFError):
        TtyPrompter().read_code("Enter your 2FA code")


def test_read_handle_closed_even_if_write_close_raises(monkeypatch):
    """On Windows read/write are distinct handles — a failure closing one must not leak the other."""
    closed = {"read": False}

    class _Write:
        def write(self, s: str) -> int:
            return len(s)

        def flush(self) -> None:
            pass

        def close(self) -> None:
            raise OSError("flush failed on close")

    class _Read(io.StringIO):
        def close(self) -> None:
            closed["read"] = True
            super().close()

    monkeypatch.setattr(tty_prompter, "_open_tty", lambda: (_Read("y\n"), _Write()))
    with pytest.raises(OSError, match="flush failed on close"):
        TtyPrompter().confirm("Approve?")
    assert closed["read"] is True


def test_no_terminal_raises_so_auth_fails_closed(monkeypatch):
    def _no_tty():
        raise OSError("no controlling terminal")

    monkeypatch.setattr(tty_prompter, "_open_tty", _no_tty)
    with pytest.raises(OSError, match="no controlling terminal"):
        TtyPrompter().confirm("Approve?")
    with pytest.raises(OSError, match="no controlling terminal"):
        TtyPrompter().read_code("Enter your 2FA code")


def test_never_touches_std_streams(monkeypatch):
    """A challenge must not read stdin or write stdout (that is the agent's MCP channel)."""

    class _Explode:
        def __getattr__(self, _name):
            raise AssertionError("prompter touched a std stream")

    monkeypatch.setattr("sys.stdin", _Explode())
    monkeypatch.setattr("sys.stdout", _Explode())
    monkeypatch.setattr(tty_prompter, "_open_tty", lambda: _fake_tty("y\n"))
    assert TtyPrompter().confirm("Approve?") is True


def test_posix_shared_handle_closed_once(monkeypatch):
    """On POSIX read and write are the SAME object — it must be closed exactly once."""

    class _Bidi:
        def __init__(self, input_text: str) -> None:
            self._in = io.StringIO(input_text)
            self.out = io.StringIO()
            self.closes = 0

        def write(self, s: str) -> int:
            return self.out.write(s)

        def flush(self) -> None:
            pass

        def readline(self) -> str:
            return self._in.readline()

        def close(self) -> None:
            self.closes += 1

    handle = _Bidi("y\n")
    monkeypatch.setattr(tty_prompter, "_open_tty", lambda: (handle, handle))
    assert TtyPrompter().confirm("Approve?") is True
    assert handle.closes == 1
