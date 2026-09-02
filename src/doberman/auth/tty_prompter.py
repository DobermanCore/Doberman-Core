"""A :class:`~doberman.auth.challenge.Prompter` that talks to the controlling terminal.

Used when Doberman runs as a stdio MCP proxy (``doberman serve``): the agent owns
this process's stdin/stdout, so an ``AUTH`` challenge must reach the human through the
controlling terminal directly — ``/dev/tty`` (POSIX) or ``CONIN$``/``CONOUT$`` (Windows).
If no terminal is attached (a headless, agent-spawned subprocess), opening it raises →
the provider treats the challenge as failed → the action is **denied** (fail closed).

SECURITY: this never reads ``sys.stdin`` or writes ``sys.stdout`` — those are the agent's
MCP channel, and a stray byte there corrupts the protocol. Any no-input/EOF condition
raises so the provider denies rather than defaulting to "yes".
"""

import sys
from typing import TextIO

from doberman.auth.challenge import DEFAULT_CHALLENGE_TIMEOUT_S
from doberman.render import deadline_note

#: Replies that count as approval for a yes/no confirm (case-insensitive).
_AFFIRMATIVE = frozenset({"y", "yes"})


def _open_tty() -> tuple[TextIO, TextIO]:
    """Open ``(read, write)`` handles to the controlling terminal.

    On POSIX both are the same bidirectional ``/dev/tty`` handle; on Windows they are
    the distinct console devices. Raises ``OSError`` when no terminal is attached — the
    caller turns that into a denial.
    """
    # Every real test fakes this whole function (``monkeypatch.setattr(tty_prompter,
    # "_open_tty", ...)``) rather than call it -- a real controlling terminal (either
    # branch) cannot be constructed in any CI sandbox, Windows or POSIX.
    if sys.platform == "win32":  # pragma: no cover — needs a real attached console
        return (
            open("CONIN$", encoding="utf-8"),  # noqa: SIM115 — closed by the caller's finally
            open("CONOUT$", "w", encoding="utf-8"),  # noqa: SIM115 — closed by the caller's finally
        )
    tty = open("/dev/tty", "r+", encoding="utf-8")  # noqa: SIM115 — pragma: no cover
    return tty, tty


class TtyPrompter:
    """Collect a challenge response from the controlling terminal (see module docstring).

    ``timeout_s`` is this channel's OWN real enforced ceiling — symmetric with
    :class:`~doberman.auth.gui_prompter.GuiPrompter`'s ``timeout_s`` — and is
    what the printed deadline note actually reflects: unlike the GUI dialog,
    the terminal has no shorter internal watchdog of its own, so its real
    ceiling IS the overall challenge deadline
    (:data:`~doberman.auth.challenge.DEFAULT_CHALLENGE_TIMEOUT_S` by default).
    Defaulting to that same constant keeps every existing caller's behavior
    unchanged; a caller that passes a different challenge timeout can pass
    the same value here so the note never drifts from what's actually
    enforced.
    """

    def __init__(self, *, timeout_s: float = DEFAULT_CHALLENGE_TIMEOUT_S) -> None:
        self._timeout_s = timeout_s

    def confirm(self, message: str) -> bool:
        """Ask a yes/no question on the terminal.

        A blank line (Enter with no input) is a non-affirmative reply → ``False`` (deny);
        EOF / a closed terminal raises (the provider also treats that as a denial). Either
        way the answer is never silently "yes".
        """
        answer = self._ask(f"\n{message} [y/N] ")
        return answer.strip().lower() in _AFFIRMATIVE

    def read_code(self, message: str) -> str:
        """Read a one-time code from the terminal. Blank/EOF input → raise (deny).

        An empty code must never be returned to the verifier, so a blank line raises rather
        than passing ``""`` through. The code may echo on the local terminal — acceptable for
        a single-use TOTP seen only by the local human; it never touches the agent's stream or a log.
        """
        code = self._ask(f"\n{message}: ").strip()
        if not code:
            raise EOFError("no code entered on the controlling terminal")
        return code

    def _ask(self, prompt: str) -> str:
        # Open a fresh handle per prompt (don't cache): a terminal that was unavailable or
        # closed earlier may be usable now, and per-call opens keep concurrent challenges
        # independent. AUTH challenges are effectively serialized by the human anyway.
        read_handle, write_handle = _open_tty()
        try:
            write_handle.write(f"{prompt.rstrip()} [{deadline_note(self._timeout_s)}] ")
            write_handle.flush()
            line = read_handle.readline()
        finally:
            # Nested so a failure closing the write handle still closes the (distinct, on
            # Windows) read handle — never leak a console handle.
            try:
                write_handle.close()
            finally:
                if read_handle is not write_handle:
                    read_handle.close()
        if not line:  # EOF / closed terminal — never silently approve
            raise EOFError("no input available on the controlling terminal")
        return line
