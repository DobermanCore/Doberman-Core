"""GUI auth prompter + the GUI→TTY fallback chain (the serve-mode AUTH channel).

When an MCP agent (Claude Code, Codex, Cursor, …) spawns ``doberman serve``, the
controlling terminal *still exists* but is owned by the agent's TUI: a prompt
written to ``CONOUT$``/``/dev/tty`` opens successfully yet is painted over
(invisible), and keystrokes go to the agent — the human can never see or answer
the Feature 7 challenge. The challenge must therefore surface **out-of-band** as
a topmost dialog window; the terminal remains only a fallback for headless/SSH
sessions where no display exists.

:class:`PrompterUnavailableError` separates "this channel cannot open at all"
(fall through to the next channel) from a human answer or a human-channel error
(EOF/timeout — FINAL, the provider denies). A denial on one channel must never
be re-asked on another — that would be answer-shopping.

SECURITY: nothing here reads ``sys.stdin`` or writes ``sys.stdout`` (the agent's
MCP channel). Cancelling/closing a dialog raises or returns ``False`` so the
provider denies — there is no silent "yes". The 2FA code entry is masked.
tkinter is stdlib; no new dependency.
"""

from collections.abc import Iterable
from typing import Any

from doberman.auth.challenge import Prompter

#: Window title for every challenge dialog.
_TITLE = "Doberman — authorization required"


class PrompterUnavailableError(RuntimeError):
    """The prompter's human channel cannot be opened at all (no display, no GUI).

    Distinct from a denial or an EOF on an *open* channel: only this error lets a
    :class:`FallbackPrompter` consult the next channel. Reaching the provider, it
    is treated like any other challenge failure — the action is denied.
    """


def _open_root() -> Any:
    """Create a hidden, topmost Tk root for one dialog. Raises when no GUI exists.

    A fresh root per challenge (never cached): Tk objects are not thread-safe to
    share and a display that was missing earlier may be available now. The caller
    must destroy it.
    """
    try:
        import tkinter
    except Exception as exc:  # pragma: no cover — needs a tkinter-less interpreter
        raise PrompterUnavailableError("tkinter is not available") from exc
    try:
        root = tkinter.Tk()
    except Exception as exc:  # tkinter.TclError — no display / no window station
        raise PrompterUnavailableError("no display available for a GUI auth dialog") from exc
    return root


def _prepare_root(root: Any) -> None:
    """Hide the empty main window and force the dialog above the agent's terminal."""
    root.withdraw()  # never flash an empty main window
    root.attributes("-topmost", True)  # the dialog must pop OVER the agent's terminal
    root.update()


def _confirm_dialog(message: str) -> bool:
    """Show a yes/no challenge dialog. Closing the window is "no" (deny)."""
    root = _open_root()
    try:
        from tkinter import messagebox

        _prepare_root(root)
        return bool(messagebox.askyesno(_TITLE, message, parent=root))
    finally:
        root.destroy()


def _code_dialog(message: str) -> str | None:
    """Show a masked one-time-code entry dialog. Cancel/close returns ``None``."""
    root = _open_root()
    try:
        from tkinter import simpledialog

        _prepare_root(root)
        return simpledialog.askstring(_TITLE, message, show="*", parent=root)
    finally:
        root.destroy()


class GuiPrompter:
    """Collect a challenge response through a topmost dialog window.

    Raises :class:`PrompterUnavailableError` when no display exists so a fallback
    chain can try the terminal instead; any other failure (cancel, blank code)
    raises and the provider denies (fail closed).
    """

    def confirm(self, message: str) -> bool:
        return _confirm_dialog(message)

    def read_code(self, message: str) -> str:
        """Read a one-time code via a masked dialog. Cancel/blank → raise (deny).

        An empty code must never reach the verifier, so cancel and whitespace-only
        entries raise instead of returning ``""``.
        """
        code = _code_dialog(message)
        if code is None or not code.strip():
            raise EOFError("no code entered in the auth dialog")
        return code.strip()


class FallbackPrompter:
    """Try each prompter in order; fall through ONLY when a channel is unavailable.

    A human answer (including "no") is final, and a human-channel error (EOF,
    timeout) propagates — the next channel is consulted only on
    :class:`PrompterUnavailableError`. With every channel unavailable it raises,
    so the provider denies (fail closed).
    """

    def __init__(self, prompters: Iterable[Prompter]) -> None:
        self._prompters: tuple[Prompter, ...] = tuple(prompters)

    @property
    def prompters(self) -> tuple[Prompter, ...]:
        """The chain, in consultation order (read-only — for wiring assertions)."""
        return self._prompters

    def confirm(self, message: str) -> bool:
        return self._first_open_channel("confirm", message)

    def read_code(self, message: str) -> str:
        return self._first_open_channel("read_code", message)

    def _first_open_channel(self, method: str, message: str) -> Any:
        last: PrompterUnavailableError | None = None
        for prompter in self._prompters:
            try:
                return getattr(prompter, method)(message)
            except PrompterUnavailableError as exc:
                last = exc
        raise PrompterUnavailableError("no auth prompter channel is available") from last
