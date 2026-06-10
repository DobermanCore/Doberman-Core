"""GUI auth prompter + the GUI→TTY fallback chain (the serve-mode AUTH channel).

When an MCP agent (Claude Code, Codex, Cursor, …) spawns ``doberman serve``, the
controlling terminal *still exists* but is owned by the agent's TUI: a prompt
written to ``CONOUT$``/``/dev/tty`` opens successfully yet is painted over
(invisible), and keystrokes go to the agent — the human can never see or answer
the Feature 7 challenge. The challenge must therefore surface **out-of-band** as
a topmost dialog window; the terminal remains only a fallback for headless/SSH
sessions where no display exists.

The dialogs are custom-built tkinter windows (dark, black-and-orange theme) —
not the stock ``messagebox``/``simpledialog`` chrome — but the security contract
is unchanged: closing/cancelling a dialog denies, the code entry is masked, and
the safe action (Deny) holds the initial keyboard focus so a stray Enter can
never approve.

:class:`PrompterUnavailableError` separates "this channel cannot open at all"
(fall through to the next channel) from a human answer or a human-channel error
(EOF/timeout — FINAL, the provider denies). A denial on one channel must never
be re-asked on another — that would be answer-shopping.

SECURITY: nothing here reads ``sys.stdin`` or writes ``sys.stdout`` (the agent's
MCP channel). tkinter is stdlib; no new dependency.
"""

import sys
from collections.abc import Iterable
from typing import Any

from doberman.auth.challenge import Prompter

#: Window title for every challenge dialog.
_TITLE = "Doberman — authorization required"

# --- palette: dark, black and orange (no purple, no neon) ---------------------------
_BG = "#101010"  # window base
_PANEL = "#1b1b1b"  # message panel
_FG = "#f2f2f2"  # primary text
_MUTED = "#9b9b9b"  # secondary text
_ACCENT = "#ff7a1a"  # orange — brand + the Approve action
_ACCENT_ACTIVE = "#ff9447"  # orange hover/active
_DENY_BG = "#262626"  # neutral dark button
_DENY_ACTIVE = "#383838"

_BODY_FONT = ("Segoe UI", 10)
_BRAND_FONT = ("Segoe UI Semibold", 13)
_SUB_FONT = ("Segoe UI", 9)
_MONO_FONT = ("Consolas", 10)
_BUTTON_FONT = ("Segoe UI Semibold", 10)


class PrompterUnavailableError(RuntimeError):
    """The prompter's human channel cannot be opened at all (no display, no GUI).

    Distinct from a denial or an EOF on an *open* channel: only this error lets a
    :class:`FallbackPrompter` consult the next channel. Reaching the provider, it
    is treated like any other challenge failure — the action is denied.
    """


def _open_root() -> Any:
    """Create a Tk root for one dialog. Raises when no GUI exists.

    A fresh root per challenge (never cached): Tk objects are not thread-safe to
    share and a display that was missing earlier may be available now. The caller
    must destroy it.
    """
    try:
        import tkinter
    except Exception as exc:  # pragma: no cover — needs a tkinter-less interpreter
        raise PrompterUnavailableError("tkinter is not available") from exc
    try:
        return tkinter.Tk()
    except Exception as exc:  # tkinter.TclError — no display / no window station
        raise PrompterUnavailableError("no display available for a GUI auth dialog") from exc


def _configure_window(root: Any) -> None:
    """Apply the window-level theme: topmost, dark base, fixed size, dark title bar."""
    root.title(_TITLE)
    root.configure(bg=_BG)
    root.resizable(False, False)
    root.attributes("-topmost", True)  # the dialog must pop OVER the agent's terminal
    _apply_dark_title_bar(root)


def _apply_dark_title_bar(root: Any) -> None:
    """Best-effort dark title bar on Windows 11/10; purely cosmetic, never fatal."""
    if sys.platform != "win32":
        return
    try:  # pragma: no cover — needs a real native window handle
        import ctypes

        root.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(root.winfo_id())
        use_dark = ctypes.c_int(1)
        DWMWA_USE_IMMERSIVE_DARK_MODE = 20
        ctypes.windll.dwmapi.DwmSetWindowAttribute(
            hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, ctypes.byref(use_dark), ctypes.sizeof(use_dark)
        )
    except Exception:  # noqa: S110 — cosmetic only; the challenge must still show
        pass


def _center_on_screen(root: Any) -> None:
    """Center the (now-populated) dialog so it lands where the human is looking."""
    root.update_idletasks()
    width, height = root.winfo_reqwidth(), root.winfo_reqheight()
    x = max((root.winfo_screenwidth() - width) // 2, 0)
    y = max((root.winfo_screenheight() - height) // 3, 0)  # slightly above center
    root.geometry(f"+{x}+{y}")


def _styled_button(parent: Any, text: str, command: Any, *, accent: bool) -> Any:
    """A flat, hover-aware button: orange for the approve action, neutral for deny."""
    import tkinter as tk

    base = _ACCENT if accent else _DENY_BG
    active = _ACCENT_ACTIVE if accent else _DENY_ACTIVE
    fg = "#1a1208" if accent else _FG
    button = tk.Button(
        parent,
        text=text,
        command=command,
        font=_BUTTON_FONT,
        bg=base,
        fg=fg,
        activebackground=active,
        activeforeground=fg,
        relief="flat",
        bd=0,
        padx=18,
        pady=7,
        cursor="hand2",
        highlightthickness=1,
        highlightbackground=_BG,
        highlightcolor=_ACCENT,
    )
    button.bind("<Enter>", lambda _e: button.configure(bg=active))
    button.bind("<Leave>", lambda _e: button.configure(bg=base))
    return button


def _build_header_and_message(root: Any, message: str) -> None:
    """The shared top of both dialogs: brand row + the exact challenge text."""
    import tkinter as tk

    header = tk.Frame(root, bg=_BG)
    header.pack(fill="x", padx=18, pady=(16, 8))
    tk.Label(header, text="🐕 DOBERMAN", font=_BRAND_FONT, fg=_ACCENT, bg=_BG).pack(anchor="w")
    tk.Label(
        header,
        text="An agent action needs your decision",
        font=_SUB_FONT,
        fg=_MUTED,
        bg=_BG,
    ).pack(anchor="w", pady=(2, 0))

    panel = tk.Frame(root, bg=_PANEL, highlightthickness=1, highlightbackground="#2c2c2c")
    panel.pack(fill="both", expand=True, padx=18, pady=(6, 4))
    tk.Label(
        panel,
        text=message,
        font=_MONO_FONT,
        fg=_FG,
        bg=_PANEL,
        justify="left",
        anchor="w",
        wraplength=480,
        padx=12,
        pady=10,
    ).pack(fill="both", expand=True)


def _populate_confirm(root: Any, message: str, answer: dict) -> None:
    """Yes/no challenge body. Deny keeps initial focus — Enter can never stray-approve."""
    import tkinter as tk

    _build_header_and_message(root, message)

    def _decide(value: bool) -> None:
        answer["value"] = value
        root.quit()

    buttons = tk.Frame(root, bg=_BG)
    buttons.pack(fill="x", padx=18, pady=(6, 16))
    deny = _styled_button(buttons, "Deny", lambda: _decide(False), accent=False)
    approve = _styled_button(buttons, "Approve", lambda: _decide(True), accent=True)
    deny.pack(side="right", padx=(8, 0))
    approve.pack(side="right")

    root.bind("<Escape>", lambda _e: _decide(False))
    root.bind(
        "<Return>",
        lambda _e: root.focus_get().invoke() if hasattr(root.focus_get(), "invoke") else None,
    )
    deny.focus_set()  # the safe action owns the keyboard by default


def _populate_code(root: Any, message: str, answer: dict) -> None:
    """Masked one-time-code entry body. Cancel/Escape/close all mean deny."""
    import tkinter as tk

    _build_header_and_message(root, message)

    entry_row = tk.Frame(root, bg=_BG)
    entry_row.pack(fill="x", padx=18, pady=(4, 4))
    entry = tk.Entry(
        entry_row,
        show="*",  # the code must never echo on screen
        font=("Consolas", 13),
        fg=_FG,
        bg=_PANEL,
        insertbackground=_ACCENT,
        relief="flat",
        highlightthickness=1,
        highlightbackground="#2c2c2c",
        highlightcolor=_ACCENT,
    )
    entry.pack(fill="x", ipady=6)

    def _submit() -> None:
        answer["value"] = entry.get()
        root.quit()

    def _cancel() -> None:
        answer["value"] = None
        root.quit()

    buttons = tk.Frame(root, bg=_BG)
    buttons.pack(fill="x", padx=18, pady=(6, 16))
    cancel = _styled_button(buttons, "Cancel", _cancel, accent=False)
    submit = _styled_button(buttons, "Submit code", _submit, accent=True)
    cancel.pack(side="right", padx=(8, 0))
    submit.pack(side="right")

    root.bind("<Escape>", lambda _e: _cancel())
    entry.bind("<Return>", lambda _e: _submit())
    entry.focus_set()


def _run_dialog(message: str, *, want_code: bool) -> Any:
    """Open one themed dialog, block until the human decides, and clean up.

    Closing the window (WM_DELETE_WINDOW) leaves the answer unset, which resolves
    to the deny default — there is no path where silence approves.
    """
    root = _open_root()
    try:
        _configure_window(root)
        answer: dict = {}
        populate = _populate_code if want_code else _populate_confirm
        populate(root, message, answer)
        root.protocol("WM_DELETE_WINDOW", root.quit)
        _center_on_screen(root)
        root.mainloop()
        return answer.get("value", None if want_code else False)
    finally:
        root.destroy()


def _confirm_dialog(message: str) -> bool:
    """Show the yes/no challenge dialog. Closing the window is "no" (deny)."""
    return bool(_run_dialog(message, want_code=False))


def _code_dialog(message: str) -> str | None:
    """Show the masked one-time-code dialog. Cancel/close returns ``None``."""
    return _run_dialog(message, want_code=True)


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
