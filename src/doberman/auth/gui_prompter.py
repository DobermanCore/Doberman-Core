"""GUI auth prompter + the GUI→TTY fallback chain (the serve-mode AUTH channel).

When an MCP agent (Claude Code, Codex, Cursor, …) spawns ``doberman serve``, the
controlling terminal *still exists* but is owned by the agent's TUI: a prompt
written to ``CONOUT$``/``/dev/tty`` opens successfully yet is painted over
(invisible), and keystrokes go to the agent — the human can never see or answer
the Feature 7 challenge. The challenge must therefore surface **out-of-band** as
a topmost dialog window; the terminal remains only a fallback for headless/SSH
sessions where no display exists.

The dialogs are plain ``tkinter``/``ttk`` windows (dark "black coat + tan" theme:
tan brand, amber Approve accent — the same palette as the landing page and
explainer video), built from real, focusable, accessible widgets — never the
stock ``messagebox``/``simpledialog`` chrome, and never hand-drawn Canvas
shapes standing in for buttons. The security contract: closing/cancelling a
dialog denies, the code entry is masked, and the safe action (Deny) is the one
an unmodified Enter invokes — :func:`_wire_keyboard` sets initial keyboard
focus on Deny and binds Return to invoke whichever button *currently* holds
real Tk focus, never a fixed target.

Two entry points exist per dialog kind: a legacy flat-string one
(``confirm``/``read_code`` — the ``Prompter`` protocol every channel, plugin,
and existing test already understands) and a structured one
(``confirm_challenge``/``read_code_challenge`` — takes the tagged-by-name
``dict`` :func:`doberman.auth.provider.challenge_parts` builds). The structured
path is what gives the target its own headline panel, a always-visible
question/risk/countdown, and a live countdown; the flat-string path renders the
whole message as one block and stays for back-compat with anything that only
ever hands this prompter a rendered string.

The bundled brand mark is loaded with stdlib ``tkinter.PhotoImage`` — never PIL/
Pillow, which is not a runtime dependency of this package.

:class:`PrompterUnavailableError` separates "this channel cannot open at all"
(fall through to the next channel) from a human answer or a human-channel error
(EOF/timeout — FINAL, the provider denies). A denial on one channel must never
be re-asked on another — that would be answer-shopping.

SECURITY: nothing here reads ``sys.stdin`` or writes ``sys.stdout`` (the agent's
MCP channel). tkinter is stdlib; no new dependency.

SECURITY (#399): every real caller runs this prompter on a background daemon
thread (see :func:`_open_root`'s docstring) so :func:`~doberman.auth.challenge`'s
wall-clock deadline can be enforced. On macOS, opening ``Tk()`` off the process's
real main thread is a Cocoa-level hazard that :func:`_open_root` refuses before
it ever happens — see that function for the full rationale.
"""

import importlib.resources as _ir
import logging
import sys
import threading
from collections.abc import Iterable
from typing import Any

from doberman.auth.challenge import Prompter

logger = logging.getLogger("doberman.auth.gui_prompter")

#: Window title for every challenge dialog.
_TITLE = "Doberman — authorization required"

# --- palette: dark warm-black coat, tan brand, amber (AUTH) approve ------------------
# Hex mirrors the canonical brand tokens shared with the landing page and the
# explainer video (their OKLCH --ink / --tan / --auth), so every Doberman surface
# reads as one system. Deny is the SOLID/filled button (the safe, fail-closed
# default reads as the visually dominant one); Approve is outlined/secondary —
# amber stays the AUTH-verdict accent, but it no longer "wins" the composition.
# The keyboard focus ring is the foreground white, a hue distinct from both.
_BG = "#100c0a"  # window base            (= --ink-1)
_PANEL = "#191411"  # message panel        (= --ink-2)
_FG = "#f2f2f2"  # primary text           (= --fg)
_MUTED = "#8f8b89"  # secondary text       (= --fg-3)
_RULE = "#2d2824"  # hairline borders      (= --rule-2)
_BRAND = "#ec9247"  # tan — brand wordmark AND Deny's solid fill (= --tan)
_BRAND_ACTIVE = "#f2a564"  # tan hover/active
_BRAND_FG = "#271700"  # dark ink on the tan Deny button
_APPROVE = "#fbb636"  # amber — Approve's outline + text (= --auth), never filled
_APPROVE_ACTIVE = "#ffca5e"  # amber hover/active (link-style hover only)
_RING = _FG  # keyboard focus ring — white, distinct from amber Approve

_BRAND_FONT = ("Segoe UI Semibold", 15, "bold")
_SUB_FONT = ("Segoe UI", 9)
_BODY_FONT = ("Segoe UI", 10)
_TARGET_FONT = ("Consolas", 12, "bold")
_SMALL_FONT = ("Segoe UI", 9)
_DEADLINE_FONT = ("Segoe UI", 9)  # >= 9pt floor (was 8pt / 10.7px, too small)
_BUTTON_FONT = ("Segoe UI Semibold", 10)

# --- layout constants (pixels; approximate — pack() auto-sizes the window) ----------
_DIALOG_W = 480
_PADX = 22
_TARGET_CHARS = 54  # Text widget width in characters (monospace target font)
_TARGET_MAX_LINES = 6  # collapsed cap: the question/risk/countdown stay below this
_TARGET_EXPANDED_MAX_LINES = 16  # past this, the expanded view scrolls

_SUBTITLE = "Doberman guards your agent's tool calls"
_REASSURANCE = "Denying stops only this action; your agent keeps running."
_QUESTION = "Approve this exact action?"
_HINT = "Tab/Arrows: switch - Enter: confirm - Esc: deny"
_CODE_PROMPT = "Enter the 6-digit code from your authenticator app to approve:"
_CODE_ERROR = "Enter the 6-digit code from your authenticator app to approve"

#: How long one dialog waits for the human before it gives up and denies.
#:
#: ``mainloop()`` blocks until something calls ``quit()``, so an unanswered
#: dialog used to hang the agent's tool call for ever — and silence is exactly
#: the "nobody is here" case that must resolve to a denial (fail closed).
#: Kept well below :data:`doberman.auth.challenge.DEFAULT_CHALLENGE_TIMEOUT_S`
#: so the dialog closes itself — visibly, and releasing its Tk root — before the
#: outer challenge deadline has to abandon the thread.
DEFAULT_DIALOG_TIMEOUT_S = 120.0


class PrompterUnavailableError(RuntimeError):
    """The prompter's human channel cannot be opened at all (no display, no GUI).

    Distinct from a denial or an EOF on an *open* channel: only this error lets a
    :class:`FallbackPrompter` consult the next channel. Reaching the provider, it
    is treated like any other challenge failure — the action is denied.
    """


def _enable_dpi_awareness() -> None:
    """Best-effort per-monitor DPI awareness on Windows; purely cosmetic, never fatal.

    Must run before ``tkinter.Tk()`` constructs the first window. A second call
    within the same process (e.g. a second challenge) returns an access-denied
    HRESULT rather than raising — caught here like every other cosmetic guard.
    """
    if sys.platform != "win32":
        return
    try:  # pragma: no cover — needs a real Windows shell DLL
        import ctypes

        ctypes.windll.shcore.SetProcessDpiAwareness(1)  # PROCESS_SYSTEM_DPI_AWARE
    except Exception:  # noqa: S110 — cosmetic only
        pass


def _screen_dpi() -> float:
    """System DPI for ``tk scaling``; 96 (100%) off Windows or on any failure."""
    if sys.platform != "win32":
        return 96.0
    try:  # pragma: no cover — needs a real Windows user32
        import ctypes

        return float(ctypes.windll.user32.GetDpiForSystem())
    except Exception:
        return 96.0


def _open_root() -> Any:
    """Create a Tk root for one dialog. Raises when no GUI exists.

    A fresh root per challenge (never cached): Tk objects are not thread-safe to
    share and a display that was missing earlier may be available now. The caller
    must destroy it.

    macOS thread-affinity guard (#399): every real caller reaches this function
    from a background daemon thread, never the process's main thread —
    :func:`~doberman.auth.challenge.run_auth_challenge` always dispatches the
    challenge through :func:`~doberman.auth.challenge._run_with_deadline`
    (a spawned ``threading.Thread``) precisely so a wall-clock deadline can be
    enforced on a channel that might otherwise block forever, and the MCP-proxy
    path does the equivalent via ``asyncio.to_thread``. Tk's Cocoa (macOS)
    backend requires its ``NSApplication`` event loop to start on the real OS
    main thread; constructing ``Tk()`` off it is a documented hazard that does
    **not** reliably surface as a catchable ``TclError`` the way a missing
    ``$DISPLAY`` does on X11 — it can silently fail to render (the dialog never
    appears, but the call also never raises) or abort the whole process, either
    of which defeats the fail-closed contract this module exists to provide.
    Refuse before ever touching ``tkinter`` so this channel reports itself
    unavailable — exactly like the "no display" case below — so
    :class:`FallbackPrompter` moves on to the terminal, and if that is also
    unavailable, the action is denied (never silently approved).
    """
    if sys.platform == "darwin" and threading.current_thread() is not threading.main_thread():
        raise PrompterUnavailableError(
            "GUI auth dialog cannot safely open off the main thread on macOS"
        )
    try:
        import tkinter
    except Exception as exc:  # pragma: no cover — needs a tkinter-less interpreter
        raise PrompterUnavailableError("tkinter is not available") from exc
    _enable_dpi_awareness()
    try:
        return tkinter.Tk()
    except Exception as exc:  # tkinter.TclError — no display / no window station
        raise PrompterUnavailableError("no display available for a GUI auth dialog") from exc


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


def _apply_ttk_style(root: Any) -> None:
    """Style the two real button roles from the palette (never the OS default).

    Deny is solid/filled (the safe, fail-closed default reads as the dominant
    button); Approve is outlined on the panel color. Both use ``clam`` (the one
    stdlib ttk theme that honors a custom ``focuscolor``/``bordercolor`` per
    state), so the keyboard focus ring is the brand ring color — never Approve's
    amber — on whichever button currently holds it.
    """
    import tkinter.ttk as ttk

    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except Exception:  # noqa: S110 — pragma: no cover — clam ships with every stdlib Tk build
        pass
    common = {"font": _BUTTON_FONT, "padding": (24, 15), "borderwidth": 2, "relief": "flat"}
    style.configure(
        "Doberman.Deny.TButton",
        background=_BRAND,
        foreground=_BRAND_FG,
        bordercolor=_BRAND,
        focuscolor=_RING,
        **common,
    )
    style.map(
        "Doberman.Deny.TButton",
        background=[("active", _BRAND_ACTIVE), ("pressed", _BRAND_ACTIVE)],
        bordercolor=[("focus", _RING), ("!focus", _BRAND)],
    )
    style.configure(
        "Doberman.Approve.TButton",
        background=_PANEL,
        foreground=_APPROVE,
        bordercolor=_APPROVE,
        focuscolor=_RING,
        **common,
    )
    style.map(
        "Doberman.Approve.TButton",
        background=[("active", _RULE), ("pressed", _RULE)],
        bordercolor=[("focus", _RING), ("!focus", _APPROVE)],
    )
    style.configure(
        "Doberman.Link.TButton",
        background=_BG,
        foreground=_BRAND,
        font=_SMALL_FONT,
        borderwidth=0,
        relief="flat",
        padding=(0, 4),
    )
    style.map("Doberman.Link.TButton", foreground=[("active", _APPROVE_ACTIVE)])


def _configure_window(root: Any) -> None:
    """Apply the window-level theme: topmost, dark base, fixed size, dark title bar."""
    root.title(_TITLE)
    root.configure(bg=_BG)
    root.resizable(False, False)
    root.attributes("-topmost", True)  # the dialog must pop OVER the agent's terminal
    _apply_dark_title_bar(root)
    try:
        root.tk.call("tk", "scaling", _screen_dpi() / 72.0)
    except Exception:  # noqa: S110 — cosmetic only (and unavailable on a fake root in tests)
        pass
    try:
        _apply_ttk_style(root)
    except Exception:  # noqa: S110 — cosmetic only (and unavailable on a fake root in tests)
        pass


def _monitor_rect_under_cursor() -> tuple[int, int, int, int] | None:
    """``(x, y, width, height)`` of the monitor under the mouse pointer.

    Windows-only, best-effort: ``None`` (fall back to the primary screen) on any
    failure or off Windows.
    """
    if sys.platform != "win32":
        return None
    try:  # pragma: no cover — needs real Win32 multi-monitor APIs
        import ctypes
        from ctypes import wintypes

        user32 = ctypes.windll.user32
        pt = wintypes.POINT()
        user32.GetCursorPos(ctypes.byref(pt))
        MONITOR_DEFAULTTONEAREST = 2
        hmon = user32.MonitorFromPoint(pt, MONITOR_DEFAULTTONEAREST)

        class _MonitorInfo(ctypes.Structure):
            _fields_ = [
                ("cbSize", wintypes.DWORD),
                ("rcMonitor", wintypes.RECT),
                ("rcWork", wintypes.RECT),
                ("dwFlags", wintypes.DWORD),
            ]

        info = _MonitorInfo()
        info.cbSize = ctypes.sizeof(_MonitorInfo)
        if not user32.GetMonitorInfoW(hmon, ctypes.byref(info)):
            return None
        r = info.rcMonitor
        return (r.left, r.top, r.right - r.left, r.bottom - r.top)
    except Exception:
        return None


def _center_on_screen(root: Any) -> None:
    """Center the (now-populated) dialog on the monitor under the mouse pointer.

    Falls back to the primary screen when that can't be determined (non-Windows,
    or any Win32 failure) — same "slightly above center" placement as before.
    """
    root.update_idletasks()
    width, height = root.winfo_reqwidth(), root.winfo_reqheight()
    monitor = _monitor_rect_under_cursor()
    if monitor is None:
        mx, my = 0, 0
        mw, mh = root.winfo_screenwidth(), root.winfo_screenheight()
    else:
        mx, my, mw, mh = monitor
    x = mx + max((mw - width) // 2, 0)
    y = my + max((mh - height) // 3, 0)  # slightly above center
    root.geometry(f"+{x}+{y}")


def _load_logo() -> Any:
    """Load the bundled brand mark via stdlib ``PhotoImage`` — never PIL/Pillow.

    The asset ships pre-sized (65x68px) at ``doberman/auth/_assets/doberman-mark.png``
    and is shown at ~34px tall via ``.subsample(2)``. Returns ``None`` on any failure
    (missing asset, a Tk build without PNG support, ...); the caller then falls back
    to a text-only "DOBERMAN" wordmark — never an emoji substitute.
    """
    try:
        import tkinter as tk

        with _ir.as_file(_ir.files("doberman.auth").joinpath("_assets/doberman-mark.png")) as p:
            return tk.PhotoImage(file=str(p)).subsample(2)
    except Exception:
        return None


def _mmss(seconds: float) -> str:
    """``"1:59"`` — minutes:seconds, floored, never negative."""
    total = max(0, int(seconds))
    return f"{total // 60}:{total % 60:02d}"


# --- shared content builders (used by both the flat-string and structured dialogs) --


def _content_frame(root: Any) -> Any:
    import tkinter as tk

    frame = tk.Frame(root, bg=_BG)
    frame.pack(fill="both", expand=True, padx=_PADX, pady=(18, 16))
    return frame


def _build_brand(frame: Any) -> None:
    import tkinter as tk

    row = tk.Frame(frame, bg=_BG)
    row.pack(fill="x", pady=(0, 6))
    logo = _load_logo()
    row._logo_ref = logo  # tkinter drops unreferenced images -- keep it alive
    if logo is not None:
        tk.Label(row, image=logo, bg=_BG).pack(side="left")
        tk.Label(row, text="DOBERMAN", fg=_BRAND, bg=_BG, font=_BRAND_FONT).pack(
            side="left", padx=(10, 0)
        )
    else:
        tk.Label(row, text="DOBERMAN", fg=_BRAND, bg=_BG, font=_BRAND_FONT).pack(side="left")
    tk.Label(
        frame, text=_SUBTITLE, fg=_MUTED, bg=_BG, font=_SUB_FONT, anchor="w", justify="left"
    ).pack(fill="x", pady=(0, 12))


def _build_line(
    frame: Any, text: str, *, font: tuple = _BODY_FONT, fg: str = _FG, pady: tuple = (0, 6)
) -> None:
    import tkinter as tk

    tk.Label(
        frame,
        text=text,
        fg=fg,
        bg=_BG,
        font=font,
        anchor="w",
        justify="left",
        wraplength=_DIALOG_W - 2 * _PADX,
    ).pack(fill="x", pady=pady)


def _target_preview(target: str, *, head: int = 220, tail: int = 90) -> str:
    """Middle-ellipsis preview: the start AND the end stay visible when collapsed.

    A malicious/confusing target can hide the dangerous part at either end (a
    long path prefix, or a destination host tacked on after a pipe), so a
    head-only truncation is not enough — this keeps both ends in view and signals
    there is more via ``...``. The full text is always one "Show full target"
    click away.
    """
    if len(target) <= head + tail + 20:
        return target
    return f"{target[:head]} ... {target[-tail:]}"


def _build_target_panel(root: Any, frame: Any, target: str) -> None:
    """The target/command: its own bold-mono panel, capped at 6 display lines.

    Sized from the REAL widget (``count("1.0","end","displaylines")``) after the
    text is actually inserted — never a predicted/estimated line count — so an
    over-wide unbroken "word" (Tk's own word-wrap already char-breaks one that
    doesn't fit) can never be undercounted and clipped. Past the cap, a
    middle-ellipsis preview shows with a "Show full target" toggle that expands
    into a scrollable region; the question/risk/countdown this function's caller
    draws afterward are never inside this panel, so they can never be pushed out
    of view by a long target.
    """
    import tkinter as tk
    import tkinter.ttk as ttk

    panel = tk.Frame(frame, bg=_PANEL, highlightthickness=1, highlightbackground=_RULE)
    panel.pack(fill="x", pady=(2, 4))

    text = tk.Text(
        panel,
        bg=_PANEL,
        fg=_FG,
        bd=0,
        highlightthickness=0,
        wrap="word",
        font=_TARGET_FONT,
        width=_TARGET_CHARS,
        padx=14,
        pady=10,
        cursor="arrow",
        state="normal",
    )
    text.pack(fill="x")

    def _fill(content: str, cap: int) -> int:
        text.configure(state="normal")
        text.delete("1.0", "end")
        text.insert("1.0", content)
        text.configure(state="disabled")
        text.update_idletasks()
        lines = min(int(text.count("1.0", "end", "displaylines")[0]), cap)
        text.configure(height=max(lines, 1))
        return lines

    total = _fill(target, 10**6)  # measure the real, unbounded line count first
    if total <= _TARGET_MAX_LINES:
        return

    scrollbar_holder: dict[str, Any] = {}
    state = {"expanded": False}

    def _collapse() -> None:
        for sb in scrollbar_holder.values():
            sb.destroy()
        scrollbar_holder.clear()
        text.configure(yscrollcommand="")
        _fill(_target_preview(target), _TARGET_MAX_LINES)

    def _expand() -> None:
        _fill(target, _TARGET_EXPANDED_MAX_LINES)
        if total > _TARGET_EXPANDED_MAX_LINES:
            sb = ttk.Scrollbar(panel, command=text.yview)
            text.configure(yscrollcommand=sb.set)
            sb.pack(side="right", fill="y")
            scrollbar_holder["y"] = sb

    def _toggle() -> None:
        state["expanded"] = not state["expanded"]
        (_expand if state["expanded"] else _collapse)()
        toggle_btn.configure(text="Hide full target" if state["expanded"] else "Show full target")
        root.update_idletasks()
        _center_on_screen(root)

    _collapse()
    toggle_btn = ttk.Button(
        frame, text="Show full target", command=_toggle, style="Doberman.Link.TButton"
    )
    toggle_btn.pack(anchor="w", pady=(0, 6))


def _build_countdown(root: Any, frame: Any, timeout_s: float, on_expire: Any) -> Any:
    """A ticking "auto-denies in M:SS" label; at zero, a brief "Denied" flash, then close.

    Reuses the CLI's ``deadline_note`` wording pattern ("auto-denies in ... if
    unanswered") at minute:second resolution instead of the CLI's coarser
    per-minute granularity, so the dialog visibly counts down rather than
    presenting a number that goes stale the instant it is drawn.
    """
    import tkinter as tk

    label = tk.Label(frame, fg=_MUTED, bg=_BG, font=_DEADLINE_FONT, anchor="w")
    label.pack(fill="x", pady=(2, 10))
    total = max(1, int(timeout_s))
    remaining = {"s": total}

    def _tick() -> None:
        remaining["s"] -= 1
        if remaining["s"] <= 0:
            label.configure(text=f"Denied - no answer in {_mmss(total)}", fg=_FG)
            logger.info("auth dialog closed after %ss with no answer", total)
            root.after(1500, on_expire)
            return
        label.configure(text=f"auto-denies in {_mmss(remaining['s'])} if unanswered")
        root.after(1000, _tick)

    label.configure(text=f"auto-denies in {_mmss(remaining['s'])} if unanswered")
    root.after(1000, _tick)
    return label


def _build_buttons(frame: Any, specs: list[tuple[str, Any, str]]) -> tuple[Any, ...]:
    """Real ``ttk.Button``s, right-aligned, in ``specs`` order (index 0 = Deny).

    Accessible by construction: a real name/role/state, native focus, >=44px
    tall (see :func:`_apply_ttk_style`'s padding). Keyboard safety is wired
    separately by :func:`_wire_keyboard` — this only creates and places them.
    """
    import tkinter as tk
    import tkinter.ttk as ttk

    row = tk.Frame(frame, bg=_BG)
    row.pack(fill="x", pady=(4, 8))
    inner = tk.Frame(row, bg=_BG)
    inner.pack(side="right")
    buttons = []
    for i, (label, command, style_name) in enumerate(specs):
        button = ttk.Button(inner, text=label, command=command, style=style_name)
        button.pack(side="left", padx=(10 if i else 0, 0))
        buttons.append(button)
    return tuple(buttons)


def _wire_keyboard(root: Any, deny_btn: Any, approve_btn: Any) -> None:
    """Deny starts focused; Return/Ctrl+Return invoke ONLY whichever button holds
    real Tk focus; Left/Right (on the buttons themselves, never globally — so a
    code entry's own cursor movement is untouched) swap focus between the two.

    This is what makes a stray Enter safe: there is no "highlighted button"
    state to track by hand any more — Tk's own focus is the single source of
    truth, and :func:`_invoke_focused` only ever acts on the widget that
    currently, really, holds it.
    """

    deny_btn.focus_force()  # grabs REAL input focus immediately -- this is a -topmost dialog

    def _invoke_focused(_event: Any = None) -> str:
        widget = root.focus_get()
        if widget in (deny_btn, approve_btn):
            widget.invoke()
        return "break"

    root.bind("<Return>", _invoke_focused)
    # A deliberate-approve accelerator is safe here for the same reason Return
    # is: it only ever invokes whichever button ALREADY has focus.
    root.bind("<Control-Return>", _invoke_focused)

    def _swap(_event: Any = None) -> str:
        (approve_btn if root.focus_get() is deny_btn else deny_btn).focus_set()
        return "break"

    for button in (deny_btn, approve_btn):
        button.bind("<Left>", _swap)
        button.bind("<Right>", _swap)


# --- confirm dialog: flat-string (legacy) + structured (parts) ----------------------


def _populate_confirm(root: Any, message: str, answer: dict, timeout_s: float) -> None:
    """Legacy flat-string body: back-compat for any ``Prompter`` caller that only
    ever hands this a rendered ``message`` string (and for tests stubbing this
    exact seam). Shows the whole message as one block — no target/headline
    hierarchy, since there is no structured data to split it from — but reuses
    the same real-widget button/countdown/escape machinery as the structured
    path below, so it is never less keyboard-safe or accessible.
    """

    def _decide(value: bool) -> None:
        answer["value"] = value
        root.quit()

    frame = _content_frame(root)
    _build_brand(frame)
    _build_line(frame, message, pady=(0, 10))
    _build_countdown(root, frame, timeout_s, on_expire=lambda: _decide(False))
    deny_btn, approve_btn = _build_buttons(
        frame,
        [
            ("Deny", lambda: _decide(False), "Doberman.Deny.TButton"),
            ("Approve", lambda: _decide(True), "Doberman.Approve.TButton"),
        ],
    )
    _wire_keyboard(root, deny_btn, approve_btn)
    _build_line(frame, _HINT, font=_DEADLINE_FONT, fg=_MUTED, pady=(4, 0))
    root.bind("<Escape>", lambda _e: _decide(False))


def _populate_confirm_parts(root: Any, parts: dict, answer: dict, timeout_s: float) -> None:
    """Structured body: the target gets its own headline panel; the question,
    risk line, and countdown are drawn OUTSIDE it, so nothing about the target
    (however long) can push them out of view. Segments are read from ``parts``
    by name — never sniffed from indentation — so the action's own target text
    can never forge itself into looking like the risk line or the question.
    """

    def _decide(value: bool) -> None:
        answer["value"] = value
        root.quit()

    frame = _content_frame(root)
    _build_brand(frame)
    if parts.get("notice"):
        _build_line(frame, parts["notice"], font=_SMALL_FONT, fg=_BRAND)
    if parts.get("headline"):
        _build_line(frame, parts["headline"])
    _build_target_panel(root, frame, parts["target"])
    _build_line(frame, _QUESTION, font=_BODY_FONT, fg=_FG, pady=(2, 8))
    if parts.get("why"):
        _build_line(frame, parts["why"], font=_SMALL_FONT, fg=_MUTED)
    if parts.get("risk"):
        _build_line(frame, parts["risk"], font=_SMALL_FONT, fg=_FG)
    _build_line(frame, _REASSURANCE, font=_SMALL_FONT, fg=_MUTED, pady=(2, 8))
    _build_countdown(root, frame, timeout_s, on_expire=lambda: _decide(False))
    deny_btn, approve_btn = _build_buttons(
        frame,
        [
            ("Deny", lambda: _decide(False), "Doberman.Deny.TButton"),
            ("Approve", lambda: _decide(True), "Doberman.Approve.TButton"),
        ],
    )
    _wire_keyboard(root, deny_btn, approve_btn)
    _build_line(frame, _HINT, font=_DEADLINE_FONT, fg=_MUTED, pady=(4, 0))
    root.bind("<Escape>", lambda _e: _decide(False))


# --- code dialog: flat-string (legacy) + structured (parts) -------------------------


def _make_code_entry(frame: Any) -> Any:
    import tkinter as tk

    entry = tk.Entry(
        frame,
        show="*",  # the code must never echo on screen
        font=("Consolas", 13),
        fg=_FG,
        bg=_PANEL,
        insertbackground=_BRAND,
        relief="flat",
        highlightthickness=1,
        highlightbackground=_RULE,
        highlightcolor=_BRAND,
    )
    vcmd = entry.register(lambda proposed: all(c.isdigit() or c.isspace() for c in proposed))
    entry.configure(validate="key", validatecommand=(vcmd, "%P"))
    entry.pack(fill="x", pady=(0, 4))
    return entry


def _wire_code_submit(root: Any, entry: Any, error_label: Any, on_code: Any) -> None:
    def _submit() -> None:
        code = "".join(entry.get().split())  # paste-safe: strip all whitespace
        if not code or not code.isdigit():
            error_label.configure(text=_CODE_ERROR)
            return  # never deny here -- let them retry within the same timeout
        on_code(code)

    def _submit_and_stop(_event: Any = None) -> str:
        # Bound on the entry itself, dispatched before root's own <Return>
        # binding -- "break" stops it there so Enter-in-the-entry submits
        # exactly once.
        _submit()
        return "break"

    entry.bind("<Return>", _submit_and_stop)
    entry.focus_force()
    return _submit


def _populate_code(root: Any, message: str, answer: dict, timeout_s: float) -> None:
    """Legacy flat-string body — see :func:`_populate_confirm`'s docstring."""
    import tkinter as tk

    def _decide(value: Any) -> None:
        answer["value"] = value
        root.quit()

    frame = _content_frame(root)
    _build_brand(frame)
    _build_line(frame, message, pady=(0, 10))
    entry = _make_code_entry(frame)
    error_label = tk.Label(frame, fg=_APPROVE, bg=_BG, font=_SMALL_FONT, anchor="w")
    error_label.pack(fill="x", pady=(0, 8))
    submit = _wire_code_submit(root, entry, error_label, lambda code: _decide(code))
    _build_countdown(root, frame, timeout_s, on_expire=lambda: _decide(None))
    deny_btn, approve_btn = _build_buttons(
        frame,
        [
            ("Deny", lambda: _decide(None), "Doberman.Deny.TButton"),
            ("Approve with code", submit, "Doberman.Approve.TButton"),
        ],
    )
    _wire_keyboard(root, deny_btn, approve_btn)
    _build_line(frame, _HINT, font=_DEADLINE_FONT, fg=_MUTED, pady=(4, 0))
    root.bind("<Escape>", lambda _e: _decide(None))
    entry.focus_force()


def _populate_code_parts(root: Any, parts: dict, answer: dict, timeout_s: float) -> None:
    """Structured body — see :func:`_populate_confirm_parts`'s docstring."""
    import tkinter as tk

    def _decide(value: Any) -> None:
        answer["value"] = value
        root.quit()

    frame = _content_frame(root)
    _build_brand(frame)
    if parts.get("notice"):
        _build_line(frame, parts["notice"], font=_SMALL_FONT, fg=_BRAND)
    _build_line(frame, _CODE_PROMPT)
    _build_target_panel(root, frame, parts["target"])
    _build_line(frame, _QUESTION, font=_BODY_FONT, fg=_FG, pady=(2, 8))
    if parts.get("risk"):
        _build_line(frame, parts["risk"], font=_SMALL_FONT, fg=_FG)
    entry = _make_code_entry(frame)
    error_label = tk.Label(frame, fg=_APPROVE, bg=_BG, font=_SMALL_FONT, anchor="w")
    error_label.pack(fill="x", pady=(0, 8))
    submit = _wire_code_submit(root, entry, error_label, lambda code: _decide(code))
    _build_countdown(root, frame, timeout_s, on_expire=lambda: _decide(None))
    deny_btn, approve_btn = _build_buttons(
        frame,
        [
            ("Deny", lambda: _decide(None), "Doberman.Deny.TButton"),
            ("Approve with code", submit, "Doberman.Approve.TButton"),
        ],
    )
    _wire_keyboard(root, deny_btn, approve_btn)
    _build_line(frame, _HINT, font=_DEADLINE_FONT, fg=_MUTED, pady=(4, 0))
    root.bind("<Escape>", lambda _e: _decide(None))
    entry.focus_force()


# --- running a dialog to completion --------------------------------------------------


def _run_dialog(populate: Any, *, want_code: bool, timeout_s: float) -> Any:
    """Open one themed dialog, run ``populate(root, answer, timeout_s)``, block
    until the human decides, and clean up.

    Closing the window (WM_DELETE_WINDOW) leaves the answer unset, which resolves
    to the deny default — there is no path where silence approves. The countdown
    :func:`_build_countdown` schedules inside ``populate`` exits by the same
    door: it only ends the loop (after its "Denied" flash), so the unset answer
    denies.
    """
    root = _open_root()
    try:
        _configure_window(root)
        answer: dict = {}
        populate(root, answer, timeout_s)
        root.protocol("WM_DELETE_WINDOW", root.quit)
        _center_on_screen(root)
        root.mainloop()
        return answer.get("value", None if want_code else False)
    finally:
        root.destroy()


def _confirm_dialog(message: str, *, timeout_s: float = DEFAULT_DIALOG_TIMEOUT_S) -> bool:
    """Show the yes/no challenge dialog (flat-string). Closing/silence is "no"."""

    def _populate(root: Any, answer: dict, t: float) -> None:
        _populate_confirm(root, message, answer, t)

    return bool(_run_dialog(_populate, want_code=False, timeout_s=timeout_s))


def _code_dialog(message: str, *, timeout_s: float = DEFAULT_DIALOG_TIMEOUT_S) -> str | None:
    """Show the masked one-time-code dialog (flat-string). Cancel/close/silence -> ``None``."""

    def _populate(root: Any, answer: dict, t: float) -> None:
        _populate_code(root, message, answer, t)

    return _run_dialog(_populate, want_code=True, timeout_s=timeout_s)


def _confirm_dialog_parts(parts: dict, *, timeout_s: float = DEFAULT_DIALOG_TIMEOUT_S) -> bool:
    """Show the yes/no challenge dialog (structured). Closing/silence is "no"."""

    def _populate(root: Any, answer: dict, t: float) -> None:
        _populate_confirm_parts(root, parts, answer, t)

    return bool(_run_dialog(_populate, want_code=False, timeout_s=timeout_s))


def _code_dialog_parts(parts: dict, *, timeout_s: float = DEFAULT_DIALOG_TIMEOUT_S) -> str | None:
    """Show the masked one-time-code dialog (structured). Cancel/close/silence -> ``None``."""

    def _populate(root: Any, answer: dict, t: float) -> None:
        _populate_code_parts(root, parts, answer, t)

    return _run_dialog(_populate, want_code=True, timeout_s=timeout_s)


class GuiPrompter:
    """Collect a challenge response through a topmost dialog window.

    Raises :class:`PrompterUnavailableError` when no display exists so a fallback
    chain can try the terminal instead; any other failure (cancel, blank code)
    raises and the provider denies (fail closed).

    ``timeout_s`` bounds how long each dialog waits for the human; ``0`` disables
    the bound and is for tests only — a live prompter with no timeout is the
    AN-4 hang (see :data:`DEFAULT_DIALOG_TIMEOUT_S`).
    """

    def __init__(self, *, timeout_s: float = DEFAULT_DIALOG_TIMEOUT_S) -> None:
        self._timeout_s = timeout_s

    def confirm(self, message: str) -> bool:
        return _confirm_dialog(message, timeout_s=self._timeout_s)

    def read_code(self, message: str) -> str:
        """Read a one-time code via a masked dialog. Cancel/blank/silence → raise (deny).

        An empty code must never reach the verifier, so cancel, timeout, and
        whitespace-only entries raise instead of returning ``""``.
        """
        code = _code_dialog(message, timeout_s=self._timeout_s)
        return self._require_code(code)

    def confirm_challenge(self, parts: dict) -> bool:
        """Structured variant of :meth:`confirm`: renders ``parts`` (from
        :func:`doberman.auth.provider.challenge_parts`) instead of a flat string —
        gives the target its own headline panel, an always-visible question/risk
        line, and a live countdown. See the module docstring.
        """
        return _confirm_dialog_parts(parts, timeout_s=self._timeout_s)

    def read_code_challenge(self, parts: dict) -> str:
        """Structured variant of :meth:`read_code` — see :meth:`confirm_challenge`."""
        code = _code_dialog_parts(parts, timeout_s=self._timeout_s)
        return self._require_code(code)

    @staticmethod
    def _require_code(code: str | None) -> str:
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

    def confirm_challenge(self, parts: dict) -> bool:
        return self._first_open_channel_structured("confirm", parts)

    def read_code_challenge(self, parts: dict) -> str:
        return self._first_open_channel_structured("read_code", parts)

    def _first_open_channel(self, method: str, message: str) -> Any:
        last: PrompterUnavailableError | None = None
        for prompter in self._prompters:
            try:
                return getattr(prompter, method)(message)
            except PrompterUnavailableError as exc:
                last = exc
        raise PrompterUnavailableError("no auth prompter channel is available") from last

    def _first_open_channel_structured(self, method: str, parts: dict) -> Any:
        """Same fall-through rule as :meth:`_first_open_channel`, but prefers a
        chained prompter's own ``{method}_challenge`` (structured) when it has
        one, and only falls back to the flat-string ``{method}`` for a prompter
        that doesn't (e.g. the TTY/dashboard channels) — never the other way
        around, so a structured-capable channel is never handed a flattened
        string just because it happens to also implement the legacy method.
        """
        from doberman.auth.provider import _message_from_parts

        fallback_message = (
            _message_from_parts(parts) if method == "confirm" else "Enter your 2FA code"
        )
        last: PrompterUnavailableError | None = None
        for prompter in self._prompters:
            try:
                structured = getattr(prompter, f"{method}_challenge", None)
                if structured is not None:
                    return structured(parts)
                return getattr(prompter, method)(fallback_message)
            except PrompterUnavailableError as exc:
                last = exc
        raise PrompterUnavailableError("no auth prompter channel is available") from last
