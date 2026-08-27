"""GUI auth prompter + the GUI→TTY fallback chain (the serve-mode AUTH channel).

When an MCP agent (Claude Code, Codex, Cursor, …) spawns ``doberman serve``, the
controlling terminal *still exists* but is owned by the agent's TUI: a prompt
written to ``CONOUT$``/``/dev/tty`` opens successfully yet is painted over
(invisible), and keystrokes go to the agent — the human can never see or answer
the Feature 7 challenge. The challenge must therefore surface **out-of-band** as
a topmost dialog window; the terminal remains only a fallback for headless/SSH
sessions where no display exists.

The dialogs are custom-built tkinter windows, drawn on a ``Canvas`` (dark "black
coat + tan" theme: tan brand, amber Approve — the same palette as the landing
page and explainer video) — not the stock ``messagebox``/``simpledialog`` chrome
— but the security contract is unchanged: closing/cancelling a dialog denies,
the code entry is masked, and the safe action (Deny/Cancel) is the one an
unmodified Enter invokes, so a stray Enter can never approve.

Canvas-drawn buttons are not real focusable widgets, so that last guarantee is
reimplemented rather than inherited from ``.focus_set()``: :func:`_add_button_row`
tracks which button is keyboard-highlighted (starting on the safe one), draws a
focus ring around it, and only THAT button's command is wired to Return.

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
import sys
import threading
from collections.abc import Iterable
from typing import Any

from doberman.auth.challenge import Prompter
from doberman.render import deadline_note

#: Window title for every challenge dialog.
_TITLE = "Doberman — authorization required"

# --- palette: dark warm-black coat, tan brand, amber (AUTH) approve ------------------
# Hex mirrors the canonical brand tokens shared with the landing page and the
# explainer video (their OKLCH --ink / --tan / --auth), so every Doberman surface
# reads as one system: tan is the brand accent, amber is the AUTH-verdict Approve
# action (never orange — that was a fourth, off-brand accent).
_BG = "#100c0a"  # window base            (= --ink-1)
_PANEL = "#191411"  # message panel        (= --ink-2)
_FG = "#f2f2f2"  # primary text           (= --fg)
_MUTED = "#8f8b89"  # secondary text       (= --fg-3)
_RULE = "#2d2824"  # hairline borders      (= --rule-2)
_BRAND = "#ec9247"  # tan — brand wordmark, caret, focus ring (= --tan)
_APPROVE = "#fbb636"  # amber — the AUTH-verdict Approve/Submit action (= --auth)
_APPROVE_ACTIVE = "#ffca5e"  # amber hover/active
_APPROVE_FG = "#271700"  # dark ink on the amber button
_DENY_BG = "#26201c"  # neutral dark button    (= --ink-3)
_DENY_ACTIVE = "#332c27"

_BRAND_FONT = ("Segoe UI Semibold", 15, "bold")
_SUB_FONT = ("Segoe UI", 9)
_MONO_FONT = ("Consolas", 10)
_DEADLINE_FONT = ("Segoe UI", 8)
_BUTTON_FONT = ("Segoe UI Semibold", 10)

# --- Canvas layout constants (pixels; mirror the approved mockup) -------------------
_DIALOG_W = 460
_PADX = 22
_TEXT_PADX = 14
_TEXT_PADY = 12
_DEADLINE_TOP_MARGIN = 10
_PANEL_RADIUS = 12
_BUTTON_H = 40
_BUTTON_GAP = 10
_BUTTON_RADIUS = 10

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


def _rrect(canvas: Any, x1: float, y1: float, x2: float, y2: float, r: float, **kwargs: Any) -> int:
    """Rounded-rectangle polygon on a Canvas (mirrors the approved mockup's ``rrect``)."""
    points = [
        x1 + r,
        y1,
        x2 - r,
        y1,
        x2,
        y1,
        x2,
        y1 + r,
        x2,
        y2 - r,
        x2,
        y2,
        x2 - r,
        y2,
        x1 + r,
        y2,
        x1,
        y2,
        x1,
        y2 - r,
        x1,
        y1 + r,
        x1,
        y1,
    ]
    return canvas.create_polygon(points, smooth=True, splinesteps=36, **kwargs)


def _wrap_to_width(font: Any, text: str, max_width_px: int) -> list[str]:
    """Greedy word-wrap ``text`` to ``max_width_px`` using real font metrics.

    Used only to PRE-COMPUTE how tall the message panel must be, before the window
    is shown: a freshly canvas-embedded window reports a stale ~1px width until the
    toplevel is actually mapped, so querying Tk's own line-wrap (``Text.count(...,
    "displaylines")``) that early returns garbage. Font metrics, unlike widget
    geometry, are available immediately. The Text widget is then given this same
    pixel width, so its real word-wrap (same greedy, space-delimited shape) lands on
    the same line count once the window is actually shown.
    """
    if not text:
        return [""]
    words = text.split(" ")
    lines: list[str] = []
    current = words[0]
    for word in words[1:]:
        candidate = f"{current} {word}"
        if not current or font.measure(candidate) <= max_width_px:
            current = candidate
        else:
            lines.append(current)
            current = word
    lines.append(current)
    return lines


def _message_segments(message: str) -> list[tuple[str, str]]:
    """Split ``message`` into ``(text, tag)`` pairs for the message panel.

    A line starting with 4+ spaces is an indented command → amber. Everything else
    in ``message`` is plain body text. A trailing muted deadline line is appended
    HERE (not detected from the input), so this is robust to any message content —
    there is nothing in ``message`` itself that must "look like" a deadline note.
    """
    segments: list[tuple[str, str]] = []
    for line in message.split("\n"):
        indent = len(line) - len(line.lstrip(" "))
        segments.append((line, "amber" if indent >= 4 else "body"))
    segments.append((deadline_note(DEFAULT_DIALOG_TIMEOUT_S), "muted"))
    return segments


def _draw_brand_and_message(root: Any, canvas: Any, message: str) -> float:
    """Brand row + sub-line + rounded, dynamically-sized message panel.

    Returns the y-coordinate the caller should start drawing the button row at.
    """
    import tkinter as tk
    import tkinter.font as tkfont

    y = 20.0
    logo = _load_logo()
    root._logo_ref = logo  # tkinter drops unreferenced images -- keep it alive
    if logo is not None:
        canvas.create_image(_PADX, y, image=logo, anchor="nw")
        logo_h = logo.height()
        canvas.create_text(
            _PADX + logo.width() + 10,
            y + logo_h / 2,
            text="DOBERMAN",
            fill=_BRAND,
            font=_BRAND_FONT,
            anchor="w",
        )
        y += max(logo_h, 24) + 6
    else:
        canvas.create_text(_PADX, y, text="DOBERMAN", fill=_BRAND, font=_BRAND_FONT, anchor="nw")
        y += 24 + 6

    canvas.create_text(
        _PADX,
        y,
        text="An agent action needs your decision",
        fill=_MUTED,
        font=_SUB_FONT,
        anchor="nw",
    )
    y += 26

    panel_top = y
    inner_w = _DIALOG_W - 2 * _PADX
    text_w = inner_w - 2 * _TEXT_PADX
    mono = tkfont.Font(font=_MONO_FONT)
    segments = _message_segments(message)
    n_lines = sum(len(_wrap_to_width(mono, text, text_w)) for text, _tag in segments)
    line_h = mono.metrics("linespace")
    # content height + top/bottom padding + the deadline line's own extra top margin
    # + a small safety margin: an underestimate here would silently clip text.
    panel_h = n_lines * line_h + 2 * _TEXT_PADY + _DEADLINE_TOP_MARGIN + 6

    _rrect(
        canvas,
        _PADX,
        panel_top,
        _DIALOG_W - _PADX,
        panel_top + panel_h,
        _PANEL_RADIUS,
        fill=_PANEL,
        outline=_RULE,
    )

    txt = tk.Text(
        canvas,
        bg=_PANEL,
        fg=_FG,
        bd=0,
        highlightthickness=0,
        wrap="word",
        font=_MONO_FONT,
        padx=_TEXT_PADX,
        pady=_TEXT_PADY,
        cursor="arrow",
        state="normal",
    )
    txt.tag_configure("amber", foreground=_APPROVE)
    txt.tag_configure("body", foreground=_FG)
    txt.tag_configure(
        "muted", foreground=_MUTED, font=_DEADLINE_FONT, spacing1=_DEADLINE_TOP_MARGIN
    )
    for i, (text, tag) in enumerate(segments):
        if i:
            txt.insert("end", "\n")
        txt.insert("end", text, tag)
    txt.configure(state="disabled")
    canvas.create_window(_PADX, panel_top, anchor="nw", window=txt, width=inner_w, height=panel_h)

    return panel_top + panel_h + 18


def _add_button_row(
    root: Any,
    canvas: Any,
    *,
    y: float,
    specs: list[tuple[str, Any, bool]],
    extra_bind_target: Any = None,
) -> float:
    """Two rounded, equal-width Canvas buttons; keyboard-safe by construction.

    ``specs`` is left-to-right: ``[(label, command, accent), ...]``. Index 0 STARTS
    keyboard-highlighted — this is the whole safety guarantee, so it must always be
    the safe action (Deny / Cancel), never the risky one.

    Canvas-drawn shapes aren't real focusable widgets, so ``deny.focus_set()``'s old
    guarantee is reimplemented rather than inherited:
    * a visible ring is drawn around the highlighted button
    * Tab / Left / Right move the highlight and redraw the ring
    * Return (bound on ``root``, and on ``extra_bind_target`` if given) invokes the
      CURRENTLY highlighted button's command — never a fixed one
    * a mouse click on either button always invokes THAT button directly

    The risky action is therefore reachable only by clicking it, or by first moving
    the highlight onto it — never by an unmodified Enter.

    Returns the y-coordinate below the button row.
    """
    import tkinter.font as tkfont

    font = tkfont.Font(font=_BUTTON_FONT)
    button_w = max(font.measure(label) for label, _cmd, _accent in specs) + 56
    total_w = len(specs) * button_w + (len(specs) - 1) * _BUTTON_GAP
    x0 = _DIALOG_W - _PADX - total_w

    state: dict[str, Any] = {"index": 0, "ring": None}
    boxes: list[tuple[float, float, float, float]] = []

    for i, (label, command, accent) in enumerate(specs):
        x1 = x0 + i * (button_w + _BUTTON_GAP)
        x2 = x1 + button_w
        fill = _APPROVE if accent else _DENY_BG
        hover = _APPROVE_ACTIVE if accent else _DENY_ACTIVE
        fg = _APPROVE_FG if accent else _FG
        tag = f"_dobermanbtn{i}"
        rect_id = _rrect(
            canvas, x1, y, x2, y + _BUTTON_H, _BUTTON_RADIUS, fill=fill, outline="", tags=(tag,)
        )
        canvas.create_text(
            (x1 + x2) / 2, y + _BUTTON_H / 2, text=label, fill=fg, font=_BUTTON_FONT, tags=(tag,)
        )
        boxes.append((x1, y, x2, y + _BUTTON_H))
        canvas.tag_bind(tag, "<Enter>", lambda _e, r=rect_id, h=hover: canvas.itemconfig(r, fill=h))
        canvas.tag_bind(tag, "<Leave>", lambda _e, r=rect_id, f=fill: canvas.itemconfig(r, fill=f))
        canvas.tag_bind(tag, "<Button-1>", lambda _e, cmd=command: cmd())

    def _draw_ring(index: int) -> None:
        if state["ring"] is not None:
            canvas.delete(state["ring"])
        bx1, by1, bx2, by2 = boxes[index]
        state["ring"] = _rrect(
            canvas,
            bx1 - 3,
            by1 - 3,
            bx2 + 3,
            by2 + 3,
            _BUTTON_RADIUS + 3,
            fill="",
            outline=_BRAND,
            width=2,
        )
        # Tk hit-tests a polygon's whole interior even with fill="" — left on top, the ring
        # would swallow clicks (and hover) on the highlighted button. Keep it beneath them.
        canvas.tag_lower(state["ring"], "_dobermanbtn0")

    def _move_highlight(_event: Any = None) -> str:
        state["index"] = (state["index"] + 1) % len(specs)
        _draw_ring(state["index"])
        canvas.focus_set()  # so a later Return (no longer inside another widget) reaches root
        return "break"

    def _invoke_highlighted(_event: Any = None) -> str:
        specs[state["index"]][1]()
        return "break"

    _draw_ring(0)
    for target in (root, extra_bind_target):
        if target is None:
            continue
        target.bind("<Tab>", _move_highlight)
        target.bind("<Left>", _move_highlight)
        target.bind("<Right>", _move_highlight)
    root.bind("<Return>", _invoke_highlighted)

    return y + _BUTTON_H + 18


def _confirm_specs(decide: Any) -> list[tuple[str, Any, bool]]:
    """Deny/Approve button specs, left-to-right, in :func:`_add_button_row` order.

    Index 0 (Deny) is the entry that starts keyboard-highlighted — the guarantee
    that an unmodified Enter can never approve rests entirely on Deny staying first.
    """
    return [("Deny", lambda: decide(False), False), ("Approve", lambda: decide(True), True)]


def _populate_confirm(root: Any, message: str, answer: dict) -> None:
    """Yes/no challenge body. Deny starts keyboard-highlighted — Enter can never stray-approve."""
    import tkinter as tk

    def _decide(value: bool) -> None:
        answer["value"] = value
        root.quit()

    canvas = tk.Canvas(root, width=_DIALOG_W, bg=_BG, highlightthickness=0, bd=0)
    canvas.pack()

    y = _draw_brand_and_message(root, canvas, message)
    y = _add_button_row(root, canvas, y=y, specs=_confirm_specs(_decide))
    canvas.configure(height=y)

    root.bind("<Escape>", lambda _e: _decide(False))


def _populate_code(root: Any, message: str, answer: dict) -> None:
    """Masked one-time-code entry body. Cancel/Escape/close all mean deny."""
    import tkinter as tk

    def _submit() -> None:
        answer["value"] = entry.get()
        root.quit()

    def _cancel() -> None:
        answer["value"] = None
        root.quit()

    canvas = tk.Canvas(root, width=_DIALOG_W, bg=_BG, highlightthickness=0, bd=0)
    canvas.pack()

    y = _draw_brand_and_message(root, canvas, message)

    entry = tk.Entry(
        canvas,
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
    inner_w = _DIALOG_W - 2 * _PADX
    canvas.create_window(_PADX, y, anchor="nw", window=entry, width=inner_w, height=32)
    y += 32 + 14

    def _submit_and_stop(_event: Any = None) -> str:
        # Bound on the entry itself, which is dispatched before root's own binding
        # (see _add_button_row) -- "break" stops it there so Enter-in-the-entry
        # submits exactly once, matching the pre-Canvas behavior.
        _submit()
        return "break"

    entry.bind("<Return>", _submit_and_stop)

    y = _add_button_row(
        root,
        canvas,
        y=y,
        specs=[("Cancel", _cancel, False), ("Submit code", _submit, True)],
        extra_bind_target=entry,
    )
    canvas.configure(height=y)

    root.bind("<Escape>", lambda _e: _cancel())
    entry.focus_set()


def _run_dialog(
    message: str, *, want_code: bool, timeout_s: float = DEFAULT_DIALOG_TIMEOUT_S
) -> Any:
    """Open one themed dialog, block until the human decides, and clean up.

    Closing the window (WM_DELETE_WINDOW) leaves the answer unset, which resolves
    to the deny default — there is no path where silence approves. The timeout
    exits by the same door: it only ends the loop, so the unset answer denies.
    """
    root = _open_root()
    try:
        _configure_window(root)
        answer: dict = {}
        populate = _populate_code if want_code else _populate_confirm
        populate(root, message, answer)
        root.protocol("WM_DELETE_WINDOW", root.quit)
        if timeout_s > 0:
            root.after(int(timeout_s * 1000), root.quit)
        _center_on_screen(root)
        root.mainloop()
        return answer.get("value", None if want_code else False)
    finally:
        root.destroy()


def _confirm_dialog(message: str, *, timeout_s: float = DEFAULT_DIALOG_TIMEOUT_S) -> bool:
    """Show the yes/no challenge dialog. Closing the window (or silence) is "no"."""
    return bool(_run_dialog(message, want_code=False, timeout_s=timeout_s))


def _code_dialog(message: str, *, timeout_s: float = DEFAULT_DIALOG_TIMEOUT_S) -> str | None:
    """Show the masked one-time-code dialog. Cancel/close/silence returns ``None``."""
    return _run_dialog(message, want_code=True, timeout_s=timeout_s)


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
