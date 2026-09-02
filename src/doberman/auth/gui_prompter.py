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
real Tk focus, never a fixed target. A countdown expiry resolves the SAME
"first answer wins" door every button/key path resolves through (see each
``_populate_*`` function's ``_decide``), so a click or keypress landing during
the post-expiry flash can never turn a denial back into an approval.

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
import math
import re
import sys
import threading
from collections.abc import Iterable
from typing import Any

from doberman.auth.challenge import Prompter
from doberman.render import deadline_note_mmss

logger = logging.getLogger("doberman.auth.gui_prompter")

#: Window title for every challenge dialog. ASCII-only (cp1252-safe legacy consoles).
_TITLE = "Doberman - authorization required"

# --- palette: dark warm-black coat, tan brand, amber (AUTH) approve ------------------
# Hex mirrors the canonical brand tokens shared with the landing page and the
# explainer video (their OKLCH --ink / --tan / --auth), so every Doberman surface
# reads as one system. Deny is the SOLID/filled button (the safe, fail-closed
# default reads as the visually dominant one); Approve is outlined/secondary —
# amber stays the AUTH-verdict accent, but it no longer "wins" the composition.
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
#: Keyboard focus ring — TWO-TONE by construction, because no single flat
#: color can clear WCAG 1.4.11's >= 3:1 non-text-contrast bar against every
#: surface it sits next to. Deny's fill (_BRAND) sits at mid-luminance: a
#: ring dark enough to read against it (<=~0.096 relative luminance) is too
#: dark to also read against the near-black window background (_BG needs
#: >=~0.112) — those two ranges don't overlap, so a single ring color for
#: Deny is mathematically impossible, not just untuned (round-2's fix reused
#: _RULE, which cleared _BRAND at 6.08:1 but only 1.25:1 against Approve's
#: actual fill _PANEL — the round-3 finding). The fix is a ring with two
#: lines per button: an INNER line touching the button's own face, and an
#: OUTER line (a wrapping frame's highlight — see _build_buttons) touching
#: the window background.
#:   - Deny:    inner = _RING_DENY (_BG, dark)   -> 8.13:1 vs _BRAND
#:              outer = _RING_OUTER (_FG, light) -> 17.38:1 vs _BG
#:   - Approve: inner = _RING_APPROVE (_FG)      -> 16.32:1 vs _PANEL
#:              outer = _RING_OUTER (_FG)        -> 17.38:1 vs _BG
#: (Approve's fill is itself near-black, so its inner/outer tones coincide —
#: it reads as one plain light ring; only Deny needs genuine two-tone.)
_RING_DENY = _BG
_RING_APPROVE = _FG
_RING_OUTER = _FG
#: BLOCK-red — dark-theme match for the dashboard's --block token
#: (oklch(66% 0.205 26)), used only for the critical/high severity ramp below.
_SEV_CRITICAL = "#f5524a"

_BRAND_FONT = (
    "Segoe UI Semibold",
    12,
    "bold",
)  # sized to sit near the 16-20px mark, not tower over it
_SUB_FONT = ("Segoe UI", 9)
_BODY_FONT = ("Segoe UI", 10)
_TARGET_FONT = ("Consolas", 12, "bold")
_SMALL_FONT = ("Segoe UI", 9)
_DEADLINE_FONT = ("Segoe UI", 9)  # >= 9pt floor (was 8pt / 10.7px, too small)
_BUTTON_FONT = ("Segoe UI Semibold", 10)
_CHIP_FONT = ("Segoe UI Semibold", 9, "bold")  # >= 9pt floor (was 8pt, below the file's own floor)

# --- layout constants (pixels; approximate — pack() auto-sizes the window) ----------
_DIALOG_W = 480
_PADX = 22
_TARGET_CHARS = 54  # Text widget width in characters (monospace target font)
_TARGET_MAX_LINES = 6  # collapsed cap: the question/risk/countdown stay below this
_TARGET_EXPANDED_MAX_LINES = 16  # fallback ceiling when no monitor rect is available
_TARGET_PREVIEW_HEAD_LINES = 4  # collapsed preview: whole LOGICAL lines kept from the start
_ELLIPSIS = " ... "
#: Generic fallback toggle label -- used when no verb/tool hint is available
#: (a caller that hands :func:`_build_target_panel` a bare string, or a
#: ``parts`` dict this doesn't recognize). See :func:`_toggle_expand_label`
#: for the noun derived from ``parts["verb"]``/``parts["tool"]`` (item 4).
_TOGGLE_EXPAND_LABEL = "Show the full target"

_SUBTITLE = "Doberman guards your agent's tool calls"
_REASSURANCE = "Denying stops only this action; your agent keeps running."
_QUESTION = "Approve this exact action?"
_HINT = "Tab/Arrows: move - Enter: use the focused button - Esc: deny"
_CODE_PROMPT = "Enter the 6-digit code from your authenticator app to approve:"
_CODE_LABEL = "6-digit code from your authenticator"
_CODE_ERROR_DIGITS = "Only digits, please."
_CODE_ERROR_COUNT = "Codes are 6 digits - you entered {n}."
_STEP_TWO = "Step 2 of 2 - enter your code"

#: WCAG 2.2.1: a human actually present can ask for one extension.
_EXTENSION_SECONDS = 120
_MORE_TIME_LABEL = "More time (+2:00)"

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
    """Best-effort DPI awareness on Windows; purely cosmetic, never fatal.

    Prefers ``SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_
    AWARE_V2)`` — the modern per-monitor-v2 API (Windows 10 1703+) — and, only
    when that call is unavailable or fails, falls back to the older, coarser
    ``SetProcessDpiAwareness(PROCESS_SYSTEM_DPI_AWARE)``. Must run before
    ``tkinter.Tk()`` constructs the first window. A second call within the
    same process (e.g. a second challenge) returns an access-denied HRESULT
    rather than raising — caught here like every other cosmetic guard.
    """
    if sys.platform != "win32":
        return
    try:  # pragma: no cover — needs a real Windows user32
        import ctypes

        windll = getattr(ctypes, "windll", None)  # absent on every non-Windows ctypes build
        if windll is None:
            return
        per_monitor_v2 = ctypes.c_void_p(-4)  # DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2
        if windll.user32.SetProcessDpiAwarenessContext(per_monitor_v2):
            return
    except Exception:  # noqa: S110 — older Windows lacks this call; fall back below
        pass
    try:  # pragma: no cover — needs a real Windows shell DLL
        import ctypes

        windll = getattr(ctypes, "windll", None)
        if windll is None:
            return
        windll.shcore.SetProcessDpiAwareness(1)  # PROCESS_SYSTEM_DPI_AWARE
    except Exception:  # noqa: S110 — cosmetic only
        pass


def _screen_dpi() -> float:
    """System DPI baseline; 96 (100%) off Windows or on any failure. Used only
    as the fallback when the per-monitor lookup (:func:`_dpi_for_dialog_placement`)
    is unavailable."""
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
    amber — on whichever button currently holds it. The link-style toggle
    ("Show all N characters") gets its own real focus ring too — previously it
    had none at all (borderwidth 0, no focus mapping).
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
        focuscolor=_RING_DENY,
        **common,
    )
    style.map(
        "Doberman.Deny.TButton",
        background=[("active", _BRAND_ACTIVE), ("pressed", _BRAND_ACTIVE)],
        bordercolor=[("focus", _RING_DENY), ("!focus", _BRAND)],
    )
    style.configure(
        "Doberman.Approve.TButton",
        background=_PANEL,
        foreground=_APPROVE,
        bordercolor=_APPROVE,
        focuscolor=_RING_APPROVE,
        **common,
    )
    style.map(
        "Doberman.Approve.TButton",
        background=[("active", _RULE), ("pressed", _RULE)],
        bordercolor=[("focus", _RING_APPROVE), ("!focus", _APPROVE)],
    )
    style.configure(
        "Doberman.Link.TButton",
        background=_BG,
        foreground=_BRAND,
        font=_SMALL_FONT,
        borderwidth=1,
        bordercolor=_BG,
        relief="flat",
        padding=(4, 4),
        focuscolor=_RING_OUTER,
    )
    style.map(
        "Doberman.Link.TButton",
        foreground=[("active", _APPROVE_ACTIVE)],
        bordercolor=[("focus", _RING_OUTER), ("!focus", _BG)],
    )


def _configure_window(root: Any) -> None:
    """Apply the window-level theme: topmost, dark base, fixed size, dark title bar."""
    root.title(_TITLE)
    root.configure(bg=_BG)
    root.resizable(False, False)
    root.attributes("-topmost", True)  # the dialog must pop OVER the agent's terminal
    _apply_dark_title_bar(root)
    try:
        root.tk.call("tk", "scaling", _dpi_for_dialog_placement() / 72.0)
    except Exception:  # noqa: S110 — cosmetic only (and unavailable on a fake root in tests)
        pass
    try:
        _apply_ttk_style(root)
    except Exception:  # noqa: S110 — cosmetic only (and unavailable on a fake root in tests)
        pass


def _hmonitor_under_cursor() -> Any | None:
    """The Win32 HMONITOR under the mouse pointer, or ``None`` off Windows or on
    any failure — shared by the monitor-rect and per-monitor-DPI lookups so both
    agree on which monitor "the dialog's monitor" means.
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
        return user32.MonitorFromPoint(pt, MONITOR_DEFAULTTONEAREST)
    except Exception:
        return None


def _monitor_rect_under_cursor() -> tuple[int, int, int, int] | None:
    """``(x, y, width, height)`` of the WORK area (``rcWork`` — excludes the
    taskbar and any docked toolbars, unlike ``rcMonitor``) of the monitor under
    the mouse pointer.

    Windows-only, best-effort: ``None`` (fall back to the primary screen) on
    any failure or off Windows.
    """
    hmon = _hmonitor_under_cursor()
    if hmon is None:
        return None
    try:  # pragma: no cover — needs real Win32 multi-monitor APIs
        import ctypes
        from ctypes import wintypes

        class _MonitorInfo(ctypes.Structure):
            _fields_ = [
                ("cbSize", wintypes.DWORD),
                ("rcMonitor", wintypes.RECT),
                ("rcWork", wintypes.RECT),
                ("dwFlags", wintypes.DWORD),
            ]

        info = _MonitorInfo()
        info.cbSize = ctypes.sizeof(_MonitorInfo)
        if not ctypes.windll.user32.GetMonitorInfoW(hmon, ctypes.byref(info)):
            return None
        r = info.rcWork
        return (r.left, r.top, r.right - r.left, r.bottom - r.top)
    except Exception:
        return None


def _dpi_for_dialog_placement() -> float:
    """DPI of the monitor the dialog will be centred on (best-effort, via
    ``GetDpiForMonitor``); falls back to the system DPI (:func:`_screen_dpi`)
    when the per-monitor lookup is unavailable (non-Windows, older Windows, or
    any Win32 failure) — keeps scaling honest when the mouse (and thus the
    dialog) sits on a different-DPI monitor than the system default.
    """
    hmon = _hmonitor_under_cursor()
    if hmon is None:
        return _screen_dpi()
    try:  # pragma: no cover — needs real Win32 multi-monitor + Shcore
        import ctypes
        from ctypes import wintypes

        MDT_EFFECTIVE_DPI = 0
        dpi_x, dpi_y = wintypes.UINT(), wintypes.UINT()
        hresult = ctypes.windll.shcore.GetDpiForMonitor(
            hmon, MDT_EFFECTIVE_DPI, ctypes.byref(dpi_x), ctypes.byref(dpi_y)
        )
        if hresult == 0 and dpi_x.value:  # S_OK
            return float(dpi_x.value)
    except Exception:  # noqa: S110 — cosmetic only; falls back to system DPI below
        pass
    return _screen_dpi()


def _center_on_screen(root: Any) -> None:
    """Center the (now-populated) dialog on the monitor under the mouse pointer.

    Falls back to the primary screen when that can't be determined (non-Windows,
    or any Win32 failure) — same "slightly above center" placement as before.
    The ``y`` coordinate is clamped so the window's bottom edge can never escape
    the work area — without this, a tall EXPANDED target panel could push the
    Deny/Approve buttons off the bottom of the screen.
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
    y = max(my, min(y, my + mh - height))  # never let the bottom edge escape the work area
    root.geometry(f"+{x}+{y}")


def _load_logo() -> Any:
    """Load the bundled brand mark via stdlib ``PhotoImage`` — never PIL/Pillow.

    The asset ships pre-sized (65x68px) at ``doberman/auth/_assets/doberman-mark.png``
    and is shown at ~16px tall via ``.subsample(4)`` — the brand block yields most of
    its footprint to the decision below it (see :func:`_build_brand`). Returns ``None``
    on any failure (missing asset, a Tk build without PNG support, ...); the caller then
    falls back to a text-only "DOBERMAN" wordmark — never an emoji substitute.
    """
    try:
        import tkinter as tk

        with _ir.as_file(_ir.files("doberman.auth").joinpath("_assets/doberman-mark.png")) as p:
            return tk.PhotoImage(file=str(p)).subsample(4)
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
    """A compact mark+wordmark row with the subtitle right under it (9pt) —
    the whole block stays under ~48px tall so the space it used to take
    (a bigger mark, a 12px bottom pad) goes to the "decide" group instead
    (see :func:`_build_group_divider`), not to the brand itself.
    """
    import tkinter as tk

    row = tk.Frame(frame, bg=_BG)
    row.pack(fill="x", pady=(0, 1))
    logo = _load_logo()
    row._logo_ref = logo  # tkinter drops unreferenced images -- keep it alive
    if logo is not None:
        tk.Label(row, image=logo, bg=_BG).pack(side="left")
        tk.Label(row, text="DOBERMAN", fg=_BRAND, bg=_BG, font=_BRAND_FONT).pack(
            side="left", padx=(8, 0)
        )
    else:
        tk.Label(row, text="DOBERMAN", fg=_BRAND, bg=_BG, font=_BRAND_FONT).pack(side="left")
    tk.Label(
        frame, text=_SUBTITLE, fg=_MUTED, bg=_BG, font=_SUB_FONT, anchor="w", justify="left"
    ).pack(fill="x", pady=(0, 4))


def _build_group_divider(frame: Any, *, pady: tuple = (4, 10)) -> None:
    """A thin hairline. The default spacing separates the "what" group
    (target/question/why/risk) from the "decide" group (countdown/buttons) —
    the vertical space freed by shrinking the brand block (:func:`_build_brand`)
    goes here, so the two groups read as visually distinct instead of one long
    undifferentiated stack of lines. A tighter ``pady`` is used inside the
    "what" group itself, above the risk row (item 6).
    """
    import tkinter as tk

    tk.Frame(frame, bg=_RULE, height=1).pack(fill="x", pady=pady)


_HELP_LABEL = "What is this?"


def _help_explanation(why: str | None) -> str:
    """The collapsed help affordance's two-line explanation (item 10) — pure
    string composition, split out from the Tk widget wiring in
    :func:`_build_help_affordance` so it is testable without a display.
    """
    clause = (why or "it looked unusual for this agent").strip().rstrip(".")
    clause = clause[:1].lower() + clause[1:] if clause else clause
    return (
        "Doberman checks each tool call your agent makes. "
        f"It stopped this one because {clause}. "
        "Approving lets exactly this action through once."
    )


def _build_help_affordance(frame: Any, why: str | None) -> None:
    """A collapsed-by-default, focusable link ("What is this?") that expands
    a plain-language explanation of what Doberman is and why THIS action
    stopped — orientation for a human seeing this dialog for the first time.
    Never the default focus: nothing here calls ``focus_set``/``focus_force``,
    so :func:`_wire_keyboard`'s own ``deny_btn.focus_force()`` (run separately
    by the caller) is unaffected regardless of build order.
    """
    import tkinter as tk
    import tkinter.ttk as ttk

    body = tk.Label(
        frame,
        text=_help_explanation(why),
        fg=_MUTED,
        bg=_BG,
        font=_SMALL_FONT,
        anchor="w",
        justify="left",
        wraplength=_wrap_px(frame),
    )
    state = {"expanded": False}

    def _toggle() -> None:
        state["expanded"] = not state["expanded"]
        if state["expanded"]:
            body.pack(fill="x", pady=(0, 6))
            link.configure(text="Hide")
        else:
            body.pack_forget()
            link.configure(text=_HELP_LABEL)

    link = ttk.Button(frame, text=_HELP_LABEL, command=_toggle, style="Doberman.Link.TButton")
    link.pack(anchor="w", pady=(0, 2))


def _wrap_px(widget: Any) -> int:
    """The dialog's standard text wraplength, scaled to whatever DPI was
    actually applied via ``tk scaling`` (see :func:`_configure_window`).

    A bare pixel ``wraplength`` does not auto-scale the way point-sized fonts
    do (``tk scaling`` only converts points to pixels), so without this a
    high-DPI monitor would wrap body text far narrower than the correctly
    scaled surrounding fonts and buttons imply. Falls back to no scaling
    (1.0) on any failure — a fake root in tests, or a widget with no ``tk``
    scaling ever applied.
    """
    try:
        scale = float(widget.tk.call("tk", "scaling")) * 72.0 / 96.0
    except Exception:
        scale = 1.0
    return int((_DIALOG_W - 2 * _PADX) * scale)


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
        wraplength=_wrap_px(frame),
    ).pack(fill="x", pady=pady)


def _make_read_only(text: Any) -> None:
    """Block edits while leaving the widget ``state="normal"`` — a "disabled"
    Tk widget drops out of the keyboard tab order and off most screen readers'
    accessible tree, so disabling was never a harmlessly-safer choice, it was
    quietly hiding the target from assistive tech and from Tab navigation.

    Navigation (arrows/Home/End/Page*/Tab), Escape (the dialog's global deny
    shortcut, which must never be swallowed here), and any Control-modified
    key (copy, select-all, ...) are left alone; every other keystroke —
    including Return, which would otherwise insert a literal newline into the
    "read-only" target — is vetoed.
    """

    def _guard(event: Any) -> str | None:
        if event.state & 0x0004:  # Control held -- copy/select-all, never blocked
            return None
        if event.keysym in ("Tab", "Escape"):
            return None
        if event.keysym in ("Delete", "BackSpace") or event.char:
            return "break"
        return None

    text.bind("<Key>", _guard)


def _expanded_line_cap(root: Any) -> int:
    """Expanded-view line cap: 70% of the monitor's WORK area height (in real
    text lines, via the target font's actual line height) — never a blind
    fixed guess, so a very tall multi-line target can't push the dialog's
    buttons past the bottom of even a small laptop panel. Falls back to the
    fixed :data:`_TARGET_EXPANDED_MAX_LINES` ceiling when no monitor rect is
    available (non-Windows, or any Win32 failure).
    """
    monitor = _monitor_rect_under_cursor()
    if monitor is None:
        return _TARGET_EXPANDED_MAX_LINES
    _, _, _, work_h = monitor
    try:
        import tkinter.font as tkfont

        line_h = tkfont.Font(root=root, font=_TARGET_FONT).metrics("linespace")
    except Exception:
        return _TARGET_EXPANDED_MAX_LINES
    return max(4, int(work_h * 0.70) // max(line_h, 1))


def _more_characters_note(n: int) -> str:
    """The muted marker for a single-logical-line target collapsed past the
    height cap: states how much is hidden instead of a silent visual clip
    (item 3). Pure string formatting, split out from the Tk widget geometry
    that computes ``n`` so it is testable without a display.
    """
    return f"... ({n} more characters)"


def _build_target_panel(
    root: Any, frame: Any, target: str, *, toggle_label: str = _TOGGLE_EXPAND_LABEL
) -> None:
    """The target/command: its own bold-mono panel, capped at 6 display lines.

    Sized from the REAL widget (``count("1.0","end","displaylines")``) after the
    text is actually inserted — never a predicted/estimated line count — so an
    over-wide unbroken "word" (Tk's own word-wrap already char-breaks one that
    doesn't fit) can never be undercounted and clipped. Past the cap, a target
    with MULTIPLE logical lines collapses by WHOLE lines only — the first
    :data:`_TARGET_PREVIEW_HEAD_LINES` lines, a muted ``" ... "`` marker (its
    own line, tagged so it can never be mistaken for real target text), then
    the last line — never a character-offset cut, which could slice through
    the middle of a single token/line and hide part of it with no indication
    (the previous design's failure mode).

    A target that is only ONE logical line (however long) is never SLICED —
    every character stays in the widget's model — but past the cap it now
    shows a muted ``"... (N more characters)"`` marker as its own last line
    (item 3) instead of a silent visual clip: ``N`` is read back from the
    widget's own wrapping (``"1.0 +K displaylines"``), never guessed from a
    chars-per-line estimate, so it can never drift from what Tk actually
    renders. A ``toggle_label`` (item 4 — named for the action, e.g. "Show
    the full command"/"path"/"URL") expands into a scrollable region (capped
    at 70% of the monitor's work area — :func:`_expanded_line_cap`). The
    question/risk/countdown this function's caller draws afterward are never
    inside this panel, so they can never be pushed out of view by a long
    target.

    The widget stays ``state="normal"`` throughout (never "disabled") so it
    stays in the keyboard tab order and reachable by assistive tech —
    :func:`_make_read_only` blocks actual edits instead.
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
        takefocus=True,
    )
    text.pack(fill="x")
    text.tag_configure("muted", foreground=_MUTED)
    _make_read_only(text)

    def _paint(segments: list[tuple[str, str | None]], cap: int) -> int:
        text.configure(state="normal")
        text.delete("1.0", "end")
        for chunk, tag in segments:
            if tag:
                text.insert("end", chunk, (tag,))
            else:
                text.insert("end", chunk)
        text.update_idletasks()
        lines = min(int(text.count("1.0", "end", "displaylines")[0]), cap)
        text.configure(height=max(lines, 1))
        return lines

    lines = target.split("\n")
    # Only ever drop WHOLE middle lines -- never cut inside one. With
    # _TARGET_PREVIEW_HEAD_LINES (4) kept from the start plus 1 kept from the
    # end, a preview only makes sense (actually hides something) once there
    # are MORE than that many lines total; a single unbroken line, or a
    # handful of short lines, is never sliced at all.
    needs_preview = len(lines) > _TARGET_PREVIEW_HEAD_LINES + 1
    total = _paint([(target, None)], 10**6)  # measure the real, unbounded line count first
    if total <= _TARGET_MAX_LINES:
        return

    # Single overflowing logical line: read back exactly how much of it fits
    # in the collapsed height (cap-1 real display lines, the last reserved
    # for the "N more characters" marker) from the widget's OWN wrapping --
    # never a guessed chars-per-line estimate. Best-effort: an older Tk build
    # without displaylines index arithmetic falls back to the pre-item-3
    # silent-clip behavior rather than raising.
    single_line_head: str | None = None
    single_line_hidden = 0
    if not needs_preview:
        try:
            boundary = text.index(f"1.0 +{max(_TARGET_MAX_LINES - 1, 1)} displaylines")
            single_line_head = text.get("1.0", boundary)
            single_line_hidden = len(target) - len(single_line_head)
        except Exception:  # pragma: no cover — every stdlib Tk >=8.5 supports displaylines
            single_line_head = None

    scrollbar_holder: dict[str, Any] = {}
    state = {"expanded": False}

    def _collapse() -> None:
        for sb in scrollbar_holder.values():
            sb.destroy()
        scrollbar_holder.clear()
        text.configure(yscrollcommand="")
        if needs_preview:
            head = "\n".join(lines[:_TARGET_PREVIEW_HEAD_LINES])
            tail = lines[-1]
            _paint(
                [
                    (head, None),
                    ("\n" + _ELLIPSIS.strip() + "\n", "muted"),
                    (tail, None),
                ],
                _TARGET_MAX_LINES,
            )
        elif single_line_head is not None and single_line_hidden > 0:
            _paint(
                [
                    (single_line_head, None),
                    ("\n" + _more_characters_note(single_line_hidden), "muted"),
                ],
                _TARGET_MAX_LINES,
            )
        else:
            _paint([(target, None)], _TARGET_MAX_LINES)

    def _expand() -> None:
        cap = _expanded_line_cap(root)
        _paint([(target, None)], cap)
        if total > cap:  # hit the cap -- offer a scrollbar rather than clip silently
            sb = ttk.Scrollbar(panel, command=text.yview)
            text.configure(yscrollcommand=sb.set)
            sb.pack(side="right", fill="y")
            scrollbar_holder["y"] = sb

    def _toggle() -> None:
        state["expanded"] = not state["expanded"]
        (_expand if state["expanded"] else _collapse)()
        toggle_btn.configure(text="Show less" if state["expanded"] else toggle_label)
        root.update_idletasks()
        _center_on_screen(root)

    _collapse()
    toggle_btn = ttk.Button(
        frame,
        text=toggle_label,
        command=_toggle,
        style="Doberman.Link.TButton",
    )
    toggle_btn.pack(anchor="w", pady=(0, 6))


def _toggle_expand_label(parts: dict[str, Any] | None) -> str:
    """Name the truncated THING instead of always saying "command" (item 4):
    derived from ``parts["verb"]``/``parts["tool"]`` (both already computed by
    :func:`doberman.auth.provider.challenge_parts`), keyword-matched rather
    than tied to one exact phrasing so it stays correct across both the
    "human" and "technical" tones. Falls back to the generic
    :data:`_TOGGLE_EXPAND_LABEL` ("Show the full target") when nothing more
    specific is known -- never a wrong guess dressed up as a specific one.
    """
    if not parts:
        return _TOGGLE_EXPAND_LABEL
    haystack = f"{parts.get('verb') or ''} {parts.get('tool') or ''}".lower()
    if any(word in haystack for word in ("url", "network", "http", "send data")):
        return "Show the full URL"
    if any(word in haystack for word in ("path", "file")):
        return "Show the full path"
    if any(word in haystack for word in ("command", "shell", "run a command")):
        return "Show the full command"
    return _TOGGLE_EXPAND_LABEL


_RISK_BRACKET_RE = re.compile(r"^\[RISK: [A-Z]+\]\s*")


def _headline_without_risk_bracket(headline: str) -> str:
    """Strip a leading ``"[RISK: HIGH] "`` bracket from a technical-tone
    headline.

    The bracket stays in ``parts["headline"]`` itself (built by
    :func:`doberman.auth.provider.challenge_parts`) for the flat-string
    TTY/dashboard rendering, which has no colored severity chip of its own and
    would otherwise show the severity nowhere at all. The GUI already draws
    that same fact as a chip (:func:`_build_risk_line`), so its own headline
    LABEL strips the bracket before display -- showing "HIGH" in the bracket,
    the chip, AND the risk sentence was needless triple repetition on a
    single dialog (item 11). A no-op when there is no bracket to strip.
    """
    return _RISK_BRACKET_RE.sub("", headline, count=1)


def _agent_identity_line(parts: dict) -> str | None:
    """``"Agent: <role> - via <tool>"`` from ``parts["role"]``/``parts["tool"]``
    — ``None`` when neither is known (nothing to show); a graceful partial
    form when only one is.
    """
    role, tool = parts.get("role"), parts.get("tool")
    if role and tool:
        return f"Agent: {role} - via {tool}"
    if role:
        return f"Agent: {role}"
    if tool:
        return f"Agent: via {tool}"
    return None


_SEVERITY_WORDS = ("critical", "high", "medium", "low")


def _severity_from_risk_text(risk_text: str) -> str | None:
    """The Risk-enum word embedded in ``parts["risk"]`` (every real
    ``challenge_parts()`` rendering, in either tone, includes one) —
    ``None`` only for a hand-built ``parts`` dict that omits it.
    """
    lowered = risk_text.lower()
    for word in _SEVERITY_WORDS:
        if word in lowered:
            return word
    return None


def _severity_ramp(word: str | None) -> tuple[str, bool]:
    """(colour, bold) for a severity word — critical/high are bold BLOCK-red,
    medium is amber, and low (or an unrecognized/missing word — the least
    alarming reading, never the most) is ordinary body text.
    """
    if word in ("critical", "high"):
        return _SEV_CRITICAL, True
    if word == "medium":
        return _APPROVE, False
    return _FG, False


def _chip_style(word: str | None) -> tuple[str | None, str]:
    """``(fill, border_and_text)`` for the severity CHIP -- distinct from
    :func:`_severity_ramp`, which colours the risk SENTENCE.

    LOW (or an unrecognized/missing word) is a muted OUTLINE chip: no fill,
    ``_MUTED`` text/border. The old code filled every chip's background with
    :func:`_severity_ramp`'s colour, and low's ramp colour is ``_FG`` (near-
    white) -- a pixel-luminance regression where the LEAST alarming severity
    painted the single BRIGHTEST chip on the dialog (item 2). Medium/high/
    critical keep a solid fill; only low is ever an outline.
    """
    if word in ("critical", "high"):
        return _SEV_CRITICAL, _BG
    if word == "medium":
        return _APPROVE, _BG
    return None, _MUTED


def _build_risk_line(frame: Any, risk_text: str, risk_word: str | None) -> None:
    """The risk line as a small severity chip (e.g. ``" HIGH "``) plus the
    risk text itself. The word (always present, in the chip AND the text)
    carries the meaning regardless of color, so nothing here rests on colour
    alone.
    """
    import tkinter as tk

    color, bold = _severity_ramp(risk_word)
    fill, chip_color = _chip_style(risk_word)
    row = tk.Frame(frame, bg=_BG)
    row.pack(fill="x", pady=(0, 6))
    chip_kwargs: dict[str, Any] = {}
    if fill is None:
        # Outline chip (low/unrecognized): no fill -- a border instead of a
        # solid block, so it can never out-luminate a real fill chip.
        chip_kwargs.update(
            highlightthickness=1, highlightbackground=chip_color, highlightcolor=chip_color
        )
    tk.Label(
        row,
        text=f" {(risk_word or 'low').upper()} ",
        bg=fill or _BG,
        fg=chip_color,
        font=_CHIP_FONT,
        **chip_kwargs,
    ).pack(side="left", padx=(0, 8), pady=1, anchor="n")
    tk.Label(
        row,
        text=risk_text,
        fg=color,
        bg=_BG,
        font=(_SMALL_FONT[0], _SMALL_FONT[1], "bold") if bold else _SMALL_FONT,
        anchor="w",
        justify="left",
        wraplength=max(_wrap_px(frame) - 60, 100),
    ).pack(side="left", fill="x", expand=True)


def _build_countdown(
    root: Any, frame: Any, timeout_s: float, on_expire: Any, *, action_id: str = "unknown"
) -> Any:
    """A ticking "auto-denies in M:SS" label, plus a one-shot "More time"
    control (WCAG 2.2.1 — a human actually present must be able to ask for
    more time). The label adopts the same severity ramp risk uses as time
    runs low — amber under 30s, bold BLOCK-red under 10s — so an urgent
    countdown reads as urgent the same way an urgent risk does; at zero, a
    brief "Denied" flash, then close.

    At zero, ``on_expire`` runs FIRST and SYNCHRONOUSLY, before this function
    ever shows the flash or schedules the window's close: it must resolve the
    shared answer to a denial (through the same "first answer wins" door every
    ``_decide`` in the populate functions resolves through) and disable every
    interactive widget, so a click or Return landing during the 1.5s flash can
    never still change the outcome. The "More time" button is disabled the
    same instant, alongside Deny/Approve/the code entry.

    "More time" is usable exactly ONCE per dialog (a real, focusable, but
    never the *default*-focused control — :func:`_wire_keyboard` always moves
    initial focus to Deny after this function returns) and extends the
    countdown by :data:`_EXTENSION_SECONDS`; each use is logged (the action id
    only, never the target).
    """
    import tkinter as tk
    import tkinter.ttk as ttk

    label = tk.Label(frame, fg=_MUTED, bg=_BG, font=_DEADLINE_FONT, anchor="w")
    label.pack(fill="x", pady=(2, 4))
    total = max(1, int(timeout_s))
    remaining = {"s": total}
    extended = {"used": False}

    def _paint(secs: int) -> None:
        if secs < 10:
            color, bold = _SEV_CRITICAL, True
        elif secs < 30:
            color, bold = _APPROVE, False
        else:
            color, bold = _MUTED, False
        font = (_DEADLINE_FONT[0], _DEADLINE_FONT[1], "bold") if bold else _DEADLINE_FONT
        label.configure(text=deadline_note_mmss(secs), fg=color, font=font)

    def _extend() -> None:
        if extended["used"]:
            return
        extended["used"] = True
        more_time_btn.state(["disabled"])
        remaining["s"] += _EXTENSION_SECONDS
        logger.info(
            "auth dialog countdown extended by %ss (action %s)", _EXTENSION_SECONDS, action_id
        )
        _paint(remaining["s"])

    more_time_btn = ttk.Button(
        frame, text=_MORE_TIME_LABEL, command=_extend, style="Doberman.Link.TButton"
    )
    more_time_btn.pack(anchor="w", pady=(0, 6))

    def _tick() -> None:
        remaining["s"] -= 1
        if remaining["s"] <= 0:
            on_expire()
            more_time_btn.state(["disabled"])
            # Block-red, not plain body text (item 7): an expiry is a denial,
            # not a neutral status update, and must read as one.
            label.configure(
                text=f"Denied - no answer in {_mmss(total)}", fg=_SEV_CRITICAL, font=_DEADLINE_FONT
            )
            root.after(1500, root.quit)
            return
        _paint(remaining["s"])
        root.after(1000, _tick)

    _paint(remaining["s"])
    root.after(1000, _tick)
    return label


def _build_buttons(frame: Any, specs: list[tuple[str, Any, str]]) -> tuple[Any, ...]:
    """Real ``ttk.Button``s, right-aligned, in ``specs`` order (index 0 = Deny).

    Accessible by construction: a real name/role/state, native focus, >=44px
    tall (see :func:`_apply_ttk_style`'s padding). Each button is wrapped in a
    small ``Frame`` whose ``highlightbackground`` becomes :data:`_RING_OUTER`
    on focus — the OUTER line of the two-tone focus ring (the ttk style's own
    per-button ``bordercolor``, set in :func:`_apply_ttk_style`, is the INNER
    line). Neither line alone can clear WCAG 1.4.11 against every surface a
    ring touches (see the module-level comment above ``_RING_DENY``); together
    they do. Keyboard safety is wired separately by :func:`_wire_keyboard` —
    this only creates and places them.
    """
    import tkinter as tk
    import tkinter.ttk as ttk

    row = tk.Frame(frame, bg=_BG)
    row.pack(fill="x", pady=(4, 8))
    inner = tk.Frame(row, bg=_BG)
    inner.pack(side="right")
    buttons = []
    for i, (label, command, style_name) in enumerate(specs):
        wrapper = tk.Frame(
            inner, bg=_BG, highlightthickness=2, highlightbackground=_BG, highlightcolor=_BG
        )
        wrapper.pack(side="left", padx=(10 if i else 0, 0))
        button = ttk.Button(wrapper, text=label, command=command, style=style_name)
        button.pack()
        # Both highlightbackground AND highlightcolor: a pixel probe found the
        # outer line never painting with only highlightbackground set (P1) --
        # the wrapper is a plain tk.Frame, never itself the Tk-focused widget
        # (the button inside it is), so leaving highlightcolor at the
        # never-updated creation value left SOME code path in this Tk build
        # painting the ring from that stale colour instead. Setting both keeps
        # the ring lit regardless of which one Tk actually consults.
        button.bind(
            "<FocusIn>",
            lambda _e, w=wrapper: w.configure(
                highlightbackground=_RING_OUTER, highlightcolor=_RING_OUTER
            ),
        )
        button.bind(
            "<FocusOut>",
            lambda _e, w=wrapper: w.configure(highlightbackground=_BG, highlightcolor=_BG),
        )
        buttons.append(button)
    return tuple(buttons)


def _wire_keyboard(root: Any, deny_btn: Any, approve_btn: Any) -> None:
    """Deny starts focused; Return invokes ONLY whichever button holds real Tk
    focus; Left/Right (on the buttons themselves, never globally — so a code
    entry's own cursor movement is untouched) swap focus between the two.

    Ctrl+Return is a DELIBERATE-APPROVE accelerator, not a second Return: it
    invokes Approve only when Approve ALREADY holds focus, and is a no-op
    everywhere else (including with Deny focused, the default) — it must
    never act as a second way to deny, only ever a second way to approve
    something you have already moved focus onto.

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

    def _invoke_if_approve_focused(_event: Any = None) -> str:
        if root.focus_get() is approve_btn:
            approve_btn.invoke()
        return "break"

    root.bind("<Control-Return>", _invoke_if_approve_focused)

    def _swap(_event: Any = None) -> str:
        (approve_btn if root.focus_get() is deny_btn else deny_btn).focus_set()
        return "break"

    for button in (deny_btn, approve_btn):
        button.bind("<Left>", _swap)
        button.bind("<Right>", _swap)


#: A CRITICAL action gets a mandatory pause before Approve is even clickable
#: -- a deliberate-gesture escalation ABOVE what "high" already requires
#: (item 2), so a reflexive click can never land before a human has had at
#: least a moment to read the dialog.
_CRITICAL_APPROVE_DELAY_S = 1.5


def _critical_approve_label(base_text: str, remaining_s: float) -> str:
    """``"Approve (2)"`` while the CRITICAL delay is still running; the bare
    label once it clears. Pure formatting, split out from the Tk ticking in
    :func:`_gate_approve_for_critical` so it is testable without a display.
    """
    if remaining_s <= 0:
        return base_text
    return f"{base_text} ({math.ceil(remaining_s)})"


def _gate_approve_for_critical(root: Any, approve_btn: Any, severity_word: str | None) -> None:
    """Disable ``approve_btn`` for :data:`_CRITICAL_APPROVE_DELAY_S` when
    ``severity_word`` is ``"critical"``; a no-op for every other severity.

    Ticks the remaining whole seconds onto the button's own label so the
    delay is visible, not just felt. Disabled the same way the countdown's
    expiry path already disables buttons (:func:`_disable_on_expiry`), so
    Return/Ctrl+Return/a real click all no-op identically while it runs --
    Tk's own ``ttk.Button.invoke()`` is a no-op on a disabled button, so
    nothing extra is needed to make the gate hold against every input path.
    """
    if severity_word != "critical":
        return
    base_text = approve_btn.cget("text")
    approve_btn.state(["disabled"])
    remaining = {"s": _CRITICAL_APPROVE_DELAY_S}

    def _tick() -> None:
        remaining["s"] -= 0.1
        if remaining["s"] <= 1e-9:
            approve_btn.configure(text=base_text)
            approve_btn.state(["!disabled"])
            return
        approve_btn.configure(text=_critical_approve_label(base_text, remaining["s"]))
        root.after(100, _tick)

    approve_btn.configure(text=_critical_approve_label(base_text, remaining["s"]))
    root.after(100, _tick)


def _disable_on_expiry(root: Any, widgets: dict) -> None:
    """Disable every interactive widget already registered in ``widgets`` (by
    the calling populate function, once built) and unbind the keys that could
    otherwise still resolve the dialog. Called from the countdown's
    ``on_expire`` STRICTLY AFTER ``_decide``'s first-answer-wins guard has
    already locked the answer — this is belt-and-suspenders so the widgets
    read visually/functionally inert too, not just resolved underneath.
    """
    for key in ("deny", "approve"):
        button = widgets.get(key)
        if button is not None:
            button.state(["disabled"])
    entry = widgets.get("entry")
    if entry is not None:
        entry.configure(state="disabled")
        entry.unbind("<Return>")
        entry.unbind("<Control-Return>")
    root.unbind("<Return>")
    root.unbind("<Control-Return>")
    root.unbind("<Escape>")


# --- confirm dialog: flat-string (legacy) + structured (parts) ----------------------


def _populate_confirm(root: Any, message: str, answer: dict, timeout_s: float) -> None:
    """Legacy flat-string body: back-compat for any ``Prompter`` caller that only
    ever hands this a rendered ``message`` string (and for tests stubbing this
    exact seam). Shows the whole message as one block — no target/headline
    hierarchy, since there is no structured data to split it from — but reuses
    the same real-widget button/countdown/escape machinery as the structured
    path below, so it is never less keyboard-safe or accessible.
    """

    def _resolve(value: bool, reason: str) -> bool:
        if "value" in answer:  # first answer wins -- a post-expiry click can't override it
            return False
        answer["value"] = value
        answer["reason"] = reason
        return True

    def _decide(value: bool, reason: str) -> None:
        _resolve(value, reason)
        root.quit()

    frame = _content_frame(root)
    _build_brand(frame)
    _build_line(frame, message, pady=(0, 10))
    _build_group_divider(frame)

    widgets: dict[str, Any] = {}

    def _lock_out() -> None:
        # Resolve WITHOUT quitting -- the window must stay open through the
        # "Denied" flash; _build_countdown's own root.after(1500, root.quit)
        # is what actually closes it.
        _resolve(False, "expired")
        _disable_on_expiry(root, widgets)

    _build_countdown(root, frame, timeout_s, on_expire=_lock_out)
    deny_btn, approve_btn = _build_buttons(
        frame,
        [
            ("Deny", lambda: _decide(False, "denied"), "Doberman.Deny.TButton"),
            ("Approve", lambda: _decide(True, "approved"), "Doberman.Approve.TButton"),
        ],
    )
    widgets["deny"], widgets["approve"] = deny_btn, approve_btn
    _wire_keyboard(root, deny_btn, approve_btn)
    _build_line(frame, _HINT, font=_DEADLINE_FONT, fg=_MUTED, pady=(4, 0))
    root.bind("<Escape>", lambda _e: _decide(False, "denied"))


def _populate_confirm_parts(root: Any, parts: dict, answer: dict, timeout_s: float) -> None:
    """Structured body: the target gets its own headline panel; the question,
    risk line, and countdown are drawn OUTSIDE it, so nothing about the target
    (however long) can push them out of view. Segments are read from ``parts``
    by name — never sniffed from indentation — so the action's own target text
    can never forge itself into looking like the risk line or the question.

    The "technical" tone already embeds its risk badge and role in the
    headline (``"[RISK: HIGH]  Doberman authentication required [...]"``);
    the severity chip is drawn regardless — severity is a visual signal (color
    AND word), not merely restating the headline's text, and every tone
    deserves the same at-a-glance signal — alongside a compact
    ``"Action: <verb>"`` line so the verb (missing from the structured
    technical rendering before) is still visible. The GUI's own headline
    label strips the technical tone's "[RISK: HIGH]" bracket (the chip already
    says it — item 11); CRITICAL additionally colours the headline text
    itself in the same BLOCK-red the chip uses (item 2).

    Layout (item 6): the target panel, the approval-memory notice (moved to
    AFTER it — "read after the action", styled as a muted note, not the
    brand-coloured alert it used to be BEFORE the human even saw the target),
    then the question. The agent identity / why / risk / reassurance lines
    are grouped together as one block (previously identity sat off on its
    own, ahead of the target panel) with a hairline above the risk row, and
    the why line is promoted to body face/colour (never smaller/muteder than
    the keyboard hint below it — the reason must outrank the hint).
    """

    def _resolve(value: bool, reason: str) -> bool:
        if "value" in answer:
            return False
        answer["value"] = value
        answer["reason"] = reason
        return True

    def _decide(value: bool, reason: str) -> None:
        _resolve(value, reason)
        root.quit()

    risk_word = _severity_from_risk_text(parts["risk"]) if parts.get("risk") else None

    frame = _content_frame(root)
    _build_brand(frame)
    if parts.get("headline"):
        headline_text = parts["headline"]
        if parts.get("tone") == "technical":
            headline_text = _headline_without_risk_bracket(headline_text)
        _build_line(frame, headline_text, fg=_SEV_CRITICAL if risk_word == "critical" else _FG)
    if parts.get("tone") == "technical":
        _build_line(frame, f"Action: {parts['verb']}", font=_SMALL_FONT, fg=_MUTED)
    _build_target_panel(root, frame, parts["target"], toggle_label=_toggle_expand_label(parts))
    if parts.get("notice"):
        _build_line(frame, parts["notice"], font=_SMALL_FONT, fg=_MUTED)
    _build_line(frame, _QUESTION, font=_BODY_FONT, fg=_FG, pady=(2, 8))
    identity = _agent_identity_line(parts)
    if identity:
        _build_line(frame, identity, font=_SMALL_FONT, fg=_MUTED)
    if parts.get("why"):
        _build_line(frame, parts["why"], font=_BODY_FONT, fg=_FG)
    if parts.get("risk"):
        _build_group_divider(frame, pady=(2, 6))
        _build_risk_line(frame, parts["risk"], risk_word)
    _build_line(frame, _REASSURANCE, font=_SMALL_FONT, fg=_MUTED, pady=(2, 8))
    _build_help_affordance(frame, parts.get("why"))
    _build_group_divider(frame)

    widgets: dict[str, Any] = {}

    def _lock_out() -> None:
        # Resolve WITHOUT quitting -- the window must stay open through the
        # "Denied" flash; _build_countdown's own root.after(1500, root.quit)
        # is what actually closes it.
        _resolve(False, "expired")
        _disable_on_expiry(root, widgets)

    _build_countdown(
        root, frame, timeout_s, on_expire=_lock_out, action_id=parts.get("action_id", "unknown")
    )
    deny_btn, approve_btn = _build_buttons(
        frame,
        [
            ("Deny", lambda: _decide(False, "denied"), "Doberman.Deny.TButton"),
            ("Approve", lambda: _decide(True, "approved"), "Doberman.Approve.TButton"),
        ],
    )
    widgets["deny"], widgets["approve"] = deny_btn, approve_btn
    _wire_keyboard(root, deny_btn, approve_btn)
    _gate_approve_for_critical(root, approve_btn, risk_word)
    _build_line(frame, _HINT, font=_DEADLINE_FONT, fg=_MUTED, pady=(4, 0))
    root.bind("<Escape>", lambda _e: _decide(False, "denied"))


# --- code dialog: flat-string (legacy) + structured (parts) -------------------------


def _check_code(raw: str) -> tuple[str | None, str | None]:
    """Validate a code-entry string. Returns ``(code, None)`` for exactly 6
    digits (whitespace-stripped, paste-safe); else ``(None, message)`` naming
    the EXACT problem instead of repeating the prompt.
    """
    code = "".join(raw.split())
    if code and not code.isdigit():
        return None, _CODE_ERROR_DIGITS
    if len(code) != 6:
        return None, _CODE_ERROR_COUNT.format(n=len(code))
    return code, None


def _wire_paste_strip(entry: Any) -> None:
    """Override the default paste so a code copied with a separator (e.g.
    "123 456") lands as clean digits immediately, rather than showing the
    separator and waiting to be stripped only at submit time.
    """

    def _paste(_event: Any = None) -> str:
        try:
            clipboard = entry.clipboard_get()
        except Exception:
            return "break"
        digits = "".join(c for c in clipboard if c.isdigit())
        if entry.selection_present():
            entry.delete("sel.first", "sel.last")
        entry.insert("insert", digits)
        return "break"

    entry.bind("<<Paste>>", _paste)


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
        width=8,
    )
    vcmd = entry.register(lambda proposed: all(c.isdigit() or c.isspace() for c in proposed))
    entry.configure(validate="key", validatecommand=(vcmd, "%P"))
    _wire_paste_strip(entry)
    entry.pack(fill="x", pady=(0, 4))
    return entry


def _wire_code_submit(root: Any, entry: Any, error_label: Any, on_code: Any) -> Any:
    def _submit() -> None:
        code, error = _check_code(entry.get())
        if error:
            error_label.configure(text=error)
            return  # never deny here -- let them retry within the same timeout
        on_code(code)

    def _submit_and_stop(_event: Any = None) -> str:
        # Bound on the entry itself, dispatched before root's own <Return>
        # binding -- "break" stops it there so Enter/Ctrl+Enter-in-the-entry
        # submits exactly once.
        _submit()
        return "break"

    entry.bind("<Return>", _submit_and_stop)
    entry.bind("<Control-Return>", _submit_and_stop)
    entry.focus_force()
    return _submit


def _populate_code(root: Any, message: str, answer: dict, timeout_s: float) -> None:
    """Legacy flat-string body — see :func:`_populate_confirm`'s docstring."""
    import tkinter as tk

    def _resolve(value: Any, reason: str) -> bool:
        if "value" in answer:
            return False
        answer["value"] = value
        answer["reason"] = reason
        return True

    def _decide(value: Any, reason: str) -> None:
        _resolve(value, reason)
        root.quit()

    frame = _content_frame(root)
    _build_brand(frame)
    _build_line(frame, message, pady=(0, 10))
    _build_line(frame, _CODE_LABEL, font=_SMALL_FONT, fg=_MUTED, pady=(0, 2))
    entry = _make_code_entry(frame)
    # Block-red, not Approve's amber (item 7): an inline validation error is
    # a denial-adjacent signal, not an affordance to keep going.
    error_label = tk.Label(frame, fg=_SEV_CRITICAL, bg=_BG, font=_SMALL_FONT, anchor="w")
    error_label.pack(fill="x", pady=(0, 4))
    submit = _wire_code_submit(root, entry, error_label, lambda code: _decide(code, "approved"))
    _build_group_divider(frame)

    widgets: dict[str, Any] = {"entry": entry}

    def _lock_out() -> None:
        # Resolve WITHOUT quitting -- the window must stay open through the
        # "Denied" flash; _build_countdown's own root.after(1500, root.quit)
        # is what actually closes it.
        _resolve(None, "expired")
        _disable_on_expiry(root, widgets)

    _build_countdown(root, frame, timeout_s, on_expire=_lock_out)
    deny_btn, approve_btn = _build_buttons(
        frame,
        [
            ("Deny", lambda: _decide(None, "denied"), "Doberman.Deny.TButton"),
            ("Approve with code", submit, "Doberman.Approve.TButton"),
        ],
    )
    widgets["deny"], widgets["approve"] = deny_btn, approve_btn
    _wire_keyboard(root, deny_btn, approve_btn)
    _build_line(frame, _HINT, font=_DEADLINE_FONT, fg=_MUTED, pady=(4, 0))
    root.bind("<Escape>", lambda _e: _decide(None, "denied"))
    entry.focus_force()


def _populate_code_parts(root: Any, parts: dict, answer: dict, timeout_s: float) -> None:
    """Structured body — see :func:`_populate_confirm_parts`'s docstring.

    This is the SECOND of a two-step flow (confirm, then code) and must
    explain itself just as much as the first dialog does: a "Step 2 of 2"
    line, the same ``why``/risk/reassurance facts, not just the code prompt
    and the target repeated — a human landing on this dialog cold (it can
    outlive the first one, or a channel could be re-entered) should never
    have to guess why they're being asked. Layout mirrors
    :func:`_populate_confirm_parts` (item 6): the notice moves after the
    target panel; identity/why/risk/reassurance are grouped with a hairline
    above risk; why is promoted to body face.
    """
    import tkinter as tk

    def _resolve(value: Any, reason: str) -> bool:
        if "value" in answer:
            return False
        answer["value"] = value
        answer["reason"] = reason
        return True

    def _decide(value: Any, reason: str) -> None:
        _resolve(value, reason)
        root.quit()

    risk_word = _severity_from_risk_text(parts["risk"]) if parts.get("risk") else None

    frame = _content_frame(root)
    _build_brand(frame)
    _build_line(frame, _STEP_TWO, font=_SMALL_FONT, fg=_MUTED)
    _build_line(frame, _CODE_PROMPT)
    _build_target_panel(root, frame, parts["target"], toggle_label=_toggle_expand_label(parts))
    if parts.get("notice"):
        _build_line(frame, parts["notice"], font=_SMALL_FONT, fg=_MUTED)
    _build_line(frame, _QUESTION, font=_BODY_FONT, fg=_FG, pady=(2, 8))
    identity = _agent_identity_line(parts)
    if identity:
        _build_line(frame, identity, font=_SMALL_FONT, fg=_MUTED)
    if parts.get("why"):
        _build_line(frame, parts["why"], font=_BODY_FONT, fg=_FG)
    if parts.get("risk"):
        _build_group_divider(frame, pady=(2, 6))
        _build_risk_line(frame, parts["risk"], risk_word)
    _build_line(frame, _REASSURANCE, font=_SMALL_FONT, fg=_MUTED, pady=(2, 8))
    _build_line(frame, _CODE_LABEL, font=_SMALL_FONT, fg=_MUTED, pady=(0, 2))
    entry = _make_code_entry(frame)
    # Block-red, not Approve's amber (item 7): an inline validation error is
    # a denial-adjacent signal, not an affordance to keep going.
    error_label = tk.Label(frame, fg=_SEV_CRITICAL, bg=_BG, font=_SMALL_FONT, anchor="w")
    error_label.pack(fill="x", pady=(0, 4))
    submit = _wire_code_submit(root, entry, error_label, lambda code: _decide(code, "approved"))
    _build_help_affordance(frame, parts.get("why"))
    _build_group_divider(frame)

    widgets: dict[str, Any] = {"entry": entry}

    def _lock_out() -> None:
        # Resolve WITHOUT quitting -- the window must stay open through the
        # "Denied" flash; _build_countdown's own root.after(1500, root.quit)
        # is what actually closes it.
        _resolve(None, "expired")
        _disable_on_expiry(root, widgets)

    _build_countdown(
        root, frame, timeout_s, on_expire=_lock_out, action_id=parts.get("action_id", "unknown")
    )
    deny_btn, approve_btn = _build_buttons(
        frame,
        [
            ("Deny", lambda: _decide(None, "denied"), "Doberman.Deny.TButton"),
            ("Approve with code", submit, "Doberman.Approve.TButton"),
        ],
    )
    widgets["deny"], widgets["approve"] = deny_btn, approve_btn
    _wire_keyboard(root, deny_btn, approve_btn)
    _gate_approve_for_critical(root, approve_btn, risk_word)
    _build_line(frame, _HINT, font=_DEADLINE_FONT, fg=_MUTED, pady=(4, 0))
    root.bind("<Escape>", lambda _e: _decide(None, "denied"))
    entry.focus_force()


# --- running a dialog to completion --------------------------------------------------


def _flash_and_bell(root: Any) -> None:
    """Best-effort attention grab once the dialog is placed: a system bell
    plus (Windows) a taskbar flash — guarded throughout so a missing sound
    device or an unavailable Win32 call never blocks or fails the challenge.
    """
    try:
        root.bell()
    except Exception:  # noqa: S110 — cosmetic only
        pass
    if sys.platform != "win32":
        return
    try:  # pragma: no cover — needs a real native window handle
        import ctypes
        from ctypes import wintypes

        class _FlashInfo(ctypes.Structure):
            _fields_ = [
                ("cbSize", wintypes.UINT),
                ("hwnd", wintypes.HWND),
                ("dwFlags", wintypes.DWORD),
                ("uCount", wintypes.UINT),
                ("dwTimeout", wintypes.DWORD),
            ]

        FLASHW_TRAY = 0x00000002
        FLASHW_TIMERNOFG = 0x0000000C
        root.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(root.winfo_id())
        info = _FlashInfo(ctypes.sizeof(_FlashInfo), hwnd, FLASHW_TRAY | FLASHW_TIMERNOFG, 3, 0)
        ctypes.windll.user32.FlashWindowEx(ctypes.byref(info))
    except Exception:  # noqa: S110 — cosmetic only
        pass


#: What :meth:`GuiPrompter.notify_outcome` shows for each outcome name.
#: ASCII-only (cp1252-safe), like every other string in this module.
_OUTCOME_TEXT = {
    "approved": "Approved",
    "denied": "Denied",
    "code_rejected": "Code rejected - denied",
    "expired": "Denied - no answer in time",
}
#: How long the outcome notice stays up before closing itself.
_OUTCOME_DISPLAY_MS = 1200

#: A one-line, actionable next step for an outcome that has one (item 5) --
#: an outcome absent here (approved/denied/expired) gets none: there is
#: nothing more useful to say than the outcome word itself.
_OUTCOME_NEXT_STEP = {
    "code_rejected": "Ask your agent to retry to get a new code.",
}


def _outcome_style(outcome: str) -> str:
    """The notice's text/border colour (item 5): the same PASS-ish amber the
    rest of the system uses for a successful decision when ``outcome`` is
    "approved", else the same BLOCK-red the risk chip already uses for
    critical/high -- so a denial notice can never read as visually
    interchangeable with an approval.
    """
    return _APPROVE if outcome == "approved" else _SEV_CRITICAL


def _populate_outcome_notice(root: Any, text: str, outcome: str = "denied") -> None:
    """Brand mark + wordmark (so the notice is recognisably Doberman, not a
    bare unlabeled toast), the outcome text in its severity colour, and — for
    outcomes with one — a one-line next step in the muted note style.
    """
    import tkinter as tk

    color = _outcome_style(outcome)
    panel = tk.Frame(
        root, bg=_PANEL, highlightthickness=1, highlightbackground=color, highlightcolor=color
    )
    panel.pack()
    brand_row = tk.Frame(panel, bg=_PANEL)
    brand_row.pack(padx=20, pady=(14, 2))
    logo = _load_logo()
    brand_row._logo_ref = logo  # tkinter drops unreferenced images -- keep it alive
    if logo is not None:
        tk.Label(brand_row, image=logo, bg=_PANEL).pack(side="left")
        tk.Label(brand_row, text="DOBERMAN", fg=_BRAND, bg=_PANEL, font=_SUB_FONT).pack(
            side="left", padx=(6, 0)
        )
    else:
        tk.Label(brand_row, text="DOBERMAN", fg=_BRAND, bg=_PANEL, font=_SUB_FONT).pack(side="left")
    tk.Label(panel, text=text, fg=color, bg=_PANEL, font=_BODY_FONT, padx=20).pack()
    next_step = _OUTCOME_NEXT_STEP.get(outcome)
    if next_step:
        tk.Label(panel, text=next_step, fg=_MUTED, bg=_PANEL, font=_SMALL_FONT, padx=20).pack(
            pady=(0, 4)
        )
    tk.Frame(panel, bg=_PANEL, height=10).pack()  # symmetric bottom padding either way


def _show_outcome_window(text: str, outcome: str = "denied") -> None:
    """A small, topmost, non-focus-stealing notice: shows ``text`` for
    :data:`_OUTCOME_DISPLAY_MS` then closes itself — no answer required, and
    it must never block longer than that or raise into the caller (a
    post-decision notice is purely cosmetic, never a decision path).

    ``overrideredirect`` drops window-manager chrome (title bar, taskbar
    entry) — the same trick used for any transient "toast" notice — so it
    never grabs keyboard focus away from whatever the human was doing.
    Reuses :func:`_open_root` (and so the macOS main-thread guard, and the
    no-display case) rather than calling ``tkinter.Tk()`` directly.
    """
    try:
        root = _open_root()
    except PrompterUnavailableError:
        return
    try:
        root.title(_TITLE)
        root.configure(bg=_BG)
        root.resizable(False, False)
        root.attributes("-topmost", True)
        try:
            root.overrideredirect(True)  # no chrome; never requests window-manager focus
        except Exception:  # noqa: S110 — cosmetic only
            pass
        _populate_outcome_notice(root, text, outcome)
        root.update_idletasks()
        _center_on_screen(root)
        root.after(_OUTCOME_DISPLAY_MS, root.quit)
        root.mainloop()
    except Exception:  # noqa: S110 — cosmetic only, must never affect the decided outcome
        pass
    finally:
        root.destroy()


def _run_dialog(
    populate: Any, *, want_code: bool, timeout_s: float, action_id: str = "unknown"
) -> Any:
    """Open one themed dialog, run ``populate(root, answer, timeout_s)``, block
    until the human decides, and clean up.

    Closing the window (WM_DELETE_WINDOW) leaves the answer unset, which resolves
    to the deny default — there is no path where silence approves. The countdown
    :func:`_build_countdown` schedules inside ``populate`` exits by the same
    door: it only ends the loop (after its "Denied" flash), so the unset answer
    denies.

    Logs exactly one INFO line per dialog, after the human (or the clock, or
    the window close) has decided — the outcome (approved/denied/expired) and
    the action id ONLY, never the target or any other action content.
    """
    root = _open_root()
    try:
        _configure_window(root)
        answer: dict = {}
        populate(root, answer, timeout_s)
        root.protocol("WM_DELETE_WINDOW", root.quit)
        _center_on_screen(root)
        _flash_and_bell(root)
        root.mainloop()
        value = answer.get("value", None if want_code else False)
        reason = answer.get("reason", "denied")  # window closed without ever resolving -> denied
        logger.info("auth dialog outcome=%s action=%s", reason, action_id)
        return value
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

    return bool(
        _run_dialog(
            _populate,
            want_code=False,
            timeout_s=timeout_s,
            action_id=parts.get("action_id", "unknown"),
        )
    )


def _code_dialog_parts(parts: dict, *, timeout_s: float = DEFAULT_DIALOG_TIMEOUT_S) -> str | None:
    """Show the masked one-time-code dialog (structured). Cancel/close/silence -> ``None``."""

    def _populate(root: Any, answer: dict, t: float) -> None:
        _populate_code_parts(root, parts, answer, t)

    return _run_dialog(
        _populate,
        want_code=True,
        timeout_s=timeout_s,
        action_id=parts.get("action_id", "unknown"),
    )


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

    def notify_outcome(self, parts: dict, outcome: str) -> None:  # noqa: ARG002 — parts unused here
        """Post-decision notice (item 4): a small topmost window shows
        approved/denied/code_rejected/expired for ~1.2s then closes — a
        wrong-but-well-formed code (or any other non-approval) no longer just
        silently closes the window. Never raises; purely cosmetic.
        """
        text = _OUTCOME_TEXT.get(outcome, outcome.replace("_", " ").strip().capitalize() or outcome)
        try:
            _show_outcome_window(text, outcome)
        except Exception:  # noqa: S110 — cosmetic only, must never affect the decided outcome
            pass

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
        #: Whichever prompter last actually answered (not merely unavailable) —
        #: used only so :meth:`notify_outcome` can forward to the SAME channel
        #: the human actually saw, never a channel that never opened.
        self._last_answering: Prompter | None = None

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

    def notify_outcome(self, parts: dict, outcome: str) -> None:
        """Forward to whichever chained prompter actually answered, if it
        implements ``notify_outcome`` — never raises, never picks a channel
        that never opened.
        """
        notify = getattr(self._last_answering, "notify_outcome", None)
        if notify is None:
            return
        try:
            notify(parts, outcome)
        except Exception:  # noqa: S110 — cosmetic only, must never affect the decided outcome
            pass

    def _first_open_channel(self, method: str, message: str) -> Any:
        last: PrompterUnavailableError | None = None
        for prompter in self._prompters:
            try:
                result = getattr(prompter, method)(message)
            except PrompterUnavailableError as exc:
                last = exc
                continue
            self._last_answering = prompter
            return result
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
            _message_from_parts(parts)
            if method == "confirm"
            # Names the exact target (item 8) -- a channel with no structured
            # code dialog of its own (TTY, dashboard) must not lose the
            # action binding the confirm step already established.
            else f"Enter your 2FA code to approve: {parts['target']}"
        )
        last: PrompterUnavailableError | None = None
        for prompter in self._prompters:
            try:
                structured = getattr(prompter, f"{method}_challenge", None)
                if structured is not None:
                    result = structured(parts)
                else:
                    result = getattr(prompter, method)(fallback_message)
            except PrompterUnavailableError as exc:
                last = exc
                continue
            self._last_answering = prompter
            return result
        raise PrompterUnavailableError("no auth prompter channel is available") from last
