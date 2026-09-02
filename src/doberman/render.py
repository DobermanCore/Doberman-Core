"""Presentation-layer helpers for CLI output (color + wrapping only).

Purely cosmetic: no decision logic lives here, and this module must never
import ``doberman.engine``/``doberman.policy``/``doberman.proxy`` internals —
it depends only on the stdlib, Typer/Click, and ``doberman.models`` (for the
``Verdict`` enum). ``typer.style``/``typer.secho`` already handle Windows
color and auto-strip ANSI when stdout isn't a TTY; the one gap this module
closes explicitly is ``NO_COLOR`` (https://no-color.org), which Click does
not honor on every version.
"""

from __future__ import annotations

import os
import shutil
import sys
import textwrap

import typer

from doberman.models import Verdict

try:  # click has exposed this in click.utils for a long time; guard anyway.
    from click.utils import should_strip_ansi as _should_strip_ansi
except ImportError:  # pragma: no cover - defensive only
    _should_strip_ansi = None

#: Fixed display width for a verdict label so colored and plain output stay
#: column-aligned (the padding is applied *inside* the styled string).
_LABEL_WIDTH = max(len(v.value) for v in Verdict)

_VERDICT_STYLES: dict[Verdict, dict[str, object]] = {
    Verdict.BLOCK: {"fg": "bright_red", "bold": True},
    Verdict.AUTH: {"fg": "yellow", "bold": True},
    Verdict.PASS: {"fg": "green"},
}

#: The same palette as a Rich style string (e.g. for `rich.text.Text(style=...)`),
#: derived from `_VERDICT_STYLES` so a Rich-based renderer (the `tui` decision
#: browser) can never drift from `doberman log`'s colors — one source of truth.
_RICH_VERDICT_STYLES: dict[Verdict, str] = {
    verdict: " ".join((["bold"] if style.get("bold") else []) + [str(style["fg"])])
    for verdict, style in _VERDICT_STYLES.items()
}

#: Inverse "chip" styles for BLOCK/AUTH (measured contrast finding: Textual's
#: default theme renders `bright_red` foreground-on-row at 3.57:1 - and 2.90:1
#: on the cursor row - both below the 4.5:1 floor). Solid-colored background
#: with pure-black (#000000, NOT the named "black", which this theme renders
#: as #1a1a1a - only ~4.15:1 on bright_red, still short of the floor) text
#: clears 4.5:1 in both states and keeps the color on the cursor row (see
#: `cursor_background_priority="renderable"` in tui.py). PASS is not a
#: warning, so it keeps its plain colored-text style, no chip.
_CHIP_VERDICT_STYLES: dict[Verdict, str] = {
    Verdict.BLOCK: "bold #000000 on bright_red",
    Verdict.AUTH: "bold #000000 on yellow",
    Verdict.PASS: _RICH_VERDICT_STYLES[Verdict.PASS],
}

#: Rich style per risk level for a redacted row's `risk` column - color is a
#: second signal alongside the plain-word label, never a replacement for it.
#: Every level above low is a chip (round 4 design critique items 5 and 10):
#: critical/high must not share a color (`red` read too close to `bright_red`
#: to form a gradient), and plain `yellow`-on-cursor-row measured only 4.06:1
#: (below the 4.5:1 floor) - `high` moves to `dark_orange` (#ff8700, 8.72:1
#: black-on-fill) and `medium` becomes a chip too (yellow fill, 5.01:1
#: black-on-fill - Rich's named "yellow" is the darker ANSI tone, not a bright
#: one, which is exactly why the plain-foreground style fell short).
_RISK_STYLES: dict[str, str] = {
    "critical": "bold #000000 on bright_red",
    "high": "bold #000000 on dark_orange",
    "medium": "bold #000000 on yellow",
    "low": "",
}

#: Plain-English labels for a decision row's raw `auth_result` value, shared by
#: `doberman log` and the `tui` browser's auth column so the two views can
#: never drift. Deliberately small: an unrecognized/future value (a raw
#: auth-tier/method name like "totp", or a corrupt row) falls back to a
#: humanized form of the value itself rather than needing to be listed here.
_AUTH_RESULT_LABELS: dict[str, str] = {
    "executed": "ran",
    "blocked": "blocked",
    "denied": "denied",
    "soft_confirm+memory": "approved via 5-minute memory (soft_confirm)",
}

#: Short forms for the labels above, used only when `short=True` (the `tui`
#: browser's 7-wide auth column, where the full label would never fit).
#: Anything not listed here is already short enough - `short=True` falls back
#: to the same full label `doberman log` and the why panel/full-screen why use.
_AUTH_RESULT_SHORT_LABELS: dict[str, str] = {
    "soft_confirm+memory": "mem ok",
}

_MIN_WRAP_WIDTH = 60
_MAX_WRAP_WIDTH = 120

#: "Next" lines: one accurate, actionable line per verdict - what a human can
#: actually do about this decision, using only real `doberman` commands/files
#: (verified against docs/CLI.md; never invented). Shared by the `tui`
#: browser's docked next-line widget and `doberman log --why` so the two
#: surfaces can never drift apart. PASS gets none - there is nothing to act
#: on. The remedy itself comes first (round 4 design critique item 1: a
#: bounded-height widget must never clip mid-remedy) - "press w for detail"
#: (the tui's own full-screen why) trails last, so it's the part safe to lose
#: if a narrower/shorter render ever clips the tail.
_NEXT_BLOCK = (
    "Next: only a policy or role change allows this - 'doberman mode' / "
    "'doberman review --yes' / .doberman/policies.yaml; press w for detail"
)
_NEXT_AUTH = (
    "Next: re-running the action asks again, or approve/deny it in "
    "'doberman dash'; press w for detail"
)


def next_step_line(verdict: str | None) -> str | None:
    """The "Next" remedy line for a raw verdict string (or `None`/anything
    unrecognized, e.g. PASS) - `None` when there's nothing to act on."""
    if verdict == Verdict.BLOCK.value:
        return _NEXT_BLOCK
    if verdict == Verdict.AUTH.value:
        return _NEXT_AUTH
    return None


def deadline_note(seconds: float) -> str:
    """'auto-denies in 2m if unanswered' - human-scale, ASCII-only."""
    mins = int(seconds // 60)
    span = f"{mins}m" if mins else f"{int(seconds)}s"
    return f"auto-denies in {span} if unanswered"


def supports_color() -> bool:
    """False if ``NO_COLOR`` is set to a non-empty value; else Click/Typer's own TTY check.

    Per https://no-color.org the variable must be *present and non-empty* to be a
    signal, so an exported-but-empty ``NO_COLOR=`` is deliberately not honored.
    """
    if os.environ.get("NO_COLOR"):
        return False
    if _should_strip_ansi is not None:
        return not _should_strip_ansi(sys.stdout)
    return sys.stdout.isatty()  # pragma: no cover - only if click lacks the helper


def style_text(text: str, fg: str, *, bold: bool = False) -> str:
    """Color ``text`` with ``fg`` (+ ``bold``) when the terminal supports it, else plain.

    Generic sibling of :func:`verdict_label` for one-off status lines (e.g. the
    setup wizard's mode/doctor lines) that aren't a :class:`Verdict`.
    """
    if not supports_color():
        return text
    return typer.style(text, fg=fg, bold=bold)


def verdict_label(verdict: Verdict) -> str:
    """A fixed-width label for ``verdict`` — colored when the terminal supports it.

    Padding is identical whether or not color is applied, so table/column
    alignment never shifts between a TTY and a redirected/NO_COLOR run.
    """
    padded = f"{verdict.value:<{_LABEL_WIDTH}}"
    if not supports_color():
        return padded
    return typer.style(padded, **_VERDICT_STYLES.get(verdict, {}))


def verdict_label_str(value: str) -> str:
    """Like :func:`verdict_label`, but for a verdict already read back as a plain string
    (e.g. a DB row's ``final_verdict``).

    An unrecognized value (corrupt row, future verdict) never raises — it is padded to
    the same fixed width and returned uncolored, so a log/status viewer can't crash on it.
    """
    try:
        return verdict_label(Verdict(value))
    except ValueError:
        return f"{value:<{_LABEL_WIDTH}}"


def verdict_rich_style(verdict: Verdict, *, chip: bool = False) -> str:
    """Rich style string for `verdict` (e.g. `rich.text.Text(..., style=...)`).

    Same palette `verdict_label` uses, just expressed for Rich instead of
    Typer/Click — the one thing any Rich-based renderer (the `tui` decision
    browser) should call rather than keeping a second copy of the colors.
    An unrecognized value returns "" (no style) rather than raising, matching
    :func:`verdict_label_str`'s fail-safe behavior on a corrupt/future value.

    ``chip=True`` returns the inverse "chip" variant (bold black text on a
    solid colored background) for BLOCK/AUTH — measured to clear a 4.5:1
    contrast floor where the plain foreground-only style does not, including
    on the cursor row. PASS is unaffected by ``chip`` (it isn't a warning).
    """
    styles = _CHIP_VERDICT_STYLES if chip else _RICH_VERDICT_STYLES
    return styles.get(verdict, "")


def risk_rich_style(risk: str) -> str:
    """Rich style string for a redacted row's `risk` value.

    Beside :func:`verdict_rich_style` — same fail-safe shape: an unrecognized
    value (corrupt row, future risk level) returns "" rather than raising, and
    the plain-word label is always kept alongside the color, never replaced
    by it (risk severity must be visible with or without color).
    """
    return _RISK_STYLES.get(risk, "")


def humanize_auth_result(auth_result: str | None, *, short: bool = False) -> str:
    """Plain-English label for a decision row's raw `auth_result` value.

    Shared by `doberman log` and the `tui` browser's auth column so the two
    views can never drift apart. ``None``/empty (still-pending AUTH) renders
    as "-". An unrecognized/future value (a raw auth-tier/method name, or a
    corrupt row) falls back to the value itself with underscores turned to
    spaces — never raises, never invents a meaning it wasn't told.

    ``short=True`` returns the narrower :data:`_AUTH_RESULT_SHORT_LABELS` form
    where one exists (e.g. "mem ok" for "soft_confirm+memory") — for the
    `tui` browser's 7-wide auth column, which can't fit the full label. Every
    other caller (`doberman log`, the why panel/full-screen why) always gets
    the full label.
    """
    if not auth_result:
        return "-"
    if short:
        short_label = _AUTH_RESULT_SHORT_LABELS.get(auth_result)
        if short_label is not None:
            return short_label
    return _AUTH_RESULT_LABELS.get(auth_result, auth_result.replace("_", " "))


def wrap_detail(text: str, indent: int = 4, width: int | None = None) -> list[str]:
    """Wrap ``text`` to a sane terminal width, indented ``indent`` spaces.

    ``width`` defaults to the real terminal width (``shutil.get_terminal_size``),
    clamped to ``[60, 120]`` columns either way — this is what keeps a long
    explanation from ever repeating the old 242-char unwrapped line.
    """
    if width is None:
        width, _ = shutil.get_terminal_size(fallback=(100, 24))
    width = max(_MIN_WRAP_WIDTH, min(_MAX_WRAP_WIDTH, width))
    prefix = " " * indent
    wrap_width = max(1, width - indent)
    return [prefix + line for line in (textwrap.wrap(text, width=wrap_width) or [""])]
