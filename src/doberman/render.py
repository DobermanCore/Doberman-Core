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

_MIN_WRAP_WIDTH = 60
_MAX_WRAP_WIDTH = 120


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
