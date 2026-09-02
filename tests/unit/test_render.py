"""Presentation-layer tests for ``doberman.render`` -- color + wrapping only.

No engine/decision logic under test here: these tests cover the color gate
(``NO_COLOR`` / Click's own TTY detection), the fixed-width verdict label,
and terminal-width-aware wrapping -- the piece that replaces the old
unwrapped (sometimes 242-char) CLI lines.
"""

import re

import click

import doberman.render as render
from doberman.models import Verdict

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


class _FakeStream:
    """A minimal stdout stand-in so TTY detection is deterministic in tests."""

    def __init__(self, is_tty: bool) -> None:
        self._is_tty = is_tty

    def isatty(self) -> bool:
        return self._is_tty


def test_no_color_env_disables_color_when_non_empty(monkeypatch):
    monkeypatch.setattr(render.sys, "stdout", _FakeStream(True))
    monkeypatch.setenv("NO_COLOR", "1")
    assert render.supports_color() is False

    monkeypatch.setenv("NO_COLOR", "0")  # any non-empty value is a signal, whatever it says
    assert render.supports_color() is False

    # https://no-color.org: present *and non-empty*. An exported-but-empty var is not a signal.
    monkeypatch.setenv("NO_COLOR", "")
    assert render.supports_color() is True


def test_supports_color_defers_to_tty_detection_when_no_color_unset(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setattr(render.sys, "stdout", _FakeStream(True))
    assert render.supports_color() is True

    monkeypatch.setattr(render.sys, "stdout", _FakeStream(False))
    assert render.supports_color() is False


def test_no_color_produces_zero_ansi_escapes(monkeypatch):
    monkeypatch.setattr(render.sys, "stdout", _FakeStream(True))
    monkeypatch.setenv("NO_COLOR", "1")
    for verdict in Verdict:
        label = render.verdict_label(verdict)
        assert _ANSI_RE.search(label) is None


def test_colored_and_uncolored_labels_share_visible_width(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    for verdict in Verdict:
        monkeypatch.setattr(render, "supports_color", lambda: True)
        colored = render.verdict_label(verdict)
        monkeypatch.setattr(render, "supports_color", lambda: False)
        plain = render.verdict_label(verdict)

        assert click.unstyle(colored) == plain
        assert len(click.unstyle(colored)) == len(plain) == render._LABEL_WIDTH


def test_wrap_detail_never_exceeds_an_explicit_clamped_width():
    text = "word " * 60  # well over any clamp bound
    below_min = render.wrap_detail(text, indent=4, width=10)
    assert all(len(line) <= 60 for line in below_min)

    above_max = render.wrap_detail(text, indent=4, width=500)
    assert all(len(line) <= 120 for line in above_max)


def test_wrap_detail_clamps_the_real_terminal_size_too(monkeypatch):
    monkeypatch.setattr(render.shutil, "get_terminal_size", lambda fallback=(100, 24): (20, 24))
    lines = render.wrap_detail("some explanation text that needs wrapping", indent=4)
    assert all(len(line) <= 60 for line in lines)

    monkeypatch.setattr(render.shutil, "get_terminal_size", lambda fallback=(100, 24): (300, 24))
    lines = render.wrap_detail("word " * 40, indent=4)
    assert all(len(line) <= 120 for line in lines)


def test_verdict_rich_style_is_bold_bright_red_for_block():
    # BLOCK must be the most legible element (design critique P1): bold +
    # bright_red, not the dim `bold red` a second copy of this palette once had.
    assert render.verdict_rich_style(Verdict.BLOCK) == "bold bright_red"


def test_verdict_rich_style_matches_the_cli_palette_for_every_verdict():
    # One source of truth: the Rich style string and the Typer/Click kwargs in
    # `_VERDICT_STYLES` must describe the same color for every verdict, so a
    # Rich-based renderer (the `tui` decision browser) can never drift from
    # `doberman log`.
    for verdict in Verdict:
        style = render.verdict_rich_style(verdict)
        kwargs = render._VERDICT_STYLES[verdict]
        assert str(kwargs["fg"]) in style
        assert kwargs.get("bold", False) is ("bold" in style)


def test_verdict_rich_style_on_an_unrecognized_value_is_empty_not_a_raise():
    assert render.verdict_rich_style("not-a-verdict") == ""  # type: ignore[arg-type]


def test_a_242_char_line_wraps_into_multiple_lines():
    phrase = "Shell, package, or git egress requires authentication because "
    text = (phrase * 4)[:242]
    assert len(text) == 242

    lines = render.wrap_detail(text, indent=4, width=100)
    assert len(lines) > 1
    assert all(len(line) <= 100 for line in lines)
