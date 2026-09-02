"""Deadline copy shared by the built-in human challenge channels."""

import io

import pytest

from doberman import render
from doberman.auth import gui_prompter, tty_prompter
from doberman.auth.tty_prompter import TtyPrompter


class _FakeWrite:
    def __init__(self) -> None:
        self.text = ""

    def write(self, value: str) -> int:
        self.text += value
        return len(value)

    def flush(self) -> None:
        pass

    def close(self) -> None:
        pass


def test_deadline_note_uses_human_scale_ascii_copy():
    assert render.deadline_note(120.0) == "auto-denies in 2m if unanswered"
    assert render.deadline_note(30.0) == "auto-denies in 30s if unanswered"


def test_tty_prompt_states_the_deadline(monkeypatch):
    output = _FakeWrite()
    monkeypatch.setattr(tty_prompter, "_open_tty", lambda: (io.StringIO("n\n"), output))

    TtyPrompter().confirm("Approve THIS exact action?")

    assert "[auto-denies in 20m if unanswered]" in output.text


def test_gui_dialog_states_the_deadline():
    """The GUI dialog's countdown label reuses the CLI's wording pattern
    ("auto-denies in ... if unanswered") at minute:second resolution — a live
    tick, not the CLI's static, coarser-grained note (see ``_build_countdown``
    in test_gui_prompter.py for the ticking/expiry behavior itself).
    """
    assert render.deadline_note(gui_prompter.DEFAULT_DIALOG_TIMEOUT_S) == (
        "auto-denies in 2m if unanswered"
    )
    assert gui_prompter._mmss(gui_prompter.DEFAULT_DIALOG_TIMEOUT_S) == "2:00"


def test_deadline_note_mmss_shares_the_same_template_as_deadline_note():
    """Item 9: one shared template (:func:`render._deadline_phrase`) backs
    both the CLI's coarse note and the GUI's live minute:second tick, so
    neither can silently drift into a different phrasing for the same fact.
    """
    assert render.deadline_note_mmss(125.0) == "auto-denies in 2:05 if unanswered"
    assert render.deadline_note_mmss(59.0) == "auto-denies in 0:59 if unanswered"
    assert render.deadline_note_mmss(-5.0) == "auto-denies in 0:00 if unanswered"


def test_gui_countdown_label_is_built_from_the_shared_render_helper():
    """Not just textually coincidental (both authors typed the same words) --
    the GUI's countdown literally calls :func:`render.deadline_note_mmss`,
    so it can never drift from the CLI's wording."""
    tkinter = pytest.importorskip("tkinter")
    try:
        root = tkinter.Tk()
    except tkinter.TclError:
        pytest.skip("no display available")
    try:
        root.after = lambda _delay_ms, _callback: None  # never actually tick
        label = gui_prompter._build_countdown(root, root, 125.0, on_expire=lambda: None)
        assert (
            label.cget("text")
            == render.deadline_note_mmss(125.0)
            == ("auto-denies in 2:05 if unanswered")
        )
    finally:
        root.destroy()
