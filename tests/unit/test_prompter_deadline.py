"""Deadline copy shared by the built-in human challenge channels."""

import io

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
