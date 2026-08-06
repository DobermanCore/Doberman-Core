"""Deadline copy shared by the built-in human challenge channels."""

import io
import sys
from types import SimpleNamespace

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


def test_gui_dialog_states_the_deadline(monkeypatch):
    labels: list[str] = []

    class _Widget:
        def __init__(self, _parent, **kwargs) -> None:
            if "text" in kwargs:
                labels.append(kwargs["text"])

        def pack(self, **_kwargs):
            return None

    fake_tk = SimpleNamespace(Frame=_Widget, Label=_Widget)
    monkeypatch.setitem(sys.modules, "tkinter", fake_tk)

    gui_prompter._build_header_and_message(object(), "Approve THIS exact action?")

    assert "auto-denies in 2m if unanswered" in labels
