"""Unit tests for the GUI auth prompter and the GUI→TTY fallback chain.

When an MCP agent (Claude Code, Codex, Cursor, …) spawns ``doberman serve``, the
*controlling terminal still exists* but is owned by the agent's TUI: a prompt written
to it is painted over (invisible) and keystrokes go to the agent, not Doberman. The
challenge must therefore surface OUT-OF-BAND as a GUI dialog, with the terminal only
as a fallback when no display is available.

Contracts under test:
* ``GuiPrompter`` collects a confirm/code via a topmost dialog window; cancel/blank
  raise so the provider denies (fail closed); never touches sys.stdin/sys.stdout.
* A GUI channel that cannot open at all raises ``PrompterUnavailableError`` — a
  *channel* failure, distinct from a human denial.
* ``FallbackPrompter`` consults the next channel ONLY on ``PrompterUnavailableError``.
  A human answer (including "no") and any human-channel error (EOF, timeout) are
  FINAL — a denial must never trigger answer-shopping on another channel.

The tkinter machinery is monkeypatched at module seams (mirroring how the TTY tests
fake ``_open_tty``) so everything here runs headless and deterministically.
"""

import pytest

from doberman.auth import gui_prompter
from doberman.auth.gui_prompter import (
    FallbackPrompter,
    GuiPrompter,
    PrompterUnavailableError,
)

# --- GuiPrompter: answers ----------------------------------------------------------


@pytest.mark.parametrize("answer", [True, False])
def test_confirm_returns_the_dialog_answer(monkeypatch, answer):
    monkeypatch.setattr(gui_prompter, "_confirm_dialog", lambda _msg: answer)
    assert GuiPrompter().confirm("Approve THIS exact action?") is answer


def test_confirm_passes_the_exact_challenge_message(monkeypatch):
    seen: list[str] = []

    def _dialog(message: str) -> bool:
        seen.append(message)
        return True

    monkeypatch.setattr(gui_prompter, "_confirm_dialog", _dialog)
    GuiPrompter().confirm("Approve THIS exact action?")
    assert seen == ["Approve THIS exact action?"]


def test_read_code_returns_stripped_code(monkeypatch):
    monkeypatch.setattr(gui_prompter, "_code_dialog", lambda _msg: "  123456 \n")
    assert GuiPrompter().read_code("Enter your 2FA code") == "123456"


def test_read_code_raises_on_cancel_so_provider_denies(monkeypatch):
    # Cancelling / closing the dialog returns None — never pass "" to the verifier.
    monkeypatch.setattr(gui_prompter, "_code_dialog", lambda _msg: None)
    with pytest.raises(EOFError):
        GuiPrompter().read_code("Enter your 2FA code")


def test_read_code_raises_on_blank_entry(monkeypatch):
    monkeypatch.setattr(gui_prompter, "_code_dialog", lambda _msg: "   ")
    with pytest.raises(EOFError):
        GuiPrompter().read_code("Enter your 2FA code")


def test_never_touches_std_streams(monkeypatch):
    """A GUI challenge must not read stdin or write stdout (the agent's MCP channel)."""

    class _Explode:
        def __getattr__(self, _name):
            raise AssertionError("prompter touched a std stream")

    monkeypatch.setattr("sys.stdin", _Explode())
    monkeypatch.setattr("sys.stdout", _Explode())
    monkeypatch.setattr(gui_prompter, "_confirm_dialog", lambda _msg: True)
    assert GuiPrompter().confirm("Approve?") is True


# --- GuiPrompter: unavailable channel ----------------------------------------------


def test_no_gui_raises_prompter_unavailable(monkeypatch):
    def _no_root():
        raise PrompterUnavailableError("no display")

    monkeypatch.setattr(gui_prompter, "_open_root", _no_root)
    with pytest.raises(PrompterUnavailableError):
        GuiPrompter().confirm("Approve?")
    with pytest.raises(PrompterUnavailableError):
        GuiPrompter().read_code("Enter your 2FA code")


def test_open_root_raises_prompter_unavailable_when_tk_init_fails(monkeypatch):
    tkinter = pytest.importorskip("tkinter")

    def _boom(*_a, **_k):
        raise tkinter.TclError("no display name and no $DISPLAY")

    monkeypatch.setattr(tkinter, "Tk", _boom)
    with pytest.raises(PrompterUnavailableError):
        gui_prompter._open_root()


# --- GuiPrompter: real dialog internals (faked root + faked tkinter dialogs) -------


class _FakeRoot:
    def __init__(self):
        self.destroyed = False
        self.withdrawn = False
        self.attrs: dict = {}

    def withdraw(self):
        self.withdrawn = True

    def attributes(self, name, value):
        self.attrs[name] = value

    def update(self):
        pass

    def destroy(self):
        self.destroyed = True


def test_confirm_dialog_uses_hidden_topmost_root_and_destroys_it(monkeypatch):
    pytest.importorskip("tkinter")
    from tkinter import messagebox

    root = _FakeRoot()
    seen: dict = {}
    monkeypatch.setattr(gui_prompter, "_open_root", lambda: root)

    def _fake_askyesno(title, message, parent=None):
        seen["title"], seen["message"], seen["parent"] = title, message, parent
        return True

    monkeypatch.setattr(messagebox, "askyesno", _fake_askyesno)
    assert gui_prompter._confirm_dialog("Approve THIS exact action?") is True
    assert seen["message"] == "Approve THIS exact action?"
    assert seen["parent"] is root
    assert root.withdrawn is True
    assert root.attrs.get("-topmost") is True
    assert root.destroyed is True  # never leak a Tk root


def test_code_dialog_masks_input_and_destroys_root(monkeypatch):
    pytest.importorskip("tkinter")
    from tkinter import simpledialog

    root = _FakeRoot()
    seen: dict = {}
    monkeypatch.setattr(gui_prompter, "_open_root", lambda: root)

    def _fake_askstring(title, message, *, show=None, parent=None):
        seen["show"], seen["parent"] = show, parent
        return "123456"

    monkeypatch.setattr(simpledialog, "askstring", _fake_askstring)
    assert gui_prompter._code_dialog("Enter your 2FA code") == "123456"
    assert seen["show"] == "*"  # the code must be masked on screen
    assert root.destroyed is True


def test_dialog_root_destroyed_even_when_dialog_raises(monkeypatch):
    pytest.importorskip("tkinter")
    from tkinter import messagebox

    root = _FakeRoot()
    monkeypatch.setattr(gui_prompter, "_open_root", lambda: root)

    def _boom(*_a, **_k):
        raise RuntimeError("dialog exploded")

    monkeypatch.setattr(messagebox, "askyesno", _boom)
    with pytest.raises(RuntimeError, match="dialog exploded"):
        gui_prompter._confirm_dialog("Approve?")
    assert root.destroyed is True


# --- FallbackPrompter ---------------------------------------------------------------


class _Recorder:
    """A scripted prompter that records which methods were consulted."""

    def __init__(self, *, confirm=None, code=None, raises=None):
        self._confirm = confirm
        self._code = code
        self._raises = raises
        self.calls: list[str] = []

    def confirm(self, message: str) -> bool:
        self.calls.append("confirm")
        if self._raises is not None:
            raise self._raises
        return self._confirm

    def read_code(self, message: str) -> str:
        self.calls.append("read_code")
        if self._raises is not None:
            raise self._raises
        return self._code


def test_first_available_answer_wins():
    first = _Recorder(confirm=True)
    second = _Recorder(confirm=False)
    assert FallbackPrompter([first, second]).confirm("Approve?") is True
    assert second.calls == []


def test_a_denial_is_final_never_answer_shopping():
    """A human "no" on the first channel must NOT be retried on the next channel."""
    first = _Recorder(confirm=False)
    second = _Recorder(confirm=True)  # would approve — must never be consulted
    assert FallbackPrompter([first, second]).confirm("Approve?") is False
    assert second.calls == []


def test_unavailable_channel_falls_through_to_the_next():
    first = _Recorder(raises=PrompterUnavailableError("no display"))
    second = _Recorder(confirm=True)
    assert FallbackPrompter([first, second]).confirm("Approve?") is True
    assert first.calls == ["confirm"]
    assert second.calls == ["confirm"]


def test_human_channel_error_propagates_without_fallthrough():
    """EOF/timeout on an OPEN channel is a denial signal, not a reason to re-ask."""
    first = _Recorder(raises=EOFError("walked away"))
    second = _Recorder(confirm=True)
    with pytest.raises(EOFError):
        FallbackPrompter([first, second]).confirm("Approve?")
    assert second.calls == []


def test_all_channels_unavailable_raises_so_provider_denies():
    first = _Recorder(raises=PrompterUnavailableError("no display"))
    second = _Recorder(raises=PrompterUnavailableError("no terminal"))
    with pytest.raises(PrompterUnavailableError):
        FallbackPrompter([first, second]).confirm("Approve?")


def test_read_code_follows_the_same_fallback_rules():
    first = _Recorder(raises=PrompterUnavailableError("no display"))
    second = _Recorder(code="123456")
    assert FallbackPrompter([first, second]).read_code("Enter your 2FA code") == "123456"
    assert second.calls == ["read_code"]


def test_chain_is_introspectable_for_wiring_assertions():
    first, second = _Recorder(confirm=True), _Recorder(confirm=True)
    chain = FallbackPrompter([first, second])
    assert list(chain.prompters) == [first, second]


# --- fail-closed through the provider ----------------------------------------------


def test_provider_denies_when_every_channel_is_unavailable():
    """End to end: no GUI + no terminal ⇒ the AUTH challenge is DENIED, never approved."""
    from datetime import datetime, timezone

    from doberman.auth.challenge import AuthTier
    from doberman.auth.provider import LocalAuthProvider
    from doberman.models import (
        ActionType,
        Decision,
        GuardrailResult,
        ReasonCode,
        Risk,
        SecurityObject,
        Verdict,
    )

    now = datetime(2026, 6, 10, tzinfo=timezone.utc)
    action = SecurityObject(
        id="act-gui-1",
        ts=now,
        agent_role="webdev",
        action_type=ActionType.file_write,
        tool_name="fs_write",
        target="backend/api.ts",
    )
    objective = GuardrailResult(
        verdict=Verdict.AUTH,
        risk=Risk.medium,
        reason_codes=[ReasonCode.sensitive_path_access],
        explanation="why",
    )
    decision = Decision(
        action_id="act-gui-1",
        final_verdict=Verdict.AUTH,
        final_risk=Risk.medium,
        objective=objective,
        reason_codes=[ReasonCode.sensitive_path_access],
        explanation="why",
        decided_at=now,
    )
    chain = FallbackPrompter(
        [
            _Recorder(raises=PrompterUnavailableError("no display")),
            _Recorder(raises=PrompterUnavailableError("no terminal")),
        ]
    )
    result = LocalAuthProvider().authenticate(
        decision, action, AuthTier.local_auth, prompter=chain, at=now
    )
    assert result.approved is False
