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

import threading
import types

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
    monkeypatch.setattr(gui_prompter, "_confirm_dialog", lambda _msg, **_kw: answer)
    assert GuiPrompter().confirm("Approve THIS exact action?") is answer


def test_confirm_passes_the_exact_challenge_message(monkeypatch):
    seen: list[str] = []

    def _dialog(message: str, **_kw) -> bool:
        seen.append(message)
        return True

    monkeypatch.setattr(gui_prompter, "_confirm_dialog", _dialog)
    GuiPrompter().confirm("Approve THIS exact action?")
    assert seen == ["Approve THIS exact action?"]


def test_read_code_returns_stripped_code(monkeypatch):
    monkeypatch.setattr(gui_prompter, "_code_dialog", lambda _msg, **_kw: "  123456 \n")
    assert GuiPrompter().read_code("Enter your 2FA code") == "123456"


def test_read_code_raises_on_cancel_so_provider_denies(monkeypatch):
    # Cancelling / closing the dialog returns None — never pass "" to the verifier.
    monkeypatch.setattr(gui_prompter, "_code_dialog", lambda _msg, **_kw: None)
    with pytest.raises(EOFError):
        GuiPrompter().read_code("Enter your 2FA code")


def test_read_code_raises_on_blank_entry(monkeypatch):
    monkeypatch.setattr(gui_prompter, "_code_dialog", lambda _msg, **_kw: "   ")
    with pytest.raises(EOFError):
        GuiPrompter().read_code("Enter your 2FA code")


def test_never_touches_std_streams(monkeypatch):
    """A GUI challenge must not read stdin or write stdout (the agent's MCP channel)."""

    class _Explode:
        def __getattr__(self, _name):
            raise AssertionError("prompter touched a std stream")

    monkeypatch.setattr("sys.stdin", _Explode())
    monkeypatch.setattr("sys.stdout", _Explode())
    monkeypatch.setattr(gui_prompter, "_confirm_dialog", lambda _msg, **_kw: True)
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


# --- GuiPrompter: macOS thread-affinity guard (#399) -------------------------------
#
# Every real caller reaches GuiPrompter on a background daemon thread by
# construction (doberman.auth.challenge._run_with_deadline / asyncio.to_thread),
# never the process's main thread. Cocoa's Tk backend requires its event loop to
# start on the real OS main thread; opening Tk() off it is a documented hazard
# that does not reliably raise a catchable error the way a missing $DISPLAY does
# -- it can silently fail to render or abort the process, which is how an AUTH
# challenge could resolve as approved without a human ever seeing a dialog. The
# guard must refuse BEFORE tkinter is ever touched.


def test_macos_off_main_thread_refuses_before_touching_tkinter(monkeypatch):
    tkinter = pytest.importorskip("tkinter")
    monkeypatch.setattr(gui_prompter.sys, "platform", "darwin")
    monkeypatch.setattr(gui_prompter.threading, "current_thread", lambda: object())
    monkeypatch.setattr(gui_prompter.threading, "main_thread", lambda: object())

    def _boom(*_a, **_k):
        raise AssertionError("tkinter.Tk() must never be called off the main thread on macOS")

    monkeypatch.setattr(tkinter, "Tk", _boom)
    with pytest.raises(PrompterUnavailableError):
        gui_prompter._open_root()


def test_macos_on_main_thread_is_unaffected(monkeypatch):
    """The guard checks thread AFFINITY, not platform alone -- on the real main
    thread, macOS proceeds to the normal Tk-open attempt exactly as before."""
    tkinter = pytest.importorskip("tkinter")
    monkeypatch.setattr(gui_prompter.sys, "platform", "darwin")
    same = object()
    monkeypatch.setattr(gui_prompter.threading, "current_thread", lambda: same)
    monkeypatch.setattr(gui_prompter.threading, "main_thread", lambda: same)

    attempted = []
    monkeypatch.setattr(tkinter, "Tk", lambda: attempted.append(True) or object())
    gui_prompter._open_root()
    assert attempted == [True]


@pytest.mark.parametrize("platform", ["win32", "linux"])
def test_non_macos_off_main_thread_is_unaffected(monkeypatch, platform):
    """Windows/Linux users see zero behavior change -- this hazard is macOS-only."""
    tkinter = pytest.importorskip("tkinter")
    monkeypatch.setattr(gui_prompter.sys, "platform", platform)
    monkeypatch.setattr(gui_prompter.threading, "current_thread", lambda: object())
    monkeypatch.setattr(gui_prompter.threading, "main_thread", lambda: object())

    attempted = []
    monkeypatch.setattr(tkinter, "Tk", lambda: attempted.append(True) or object())
    gui_prompter._open_root()
    assert attempted == [True]


def test_real_background_thread_on_macos_is_refused(monkeypatch):
    """End to end against the REAL stdlib threading module (no identity mocking):
    a genuine background thread is refused when the platform is macOS."""
    tkinter = pytest.importorskip("tkinter")
    monkeypatch.setattr(gui_prompter.sys, "platform", "darwin")

    def _boom(*_a, **_k):
        raise AssertionError("tkinter.Tk() must never be called off the main thread on macOS")

    monkeypatch.setattr(tkinter, "Tk", _boom)

    outcome: dict = {}

    def _worker():
        try:
            gui_prompter._open_root()
        except BaseException as exc:  # noqa: BLE001 — captured for the caller's thread to assert
            outcome["error"] = exc

    thread = threading.Thread(target=_worker)
    thread.start()
    thread.join(timeout=5)
    assert isinstance(outcome.get("error"), PrompterUnavailableError)


def test_gui_prompter_confirm_refuses_off_main_thread_on_macos(monkeypatch):
    """The guard is reachable through the public GuiPrompter API, not just _open_root."""
    monkeypatch.setattr(gui_prompter.sys, "platform", "darwin")
    monkeypatch.setattr(gui_prompter.threading, "current_thread", lambda: object())
    monkeypatch.setattr(gui_prompter.threading, "main_thread", lambda: object())
    with pytest.raises(PrompterUnavailableError):
        GuiPrompter().confirm("Approve?")


def test_fallback_chain_falls_through_gui_to_tty_on_macos_background_thread(monkeypatch):
    """The #399 shape: GuiPrompter is refused (macOS, background thread), and the
    chain falls through to the next channel rather than silently approving."""
    monkeypatch.setattr(gui_prompter.sys, "platform", "darwin")
    monkeypatch.setattr(gui_prompter.threading, "current_thread", lambda: object())
    monkeypatch.setattr(gui_prompter.threading, "main_thread", lambda: object())

    tty = _Recorder(confirm=True)
    assert FallbackPrompter([GuiPrompter(), tty]).confirm("Approve?") is True
    assert tty.calls == ["confirm"]


def test_fallback_chain_denies_when_gui_and_tty_both_unavailable_on_macos(monkeypatch):
    """Full #399 reproduction: macOS + background thread + no real terminal either
    -- both channels report unavailable, and the provider denies, never approves."""
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

    monkeypatch.setattr(gui_prompter.sys, "platform", "darwin")
    monkeypatch.setattr(gui_prompter.threading, "current_thread", lambda: object())
    monkeypatch.setattr(gui_prompter.threading, "main_thread", lambda: object())

    now = datetime(2026, 6, 10, tzinfo=timezone.utc)
    action = SecurityObject(
        id="act-399-1",
        ts=now,
        agent_role="webdev",
        action_type=ActionType.file_write,
        tool_name="fs_write",
        target="migrations/anything.sql",
    )
    objective = GuardrailResult(
        verdict=Verdict.AUTH,
        risk=Risk.medium,
        reason_codes=[ReasonCode.sensitive_path_access],
        explanation="why",
    )
    decision = Decision(
        action_id="act-399-1",
        final_verdict=Verdict.AUTH,
        final_risk=Risk.medium,
        objective=objective,
        reason_codes=[ReasonCode.sensitive_path_access],
        explanation="why",
        decided_at=now,
    )
    no_tty = _Recorder(raises=PrompterUnavailableError("no controlling terminal"))
    chain = FallbackPrompter([GuiPrompter(), no_tty])
    result = LocalAuthProvider().authenticate(
        decision, action, AuthTier.local_auth, prompter=chain, at=now
    )
    assert result.approved is False


# --- GuiPrompter: custom dialog internals (faked root + faked widget builders) -----


class _FakeRoot:
    """Duck-typed stand-in for a Tk root so the dialog plumbing runs headless."""

    def __init__(self):
        self.destroyed = False
        self.attrs: dict = {}
        self.config: dict = {}
        self.titles: list[str] = []
        self.resizable_args: tuple | None = None
        self.protocols: dict = {}
        self.bindings: dict = {}
        self.geometries: list[str] = []
        self.close_on_mainloop = False
        self.scheduled: list[int] = []
        self.iconphoto_calls: list = []

    def after(self, delay_ms, callback):  # noqa: ARG002 — the timeout never fires here
        # The dialog now schedules its own deny-on-silence bound; these tests
        # exercise the answered paths, so record it and leave it unfired.
        self.scheduled.append(delay_ms)

    def attributes(self, name, value):
        self.attrs[name] = value

    def configure(self, **kwargs):
        self.config.update(kwargs)

    def title(self, text):
        self.titles.append(text)

    def resizable(self, w, h):
        self.resizable_args = (w, h)

    def protocol(self, name, callback):
        self.protocols[name] = callback

    def bind(self, sequence, callback):
        self.bindings[sequence] = callback

    def geometry(self, spec):
        self.geometries.append(spec)

    def iconphoto(self, default, image):
        self.iconphoto_calls.append((default, image))

    def update_idletasks(self):
        pass

    def winfo_reqwidth(self):
        return 420

    def winfo_reqheight(self):
        return 220

    def winfo_screenwidth(self):
        return 1920

    def winfo_screenheight(self):
        return 1080

    def winfo_id(self):
        return 0

    def mainloop(self):
        # Simulate the human closing the window instead of answering.
        if self.close_on_mainloop:
            self.protocols["WM_DELETE_WINDOW"]()

    def quit(self):
        pass

    def destroy(self):
        self.destroyed = True


@pytest.fixture
def fake_root(monkeypatch):
    root = _FakeRoot()
    monkeypatch.setattr(gui_prompter, "_open_root", lambda: root)
    return root


def test_run_dialog_returns_the_populated_answer_and_destroys_root(monkeypatch, fake_root):
    def _fake_populate(root, message, answer):
        assert message == "Approve THIS exact action?"
        answer["value"] = True

    monkeypatch.setattr(gui_prompter, "_populate_confirm", _fake_populate)
    assert gui_prompter._confirm_dialog("Approve THIS exact action?") is True
    assert fake_root.destroyed is True  # never leak a Tk root


def test_closing_the_window_is_a_denial_never_an_approval(monkeypatch, fake_root):
    fake_root.close_on_mainloop = True
    monkeypatch.setattr(gui_prompter, "_populate_confirm", lambda *_a: None)
    monkeypatch.setattr(gui_prompter, "_populate_code", lambda *_a: None)
    assert gui_prompter._confirm_dialog("Approve?") is False
    assert gui_prompter._code_dialog("Enter your 2FA code") is None


def test_root_destroyed_even_when_the_widget_builder_raises(monkeypatch, fake_root):
    def _boom(*_a):
        raise RuntimeError("dialog exploded")

    monkeypatch.setattr(gui_prompter, "_populate_confirm", _boom)
    with pytest.raises(RuntimeError, match="dialog exploded"):
        gui_prompter._confirm_dialog("Approve?")
    assert fake_root.destroyed is True


def test_window_is_topmost_dark_and_fixed_size(monkeypatch, fake_root):
    """The dialog must pop OVER the agent terminal and use the dark theme base."""
    monkeypatch.setattr(gui_prompter, "_populate_confirm", lambda *_a: None)
    gui_prompter._confirm_dialog("Approve?")
    assert fake_root.attrs.get("-topmost") is True
    assert fake_root.titles and fake_root.titles[0] == gui_prompter._TITLE
    assert fake_root.config.get("bg") == gui_prompter._BG
    assert fake_root.resizable_args == (False, False)


def test_palette_is_dark_tan_and_amber():
    """Design contract: warm near-black surfaces, tan brand, amber Approve — no neon.

    The hex must stay on the shared brand system (landing + explainer video): a tan
    brand accent and an amber (AUTH-verdict) Approve action, never the old off-brand
    orange. Both accents stay red/green-dominant with low blue (no purple, no neon).
    """

    def _rgb(color: str) -> tuple[int, int, int]:
        return int(color[1:3], 16), int(color[3:5], 16), int(color[5:7], 16)

    for surface in (gui_prompter._BG, gui_prompter._PANEL):
        assert max(_rgb(surface)) < 48  # near-black surfaces

    br, bg_, bb = _rgb(gui_prompter._BRAND)
    assert br > 200 and br > bg_ > bb and bb < 100  # tan: red-dominant, low blue

    ar, ag, ab = _rgb(gui_prompter._APPROVE)
    assert ar > 200 and ag > 150 and ab < 100  # amber: red + green high, low blue
    assert ag > bg_  # amber is more yellow (greener) than the tan brand

    assert max(_rgb(gui_prompter._APPROVE_FG)) < 60  # dark ink for contrast on amber


def test_confirm_dialog_default_keyboard_action_denies():
    """The Canvas-drawn buttons aren't real focusable widgets, so ``deny.focus_set()``
    no longer guarantees a stray Enter can't approve -- ``_add_button_row`` always
    starts the keyboard highlight on ``specs[0]`` and binds Return to invoke whichever
    button is currently highlighted (see its docstring). That guarantee rests entirely
    on ``_confirm_specs`` placing Deny first; this checks that contract directly,
    without constructing any tkinter widget, so it runs deterministically even where
    no display is available (unlike the real-widget test below, which skips there).
    """
    calls: list[bool] = []
    specs = gui_prompter._confirm_specs(calls.append)

    label, command, accent = specs[0]
    assert label == "Deny"
    assert accent is False  # never the amber/approve styling

    command()  # invoking the button _add_button_row starts highlighted on
    assert calls == [False]  # ... must deny, not approve


def test_real_dialog_widgets_dark_theme_and_masked_entry(monkeypatch):
    """With a real display: the code entry is masked and surfaces use the dark palette.

    Skipped where Tk cannot open (headless CI) — the contract above still covers the
    plumbing; this verifies the actual widget construction when a display exists.
    """
    tkinter = pytest.importorskip("tkinter")
    try:
        root = tkinter.Tk()
    except tkinter.TclError:
        pytest.skip("no display available")
    try:
        root.withdraw()
        answer: dict = {}
        gui_prompter._configure_window(root)
        gui_prompter._populate_code(root, "Enter your 2FA code", answer)

        def _walk(widget):
            yield widget
            for child in widget.winfo_children():
                yield from _walk(child)

        widgets = list(_walk(root))
        entries = [w for w in widgets if isinstance(w, tkinter.Entry)]
        assert entries, "code dialog must contain an entry field"
        assert entries[0].cget("show") == "*"  # the code must be masked on screen
        assert root.cget("bg") == gui_prompter._BG
    finally:
        root.destroy()


def test_configure_window_sets_icon(monkeypatch):
    tkimage = pytest.importorskip("tkinter")
    monkeypatch.setattr(tkimage, "PhotoImage", lambda **_kw: _kw.get("file"))

    root = _FakeRoot()
    gui_prompter._configure_window(root)

    assert len(root.iconphoto_calls) == 1

    default, _ = root.iconphoto_calls[0]
    assert default is True


def test_configure_window_continues_when_icon_load_fails(monkeypatch):
    tkinter = pytest.importorskip("tkinter")

    def _boom(*_a):
        raise RuntimeError("Icon load failed")

    monkeypatch.setattr(tkinter, "PhotoImage", _boom)

    root = _FakeRoot()
    gui_prompter._configure_window(root)

    assert root.titles == [gui_prompter._TITLE]
    assert root.iconphoto_calls == []


class _FakeCanvas:
    """Records the Canvas display list (bottom → top) and mirrors Tk's ``tag_lower``."""

    def __init__(self):
        self.items: list[int] = []  # display list: creation order = stacking order
        self.tags: dict[int, tuple] = {}
        self.texts: dict[int, str] = {}

    def _create(self, tags):
        item = len(self.tags) + 1
        self.items.append(item)
        self.tags[item] = tuple(tags)
        return item

    def create_polygon(self, _points, **kw):
        return self._create(kw.get("tags", ()))

    def create_text(self, _x, _y, **kw):
        item = self._create(kw.get("tags", ()))
        self.texts[item] = kw.get("text", "")
        return item

    def tag_lower(self, item, below):
        # Tk: move `item` to just before the LOWEST item carrying tag `below`.
        self.items.remove(item)
        self.items.insert(
            next(i for i, it in enumerate(self.items) if below in self.tags[it]), item
        )

    def delete(self, item):
        self.items.remove(item)

    def tag_bind(self, *_a, **_kw):
        pass

    def itemconfig(self, *_a, **_kw):
        pass

    def focus_set(self):
        pass

    def ring_is_beneath_every_button(self) -> bool:
        [ring] = [
            i for i in self.items if not self.tags[i] and i not in self.texts
        ]  # the ring is the only untagged non-text item
        return all(self.items.index(ring) < self.items.index(i) for i in self.items if self.tags[i])

    def bbox(self, item):
        # Geometry is irrelevant for these fake canvas tests.
        return (0, 0, 0, 0)


def test_focus_ring_is_stacked_beneath_the_buttons(monkeypatch):
    """Tk hit-tests a polygon's WHOLE interior even when it is unfilled, so a focus ring
    drawn on top of the highlighted button receives that button's clicks (and hover)
    instead of the button — clicking Deny did nothing. The ring must sit beneath every
    button item, both at the start and after each highlight move (it is redrawn each
    time). Faked canvas, so this runs on headless CI; the real-Tk check is below.
    """
    tkfont = pytest.importorskip("tkinter.font")
    monkeypatch.setattr(tkfont, "Font", lambda **_kw: types.SimpleNamespace(measure=len))
    canvas, root = _FakeCanvas(), _FakeRoot()
    specs = [("Deny", lambda: None, False), ("Approve", lambda: None, True)]

    gui_prompter._add_button_row(root, canvas, y=100, specs=specs)
    assert canvas.ring_is_beneath_every_button()

    root.bindings["<Tab>"]()  # highlight → Approve; ring deleted and redrawn
    assert canvas.ring_is_beneath_every_button()


def test_button_row_displays_keyboard_hint(monkeypatch):
    tkfont = pytest.importorskip("tkinter.font")
    monkeypatch.setattr(tkfont, "Font", lambda **_kw: types.SimpleNamespace(measure=len))
    canvas, root = _FakeCanvas(), _FakeRoot()
    specs = [("Deny", lambda: None, False), ("Approve", lambda: None, True)]

    gui_prompter._add_button_row(root, canvas, y=100, specs=specs)
    hints = [text for text in canvas.texts.values() if "Enter" in text]
    assert hints, "keyboard hint was not drawn"
    # The dialog text is ASCII-only (a middle dot breaks cp1252 consoles); pin the hint to it.
    assert all(text.isascii() for text in hints)


def test_real_canvas_click_target_is_the_highlighted_button_not_the_ring():
    """With a real display: the item Tk would hand a click to — the topmost item under the
    button's centre, which is exactly ``find_closest``'s tie-break — must be the button
    itself (tagged), never the untagged focus ring, for Deny (highlighted at open) and
    Approve alike. Skipped where Tk cannot open (headless CI); the faked-canvas test above
    still covers the stacking contract there.
    """
    tkinter = pytest.importorskip("tkinter")
    try:
        root = tkinter.Tk()
    except tkinter.TclError:
        pytest.skip("no display available")
    try:
        root.withdraw()
        canvas = tkinter.Canvas(root, width=gui_prompter._DIALOG_W, height=200)
        canvas.pack()
        specs = gui_prompter._confirm_specs(lambda _value: None)
        gui_prompter._add_button_row(root, canvas, y=60, specs=specs)
        root.update_idletasks()

        for tag in ("_dobermanbtn0", "_dobermanbtn1"):
            x1, y1, x2, y2 = canvas.bbox(tag)
            topmost = canvas.find_closest((x1 + x2) / 2, (y1 + y2) / 2)[0]
            assert tag in canvas.gettags(topmost), f"click on {tag} would land on item {topmost}"
    finally:
        root.destroy()


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
