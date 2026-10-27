"""Regression test: a GUI auth dialog run on its production worker thread must
never corrupt the HOST PROCESS's exit code.

Every real host hook (``doberman hook pre``/``hook_post``/``hook_cursor``/...)
writes its decision JSON to stdout and then ``raise typer.Exit(code)``. When
the decision needs a human, the dialog opens through
``challenge._run_with_deadline`` -- a daemon ``threading.Thread``, never the
process's real main thread. If a Tk-backed Python object (a ``PhotoImage``, a
button's bound closure) is still alive in a reference cycle when that worker
thread's function returns, Python's cyclic GC only reclaims it later, on
whichever thread happens to allocate next -- typically the MAIN thread during
interpreter shutdown, which never entered that dialog's Tcl interpreter. Tcl
then aborts the whole process (``Tcl_AsyncDelete: async handler deleted by the
wrong thread``) instead of letting it exit with the code the hook actually
raised: Claude Code treats any hook exit other than 0/2 as a *non-blocking*
error and runs the tool anyway (fail-open), and Cursor's ``failClosed`` flips
a corrupted-exit *allow* into a deny (approvals become impossible).

A second, independent defect: an unresolved countdown's ``root.after(1000,
_tick)`` (or the CRITICAL-approve gate's 100ms tick) can still be queued in
Tcl's timer queue after the dialog closes early -- ``root.destroy()`` does not
itself cancel a still-pending ``after`` callback -- and firing it against the
now-destroyed widget names raises ``invalid command name "..."`` from
inside Tcl's own event processing.

This test reproduces the production worker-thread shape and asserts the
subprocess's exit code and stderr are untouched by either defect. On macOS,
the intentional main-thread guard refuses this channel before creating Tk;
the caller must catch that refusal and preserve its own fail-closed exit code.
Other platforms build real widgets, button closures, and a countdown.
"""

import gc
import subprocess
import sys
import textwrap

import pytest

from doberman.auth import gui_prompter

pytestmark = pytest.mark.timeout(120, method="thread")

# The dialog closes itself via root.after(150, root.quit) -- well under a
# second -- so this never waits on a human. sys.exit(2) at the end mirrors
# a real hook's `raise typer.Exit(2)` after the decision JSON is written.
_SUBPROCESS_CODE = textwrap.dedent(
    """
    import sys

    from doberman.auth import challenge, gui_prompter

    populated = False


    def _populate(root, answer, timeout_s):
        global populated
        populated = True
        gui_prompter._populate_confirm(root, "regression test dialog", answer, timeout_s)
        root.after(150, root.quit)


    def _run_challenge():
        return gui_prompter._run_dialog(
            _populate, want_code=False, timeout_s=5.0, action_id="test-exit-code"
        )


    try:
        result = challenge._run_with_deadline(
            _run_challenge, timeout_s=10.0, on_timeout=lambda: None, label="test-exit-code"
        )
    except gui_prompter.PrompterUnavailableError as exc:
        assert gui_prompter.sys.platform == "darwin"
        assert str(exc) == "GUI auth dialog cannot safely open off the main thread on macOS"
        assert not populated
    else:
        assert gui_prompter.sys.platform != "darwin", "macOS must refuse worker-thread Tk"
        assert populated
        assert result is False  # closing without an answer denies
    sys.exit(2)
    """
)


# The exception path: ``populate`` builds real widgets and then raises. The
# worker stores the exception (traceback and all) and re-raises it on the main
# thread, where the caller fails closed. Without the traceback being dropped
# before the worker-thread collection, those traceback frames carry the Tk
# widgets across to the main thread and the abort comes back.
_SUBPROCESS_CODE_RAISING = textwrap.dedent(
    """
    import sys

    from doberman.auth import challenge, gui_prompter

    populated = False


    def _populate(root, answer, timeout_s):
        global populated
        populated = True
        gui_prompter._populate_confirm(root, "regression test dialog", answer, timeout_s)
        raise RuntimeError("populate failed after building widgets")


    def _run_challenge():
        return gui_prompter._run_dialog(
            _populate, want_code=False, timeout_s=5.0, action_id="test-exit-code"
        )


    try:
        challenge._run_with_deadline(
            _run_challenge, timeout_s=10.0, on_timeout=lambda: None, label="test-exit-code"
        )
    except gui_prompter.PrompterUnavailableError as exc:
        assert gui_prompter.sys.platform == "darwin"
        assert str(exc) == "GUI auth dialog cannot safely open off the main thread on macOS"
        assert not populated
    except RuntimeError as exc:
        assert gui_prompter.sys.platform != "darwin", "macOS must refuse worker-thread Tk"
        assert populated
        assert str(exc) == "populate failed after building widgets"
    else:
        raise AssertionError("populate must raise, or the macOS guard must refuse Tk")
    sys.exit(2)
    """
)


@pytest.mark.parametrize(
    "code", [_SUBPROCESS_CODE, _SUBPROCESS_CODE_RAISING], ids=["decided", "populate-raises"]
)
@pytest.mark.parametrize("macos_guard", [False, True], ids=["native", "macos-guard"])
def test_a_worker_thread_dialog_leaves_the_hooks_exit_code_intact(code, macos_guard):
    if not macos_guard:
        try:
            probe = gui_prompter._open_root()
        except gui_prompter.PrompterUnavailableError:
            pytest.skip("no display available for a GUI auth dialog")
        probe.destroy()
        gc.collect()

    if macos_guard:
        # Exercise Cocoa's intentional worker-thread refusal on every OS,
        # without constructing an unsafe Cocoa Tk root or changing global sys.
        code = code.replace(
            "from doberman.auth import challenge, gui_prompter",
            "from doberman.auth import challenge, gui_prompter\n"
            "from types import SimpleNamespace\n"
            "gui_prompter.sys = SimpleNamespace(platform='darwin')",
        )

    proc = subprocess.run(  # noqa: S603 - fixed args, no shell, this is the test
        [sys.executable, "-c", code],
        capture_output=True,
        timeout=60,
    )

    stderr_text = proc.stderr.decode("utf-8", "replace")
    assert proc.returncode == 2, f"exit code {proc.returncode} (expected 2); stderr:\n{stderr_text}"
    for needle in (
        b"Tcl_AsyncDelete",
        b"invalid command name",
        b"main thread is not in main loop",
    ):
        assert needle not in proc.stderr, f"{needle!r} found in stderr:\n{stderr_text}"
