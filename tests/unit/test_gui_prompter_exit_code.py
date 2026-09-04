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

This test reproduces the exact production shape (real dialog widgets, real
button closures, real countdown, run via ``challenge._run_with_deadline`` on a
daemon worker thread) and asserts the subprocess's exit code and stderr are
untouched by either defect.
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


    def _populate(root, answer, timeout_s):
        gui_prompter._populate_confirm(root, "regression test dialog", answer, timeout_s)
        root.after(150, root.quit)


    def _run_challenge():
        return gui_prompter._run_dialog(
            _populate, want_code=False, timeout_s=5.0, action_id="test-exit-code"
        )


    challenge._run_with_deadline(
        _run_challenge, timeout_s=10.0, on_timeout=lambda: None, label="test-exit-code"
    )
    sys.exit(2)
    """
)


def test_a_worker_thread_dialog_leaves_the_hooks_exit_code_intact():
    try:
        probe = gui_prompter._open_root()
    except gui_prompter.PrompterUnavailableError:
        pytest.skip("no display available for a GUI auth dialog")
    probe.destroy()
    gc.collect()

    proc = subprocess.run(  # noqa: S603 - fixed args, no shell, this is the test
        [sys.executable, "-c", _SUBPROCESS_CODE],
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
