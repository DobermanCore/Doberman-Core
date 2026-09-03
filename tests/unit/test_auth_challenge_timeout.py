"""The AUTH challenge deadline — fail-closed against a prompter that never returns.

Prime Directive 1 says an error or unhandled case denies. That was implemented as
``except Exception`` around the challenge, which only catches a prompter that
*raises*. A prompter that **blocks** — ``GuiPrompter``'s ``mainloop()`` with nobody
at the screen, ``TtyPrompter``'s ``readline()`` on an unattended terminal, or any
channel/provider registered by a plugin — neither returns nor raises, so no handler
fires: the decision is never persisted and the agent's tool call hangs for ever.
**An indefinite block is not a denial**, and it fails worst exactly where agents
actually run (headless, unattended).

Contracts under test:
* an unanswered challenge returns within the deadline, non-approved, and tagged
  :data:`TIMEOUT_METHOD` so an audit can tell silence from a human "no";
* an answer that arrives *after* the deadline is never honoured (no late approval);
* the deadline does not change the fast path, does not swallow raised errors, and
  does not break the challenge ContextVar the dashboard channel depends on;
* the abandoned worker is a daemon, so a wedged channel cannot block interpreter exit;
* ``GuiPrompter``'s dialog schedules its own bound and denies when it fires.
"""

import asyncio
import threading
from datetime import datetime, timezone

import pytest

from doberman.auth import gui_prompter
from doberman.auth.challenge import (
    DEFAULT_CHALLENGE_TIMEOUT_S,
    TIMEOUT_METHOD,
    AuthTier,
    current_challenge,
    run_auth_challenge,
)
from doberman.models import (
    ActionType,
    Decision,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    Verdict,
)

_NOW = datetime(2026, 7, 26, tzinfo=timezone.utc)

#: For tests that DELIBERATELY hit the deadline — short so the suite stays fast.
_FAST = 0.3

#: For tests that must NOT hit the deadline. Deliberately generous: each of those
#: spawns a thread and round-trips through the provider, and a 300ms budget on a
#: loaded CI box could expire on its own — producing exactly the spurious timeout
#: denial those tests exist to rule out. Never reuse `_FAST` for them.
_GENEROUS = 30.0


def _action(action_id: str = "act-an4") -> SecurityObject:
    return SecurityObject(
        id=action_id,
        ts=_NOW,
        agent_role="webdev",
        action_type=ActionType.file_write,
        tool_name="fs_write",
        target="backend/api.ts",
    )


def _auth_decision(
    action_id: str = "act-an4",
    reasons=(ReasonCode.sensitive_path_access,),
    risk: Risk = Risk.medium,
) -> Decision:
    objective = GuardrailResult(
        verdict=Verdict.AUTH, risk=risk, reason_codes=list(reasons), explanation="why"
    )
    return Decision(
        action_id=action_id,
        final_verdict=Verdict.AUTH,
        final_risk=risk,
        objective=objective,
        reason_codes=list(reasons),
        explanation="why",
        decided_at=_NOW,
    )


class HangingPrompter:
    """A prompter that blocks until released — the AN-4 shape, without a real GUI.

    Stands in for ``mainloop()``/``readline()``: it does not raise, so nothing the
    old ``except``-based fail-closed path could catch ever happens.
    """

    def __init__(self) -> None:
        self.release = threading.Event()
        self.entered = threading.Event()
        self.answer = True  # would APPROVE if it were ever allowed to finish

    def confirm(self, message: str) -> bool:  # noqa: ARG002 — message unused
        self.entered.set()
        self.release.wait()
        return self.answer

    def read_code(self, message: str) -> str:  # noqa: ARG002 — message unused
        self.entered.set()
        self.release.wait()
        return "123456"


# --- the core contract --------------------------------------------------------------


@pytest.mark.guarantee("auth-deadline", host="claude-code")
def test_a_blocked_prompter_denies_within_the_deadline():
    """The AN-4 regression: silence resolves to a denial instead of hanging for ever."""
    prompter = HangingPrompter()
    try:
        result = run_auth_challenge(_auth_decision(), _action(), prompter=prompter, timeout_s=_FAST)
        assert result.approved is False  # fail closed
        assert result.method == TIMEOUT_METHOD
        assert result.action_id == "act-an4"  # still bound to THIS action
    finally:
        prompter.release.set()  # never leave the worker parked on the event


@pytest.mark.guarantee("timeout-vs-deny-logging", host="claude-code")
def test_a_timeout_is_distinguishable_from_a_human_denial():
    """The audit log must not read an unwatched channel as "the human said no"."""

    class _SaysNo:
        def confirm(self, message: str) -> bool:  # noqa: ARG002
            return False

        def read_code(self, message: str) -> str:  # noqa: ARG002
            raise EOFError("no code")

    denied = run_auth_challenge(
        _auth_decision(), _action(), prompter=_SaysNo(), timeout_s=_GENEROUS
    )
    prompter = HangingPrompter()
    try:
        timed_out = run_auth_challenge(
            _auth_decision(), _action(), prompter=prompter, timeout_s=_FAST
        )
    finally:
        prompter.release.set()

    assert denied.approved is timed_out.approved is False  # both deny
    assert denied.method != TIMEOUT_METHOD  # ...but they are not the same event
    assert timed_out.method == TIMEOUT_METHOD


def test_an_answer_arriving_after_the_deadline_is_never_honoured():
    """A late "approve" must not resurrect an action Doberman already denied."""
    prompter = HangingPrompter()
    prompter.answer = True
    result = run_auth_challenge(_auth_decision(), _action(), prompter=prompter, timeout_s=_FAST)
    assert result.method == TIMEOUT_METHOD

    prompter.release.set()  # the "human" finally clicks Approve — far too late
    assert result.approved is False  # the already-returned verdict cannot change


def test_the_deadline_does_not_disturb_a_prompt_answer():
    """A human who answers immediately is unaffected by the bound."""

    class _SaysYes:
        def confirm(self, message: str) -> bool:  # noqa: ARG002
            return True

        def read_code(self, message: str) -> str:  # noqa: ARG002
            return "123456"

    result = run_auth_challenge(
        _auth_decision(), _action(), prompter=_SaysYes(), timeout_s=_GENEROUS
    )
    assert result.approved is True
    assert result.tier is AuthTier.local_auth  # sensitive_path_access floors the tier here
    assert result.method != TIMEOUT_METHOD


def test_a_raised_error_still_propagates_not_swallowed_by_the_worker():
    """Running off-thread must not hide a provider failure from the caller's handler."""

    class _BoomProvider:
        def authenticate(self, *_a, **_k):
            raise RuntimeError("provider exploded")

    import doberman.auth.provider as provider_mod

    original = provider_mod.active_provider
    provider_mod.active_provider = lambda: _BoomProvider()
    try:
        with pytest.raises(RuntimeError, match="provider exploded"):
            run_auth_challenge(_auth_decision(), _action(), timeout_s=_GENEROUS)
    finally:
        provider_mod.active_provider = original


def test_a_systemexit_from_the_provider_denies_instead_of_escaping():
    """AN-4b: a provider raising a *non-Exception* BaseException must fail closed.

    A registered ``AuthProvider`` (a plugin seam) that raises ``SystemExit`` used to be
    re-raised verbatim past every caller's ``except Exception`` — so no fail-closed
    handler fired and the action was neither approved nor denied. The seam now converts
    it to a denial, tagged ``"error"``: never a silent escape, never a spurious approval.
    """

    class _ExitingProvider:
        def authenticate(self, *_a, **_k):
            raise SystemExit(2)

    import doberman.auth.provider as provider_mod

    original = provider_mod.active_provider
    provider_mod.active_provider = lambda: _ExitingProvider()
    try:
        result = run_auth_challenge(_auth_decision(), _action(), timeout_s=_GENEROUS)
    finally:
        provider_mod.active_provider = original
    assert result.approved is False  # fail closed — not a silent escape
    assert result.method == "error"  # distinct from a timeout and from a human "no"
    assert result.action_id == "act-an4"  # still bound to THIS action


def test_an_arbitrary_baseexception_from_the_provider_denies():
    """Fail-closed cannot depend on enumerating exception types: a plugin may raise any
    ``BaseException`` subclass it likes and it must still resolve to a denial."""

    class _Sneaky(BaseException):
        pass

    class _SneakyProvider:
        def authenticate(self, *_a, **_k):
            raise _Sneaky("not an Exception subclass")

    import doberman.auth.provider as provider_mod

    original = provider_mod.active_provider
    provider_mod.active_provider = lambda: _SneakyProvider()
    try:
        result = run_auth_challenge(_auth_decision(), _action(), timeout_s=_GENEROUS)
    finally:
        provider_mod.active_provider = original
    assert result.approved is False
    assert result.method == "error"


def test_a_cooperative_cancellation_still_propagates():
    """Denying a plugin's ``SystemExit`` must not also swallow a genuine
    ``CancelledError``: asyncio cancellation is cooperative and has to reach the event
    loop, never a denial."""

    class _CancelledProvider:
        def authenticate(self, *_a, **_k):
            raise asyncio.CancelledError()

    import doberman.auth.provider as provider_mod

    original = provider_mod.active_provider
    provider_mod.active_provider = lambda: _CancelledProvider()
    try:
        with pytest.raises(asyncio.CancelledError):
            run_auth_challenge(_auth_decision(), _action(), timeout_s=_GENEROUS)
    finally:
        provider_mod.active_provider = original


def test_the_challenge_contextvar_reaches_the_worker_thread():
    """DashboardPrompter reads ``current_challenge()``; losing it would silently
    disable the dashboard approval channel (it falls back when the context is absent)."""
    seen: list = []

    class _Peeking:
        def confirm(self, message: str) -> bool:  # noqa: ARG002
            seen.append(current_challenge())
            return True

        def read_code(self, message: str) -> str:  # noqa: ARG002
            return "123456"

    run_auth_challenge(_auth_decision(), _action(), prompter=_Peeking(), timeout_s=_GENEROUS)
    assert len(seen) == 1
    challenge = seen[0]
    assert challenge is not None, "the worker thread lost the challenge ContextVar"
    _decision, action, tier = challenge
    assert action.id == "act-an4"
    assert tier is AuthTier.local_auth


def test_the_abandoned_worker_is_a_daemon_so_it_cannot_block_exit():
    """Python cannot kill a thread wedged in native code — it must not be joinable-on-exit."""
    prompter = HangingPrompter()
    before = set(threading.enumerate())
    try:
        run_auth_challenge(_auth_decision(), _action(), prompter=prompter, timeout_s=_FAST)
        prompter.entered.wait(timeout=5)
        stranded = [t for t in set(threading.enumerate()) - before if t.is_alive()]
        assert stranded, "expected the blocked challenge worker to still be running"
        assert all(t.daemon for t in stranded)
    finally:
        prompter.release.set()


def test_the_default_deadline_exceeds_the_worst_case_channel_chain():
    """The bound must never preempt a channel a human is legitimately still using.

    The chain is dispatched **twice** for a ``two_factor``/``role_elevation`` tier —
    ``LocalAuthProvider._run_tier`` calls ``confirm()`` and then ``read_code()``, both
    under this one budget. Sizing the deadline for a single pass would cut off a human
    who approved the confirm late in the budget while they were typing their TOTP code,
    manufacturing a denial of an action they were actively approving — on the highest-risk
    tiers. Hence the ``* 2``: the channel budgets are sized so two passes still fit
    under the ten-minute ceiling.

    One pass is the dashboard window (its timeout raises ``PrompterUnavailableError``,
    so ``FallbackPrompter`` moves on) plus the FIRST open human channel: elicitation or
    the GUI dialog. Their expiry is a human-channel outcome (``EOFError`` / expired), which
    is final — the next channel is never consulted — so the two never stack.
    """
    from doberman.auth.dashboard_prompter import DEFAULT_TIMEOUT_S as DASH_S
    from doberman.auth.elicitation_prompter import ANSWER_TIMEOUT_S as ELICIT_S

    one_pass = DASH_S + max(ELICIT_S, gui_prompter.DEFAULT_DIALOG_TIMEOUT_S)
    assert DEFAULT_CHALLENGE_TIMEOUT_S > one_pass * 2


def test_an_unanswered_challenge_expires_within_ten_minutes():
    """The whole-challenge ceiling is ten minutes, and the channel chain fits under it.

    Before this pin the ceiling was 20 minutes and a live proxy-path challenge nobody answered
    was still approvable ~13.5 minutes in, while the README promised a 2-minute dialog. Both
    halves are pinned: the ceiling itself, and that two passes (dashboard window + the longest
    single human channel) finish before it, so the ceiling only ever bites on silence and
    never preempts a human mid-answer.
    """
    from doberman.auth.dashboard_prompter import DEFAULT_TIMEOUT_S as DASH_S
    from doberman.auth.elicitation_prompter import ANSWER_TIMEOUT_S as ELICIT_S

    assert DEFAULT_CHALLENGE_TIMEOUT_S == 600.0
    one_pass = DASH_S + max(ELICIT_S, gui_prompter.DEFAULT_DIALOG_TIMEOUT_S)
    assert one_pass * 2 <= DEFAULT_CHALLENGE_TIMEOUT_S


# --- the GUI dialog's own bound ------------------------------------------------------


class _TimeoutRoot:
    """A Tk root stand-in whose ``mainloop`` fires the scheduled timeout callback."""

    def __init__(self) -> None:
        self.destroyed = False
        self.scheduled: list[int] = []
        self._after: list = []
        self.protocols: dict = {}

    # -- window plumbing the dialog touches, all inert here --
    def attributes(self, name, value): ...
    def configure(self, **kwargs): ...
    def title(self, text): ...
    def resizable(self, w, h): ...
    def bind(self, sequence, callback): ...
    def geometry(self, spec): ...
    def update_idletasks(self): ...

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

    def protocol(self, name, callback):
        self.protocols[name] = callback

    def after(self, delay_ms, callback):
        self.scheduled.append(delay_ms)
        self._after.append(callback)

    def mainloop(self):
        # Nobody answers: the only thing that ends the loop is the timeout.
        for callback in self._after:
            callback()

    def quit(self): ...

    def destroy(self):
        self.destroyed = True


@pytest.fixture
def timeout_root(monkeypatch):
    root = _TimeoutRoot()
    monkeypatch.setattr(gui_prompter, "_open_root", lambda: root)
    monkeypatch.setattr(gui_prompter, "_populate_confirm", lambda *_a: None)
    monkeypatch.setattr(gui_prompter, "_populate_code", lambda *_a: None)
    return root


def test_an_unanswered_dialog_denies_and_releases_its_root(timeout_root):
    """``_populate_confirm`` is stubbed to a no-op here (the fake root isn't a real
    Tk widget, so the real widget-building populate can't run against it) — the
    countdown scheduling itself now lives inside ``_build_countdown``, called
    from the real populate, and is covered directly (with a real Tk root) by
    ``test_countdown_ticks_then_denies_on_expiry`` in test_gui_prompter.py. What
    this test still pins: with nothing ever resolving ``answer``, ``_run_dialog``
    returns the fail-closed default and always releases the Tk root, never leaks it.
    """
    assert gui_prompter._confirm_dialog("Approve?", timeout_s=1.5) is False
    assert timeout_root.destroyed is True  # the Tk root is released, not leaked


def test_an_unanswered_code_dialog_yields_no_code(timeout_root):
    """A timed-out code dialog must raise, never hand ``""`` to the TOTP verifier."""
    assert gui_prompter._code_dialog("Enter your 2FA code", timeout_s=1.5) is None
    with pytest.raises(EOFError):
        gui_prompter.GuiPrompter(timeout_s=1.5).read_code("Enter your 2FA code")


def test_gui_prompter_defaults_to_a_bounded_dialog():
    """A default-constructed prompter is bounded — the hang must not be opt-out-able."""
    assert gui_prompter.GuiPrompter()._timeout_s == gui_prompter.DEFAULT_DIALOG_TIMEOUT_S
    assert gui_prompter.DEFAULT_DIALOG_TIMEOUT_S > 0
