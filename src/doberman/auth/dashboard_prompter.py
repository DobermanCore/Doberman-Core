"""``DashboardPrompter`` — the dashboard channel in the MCP-proxy auth chain (D3).

Implements the existing :class:`~doberman.auth.challenge.Prompter` Protocol, so
it slots into the same :class:`~doberman.auth.gui_prompter.FallbackPrompter`
chain as :class:`~doberman.auth.gui_prompter.GuiPrompter`/``TtyPrompter`` with
zero changes to the provider/challenge machinery. It never verifies anything
itself (no TOTP logic here) — it only relays a human's decision (and, for
tiers that need one, a TOTP code) from the dashboard's pending-approval queue
back to :class:`~doberman.auth.provider.LocalAuthProvider._run_tier`, which
runs the EXISTING verification (:func:`doberman.auth.totp.verify`) unchanged.

Two things gate whether this channel engages at all, both fail-open to the
next channel (never a hang, never an invented answer):

* **Heartbeat freshness** — a dashboard process not running (or stuck) has a
  stale/missing heartbeat; :meth:`confirm` then raises
  :class:`~doberman.auth.gui_prompter.PrompterUnavailableError` immediately,
  with zero added latency, so GUI/TTY get the challenge instead.
* **Poll timeout** — a heartbeat can be fresh (the dash *server* is alive)
  while nobody is watching the browser tab. Deliberate divergence from
  :class:`FallbackPrompter`'s general convention (a channel timeout is normally
  final, not a fall-through — see ``gui_prompter.py``'s docstring): here a
  dashboard timeout SHOULD still let a human at the terminal/GUI answer, so it
  also raises ``PrompterUnavailableError`` rather than propagating as a denial.
  The row's expiry is the same window, and when the window closes this channel
  moves the row out of ``pending`` in one write, so a late click on the
  dashboard is refused (409) instead of being lost, and a click that committed
  just before that write is still honoured.
"""

import asyncio
import threading
from datetime import datetime, timezone

from doberman.auth.challenge import EFFECT_SET_LABEL, current_challenge, format_effect_set
from doberman.auth.gui_prompter import PrompterUnavailableError
from doberman.storage import approvals
from doberman.storage.heartbeat import DEFAULT_HEARTBEAT_MAX_AGE_S, heartbeat_is_fresh
from doberman.storage.log import exportable_session_id, path_class

#: How often to poll the pending row while waiting for a human decision.
DEFAULT_POLL_INTERVAL_S = 1.0

#: How long to wait for a decision before falling back to the next channel.
DEFAULT_TIMEOUT_S = 90.0

# ponytail: one thread-local slot for the TOTP code a resolved row carried,
# plus a flag for whether THIS channel actually answered confirm(). _run_tier
# always calls confirm() then (for 2FA tiers) read_code() next, on the same
# thread doing the challenge - a per-thread stash is enough to hand the code
# across those two calls without changing the Prompter signatures. The flag
# matters for FallbackPrompter: confirm() and read_code() are dispatched as
# TWO SEPARATE calls through the chain, so if confirm() fell back (stale
# heartbeat / no challenge context / timeout), read_code() must ALSO raise
# PrompterUnavailableError - not EOFError - so the chain tries the next
# channel's read_code() instead of treating a channel this prompter never
# engaged as a final "no code entered" denial.
_last_code = threading.local()
_engaged = threading.local()


class DashboardPrompter:
    """Queue an approval into the dashboard; fall back if it's not answered there."""

    def __init__(
        self,
        repo_root: str = ".",
        *,
        heartbeat_max_age_s: float = DEFAULT_HEARTBEAT_MAX_AGE_S,
        poll_interval_s: float = DEFAULT_POLL_INTERVAL_S,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        session_id: str | None = None,
    ) -> None:
        self._repo_root = repo_root
        self._heartbeat_max_age_s = heartbeat_max_age_s
        self._poll_interval_s = poll_interval_s
        self._timeout_s = timeout_s
        # shortcut: the session id is fixed per prompter, which fits a host hook
        # (one process per tool call); move it into the challenge context if a
        # host ever shares one prompter across sessions.
        self._session_id = session_id

    def confirm(self, message: str) -> bool:  # noqa: ARG002 - message unused; we build our own
        _engaged.value = False  # reset: this thread may reuse the same prompter across challenges

        if not heartbeat_is_fresh(self._repo_root, max_age_s=self._heartbeat_max_age_s):
            raise PrompterUnavailableError("no live dashboard heartbeat")

        challenge = current_challenge()
        if challenge is None:
            # No ContextVar set (e.g. called outside run_auth_challenge) - we
            # have nothing redaction-safe to queue. Fall back rather than guess.
            raise PrompterUnavailableError("no active challenge context for the dashboard")
        decision, action, tier = challenge

        # ADR 0094: the same shared blast-radius display string every other
        # prompter renders (doberman.auth.challenge.format_effect_set),
        # appended to the explanation -- pending_approvals has no dedicated
        # column for it (a schema migration is a named follow-up, not this
        # slice's scope), and explanation is already free, redaction-safe
        # text the dash UI shows verbatim (as prose, not preformatted, so a
        # single space -- not a blank line -- is what the row actually
        # renders). None (a non-delete-class AUTH, or no effects) leaves the
        # explanation exactly as it was.
        effects_line = format_effect_set(decision.effects)
        explanation = (
            f"{decision.explanation} {EFFECT_SET_LABEL}: {effects_line}"
            if effects_line
            else decision.explanation
        )

        approval_id = asyncio.run(
            approvals.create_pending(
                decision.action_id,
                tier=tier.value,
                action_type=action.action_type.value,
                risk=decision.final_risk.value,
                reason_codes=[rc.value for rc in decision.reason_codes],
                explanation=explanation,
                target_path_class=path_class(action),
                repo_root=self._repo_root,
                # The row dies when this channel gives up, so no late answer is lost.
                ttl_s=self._timeout_s,
                # The host sends any string; keep it only if it has an id's shape.
                session_id=exportable_session_id(self._session_id),
            )
        )

        deadline = datetime.now(timezone.utc).timestamp() + self._timeout_s
        while True:
            row = asyncio.run(approvals.get_pending(approval_id, repo_root=self._repo_root))
            if row is not None and row["status"] == "resolved":
                return self._take_answer(approval_id, decision.action_id)
            # Checked after the poll, so an answer given during the last wait is still read.
            if datetime.now(timezone.utc).timestamp() >= deadline:
                # One write settles the race with a click: the row leaves 'pending', so a
                # later click gets 409, unless a click committed after the poll above.
                if asyncio.run(approvals.expire(approval_id, repo_root=self._repo_root)):
                    break
                return self._take_answer(approval_id, decision.action_id)
            _sleep(self._poll_interval_s)

        # Timed out with no human answer via the dashboard - NOT a denial: a
        # stale/unattended dashboard must not silently deny a real human who
        # can still answer at the terminal/GUI. See the module docstring.
        raise PrompterUnavailableError("dashboard approval timed out with no response")

    def _take_answer(self, approval_id: str, action_id: str) -> bool:
        """Consume the resolved row (its code is cleared in the same write) as this answer."""
        row = asyncio.run(approvals.consume(approval_id, repo_root=self._repo_root))
        # Only a resolved row for the action this channel queued is an answer; a row
        # rewritten for another action (or gone) is no answer from this channel.
        if row is None or row["action_id"] != action_id:
            raise PrompterUnavailableError("the dashboard holds no answer for this action")
        _last_code.value = row.get("totp_code")
        _engaged.value = True
        return row["decision"] == "approved"

    def read_code(self, message: str) -> str:  # noqa: ARG002 - code already collected in confirm()
        if not getattr(_engaged, "value", False):
            # confirm() never actually answered through THIS channel (stale
            # heartbeat / no context / timeout) - read_code() must fall back
            # too, not report a final "no code" denial for a channel that was
            # never open. See the module docstring and the _engaged comment.
            raise PrompterUnavailableError("dashboard did not answer this challenge")
        code = getattr(_last_code, "value", None)
        if not code:
            raise EOFError("no TOTP code was supplied through the dashboard")
        return code


def _sleep(seconds: float) -> None:
    """Broken out so tests can monkeypatch the wait without a real sleep."""
    import time

    time.sleep(seconds)
