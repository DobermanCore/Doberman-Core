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
"""

import asyncio
import threading
from datetime import datetime, timezone

from doberman.auth.challenge import EFFECT_SET_LABEL, current_challenge, format_effect_set
from doberman.auth.gui_prompter import PrompterUnavailableError
from doberman.storage import approvals
from doberman.storage.heartbeat import DEFAULT_HEARTBEAT_MAX_AGE_S, heartbeat_is_fresh
from doberman.storage.log import path_class

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
    ) -> None:
        self._repo_root = repo_root
        self._heartbeat_max_age_s = heartbeat_max_age_s
        self._poll_interval_s = poll_interval_s
        self._timeout_s = timeout_s

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
            )
        )

        deadline = datetime.now(timezone.utc).timestamp() + self._timeout_s
        while datetime.now(timezone.utc).timestamp() < deadline:
            row = asyncio.run(approvals.get_pending(approval_id, repo_root=self._repo_root))
            if row is not None and row["status"] == "resolved":
                _last_code.value = row.get("totp_code")
                _engaged.value = True
                return row["decision"] == "approved"
            _sleep(self._poll_interval_s)

        # Timed out with no human answer via the dashboard - NOT a denial: a
        # stale/unattended dashboard must not silently deny a real human who
        # can still answer at the terminal/GUI. See the module docstring.
        raise PrompterUnavailableError("dashboard approval timed out with no response")

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
