"""Auth-tier selection and the action-specific challenge (Feature 7, slices 7.1, 7.3).

When the engine returns ``AUTH``, Doberman must prove the action is *deliberate*.
The proof required scales with risk:

* ``soft_confirm`` — a yes/no acknowledgement (minor, unusual-but-allowed).
* ``local_auth`` — local human presence at the CLI.
* ``two_factor`` — local presence **plus** a TOTP code (sensitive / high risk).
* ``role_elevation`` — the action crosses the agent's role boundary; satisfying
  it grants a narrow, temporary elevation (slice 7.4) for that one target.

:func:`select_tier` derives the tier from the **already-final** risk and reason
codes (so a subjective/role escalation correctly bumps the proof required), and
:func:`run_auth_challenge` presents the *specific* action and collects the proof
through the active :class:`~doberman.auth.provider.AuthProvider`.

SECURITY: the challenge always names the exact action and reason — never a
generic "enter 2FA". Any timeout, input error, or denial yields a non-approved
:class:`AuthResult` (fail closed). A hard block (``BLOCK``) never reaches here:
:func:`select_tier` rejects a non-``AUTH`` decision.

That fail-closed guarantee is enforced by :data:`DEFAULT_CHALLENGE_TIMEOUT_S`,
not by exception handling alone. An ``except`` clause only catches a prompter
that *raises*; a prompter that blocks forever — a GUI dialog nobody closes, a
``readline`` on an unattended terminal — never returns and never raises, so no
handler can fire and the agent's tool call hangs indefinitely. **An indefinite
block is not a denial.** :func:`run_auth_challenge` therefore imposes a hard
wall-clock deadline on every challenge and denies when it expires.
"""

import asyncio
import contextvars
import logging
import threading
from collections.abc import Callable
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Protocol

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from doberman.models import Decision, ReasonCode, Risk, SecurityObject, Verdict

logger = logging.getLogger("doberman.auth.challenge")

#: Hard wall-clock ceiling on ONE challenge, whichever channel it runs on.
#:
#: Sized above the worst-case *legitimate* fallback chain (dashboard 90s →
#: elicitation 300s → GUI 120s → terminal) run **twice**, because a
#: ``two_factor``/``role_elevation`` tier dispatches the whole chain once for
#: ``confirm()`` and again for ``read_code()``
#: (:meth:`~doberman.auth.provider.LocalAuthProvider._run_tier`) under this one
#: budget. Sizing it for a single pass would let a human who approved the
#: confirm late in the budget be cut off mid-TOTP-entry — manufacturing a denial
#: of an action someone was actively approving, on the highest-risk tiers.
#: It therefore bites only when nobody answers anywhere, where denying is the
#: correct outcome regardless. ``test_the_default_deadline_exceeds_the_worst_case_channel_chain``
#: pins the arithmetic.
DEFAULT_CHALLENGE_TIMEOUT_S = 1200.0

#: :attr:`AuthResult.method` (and the decision log's ``auth_result``) when the
#: deadline expired. Deliberately distinct from ``"denied"`` (a human said no)
#: and ``"error"`` (a channel failed): an audit must be able to tell silence
#: apart from refusal, because they call for different operator responses.
TIMEOUT_METHOD = "timeout"


class AuthTier(StrEnum):
    """The proof an ``AUTH`` requires, weakest → strongest."""

    soft_confirm = "soft_confirm"
    local_auth = "local_auth"
    two_factor = "two_factor"
    role_elevation = "role_elevation"


#: Strength order so "strongest tier wins" is a simple max.
_TIER_ORDER: dict[AuthTier, int] = {
    AuthTier.soft_confirm: 0,
    AuthTier.local_auth: 1,
    AuthTier.two_factor: 2,
    AuthTier.role_elevation: 3,
}

#: Base tier implied by the final risk alone (before reason-specific bumps).
_RISK_TIER: dict[Risk, AuthTier] = {
    Risk.low: AuthTier.soft_confirm,
    Risk.medium: AuthTier.local_auth,
    Risk.high: AuthTier.two_factor,
    Risk.critical: AuthTier.two_factor,
}

#: Minimum tier each reason code warrants. A reason absent here imposes no floor
#: of its own (the risk-derived base still applies). ``role_out_of_scope`` is the
#: one reason that routes to the elevation flow — it is satisfiable by a grant.
_REASON_TIER: dict[ReasonCode, AuthTier] = {
    ReasonCode.role_out_of_scope: AuthTier.role_elevation,
    ReasonCode.policy_source_sensitive: AuthTier.two_factor,
    ReasonCode.sensitive_secret_access: AuthTier.two_factor,
    ReasonCode.opaque_command: AuthTier.two_factor,
    ReasonCode.encoded_exfiltration: AuthTier.two_factor,
    ReasonCode.unknown_external_destination: AuthTier.local_auth,
    ReasonCode.sensitive_path_access: AuthTier.local_auth,
    ReasonCode.bulk_operation: AuthTier.local_auth,
}


def _stronger(a: AuthTier, b: AuthTier) -> AuthTier:
    return a if _TIER_ORDER[a] >= _TIER_ORDER[b] else b


def select_tier(decision: Decision) -> AuthTier:
    """Pick the authentication tier an ``AUTH`` decision requires.

    Strongest-wins across the risk-derived base tier and every reason code's
    minimum, so the result is never weaker than any single signal warrants.

    Raises ``ValueError`` if ``decision`` is not an ``AUTH`` — a ``PASS`` needs
    no challenge and a hard ``BLOCK`` must never be turned into one (the proof
    flow can only *grant*; it can never lift a block).
    """
    if decision.final_verdict is not Verdict.AUTH:
        raise ValueError(f"select_tier requires an AUTH decision, got {decision.final_verdict}")
    tier = _RISK_TIER.get(decision.final_risk, AuthTier.two_factor)
    for reason in decision.reason_codes:
        floor = _REASON_TIER.get(reason)
        if floor is not None:
            tier = _stronger(tier, floor)
    return tier


class Prompter(Protocol):
    """Collects human input for a challenge (injected so tests stay headless).

    Implementations must raise on timeout / no-input so the provider can treat
    it as a denial (fail closed). The default CLI implementation lives in
    :mod:`doberman.auth.provider`.
    """

    def confirm(self, message: str) -> bool: ...

    def read_code(self, message: str) -> str: ...


class AuthResult(BaseModel):
    """The outcome of one challenge (immutable, audit-friendly).

    ``action_id`` ties the approval to exactly one action (no replay onto a
    different call). ``elevation_id`` is set only when a ``role_elevation`` tier
    produced a grant.
    """

    model_config = ConfigDict(frozen=True)

    approved: bool
    tier: AuthTier
    method: str
    at: AwareDatetime
    action_id: str = Field(min_length=1)
    elevation_id: str | None = None


#: The (decision, action, tier) of the challenge currently running on this
#: thread/task, if any — see :func:`current_challenge`.
_current_challenge: contextvars.ContextVar[tuple[Decision, SecurityObject, AuthTier] | None] = (
    contextvars.ContextVar("_current_challenge", default=None)
)


def current_challenge() -> tuple[Decision, SecurityObject, AuthTier] | None:
    """The real ``(decision, action, tier)`` of the challenge in progress here.

    Lets a :class:`Prompter` (e.g. the dashboard's ``DashboardPrompter``) derive
    redaction-safe display fields (risk, reason codes, explanation, path class)
    straight from the typed objects instead of parsing
    :func:`~doberman.auth.provider._challenge_message`'s free-text string, which
    embeds the raw target and is unsafe to persist. ``None`` outside a challenge.

    Set only for the duration of :func:`run_auth_challenge` on the calling
    thread/task; ``asyncio.to_thread`` propagates the current
    ``contextvars.Context`` into its worker thread, so a prompter running there
    (as the proxy's auth challenge does) still sees it.
    """
    return _current_challenge.get()


def _run_with_deadline(
    call: Callable[[], AuthResult],
    *,
    timeout_s: float,
    on_timeout: Callable[[], AuthResult],
    label: str,
) -> AuthResult:
    """Run ``call`` on a daemon worker; give up and deny after ``timeout_s``.

    The deadline lives here rather than inside each prompter for two reasons.
    First, more than one built-in channel can block without end (``GuiPrompter``'s
    ``mainloop``, ``TtyPrompter``'s ``readline`` on a terminal nobody is at), and a
    guarantee re-implemented per channel is one new channel away from being false.
    Second, both the prompter and the provider are **plugin seams** — anything
    registered through ``doberman.auth_providers`` runs here too, and core cannot
    audit code it never imports. A single deadline at the seam covers all of it.

    Python cannot kill a thread blocked in native code, so the worker is a
    **daemon**: on expiry we abandon it. Its answer is discarded — an approval
    that arrives after the deadline is never honoured — and it can never hold up
    interpreter exit.

    A ``BaseException`` from the worker is re-raised verbatim on the caller's
    thread. :func:`run_auth_challenge` (the sole caller) converts a *non-cooperative*
    one — ``SystemExit`` or any other non-``Exception`` ``BaseException`` a plugin
    provider might raise — into a fail-closed denial there, so it can never escape
    past a caller's ``except Exception``. ``asyncio.CancelledError`` alone still
    propagates (cancellation is cooperative). See ADR 0064.

    One known limit remains, pre-existing and deliberately not widened here: an
    abandoned worker keeps running its channel to completion, so a late answer can
    still touch state the challenge itself no longer reads (notably the TOTP lockout
    counter). It cannot approve the action — the result is discarded here — but it is
    not a clean kill.
    """
    box: dict[str, Any] = {}
    # Copy the caller's context so `_current_challenge` (set just above) reaches
    # the worker: DashboardPrompter reads it and falls back when it is missing.
    ctx = contextvars.copy_context()

    def _worker() -> None:
        try:
            box["result"] = ctx.run(call)
        except BaseException as exc:  # noqa: BLE001 — re-raised on the caller's thread
            box["error"] = exc

    worker = threading.Thread(target=_worker, name=f"doberman-auth-{label}", daemon=True)
    worker.start()
    worker.join(timeout_s)
    if worker.is_alive():
        logger.warning(
            "auth challenge unanswered after %.0fs (action %s); denying (fail closed)",
            timeout_s,
            label,
        )
        return on_timeout()
    if "error" in box:
        raise box["error"]
    return box["result"]


def run_auth_challenge(
    decision: Decision,
    action: SecurityObject,
    *,
    prompter: Prompter | None = None,
    at: AwareDatetime | None = None,
    timeout_s: float = DEFAULT_CHALLENGE_TIMEOUT_S,
) -> AuthResult:
    """Select the tier and run the challenge through the active provider.

    ``action`` carries the role/target/tool the challenge names to the human
    (the ``Decision`` alone does not). The provider can only *grant or deny* —
    it never alters the decision's verdict or the required tier. With nothing
    installed, the local provider runs (CLI confirm + TOTP). Lazy-imports the
    provider to avoid an import cycle (challenge defines the types it consumes).

    Returns within ``timeout_s`` no matter what the channel does: an unanswered
    challenge yields a non-approved result with ``method`` set to
    :data:`TIMEOUT_METHOD`. See :func:`_run_with_deadline`.
    """
    from doberman.auth.provider import active_provider

    tier = select_tier(decision)
    token = _current_challenge.set((decision, action, tier))
    try:
        return _run_with_deadline(
            lambda: active_provider().authenticate(
                decision, action, tier, prompter=prompter, at=at
            ),
            timeout_s=timeout_s,
            on_timeout=lambda: AuthResult(
                approved=False,
                tier=tier,
                method=TIMEOUT_METHOD,
                at=at or datetime.now(timezone.utc),
                action_id=action.id,
            ),
            label=action.id,
        )
    except asyncio.CancelledError:
        raise  # cooperative cancellation must reach the event loop, never a denial
    except BaseException as exc:  # noqa: BLE001 — fail closed on ANY non-cooperative BaseException
        if isinstance(exc, Exception):
            raise  # a regular error keeps propagating to the caller's own `except Exception`
        # A non-``Exception`` BaseException (``SystemExit``, or a plugin provider's own
        # BaseException subclass) would slip past every caller's ``except Exception`` and
        # escape the fail-closed path entirely. Deny it here, at the one provider seam —
        # tagged ``"error"`` so the audit tells it apart from a timeout or a human "no".
        # ADR 0064; Prime Directive 1 (fail closed) is why this catch is this broad.
        # ponytail: a BaseExceptionGroup wrapping a CancelledError also denies here rather
        # than unwrapping to re-raise — the worker ran on a daemon thread whose result is
        # discarded, so there is no live coroutine to cancel cooperatively; a fail-closed
        # deny is the correct outcome, not an unwrap TODO.
        logger.warning(
            "auth challenge worker raised %s (action %s); denying (fail closed)",
            type(exc).__name__,
            action.id,
        )
        return AuthResult(
            approved=False,
            tier=tier,
            method="error",
            at=at or datetime.now(timezone.utc),
            action_id=action.id,
        )
    finally:
        _current_challenge.reset(token)
