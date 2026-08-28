"""Pluggable approval methods — the second factor as a tap, not a typed code.

An :class:`ApprovalMethod` answers one yes/no question about one specific action
(a Windows Hello / Touch ID biometric prompt, a push to a phone, ...). It is the
*possession/inherence* factor that can stand in for the TOTP code on a
``two_factor`` / ``role_elevation`` challenge: the human proves presence AND
possession with a single tap instead of reading a code off an authenticator app.

Wiring lives in :func:`doberman.auth.provider.LocalAuthProvider._run_tier`: on a
2FA-tier challenge, the configured method (if any is enabled AND available) runs
first; TOTP remains the fallback whenever no method is available. Methods are
strictly **opt-in** (see :mod:`doberman.auth.approval_config`) — with nothing
enabled, the challenge behaves exactly as before.

SECURITY CONTRACT (every method must honour it; the resolver enforces it too):

* **Fail closed.** A timeout, a cancel, an error, or any ambiguity resolves to
  ``denied`` — never ``approved``. :func:`request_approval` wraps a method so a
  raised exception can never leak out as an approval.
* **Available means available.** :meth:`ApprovalMethod.is_available` is
  conservative: it returns ``False`` on any doubt (wrong OS, missing optional
  dependency, no enrolled device). An unavailable method yields ``unavailable``,
  and the caller falls back to TOTP — still a real second factor, never a bypass.
* **Action-bound.** ``request`` is handed a human prompt naming the exact action
  and the action id, so an approval can be tied to one action (a push backend
  correlates its callback by that id; a local biometric shows the prompt).
* **Never a bypass.** ``unavailable`` must not skip the second factor — it only
  defers to TOTP. Only an explicit human ``approved`` satisfies the tier.
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import Protocol, runtime_checkable

logger = logging.getLogger("doberman.auth.approval")

#: How long one approval request waits for the human before it gives up and
#: denies. Kept below :data:`doberman.auth.challenge.DEFAULT_CHALLENGE_TIMEOUT_S`
#: so the method resolves (visibly denying) before the outer challenge deadline
#: has to abandon the thread — same discipline as the GUI dialog timeout.
DEFAULT_APPROVAL_TIMEOUT_S: float = 90.0


class ApprovalOutcome(Enum):
    """The result of one approval request.

    ``unavailable`` is distinct from ``denied`` on purpose: it means "this
    channel could not run at all" (fall through to the next factor / TOTP),
    whereas ``denied`` is a real human "no" (final — never fall through, or that
    would be answer-shopping). Silence, timeout, and errors are ``denied``.
    """

    approved = "approved"
    denied = "denied"
    unavailable = "unavailable"


@runtime_checkable
class ApprovalMethod(Protocol):
    """A possession/inherence factor that approves one specific action.

    Implementations are discovered as built-ins or via the
    ``doberman.approval_methods`` entry-point group. They MUST honour the
    security contract in this module's docstring.
    """

    #: Stable, lowercase identifier used in config and audit (``windows_hello``,
    #: ``duo``, ``telegram``, ...). Must match the config/CLI name.
    name: str

    def is_available(self) -> bool:
        """True only if this method can run a real challenge right now.

        Conservative: any doubt (wrong platform, missing optional dependency, no
        enrolled device/credential) returns ``False``. Must never raise.
        """
        ...

    def request(self, prompt: str, *, action_id: str, timeout_s: float) -> ApprovalOutcome:
        """Ask the human to approve the action described by ``prompt``.

        Blocks up to ``timeout_s``. Returns ``approved`` only on an explicit human
        yes; ``denied`` on a human no, a timeout, or any error; ``unavailable`` if
        the channel turns out unusable (the caller then falls back to TOTP). Must
        never raise — see :func:`request_approval`, which enforces this.
        """
        ...


def request_approval(
    method: ApprovalMethod,
    prompt: str,
    *,
    action_id: str,
    timeout_s: float = DEFAULT_APPROVAL_TIMEOUT_S,
) -> ApprovalOutcome:
    """Run ``method.request`` fail-closed: any exception becomes ``denied``.

    This is the ONLY sanctioned way to invoke a method, so a buggy or hostile
    backend can never turn a raised exception (or a non-outcome return) into an
    approval. A method that reports itself unavailable up front short-circuits to
    ``unavailable`` without being asked.
    """
    try:
        if not method.is_available():
            return ApprovalOutcome.unavailable
        outcome = method.request(prompt, action_id=action_id, timeout_s=timeout_s)
    except Exception:  # noqa: BLE001 — fail closed: a broken method must deny, never approve
        logger.warning(
            "approval method %r raised; denying (fail closed)", getattr(method, "name", method)
        )
        return ApprovalOutcome.denied
    if not isinstance(outcome, ApprovalOutcome):
        # A backend that returned something other than an ApprovalOutcome is
        # broken; treat it as a denial rather than truthiness-testing it.
        logger.warning(
            "approval method %r returned a non-outcome; denying", getattr(method, "name", method)
        )
        return ApprovalOutcome.denied
    return outcome


def resolve_approval_method() -> ApprovalMethod | None:
    """The highest-preference ENABLED and AVAILABLE approval method, or ``None``.

    Reads the opt-in enabled list (:func:`doberman.auth.approval_config.enabled_methods`,
    in preference order) and the built-in + entry-point registry
    (:func:`doberman.engine.registry.discover_approval_methods`). Returns the first
    enabled method that is currently available; ``None`` if none are (the caller
    then uses TOTP). Never raises — any error resolving config/registry yields
    ``None`` (fail-safe: fall back to TOTP, which is still a real second factor).
    """
    try:
        from doberman.auth.approval_config import enabled_methods
        from doberman.engine.registry import discover_approval_methods

        wanted = enabled_methods()
        if not wanted:
            return None
        available = {
            m.name: m for m in discover_approval_methods() if isinstance(m, ApprovalMethod)
        }
        for name in wanted:
            method = available.get(name)
            if method is not None and method.is_available():
                return method
        return None
    except Exception:  # noqa: BLE001 — resolution failure must fall back to TOTP, never bypass
        logger.warning("resolving an approval method failed; falling back to TOTP", exc_info=True)
        return None
