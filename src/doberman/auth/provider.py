"""The ``AuthProvider`` seam + the local provider (Feature 7, slice 7.6).

Core ships exactly one auth backend — the **local** provider (CLI confirm +
TOTP, slices 7.1–7.3). Alternative backends (SSO/RBAC, hosted/push approvals)
live in separately-installed packages that register an :class:`AuthProvider`
through the ``doberman.auth_providers`` entry-point group — so core never
imports them by name (the repo-boundary rule).

SECURITY: a provider can only **grant or deny**. It cannot change the decision's
verdict or the required :class:`~doberman.auth.challenge.AuthTier`, and it
receives only the already-final :class:`~doberman.models.Decision` plus the
redacted action. If a provider raises, times out, or returns a non-approval, the
action is **denied** (fail closed). With nothing registered, the local provider
runs and behavior is identical to core-only.

This module imports the F3 entry-point registry for discovery but never imports
``doberman.proxy``.
"""

import logging
from datetime import datetime, timezone
from typing import Protocol, runtime_checkable

from doberman.auth import totp
from doberman.auth.challenge import AuthResult, AuthTier, Prompter
from doberman.models import Decision, SecurityObject

logger = logging.getLogger("doberman.auth.provider")


@runtime_checkable
class AuthProvider(Protocol):
    """A backend that turns a challenge into an :class:`AuthResult`.

    Implementations live in core (the local provider) or in installed packages
    registered via ``doberman.auth_providers``. ``authenticate`` must never
    raise into the caller — failure is expressed as a non-approved result.
    """

    def authenticate(
        self,
        decision: Decision,
        action: SecurityObject,
        tier: AuthTier,
        *,
        prompter: Prompter | None = None,
        at: datetime | None = None,
    ) -> AuthResult: ...


class CliPrompter:
    """The default :class:`Prompter`: ask the local human at the terminal.

    Backed by Typer/Click. On EOF/abort it raises (Click's ``Abort``), which the
    provider treats as a denial — there is no silent default-yes.
    """

    def confirm(self, message: str) -> bool:
        import typer

        return bool(typer.confirm(message))

    def read_code(self, message: str) -> str:
        import typer

        return str(typer.prompt(message, hide_input=True))


def _challenge_message(decision: Decision, action: SecurityObject, tier: AuthTier) -> str:
    """Build a prompt that names the EXACT action, target, and reason.

    Shown only to the local human approving the action (never logged), so it may
    include the concrete target — that is the whole point of an action-specific
    challenge ("approve THIS file", not a generic "enter 2FA").
    """
    reasons = ", ".join(decision.reason_codes) or "unspecified"
    target = action.target or "(no target)"
    return (
        f"[RISK: {decision.final_risk.upper()}]  Doberman authentication required [{tier.value}]\n"
        f"  role:   {action.agent_role}\n"
        f"  action: {action.tool_name} -> {target}\n"
        f"  reason: {reasons} - {decision.explanation.strip() or 'no further detail'}\n"
        f"Approve THIS exact action?"
    )


class LocalAuthProvider:
    """Local CLI + TOTP provider. The default when no other is registered."""

    name = "local"

    def authenticate(
        self,
        decision: Decision,
        action: SecurityObject,
        tier: AuthTier,
        *,
        prompter: Prompter | None = None,
        at: datetime | None = None,
    ) -> AuthResult:
        prompter = prompter or CliPrompter()
        when = at or datetime.now(timezone.utc)
        message = _challenge_message(decision, action, tier)

        try:
            approved, method = self._run_tier(tier, message, prompter)
        except Exception:  # noqa: BLE001 — any input/timeout error is a denial
            logger.info("local auth challenge failed for action %s; denying", action.id)
            approved, method = False, "error"

        return AuthResult(
            approved=approved,
            tier=tier,
            method=method,
            at=when,
            action_id=action.id,
        )

    @staticmethod
    def _run_tier(tier: AuthTier, message: str, prompter: Prompter) -> tuple[bool, str]:
        """Collect tier-appropriate proof. Returns (approved, method)."""
        if tier in (AuthTier.soft_confirm, AuthTier.local_auth):
            return prompter.confirm(message), tier.value

        # two_factor and role_elevation both require presence AND a TOTP code.
        if not prompter.confirm(message):
            return False, "denied"
        code = prompter.read_code("Enter your 2FA code")
        return totp.verify(code), "totp" if tier is AuthTier.two_factor else "totp+elevation"


#: The single built-in provider, constructed once.
LOCAL_PROVIDER = LocalAuthProvider()


def _looks_like_auth_provider(obj: object) -> bool:
    """Structural check (the Protocol's isinstance is method-name only)."""
    return callable(getattr(obj, "authenticate", None))


def active_provider() -> AuthProvider:
    """Return the active provider: the first registered one, else local.

    Discovery uses the F3 entry-point registry (group
    ``doberman.auth_providers``); a registered provider that is not
    auth-provider-shaped is skipped. With nothing installed, returns the local
    provider — standalone behavior is unchanged.
    """
    # Lazy import: the registry lives in the engine layer.
    from doberman.engine.registry import discover_auth_providers

    for candidate in discover_auth_providers():
        if _looks_like_auth_provider(candidate):
            return candidate  # type: ignore[return-value]
        logger.warning("skipping auth provider %r: not auth-provider-shaped", candidate)
    return LOCAL_PROVIDER
