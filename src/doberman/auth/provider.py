"""The ``AuthProvider`` seam + the local provider (Feature 7, slice 7.6).

Core ships exactly one auth backend — the **local** provider (CLI confirm +
TOTP, slices 7.1–7.3). Alternative backends (SSO/RBAC, hosted/push approvals)
live in separately-installed packages that register an :class:`AuthProvider`
through the ``doberman.auth_providers`` entry-point group — so core never
imports them by name (the repo-boundary rule).

A registered provider is **opt-in by name**, via the shared plugins allowlist
(:mod:`doberman.engine.plugin_config` — ``doberman plugins enable <name>``).
Installing a package is never enough on its own — otherwise any installed
package could silently become the sole authenticator. A chosen provider is
wrapped in :class:`CoGatedProvider`, which ALWAYS additionally requires the
built-in local provider's consent, for every tier — a plugin's approval is
necessary but never sufficient, so a compromised or malicious plugin can
never authenticate anything alone; the human is always asked too.

SECURITY: a provider can only **grant or deny**. It cannot change the decision's
verdict or the required :class:`~doberman.auth.challenge.AuthTier`, and it
receives only the already-final :class:`~doberman.models.Decision` plus the
redacted action. If a provider raises, times out, or returns a non-approval, the
action is **denied** (fail closed). With nothing opted in, or no opted-in
provider found, the local provider runs and behavior is identical to
core-only.

This module imports the F3 entry-point registry for discovery but never imports
``doberman.proxy``.
"""

import logging
from datetime import datetime, timezone
from typing import Protocol, runtime_checkable

from doberman.auth import totp
from doberman.auth.approval import ApprovalOutcome, request_approval, resolve_approval_method
from doberman.auth.challenge import AuthResult, AuthTier, Prompter
from doberman.explain import _describe_reason
from doberman.models import ActionType, Decision, SecurityObject

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
        message_tone: str = "human",
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


#: Plain-language verb for the S1 "human" tone's first line. ``other`` is what
#: an unrecognized/generic MCP tool normalizes to (see proxy/normalize.py), so
#: it reads as "use a tool" rather than the more generic fallback below. An
#: ActionType genuinely absent here falls back to "do this" — never inventing
#: a more specific-sounding claim than the action type actually supports.
_PLAIN_VERBS: dict[ActionType, str] = {
    ActionType.file_write: "write to a file",
    ActionType.file_read: "read a file",
    ActionType.file_delete: "delete a file",
    ActionType.shell_exec: "run a command",
    ActionType.network_request: "send data out",
    ActionType.other: "use a tool",
}


def _plain_verb(action_type: ActionType) -> str:
    return _PLAIN_VERBS.get(action_type, "do this")


def _plain_why(decision: Decision) -> str:
    """One capitalized sentence explaining the reason, reusing explain.py's copy.

    No reason codes → the decision's own explanation, or a safe generic default.
    Never oversells — it states the recorded reason, not a verdict on intent.
    """
    if decision.reason_codes:
        fragments = [_describe_reason(code) for code in decision.reason_codes]
        sentence = "; ".join(fragments)
    else:
        sentence = decision.explanation.strip() or "Doberman flagged this action for review"
    sentence = sentence.strip().rstrip(".")
    return sentence[:1].upper() + sentence[1:] + "."


def _challenge_message(
    decision: Decision, action: SecurityObject, tier: AuthTier, tone: str = "human"
) -> str:
    """Build a prompt that names the EXACT action, target, and reason.

    Shown only to the local human approving the action (never logged), so it may
    include the concrete target — that is the whole point of an action-specific
    challenge ("approve THIS file", not a generic "enter 2FA"). ``tone``
    controls wording only: "technical" is the original detailed format,
    "human" (the default, S1) is a plain, friendly rendering of the exact same
    facts — reason codes stay on the Decision and in the logs either way.
    """
    target = action.target or "(no target)"
    notice = action.metadata.get("approval_memory_notice")
    prefix = f"{notice}\n\n" if isinstance(notice, str) and notice else ""
    if tone == "technical":
        reasons = ", ".join(decision.reason_codes) or "unspecified"
        return prefix + (
            f"[RISK: {decision.final_risk.upper()}]  Doberman authentication required [{tier.value}]\n"
            f"  role:   {action.agent_role}\n"
            f"  action: {action.tool_name} -> {target}\n"
            f"  reason: {reasons} - {decision.explanation.strip() or 'no further detail'}\n"
            f"Approve THIS exact action?"
        )
    return prefix + (
        f"Your agent wants to {_plain_verb(action.action_type)}:\n"
        f"\n"
        f"    {target}\n"
        f"\n"
        f"{_plain_why(decision)}\n"
        f"\n"
        f"Approve this exact action?"
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
        message_tone: str = "human",
    ) -> AuthResult:
        prompter = prompter or CliPrompter()
        when = at or datetime.now(timezone.utc)
        message = _challenge_message(decision, action, tier, message_tone)

        try:
            approved, method = self._run_tier(tier, message, prompter, action.id)
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
    def _run_tier(
        tier: AuthTier, message: str, prompter: Prompter, action_id: str = ""
    ) -> tuple[bool, str]:
        """Collect tier-appropriate proof. Returns (approved, method).

        For the 2FA tiers, a configured approval method (a Windows Hello / Touch ID
        biometric, a phone push — :mod:`doberman.auth.approval`) is presence AND
        possession in a single tap and **replaces the TOTP code**. It runs only when
        the user has explicitly enabled an available method; if none is enabled, or
        the method reports itself unavailable, the flow falls back to confirm + TOTP
        — still a real second factor, never a bypass. Only an explicit human
        ``approved`` (or a valid TOTP code) satisfies the tier; a timeout, cancel,
        error, or ``denied`` all deny.
        """
        if tier in (AuthTier.soft_confirm, AuthTier.local_auth):
            return prompter.confirm(message), tier.value

        # two_factor and role_elevation require presence AND possession.
        elevation = tier is AuthTier.role_elevation
        method = resolve_approval_method()
        if method is not None:
            outcome = request_approval(method, message, action_id=action_id)
            if outcome is ApprovalOutcome.approved:
                return True, f"{method.name}+elevation" if elevation else method.name
            if outcome is ApprovalOutcome.denied:
                return False, "denied"
            # ApprovalOutcome.unavailable -> fall through to the TOTP path below.

        if not prompter.confirm(message):
            return False, "denied"
        code = prompter.read_code("Enter your 2FA code")
        return totp.verify(code), "totp+elevation" if elevation else "totp"


#: The single built-in provider, constructed once.
LOCAL_PROVIDER = LocalAuthProvider()


def _looks_like_auth_provider(obj: object) -> bool:
    """Structural check (the Protocol's isinstance is method-name only)."""
    return callable(getattr(obj, "authenticate", None))


class CoGatedProvider:
    """Wraps an opted-in plugin provider; ALWAYS also requires local consent.

    A plugin's approval is necessary but never sufficient: after the wrapped
    provider approves (and the result is bound to THIS action id), the
    built-in :data:`LOCAL_PROVIDER` is ALSO run, for every tier — the human is
    always asked, so a compromised or malicious plugin can never authenticate
    anything on its own. Both must approve; the method name records both
    (``"<plugin>+local"``). A plugin raise, denial, or mismatched action id is
    a denial WITHOUT running the local side (no reason to bother the human
    when the plugin has already said no or produced garbage). Never raises.
    """

    def __init__(self, inner: AuthProvider) -> None:
        self.inner = inner

    def authenticate(
        self,
        decision: Decision,
        action: SecurityObject,
        tier: AuthTier,
        *,
        prompter: Prompter | None = None,
        at: datetime | None = None,
        message_tone: str = "human",
    ) -> AuthResult:
        when = at or datetime.now(timezone.utc)
        try:
            result = self.inner.authenticate(
                decision, action, tier, prompter=prompter, at=at, message_tone=message_tone
            )
        except Exception:  # noqa: BLE001 — a plugin error must not crash the auth path
            logger.warning("auth provider %r raised; denying", type(self.inner).__name__)
            return AuthResult(
                approved=False, tier=tier, method="error", at=when, action_id=action.id
            )

        if not result.approved or result.action_id != action.id:
            return AuthResult(
                approved=False, tier=tier, method=result.method, at=when, action_id=action.id
            )

        local_result = LOCAL_PROVIDER.authenticate(
            decision, action, tier, prompter=prompter, at=at, message_tone=message_tone
        )
        return AuthResult(
            approved=local_result.approved,
            tier=tier,
            method=f"{result.method}+local",
            at=when,
            action_id=action.id,
        )


def active_provider() -> AuthProvider:
    """Return the active provider: an opted-in plugin (co-gated), else local.

    A registered ``doberman.auth_providers`` plugin is used only if its name is
    in the shared plugins allowlist (:mod:`doberman.engine.plugin_config`) —
    installing the package is never enough on its own. The chosen plugin is
    wrapped in :class:`CoGatedProvider`, which additionally requires the local
    provider's consent for EVERY tier, not just role elevation. Nothing opted
    in, or no opted-in provider found, returns the local provider unchanged
    (fail closed).
    """
    # Lazy import: the registry lives in the engine layer.
    from doberman.engine.registry import discover_auth_providers

    for candidate in discover_auth_providers():
        if _looks_like_auth_provider(candidate):
            return CoGatedProvider(candidate)  # type: ignore[arg-type]
        logger.warning("skipping auth provider %r: not auth-provider-shaped", candidate)

    return LOCAL_PROVIDER
