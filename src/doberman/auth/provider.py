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
from typing import Any, Protocol, runtime_checkable

from doberman.auth import totp
from doberman.auth.approval import ApprovalOutcome, request_approval, resolve_approval_method
from doberman.auth.challenge import (
    EFFECT_SET_LABEL,
    AuthResult,
    AuthTier,
    Prompter,
    format_effect_set,
)
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


#: What satisfying each tier actually requires, in plain words, for the risk line
#: ("Risk: high - this needs your code"). Keyed by tier (not risk) because the
#: proof required is a function of the tier, not the raw risk label.
_TIER_HINT: dict[AuthTier, str] = {
    AuthTier.soft_confirm: "confirm to continue",
    AuthTier.local_auth: "confirm to continue",
    AuthTier.two_factor: "this needs your code",
    AuthTier.role_elevation: "this needs your code",
}


def challenge_parts(
    decision: Decision, action: SecurityObject, tier: AuthTier, tone: str = "human"
) -> dict[str, Any]:
    """The structured facts behind one challenge, tagged by NAME rather than by
    position or leading whitespace.

    Feeds both :func:`_challenge_message` (the plain-string message every
    ``Prompter`` — TTY, dashboard, a plugin — already understands) and a
    structured prompter's ``confirm_challenge``/``read_code_challenge`` (the
    GUI): both render the exact same underlying facts, only the plain-string
    path flattens them into prose first. Because the GUI reads named fields
    instead of sniffing indentation out of a rendered string, nothing in
    ``action.target`` can forge itself into looking like the risk line or the
    question (the old leading-whitespace-means-"the command" heuristic).

    ``tone`` changes wording only ("technical" is the original detailed
    format; "human", the default, is a plain rendering of the same facts) —
    reason codes stay on the ``Decision`` and in the logs either way.

    ``deadline_s`` is deliberately left ``None`` here: this module has no
    opinion on any one channel's timeout (the GUI dialog's real, enforced
    countdown is owned by :class:`~doberman.auth.gui_prompter.GuiPrompter`
    itself) — a value here would be decorative at best and misleading at
    worst if a renderer trusted it over the deadline it actually enforces.

    ``action_id`` is included for outcome LOGGING only (the GUI logs one INFO
    line per dialog: the outcome and this id, never the target) — it is never
    itself rendered to the human.

    ``effects`` is the ONE shared blast-radius display string (ADR 0094,
    :func:`~doberman.auth.challenge.format_effect_set`) for a delete-class
    AUTH's ``decision.effects`` — every prompter renders this exact string,
    so the channels cannot drift. ``None`` for every non-delete-class AUTH.
    """
    # The challenge copy of the action carries a prompt-only rendering of the
    # raw arguments when the caller could build one (proxy.normalize
    # .display_target), so the human reads the command rather than the log's
    # wholesale "<redacted>" target.
    shown = action.metadata.get("display_target")
    target = shown if isinstance(shown, str) and shown else (action.target or "(no target)")
    notice = action.metadata.get("approval_memory_notice")
    notice = notice if isinstance(notice, str) and notice else None
    risk_word = decision.final_risk.value
    tier_hint = _TIER_HINT.get(tier, "confirm to continue")

    if tone == "technical":
        reasons = ", ".join(decision.reason_codes) or "unspecified"
        # The bracket embedded in the HEADLINE stays a bare "RISK: HIGH" (the
        # flat-string TTY/dashboard rendering has no severity chip of its own,
        # so the bracket is that channel's only severity signal); parts["risk"]
        # itself, which the GUI's risk LINE renders, additionally carries the
        # tier hint -- "RISK: HIGH - this needs your code" -- so it never reads
        # as a bare, unexplained repeat of the word the chip/bracket already
        # show (item 4: never "HIGH  RISK: HIGH" with nothing else said).
        risk = f"RISK: {risk_word.upper()} - {tier_hint}"
        headline = f"[RISK: {risk_word.upper()}]  Doberman authentication required [{tier.value}]"
        verb = action.tool_name
        why = f"{reasons} - {decision.explanation.strip() or 'no further detail'}"
    else:
        risk = f"Risk: {risk_word} - {tier_hint}"
        verb = _plain_verb(action.action_type)
        headline = f"Your agent wants to {verb}:"
        why = _plain_why(decision)

    return {
        "tone": tone,
        "headline": headline,
        "verb": verb,
        "target": target,
        "why": why,
        "risk": risk,
        "tier": tier.value,
        "role": action.agent_role,
        "tool": action.tool_name,
        "notice": notice,
        "deadline_s": None,
        "action_id": action.id,
        "effects": format_effect_set(decision.effects),
    }


def _message_from_parts(parts: dict[str, Any]) -> str:
    """Flatten :func:`challenge_parts` into the plain-string message every
    ``Prompter`` (TTY, dashboard, a plugin that only implements ``confirm``)
    already understands. Shared by :func:`_challenge_message` and the
    ``FallbackPrompter`` chain's per-channel fallback.

    ``parts.get("effects")`` (ADR 0094's blast-radius line — see
    :func:`challenge_parts`) renders as one extra line when present, nothing
    when it is ``None`` or absent (a hand-built ``parts`` dict from an older
    caller/test). ``.get`` throughout, never ``parts["effects"]`` — the key
    was added after this function's original contract.
    """
    prefix = f"{parts['notice']}\n\n" if parts["notice"] else ""
    effects = parts.get("effects")
    if parts["tone"] == "technical":
        effects_line = f"  {EFFECT_SET_LABEL.lower()}: {effects}\n" if effects else ""
        return prefix + (
            f"{parts['headline']}\n"
            f"  role:   {parts['role']}\n"
            f"  action: {parts['verb']} -> {parts['target']}\n"
            f"  reason: {parts['why']}\n"
            f"{effects_line}"
            f"Approve THIS exact action?"
        )
    effects_line = f"{EFFECT_SET_LABEL}: {effects}\n\n" if effects else ""
    return prefix + (
        f"{parts['headline']}\n"
        f"\n"
        f"    {parts['target']}\n"
        f"\n"
        f"{parts['why']}\n"
        f"\n"
        f"{effects_line}"
        f"{parts['risk']}\n"
        f"\n"
        f"Approve this exact action?"
    )


def _challenge_message(
    decision: Decision, action: SecurityObject, tier: AuthTier, tone: str = "human"
) -> str:
    """Build a prompt that names the EXACT action, target, and reason.

    Shown only to the local human approving the action (never logged), so it may
    include the concrete target — that is the whole point of an action-specific
    challenge ("approve THIS file", not a generic "enter 2FA"). A thin wrapper
    over :func:`challenge_parts` + :func:`_message_from_parts` — see
    :func:`challenge_parts` for what "tone" changes and what it doesn't.
    """
    return _message_from_parts(challenge_parts(decision, action, tier, tone))


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
        parts = challenge_parts(decision, action, tier, message_tone)
        message = _message_from_parts(parts)

        try:
            approved, method = self._run_tier(tier, message, prompter, action.id, parts=parts)
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
        tier: AuthTier,
        message: str,
        prompter: Prompter,
        action_id: str = "",
        *,
        parts: dict[str, Any] | None = None,
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

        ``parts`` (from :func:`challenge_parts`) is optional and keyword-only so
        every existing positional call (``message`` alone) keeps working
        unchanged: when a prompter implements ``confirm_challenge``/
        ``read_code_challenge`` (the GUI) it is consulted with the structured
        facts instead of the flattened ``message`` string; any other prompter
        (TTY, dashboard, a plugin, or ``parts=None``) falls back to
        ``confirm(message)``/``read_code(message)`` exactly as before.

        Every branch reports its outcome through the prompter's OPTIONAL
        ``notify_outcome(parts, outcome)`` (getattr-gated, never raises, never
        called when ``parts`` is unavailable) — a wrong-but-well-formed code
        must not just silently close the window (item 4).
        """

        def _confirm() -> bool:
            structured = getattr(prompter, "confirm_challenge", None) if parts else None
            if structured is not None:
                return bool(structured(parts))
            return bool(prompter.confirm(message))

        def _read_code(fallback_message: str) -> str:
            structured = getattr(prompter, "read_code_challenge", None) if parts else None
            if structured is not None:
                return str(structured(parts))
            return str(prompter.read_code(fallback_message))

        def _notify(outcome: str) -> None:
            notify = getattr(prompter, "notify_outcome", None) if parts else None
            if notify is None:
                return
            try:
                notify(parts, outcome)
            except Exception:  # noqa: S110 — cosmetic only, must never affect the auth outcome
                pass

        def _deny_outcome() -> str:
            """ "denied" normally, but "expired" when the prompter's own last
            answer resolved via a countdown timeout rather than a real Deny
            click/keypress (``GuiPrompter.last_reason`` -- getattr-gated, so a
            prompter with no such concept, e.g. the TTY channel, always reads
            as a plain denial). Distinguishing the two matters for
            ``notify_outcome``'s toast text (item 3): a silent timeout and a
            deliberate Deny are different facts for the human to see.
            """
            if getattr(prompter, "last_reason", None) == "expired":
                return "expired"
            return "denied"

        if tier in (AuthTier.soft_confirm, AuthTier.local_auth):
            approved = _confirm()
            _notify("approved" if approved else _deny_outcome())
            return approved, tier.value

        # two_factor and role_elevation require presence AND possession.
        elevation = tier is AuthTier.role_elevation
        method = resolve_approval_method()
        if method is not None:
            outcome = request_approval(method, message, action_id=action_id)
            if outcome is ApprovalOutcome.approved:
                _notify("approved")
                return True, f"{method.name}+elevation" if elevation else method.name
            if outcome is ApprovalOutcome.denied:
                _notify("denied")
                return False, "denied"
            # ApprovalOutcome.unavailable -> fall through to the TOTP path below.

        if not _confirm():
            outcome = _deny_outcome()
            _notify(outcome)
            return False, outcome
        # Names the exact target, mirroring the GUI's structured code dialog
        # (item 8) -- a human landing on a bare terminal code prompt should
        # not have to trust that it's still about the same action the first
        # (confirm) prompt named.
        code_prompt = (
            f"Enter your 2FA code to approve: {parts['target']}"
            if parts
            else ("Enter your 2FA code")
        )
        code = _read_code(code_prompt)
        verified = totp.verify(code)
        _notify("approved" if verified else "code_rejected")
        return verified, "totp+elevation" if elevation else "totp"


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
