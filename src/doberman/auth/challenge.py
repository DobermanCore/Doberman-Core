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
"""

from enum import StrEnum
from typing import Protocol

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from doberman.models import Decision, ReasonCode, Risk, SecurityObject, Verdict


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


def run_auth_challenge(
    decision: Decision,
    action: SecurityObject,
    *,
    prompter: Prompter | None = None,
    at: AwareDatetime | None = None,
) -> AuthResult:
    """Select the tier and run the challenge through the active provider.

    ``action`` carries the role/target/tool the challenge names to the human
    (the ``Decision`` alone does not). The provider can only *grant or deny* —
    it never alters the decision's verdict or the required tier. With nothing
    installed, the local provider runs (CLI confirm + TOTP). Lazy-imports the
    provider to avoid an import cycle (challenge defines the types it consumes).
    """
    from doberman.auth.provider import active_provider

    tier = select_tier(decision)
    return active_provider().authenticate(decision, action, tier, prompter=prompter, at=at)
