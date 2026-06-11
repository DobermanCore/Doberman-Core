"""Security strength modes (Feature 6, slice 6.3).

One dial — **Light / Balanced / Strict / Paranoid** (default Balanced) — tunes
how aggressively Doberman steps up to authentication, instead of dozens of
toggles. Stricter modes lower step-up thresholds (→ *more* AUTH); they never
touch the **floor** of core hard blocks, which are identical across every mode.

SECURITY: modes may only tune **step-ups** (AUTH thresholds). They can never
remove or weaken a core hard **BLOCK** — that floor (:data:`FLOOR_HARD_BLOCKS`)
is mode-independent, and even Light keeps every one of them. Loosening a hard
block is not a mode change; it is a policy weakening that must go through the
Feature 10 human-approved path.

This module is policy core: it imports only ``doberman.models`` and never the
proxy.
"""

from dataclasses import dataclass
from enum import StrEnum

from doberman.models import ReasonCode


class SecurityMode(StrEnum):
    """The four security strength modes, from most permissive to most strict."""

    light = "light"
    balanced = "balanced"
    strict = "strict"
    paranoid = "paranoid"


#: The default mode when none is configured.
DEFAULT_MODE = SecurityMode.balanced


@dataclass(frozen=True)
class ModeThresholds:
    """Tunable step-up thresholds for a mode (never affects hard blocks).

    Attributes:
        bulk_delete_threshold: delete operand count at/above which a delete
            steps up to AUTH (lower = stricter = more AUTH).
        escalate_out_of_scope: whether an out-of-scope (role) action steps up.
        escalate_unknown_destination: whether an unknown network destination
            steps up on its own.
        escalate_unusual: whether an unusual/abnormal action (F9) steps up.
    """

    bulk_delete_threshold: int
    escalate_out_of_scope: bool = True
    escalate_unknown_destination: bool = True
    escalate_unusual: bool = True
    #: Abnormality score (0..1) at/above which the subjective guardrail (F9)
    #: steps an action up to AUTH. Lower = stricter (more AUTH). Only applies
    #: when ``escalate_unusual`` is True (Light disables the step-up entirely).
    abnormality_threshold: float = 0.7


#: Per-mode thresholds. Stricter modes lower the bulk threshold (more AUTH);
#: Balanced's 25 matches the historical default so existing behavior is stable.
MODES: dict[SecurityMode, ModeThresholds] = {
    SecurityMode.light: ModeThresholds(
        bulk_delete_threshold=100,
        escalate_unusual=False,
        abnormality_threshold=1.1,  # unreachable: Light never steps up on abnormality
    ),
    SecurityMode.balanced: ModeThresholds(
        bulk_delete_threshold=25,
        abnormality_threshold=0.7,
    ),
    SecurityMode.strict: ModeThresholds(
        bulk_delete_threshold=10,
        abnormality_threshold=0.5,
    ),
    SecurityMode.paranoid: ModeThresholds(
        bulk_delete_threshold=3,
        abnormality_threshold=0.3,
    ),
}

#: The non-negotiable floor: reason codes that are ALWAYS a hard BLOCK, in every
#: mode. No mode or checklist toggle removes these (that requires F10's flow).
FLOOR_HARD_BLOCKS: frozenset[ReasonCode] = frozenset(
    {
        ReasonCode.secret_exfiltration,
        ReasonCode.protected_path_blocked,
        ReasonCode.destructive_command,
        ReasonCode.role_blocked_target,
        ReasonCode.policy_source_blocked,
    }
)


def resolve_mode(name: str | SecurityMode) -> SecurityMode:
    """Resolve a mode name (case-insensitive) to a :class:`SecurityMode`.

    Raises ``ValueError`` on an unknown mode — an unrecognized strength setting
    must be rejected, never silently treated as permissive.
    """
    if isinstance(name, SecurityMode):
        return name
    try:
        return SecurityMode(str(name).strip().lower())
    except ValueError as exc:
        valid = ", ".join(m.value for m in SecurityMode)
        raise ValueError(f"unknown security mode {name!r}; valid modes: {valid}") from exc


def thresholds_for(name: str | SecurityMode) -> ModeThresholds:
    """Return the :class:`ModeThresholds` for ``name``.

    An unknown/garbage mode falls back to the **strictest** thresholds (fail
    toward more authentication, never less) rather than raising — callers in the
    decision path must never crash on a bad stored mode.
    """
    try:
        mode = resolve_mode(name)
    except ValueError:
        return MODES[SecurityMode.paranoid]
    return MODES[mode]
