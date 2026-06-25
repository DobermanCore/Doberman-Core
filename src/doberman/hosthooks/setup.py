"""Non-interactive helper logic for ``doberman setup`` (HK.4).

This module contains pure/non-IO functions so they are easy to unit-test and
so the ``setup`` CLI command stays thin (IO only). None of these functions
prompt, echo, or write files — the command layer does that.
"""

from __future__ import annotations

from doberman.policy.modes import SecurityMode

#: One-line description for each mode shown during the setup wizard.
MODE_DESCRIPTIONS: dict[SecurityMode, str] = {
    SecurityMode.light: "Minimal step-ups; only hard blocks apply. Good for trusted solo use.",
    SecurityMode.balanced: (
        "Moderate step-ups for risky actions (default). Balances security and flow."
    ),
    SecurityMode.strict: (
        "Frequent step-ups; trifecta actions become hard blocks. Good for shared repos."
    ),
    SecurityMode.paranoid: ("Maximum step-ups; very low thresholds. For high-risk environments."),
}

#: Profile options presented to the user (informational only — not persisted).
PROFILE_CHOICES: tuple[str, ...] = ("coding", "mail-or-workflow", "browsing", "other")


def mode_menu_lines() -> list[str]:
    """Return formatted menu lines for the four security modes."""
    lines: list[str] = []
    for i, mode in enumerate(SecurityMode, start=1):
        lines.append(f"  {i}) {mode.value:<10} {MODE_DESCRIPTIONS[mode]}")
    return lines


def parse_mode_choice(raw: str) -> SecurityMode:
    """Parse a mode choice from either a number (1-4) or a mode name.

    Raises ``ValueError`` for invalid input so the wizard can re-prompt.
    """
    modes = list(SecurityMode)
    stripped = raw.strip().lower()
    # Numeric shortcut
    if stripped.isdigit():
        idx = int(stripped) - 1
        if 0 <= idx < len(modes):
            return modes[idx]
        raise ValueError(
            f"choose 1–{len(modes)} or type a mode name "
            f"({', '.join(m.value for m in SecurityMode)})"
        )
    # Named
    try:
        return SecurityMode(stripped)
    except ValueError:
        valid = ", ".join(m.value for m in SecurityMode)
        raise ValueError(f"unknown mode {raw!r}; valid: {valid}") from None
