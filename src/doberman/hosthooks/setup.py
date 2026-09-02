"""Non-interactive helper logic for ``doberman setup`` (HK.4).

This module contains pure/non-IO functions so they are easy to unit-test and
so the ``setup`` CLI command stays thin (IO only). None of these functions
prompt, echo, or write files — the command layer does that.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

from doberman.policy.modes import SecurityMode

#: One-line description for each mode shown during the setup wizard.
MODE_DESCRIPTIONS: dict[SecurityMode, str] = {
    SecurityMode.light: "Minimal step-ups; only hard blocks apply. Good for trusted solo use.",
    SecurityMode.balanced: (
        "Moderate step-ups for risky actions (default). Balances security and flow."
    ),
    SecurityMode.strict: (
        "Frequent step-ups; trifecta actions (sensitive data + untrusted content + external "
        "destination, together) become hard blocks. Good for shared repos."
    ),
    SecurityMode.paranoid: ("Maximum step-ups; very low thresholds. For high-risk environments."),
}

#: Plain-English meaning of each preference dimension shown during tuning.
DIMENSION_DESCRIPTIONS: dict[str, str] = {
    "confidentiality": "How strongly to step up for sensitive data or external destinations.",
    "reversibility": "How strongly to step up for actions that are difficult to undo.",
    "interruption_tolerance": (
        "How willing you are to be asked before risky actions; higher means more prompts."
    ),
    "blast_radius": "How strongly to step up for actions that affect many targets.",
}


@dataclass(frozen=True)
class Host:
    """One host `setup` can wire, in wizard menu/wiring order."""

    key: str  # "claude" | "codex" | "mcp" | "openclaw"
    label: str
    kind: str  # "hooks" | "mcp" | "plugin"
    restart_hint: str  # printed in the summary for "hooks"-kind hosts only


#: Hosts the wizard offers, in menu/wiring order. ``restart_hint`` is only ever
#: shown for "hooks"-kind hosts (claude, codex); mcp/openclaw print their own
#: one-line pointers during per-host wiring instead.
HOSTS: tuple[Host, ...] = (
    Host("claude", "Claude Code (hooks)", "hooks", "Restart your Claude Code session."),
    Host("codex", "Codex CLI (hooks)", "hooks", "Restart your Codex CLI session."),
    Host(
        "mcp",
        "Cursor / Claude Desktop / other MCP agent (proxy: doberman serve)",
        "mcp",
        "",
    ),
    Host("openclaw", "OpenClaw (plugin hook)", "plugin", ""),
)


def _home() -> Path:
    """The real user home directory. A seam: tests monkeypatch this function
    (never the real home) so host detection never reads this machine's actual
    ``~/.claude`` / ``~/.codex`` / Claude Desktop config."""
    return Path.home()


def _claude_desktop_config_path(home: Path) -> Path:
    """Where Claude Desktop's MCP config lives, derived from *home* — never the
    real OS env — so this is deterministic under test."""
    if sys.platform == "darwin":
        return home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
    if sys.platform == "win32":
        return home / "AppData" / "Roaming" / "Claude" / "claude_desktop_config.json"
    return home / ".config" / "Claude" / "claude_desktop_config.json"


def detect_hosts(project_root: str, home: Path) -> set[str]:
    """Best-effort detection of which hosts are already set up on this machine.

    ``openclaw`` has no reliable marker, so it is never auto-detected — the
    wizard always offers it, never preselects it.
    """
    root = Path(project_root)
    detected: set[str] = set()
    if (home / ".claude").exists() or (root / ".claude").exists():
        detected.add("claude")
    if (home / ".codex").exists() or (root / ".codex").exists():
        detected.add("codex")
    if (
        (root / ".cursor").exists()
        or (home / ".cursor").exists()
        or _claude_desktop_config_path(home).exists()
    ):
        detected.add("mcp")
    return detected


def host_menu_lines(detected: set[str]) -> list[str]:
    """Return formatted menu lines for the four hosts, marking detected ones.

    Labels are padded to the widest one so every ``<- detected`` tag lines up
    in a column, regardless of which host it's marking.
    """
    width = max(len(host.label) for host in HOSTS)
    lines: list[str] = []
    for i, host in enumerate(HOSTS, start=1):
        tag = "   <- detected" if host.key in detected else ""
        lines.append(f"  [{i}] {host.label:<{width}}{tag}".rstrip())
    return lines


def default_hosts(detected: set[str]) -> list[str]:
    """Detected hosts in :data:`HOSTS` order, else just ``["claude"]``."""
    ordered = [h.key for h in HOSTS if h.key in detected]
    return ordered if ordered else ["claude"]


def parse_host_choice(raw: str, detected: set[str]) -> list[str]:
    """Parse a hosts choice: numbers, names, mixed, comma/space separated, or "all".

    Blank input returns :func:`default_hosts`. Raises ``ValueError`` on any
    unrecognized token so the wizard can re-prompt. Result preserves
    :data:`HOSTS` order and de-duplicates.
    """
    stripped = raw.strip()
    if not stripped:
        return default_hosts(detected)
    if stripped.lower() == "all":
        return [h.key for h in HOSTS]

    by_number = {str(i): h.key for i, h in enumerate(HOSTS, start=1)}
    by_name = {h.key: h.key for h in HOSTS}
    chosen: set[str] = set()
    for token in stripped.replace(",", " ").split():
        low = token.lower()
        if token in by_number:
            chosen.add(by_number[token])
        elif low in by_name:
            chosen.add(by_name[low])
        else:
            valid = ", ".join(h.key for h in HOSTS)
            raise ValueError(
                f"unknown host {token!r}; valid: {valid}, numbers 1-{len(HOSTS)}, or 'all'"
            )
    return [h.key for h in HOSTS if h.key in chosen]


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
            f"choose 1-{len(modes)} or type a mode name "
            f"({', '.join(m.value for m in SecurityMode)})"
        )
    # Named
    try:
        return SecurityMode(stripped)
    except ValueError:
        valid = ", ".join(m.value for m in SecurityMode)
        raise ValueError(f"unknown mode {raw!r}; valid: {valid}") from None
