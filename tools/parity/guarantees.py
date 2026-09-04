"""The parity matrix's row/column space (W3).

A ``@pytest.mark.guarantee`` marker naming a key outside these tuples fails the
build — a typo can't silently create a cell, and a cell can't be claimed for a
guarantee/host that doesn't exist. Order here is the row order in
``docs/PARITY.md``.
"""

#: Columns — the hosts a guarantee can be proven on.
HOSTS: tuple[str, ...] = ("claude-code", "codex", "cursor", "mcp-proxy", "openclaw")

#: Rows — (key, human title). The key is what a test marker cites.
GUARANTEES: tuple[tuple[str, str], ...] = (
    ("destructive-command-gate", "Destructive shell commands are blocked or AUTH-gated"),
    ("gitignored-delete-gate", "Deleting unrecoverable gitignored data is gated (AN-1)"),
    ("secret-egress-taint-floor", "A session that read a secret gets a raised floor on egress"),
    ("read-vs-send-fingerprint-block", "An outbound value matching a read secret is blocked"),
    ("output-secret-scan", "Tool output carrying credentials is blocked from the model"),
    ("control-plane-self-protection", "The agent cannot edit Doberman's own config or hooks"),
    ("auth-action-bound", "Approvals are single-use and bound to one action id"),
    ("auth-deadline", "AUTH challenges auto-deny at the wall-clock deadline"),
    ("timeout-vs-deny-logging", "A timeout is logged distinctly from a refusal"),
    ("raise-only-drift", "Policy weakening requires the human-approved path"),
)

#: Cells that are structurally N/A (the host cannot express the guarantee today),
#: each with an honest one-line footnote. A ◻ (not-yet-proven) cell needs NO entry
#: here — absence renders as ◻. Only claim ``—`` when the host genuinely cannot.
NOT_APPLICABLE: dict[tuple[str, str], str] = {
    ("output-secret-scan", "openclaw"): (
        "the OpenClaw adapter has no after_tool_call hook in the current slice, "
        "so it cannot scan tool output (documented limitation, not a gap to fill)"
    ),
}
