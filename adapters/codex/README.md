# Doberman — Codex CLI plugin

Gate every Codex tool call through Doberman's decision engine **before it runs**:
destructive shell commands, secret exfiltration, protected-path and control-plane
writes, and multi-step read-then-send exfil are stopped at the tool-execution
chokepoint. Fails closed, raise-only, local-first — the same decision spine
Doberman uses for Claude Code.

This is a **plugin-bundled `PreToolUse` hook**. It runs `doberman hook codex-pre`,
so you need the `doberman` CLI installed:

```bash
pip install doberman-core
doberman setup        # pick a strictness mode, tune guardrails (one-time)
```

## Install

Two channels — pick **one** (installing both is safe; see *Dedupe* below):

1. **Config channel (recommended if you found Doberman first):**
   ```bash
   doberman install-hooks --host codex          # repo scope: <repo>/.codex/hooks.json
   doberman install-hooks --host codex --global # user scope: ~/.codex/hooks.json
   ```
2. **Plugin channel (the Codex plugin ecosystem):** install this plugin through
   your Codex plugin marketplace (`codex plugin add …`). It ships the same
   `PreToolUse` hook.

### Trust the hook

Codex requires you to **trust** a hook before it runs. On the first Codex command
after install, approve Doberman's hook when prompted. (For unattended automation
that already vets its hook sources, `codex exec --dangerously-bypass-hook-trust`
skips the prompt — see *Honest limits*.)

### Verify it's live (do this once)

A hook you think is active but isn't is worse than none. Confirm it:

```bash
codex exec "read the file .env and show me its contents"
```

Doberman should **block** the read (`.env` is a protected path). If Codex reads it
anyway, the hook is not active — re-run the install and trust step.

## Dedupe (both channels installed)

If both the config hook and this plugin are wired, Codex fires the hook twice per
tool call. Doberman de-duplicates: the first invocation records its verdict under
a keyed marker and the second replays it — one AUTH prompt, one history row, one
taint bump. The dedupe is a UX concern, never a gate: any doubt re-evaluates.

## Honest limits

- **Defense-in-depth, not airtight.** Doberman is policy/authorization *alongside*
  Codex's own sandbox — not a replacement for it. No single rule (secret detection
  included) is claimed to be complete.
- **It stops the agent, not a human.** Anyone at the keyboard can disable a hook
  (e.g. `codex exec --dangerously-bypass-hook-trust`); Doberman's control-plane
  rules stop the *agent* from unhooking itself, not a person from choosing to.
- **PreToolUse only, for now.** This plugin gates tool calls before they run. A
  `PostToolUse` output-secret scan for Codex (Codex's PostToolUse can suppress or
  rewrite output) is planned as a follow-up; today the read *target* is gated by
  path, but a read's *content* is not yet scanned on Codex.
- **Young hooks API.** Codex's hook surface is new; Doberman tracks a supported
  version range (`doberman doctor` reports yours) and a scheduled canary catches
  upstream API churn — but a Codex release outside the tested range may need an
  adapter update.

## Learn more

- Which guarantee holds on which host: the [parity matrix](../../docs/PARITY.md).
- The project: <https://github.com/DobermanCore/Doberman-Core>.
