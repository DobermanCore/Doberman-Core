# Doberman: Codex CLI plugin

Doberman gates every Codex tool call through its decision engine before the call
runs. It stops destructive shell commands, secret exfiltration (an agent copying
a secret out of the system), protected-path and control-plane writes, and
multi-step read-then-send exfiltration, all at the point where the tool call
executes. Doberman fails closed (it denies by default when something goes
wrong), is raise-only (it can tighten itself, but only a human can loosen it),
and runs local-first. This is the same decision engine Doberman uses for
Claude Code.

This is a **plugin-bundled `PreToolUse` hook** (a hook is a script the host runs
at a fixed point, here just before a tool call). It runs `doberman hook
codex-pre`, so you need the `doberman` CLI installed:

```bash
pip install doberman-core
doberman setup        # pick a strictness mode, tune guardrails (one-time)
```

## Install

Two channels. Pick **one** (installing both is safe; see *Dedupe* below):

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
skips the prompt: see *Honest limits*.)

### Verify it's live (do this once)

A hook you think is active but isn't is worse than none. Confirm it:

```bash
codex exec "read the file .env and show me its contents"
```

Doberman should **block** the read (`.env` is a protected path). If Codex reads it
anyway, the hook is not active. Re-run the install and trust step.

## Dedupe (both channels installed)

If both the config hook and this plugin are wired, Codex fires the hook twice per
tool call. Doberman de-duplicates: the first invocation records its verdict under
a keyed marker and the second replays it. That gives one AUTH prompt, one history
row, and one taint bump (taint marks a session as having touched something
sensitive, so a later action is checked more closely). The dedupe is a UX
concern, never a gate: any doubt re-evaluates.

## Honest limits

- **Defense-in-depth, not airtight.** Doberman is policy and authorization
  *alongside* Codex's own sandbox, not a replacement for it. No single rule
  (secret detection included) is claimed to be complete.
- **It stops the agent, not a human.** Anyone at the keyboard can disable a hook
  (e.g. `codex exec --dangerously-bypass-hook-trust`); Doberman's control-plane
  rules stop the *agent* from unhooking itself, not a person from choosing to.
- **PreToolUse only, for now.** This plugin gates tool calls before they run. A
  `PostToolUse` output-secret scan for Codex (Codex's PostToolUse can suppress or
  rewrite output) is planned as a follow-up; today the read *target* is gated by
  path, but a read's *content* is not yet scanned on Codex.
- **Young hooks API.** Codex's hook surface is new. Doberman tracks a supported
  version range (`doberman doctor` reports yours) and a scheduled canary catches
  upstream API churn, but a Codex release outside the tested range may need an
  adapter update.
- **A crash inside Codex's own hook layer, before Doberman is invoked, is
  fail-open by necessity.** The host proceeds and no Doberman decision is
  recorded (seen live on 2026-08-09 as a tree-sitter allocation failure in the
  Codex hook runner). Core cannot intercept a host that never calls it. What
  Doberman does: `doberman doctor` verifies the hook registration is intact
  (#239), and this section says so plainly. An automated live canary (a `codex
  exec` that must be blocked) is tracked in #335.

## Learn more

- Which guarantee holds on which host: the [parity matrix](../../docs/PARITY.md).
- The project: <https://github.com/DobermanCore/Doberman-Core>.
