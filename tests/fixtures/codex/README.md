# Codex CLI hook payload fixtures

Captured from a live **Codex CLI 0.146.1** (`codex exec`) on 2026-08-08, sanitized (synthetic
session/turn/tool-use ids and a placeholder `cwd` that tests override). These are the ground truth the
Codex adapter (`doberman/hosthooks/codex.py`) is built and tested against — Codex's hook payloads are
**not assumed**, they are captured.

## What the capture established (correcting the pre-implementation design)

The design guessed Codex used tool names `shell` / `apply_patch` / `web_search` with an argv-list
`command`. Two live captures (2026-08-08) showed a **mixed catalog** — part Claude-Code compatible,
part Codex-native — which is why the adapter uses OpenClaw's gate-by-default posture, not Claude
Code's allowlist-abstain:

- **Shell arrives as `tool_name: "Bash"`** (not `shell`) with a **plain-string** `tool_input.command`
  (`{"command": "echo hello"}`), not an argv list — no `shlex.join` needed. Reads happen through `Bash`
  (`cat` / `rtk read`), not a separate read tool.
- **File edits arrive as `tool_name: "apply_patch"`** (Codex-native, NOT `Edit`/`Write`), whose
  `tool_input.command` is an **apply-patch envelope** — the target path is inside it
  (`*** Add File: <p>` / `*** Update File: <p>` / `*** Delete File: <p>` / `*** Move to: <p>`). The
  adapter parses the envelope so the protected-path rule gates the real target(s). **This is the fail-open
  gap the first Bash-only capture missed:** copying Claude Code's `{Bash,Edit,Write,...}` allowlist would
  have abstained on `apply_patch` and let file writes pass unmediated.
- **Input payload keys are snake_case:** `session_id`, `turn_id`, `transcript_path`, `cwd`,
  `hook_event_name`, `model`, `permission_mode`, `tool_name`, `tool_input`, `tool_use_id`.
- **`session_id` is present** — a UUID. Codex carries session identity, so taint keys on the real
  session (no repo-scope-only fallback footnote needed on the parity matrix).
- **Posture: gate-by-default.** Because the catalog is only partly documented, the adapter evaluates
  *every* tool through the decision spine (a benign/no-target call just PASSes); it never treats an
  unrecognized tool name as trusted. Fixtures: `pre_bash.json`, `pre_apply_patch.json`.

## Hook output shape (from the compiled JSON schema in `codex.exe`, 0.146.1)

The **output** a hook writes to stdout is camelCase (distinct from the snake_case input):

```json
{"hookSpecificOutput": {"hookEventName": "PreToolUse",
  "permissionDecision": "allow|deny|ask", "permissionDecisionReason": "..."}}
```

Top-level fields also exist: `continue` (bool), `decision` (`approve|block`), `reason`, `stopReason`,
`suppressOutput` (bool). PostToolUse hooks additionally support `additionalContext` and
`updatedMCPToolOutput` (rewrite MCP tool output) plus top-level `suppressOutput` — so a PostToolUse
hook *can* suppress or rewrite tool output.

## Confirmed behaviors

- A PreToolUse `deny` blocks the command and Codex surfaces the reason to the user
  ("The command did not execute. The workspace's PreToolUse hook denied it: ...").
- Events supported (0.146.1): `PreToolUse`, `PostToolUse`, `PermissionRequest`, `SessionStart`,
  `SessionEnd`, `UserPromptSubmit`, `SubagentStart`, `SubagentStop`, `Stop`, `PreCompact`,
  `PostCompact`.
- `hooks.json` structure is Claude-Code-shaped:
  `{"hooks":{"<Event>":[{"matcher":"<regex>","hooks":[{"type":"command","command":"..."}]}]}}`.
  Config key `hooks` in `~/.codex/config.toml` may point to a `hooks.json`; `~/.codex/hooks.json` is
  the user-scope default. Hooks require persisted trust unless invoked with
  `--dangerously-bypass-hook-trust`.

## Operational gotcha (drives the install/canary slices)

A user-scope `~/.codex/hooks.json` intercepts **every** running Codex session on the machine, not just
one — during capture, a deny-all hook briefly caught a concurrent background Codex session's calls.
The installer must document this, and a deny-based canary must be scoped/short-lived.
