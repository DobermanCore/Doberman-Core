# Connector memo: Cursor

> Decision memo for issue #244. Evidence gathered 2026-09-03 against Cursor's current hook
> documentation and the Cursor forum; every claim below carries its source. This memo decides
> whether a Cursor connector can hold Doberman's fail-closed guarantee and, if so, what envelope
> it would use. It is not code.

## Summary

**Recommendation: build it, scoped.** Cursor exposes a real pre-execution gate for every built-in
tool, `deny` is honored on every surface, and a per-hook `failClosed` flag turns hook failure into
a block. Two honest limits shape the design: Cursor's own approval system ignores a hook's `allow`
and `ask`, so a human-in-the-loop AUTH has to be Doberman's own challenge inside the hook, and the
default failure mode is fail-open, so the installer must set `failClosed` on every registration and
the install-integrity manifest must fingerprint that flag.

Today Cursor users reach Doberman only through the MCP proxy, which sees MCP tool calls and nothing
else. A hook connector adds shell commands, file writes, and file reads, which is where the
destructive-command, secret, and exfiltration rules do their work.

## Capability matrix

Cursor ships 20 hook events. Seven can block; the rest observe. Hooks live in `hooks.json` at
project scope (`.cursor/hooks.json`), user scope (`~/.cursor/hooks.json`), and enterprise or team
scope, with precedence Enterprise > Team > Project > User. Every hook is a command that reads one
JSON document on stdin and writes one on stdout. [1]

| Surface | Hook | Payload Doberman needs | Verdicts honored | Notes |
|---|---|---|---|---|
| Any built-in tool (Shell, Read, Write, Task, MCP) | `preToolUse` | `tool_name`, `tool_input`, `workspace_roots`, `conversation_id`, `generation_id` | `deny` honored; `allow`/`ask` subject to Cursor's own approvals | The universal chokepoint. Fires before file writes with the target path in `tool_input`; a staff-suggested workaround in [5] relies on exactly that. |
| Shell command | `beforeShellExecution` | `command`, `cwd` | `deny` reliable; `allow` and `ask` overridden by the shell allow-list [3] | Richer than `preToolUse` for shell (explicit `cwd`). |
| MCP tool call | `beforeMCPExecution` | `tool_name`, `tool_input`, `mcp_server_name`, server URL or launch command | `deny` reliable; `allow` does not suppress Cursor's MCP approval prompt (staff-confirmed) [4] | Overlaps the MCP proxy; the proxy stays the canonical MCP path. |
| File read | `beforeReadFile` | `file_path`, `content`, `attachments` | `allow`/`deny` only | Deny keeps the contents away from the model; the docs do not say whether it is a block or a redaction. [2] |
| Prompt submission | `beforeSubmitPrompt` | prompt text | `continue: true` or `false` | Out of scope for a v1 (Doberman gates actions, not prompts). |
| Subagent start | `subagentStart` | subagent descriptor | `deny` only | Out of scope for a v1. |
| File edit | `afterFileEdit` | old and new contents | none (observe only) | Post-hoc. Not a gate; `preToolUse` on `Write` is the gate. |

Response shape on every gating hook: `{"permission": "allow" | "deny" | "ask", "user_message": ...,
"agent_message": ...}`. Exit code 2 also blocks, independent of the JSON. [1], [2]

**Ask-the-human.** Not expressible through Cursor. Since November 2025 a hook's `ask` on an
allow-listed command auto-runs and its `allow` on a non-listed command still prompts ("Only 'deny'
works correctly in all cases", two reporters, no staff reply, no fix version) [3]; for MCP, staff
confirmed in March 2026 that "hooks can only deny actions" and `allow` does not override the MCP
approval system [4]. Doberman's AUTH therefore runs the same way it does for Codex: the hook process
issues Doberman's own challenge (local confirm, TOTP, or dashboard approval) and returns `allow` or
`deny` to Cursor. Cursor's own prompt may then appear on top. That is a UX cost, not a security one.

**Payload limits.** None documented. `tool_input` carries the full write content for `Write`; the
adapter must never persist it (the shared spine already redacts before logging).

**Stability.** Hooks arrived in Cursor 1.7 (October 2025) [6]. The event list has grown since;
schema fields have been stable across the sources consulted. The CLI agent (`cursor-agent`) is
versioned separately from the IDE and has its own hook bugs (below). The `allow`/`ask` limitation has
stood unfixed for ten months. Multi-hook conflict resolution (first deny wins, or all must allow) is
not documented; only scope precedence is. [1]

## The fail-closed honesty test

The test from #244: can a deny be expressed so the client cannot mistake silence for a crash, and
does an uninstalled or failed state ever read as an explicit allow?

| Case | Cursor behavior | Verdict |
|---|---|---|
| Doberman says BLOCK | `permission: deny` plus exit code 2, with `user_message` carrying the reason codes and explanation | Explicit, distinguishable from failure. Pass. |
| Hook crashes, exits non-zero, or times out | **Fail-open by default.** With `failClosed: true` on the registration, crash and timeout block instead. [2] | Pass only with `failClosed: true`; the installer must set it and the manifest must pin it. |
| Hook prints invalid JSON, or the binary is missing | Fail-open by default; whether `failClosed` covers these two cases is not stated. [2] | Mitigation: the hook always exits 2 on any internal failure before it can print a malformed document, so the exit-code path blocks regardless. |
| Windows CLI prefixes stdin with a UTF-8 BOM, JSON parse fails | Fails open silently on `cursor-agent` for Windows; staff-confirmed, no fix ETA (2026-08-14). [7] | The adapter strips a leading BOM before parsing. Turns a fail-open into a working hook. |
| Hooks intermittently do not fire (several Windows reports) | Cursor has no built-in self-check. [7], [8] | A `sessionStart` hook writes a per-session heartbeat; `doberman doctor` reports a Cursor project whose session never called back. |
| hooks.json edited or removed | Cursor runs its own approval flow, as if Doberman were never installed | Same class as Claude Code and Codex. The install-integrity manifest (#239) covers `.cursor/hooks.json`, including the `failClosed` field, so a stripped or weakened registration is reported at the next surviving hook and by `doctor`. |
| Hook says `allow` | Cursor may still prompt (allow-list, MCP approvals) | Stricter than Doberman, never weaker. Pass. |

Nothing here is disqualifying. A deny is explicit, failure can be made to block, and the
uninstalled state is the host's native behavior rather than a fabricated allow. The cost is that
two of the guarantees depend on configuration Cursor does not enforce (`failClosed`, the BOM strip),
so both must be owned by the installer and checked by `doctor`, not left to the user.

## Envelope contract for a v1 connector

- **Registrations.** One command, `doberman hook cursor-pre`, registered for `preToolUse`
  (no matcher, so every built-in tool), `beforeShellExecution`, and `beforeMCPExecution`, each with
  `"failClosed": true` and an explicit `"timeout"`. A `sessionStart` registration writes the
  heartbeat. Doubled invocations (a shell command seen by both `preToolUse` and
  `beforeShellExecution`) are collapsed by the existing singleflight keyed on
  `(conversation_id, generation_id, action fingerprint)`, the same mechanism the Codex adapter uses
  for its doubled channels.
- **Translation.** `Shell` and `beforeShellExecution` map to the canonical shell action with
  `command` and `cwd`; `Write` and edit-shaped tools map to `file_write` with the target path;
  `Read` and `beforeReadFile` map to `file_read`; `MCP: <server>` tools map through the same
  tool-name translation the MCP proxy uses. The repo root comes from `workspace_roots[0]`, falling
  back to `cwd`. The session id is `conversation_id`.
- **Enforcement.** PASS returns `{"permission": "allow"}` and exit 0. BLOCK returns
  `{"permission": "deny", "user_message": <explanation + reason codes>, "agent_message":
  <one line>}` and exit 2. AUTH runs Doberman's challenge inside the hook and then returns allow or
  deny; it never returns `ask`. Any exception, unparseable payload, missing tool name, or missing
  target resolves to deny and exit 2 before any output is written.
- **Not covered in v1.** `beforeSubmitPrompt`, `subagentStart`, cloud and background agents
  (project-scope hooks only; user-scope hooks are unavailable there), and `afterFileEdit`.

**Effort.** Two slices. First, `hosthooks/cursor.py` mirroring `codex.py` (translation, enforcement,
BOM strip, singleflight) with `adapters/cursor/README.md` and integration tests that a BLOCK leaves
the fake tool unrun. Second, `install-hooks --host cursor` (hooks.json merge with `failClosed`),
the manifest scope, the heartbeat, and the `doctor` checks.

## Sources

1. Cursor hooks documentation: https://cursor.com/docs/hooks (event list, scopes, precedence,
   response shape).
2. Hook JSON reference guide with the failure table, `failClosed`, and `timeout`:
   https://ntorres.dev/blog/cursor-hooks-json-guide
3. Forum, 2025-11-26: "beforeShellExecution hook permissions (allow/ask) ignored, allow-list takes
   precedence": https://forum.cursor.com/t/beforeshellexecution-hook-permissions-allow-ask-ignored-allow-list-takes-precedence/144244
4. Forum, 2026-03-12, staff reply "hooks can only deny actions":
   https://forum.cursor.com/t/hooks-return-allow-but-mcp-tool-still-requires-manual-approval-gets-skipped/155434
5. Forum, 2026-07-17, staff workaround using `preToolUse` deny on the `Write` tool:
   https://forum.cursor.com/t/pretooluse-hook-updated-input-silently-discarded-for-write-tool-file-creation-edit/165962
6. InfoQ on Cursor 1.7 introducing hooks: https://www.infoq.com/news/2025/10/cursor-hooks/
7. Forum, 2026-08-14, Windows CLI BOM bug, staff-confirmed:
   https://forum.cursor.com/t/hooks-not-firing-cannot-have-guardrails/168407
8. Forum, 2026-08-31, lowered timeout silently disables deny hooks on Windows CLI:
   https://forum.cursor.com/t/cli-hooks-block-each-tool-call-for-the-full-timeout-lowering-it-silently-disables-deny-hooks-windows/169942
