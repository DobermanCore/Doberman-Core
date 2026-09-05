# Connector memo: Aider, Continue CLI, generic MCP/stdio bridge

> Decision memo for the three hosts left on issue #202 after Cursor shipped (#568, #569, #571). It decides, per host, whether a connector can hold Doberman's fail-closed guarantee today and what the next step is. It is not code.
>
> **Decision (2026-09-03).** (1) The stdio half of the generic-bridge bullet is already shipped as `doberman serve`; the transport gap is the next slice: `doberman serve --url <streamable-http-or-sse endpoint>` so a remote MCP (Model Context Protocol) server is fronted the same way a spawned one is. (2) Continue CLI waits on upstream: its `PreToolUse` hook has no caller in the tool-execution path, so an adapter would guard nothing; re-verify on the next `cn` release before building. (3) Aider is not guardable without patching internals its authors disclaim; not building it unless someone owns a version-pinned launcher.
>
> Research memo for issue #202 (Cursor is already scoped separately in
> `docs/CONNECTOR_MEMO_CURSOR.md` and off this menu per the maintainer's 2026-08-17 comment [S1]).
>
> **Cursor status update (2026-09-04).** A live `cursor-agent` capture found Cursor's opt-in "Third
> Party Hooks" setting *also* loads and invokes Claude Code hooks (Cursor's own payload shape, not
> Claude Code's). `doberman hook pre` now recognises and answers those calls through the Cursor
> adapter (see `adapters/cursor/README.md`'s "Cursor also runs your Claude Code hooks").
> Evidence gathered 2026-09-03 against Aider's docs/source (Aider-AI/aider, main branch), Continue's
> docs/source (continuedev/continue, main branch), and Doberman's own `src/doberman/proxy/`. Every
> claim below carries its source; anything I could not confirm is marked UNVERIFIED.

## Executive summary

1. **Continue CLI next.** Its hooks system (`PR #11029` [S6]) is a byte-for-byte clone of Claude
   Code's `PreToolUse` schema and, unlike Cursor, **auto-loads `.claude/settings.json`**. Doberman's
   existing Claude Code hook registration may already be firing there today. **Blocker:** as read on
   main, nothing in the tool-execution path calls the function that fires the `PreToolUse` event
   (`firePreToolUse` has zero callers outside its own definition file). The gate is scaffolded but
   not wired to anything that can actually deny a tool call yet.
2. **Generic MCP/stdio bridge is effectively already shipped.** `doberman serve` (`src/doberman/proxy/serve.py`)
   already is a generic stdio MCP bridge: any MCP client, any MCP stdio server. **Blocker:** stdio is
   the only downstream transport; there's no HTTP/Streamable-HTTP/SSE downstream client, though the
   `mcp` SDK Doberman already depends on ships one (`mcp.client.streamable_http`, verified installed,
   v1.27.2).
3. **Aider has no interception surface at all.** No hooks, no plugins, no MCP client. Shell commands
   and file writes are plain Python calls (`subprocess`/`pexpect`, `open().write()`). **Blocker:** any
   adapter must patch or fork Aider's internals, which Aider's own docs disclaim as unstable [S13].

## 1. Continue CLI (`cn`)

### 1.1 Interception surfaces

| Surface | Config | Payload | Verdict handling | Evidence |
|---|---|---|---|---|
| `PreToolUse` hook | `hooks` key in `~/.claude/settings.json`, `~/.continue/settings.json`, `.claude/settings.json`, `.continue/settings.json`, `.claude/settings.local.json`, `.continue/settings.local.json`: **all six merged, all run** [S7 hookConfig.ts:6-14,73-92] | `{hook_event_name:"PreToolUse", tool_name, tool_input, tool_use_id, session_id, transcript_path, cwd, permission_mode?}` [S8 types.ts, via fireHook.ts:64-76] | Response `hookSpecificOutput.permissionDecision: "allow"\|"deny"\|"ask"` + exit 0/2, aggregated in `aggregateResults()` [S9 hookRunner.ts:334-353] | Types + runner confirmed by direct source read |
| `PermissionRequest` hook | same settings files | `{hook_event_name:"PermissionRequest", tool_name, tool_input, ...}` | `decision: {behavior:"allow"} \| {behavior:"deny", message?}` [S9 hookRunner.ts:356-364] | Aggregation logic exists. No `fire*` function for this event exists anywhere in `fireHook.ts`. **Nothing ever raises it** (verified: `fireHook.ts` exports only `firePreToolUse/firePostToolUse/firePostToolUseFailure/fireUserPromptSubmit/fireSessionStart/fireSessionEnd/fireStop/fireNotification/firePreCompact` [S8]) |
| Native tool-permission gate (separate from hooks) | `~/.continue/permissions.yaml`, three tiers `allow`/`ask`/`exclude`, glob patterns like `Write(**/*.ts)` [S4] | n/a (no external process) | `ask` opens a TUI approval prompt; in headless mode `ask` silently becomes deny-by-exclusion [S4] | docs.continue.dev/cli/tool-permissions, fetched |

**The hard blocker, in the actual code.** `executeStreamedToolCalls()` (`extensions/cli/src/stream/streamChatResponse.helpers.ts`) is what really runs a tool: it calls `checkToolPermissionApproval()` → `checkToolPermission()` (the yaml gate) and then `executeToolCall()`. It never calls `firePreToolUse` or anything in `hooks/`. `executeToolCall()` (`extensions/cli/src/tools/index.tsx:228,244`) does call `services.gitAiIntegration.trackToolUse(toolCall, "PreToolUse")`, but that is a **Git-AI-integration telemetry label**, not the hooks subsystem. It feeds `GitAiIntegrationService`, not `hookRunner.ts`. A whole-repo code search for `firePreToolUse(` returns exactly one hit, its own definition (`gh search code "firePreToolUse(" --repo continuedev/continue`, 2026-09-03) [S10]. **Conclusion: registering a Doberman hook for `PreToolUse` in `.claude/settings.json` today would sit there and never be invoked by `cn`.** This could be a currently-in-flight feature (issue #11758 "Docs: document recent CLI features (hooks...)" is still open, filed after the hooks PR merged, and doesn't claim tool-blocking works end-to-end [S11]). It's worth re-checking on a newer `cn` release before committing engineering time.

### 1.2 Failure behaviour (of the hook subsystem itself, once/if wired)

| Case | Behavior | Evidence |
|---|---|---|
| Hook process crashes / spawn fails | `blocked: false` returned; only a `logger.warn` | `hookRunner.ts:113-119` (`child.on("error", ...)`) |
| Hook exceeds its timeout (default 600s) | **Fails open.** Node's `execFile` kills the process on timeout, `close` fires with `code === null`, and `const exitCode = code ?? 0` (line 88) coerces that to **0**, indistinguishable from a hook that ran fine and said nothing | `hookRunner.ts:19,37,88` (read directly, not inferred) |
| Hook prints invalid JSON | `tryParseJson` returns `null`; only blocks if exit code was independently 2 | `hookRunner.ts:23-29,90-97` |
| Hooks subsystem not "ready" (config not loaded, disabled, or event fired before init) | Silent `NOOP_RESULT = {blocked:false}` | `fireHook.ts:27,56-59,73` |
| `disableAllHooks: true` anywhere in the merged settings | All hooks skipped, no warning surfaced to the model/user beyond logs | `hookConfig.ts` (`disabled` flag propagation) |

Every one of these is fail-**open**, with no flag to flip it. This is the same shape as Cursor's default (fail-open, `failClosed`-style flag absent here) but Continue additionally fails open on **timeout** via the `code ?? 0` bug, which Cursor's memo did not have to contend with.

### 1.3 Approval / synchronous blocking

The command-hook path is synchronous (`await Promise.all(syncHandlers...)`, `hookRunner.ts` bottom) with a 600s default timeout. That's long enough for a human approval dialog, *if* the timeout-fails-open bug (1.2) doesn't quietly let a slow AUTH challenge through as an allow. Continue's own `ask` permission tier is a **separate, competing** approval UI (TUI prompt) that a hook's `permissionDecision` doesn't appear to suppress in the current wiring (moot until PreToolUse is actually called; see 1.1).

### 1.4 Platform notes

Windows: command hooks launch via `cmd.exe /c <command>` (POSIX: `/bin/sh -c`). Argv is never used, so quoting is the adapter's problem, same as Claude Code [S9 hookRunner.ts:45-51]. `CLAUDE_PROJECT_DIR` and `CONTINUE_PROJECT_DIR` are both set in the hook's environment (line 40-43); a Doberman adapter can read either. No BOM-specific bug found in the files read (unlike Cursor's confirmed Windows BOM bug). UNVERIFIED beyond that: no Windows-specific Continue CLI hook bug reports were found in this pass.

### 1.5 Effort

**T-shirt size: M, but blocked.** The translation layer would be a near-copy of `hosthooks/claude_code.py` (same field names, same exit-code convention, same settings.json shape). That's genuinely the cheapest of the three hosts to write *mechanically*. The one hard blocker is real: there is currently nothing to call it. Recommendation: file or track upstream (or re-verify on the next `cn` release) rather than building against dead wiring. Revisit once `firePreToolUse` has a caller in `executeStreamedToolCalls` or equivalent.

---

## 2. Aider

### 2.1 No pre-tool surface exists

Exhaustive search, not inference: `gh search code "hook"` and `"plugin"` across `Aider-AI/aider` return only doc/build-tooling files (README, HISTORY, CI configs, a git-hooks-for-*users* doc). Nothing resembling a tool-call interception API turned up [S12]. Aider's own FAQ's only relevant answer, "Can I script Aider?", points to a Python `Coder` API explicitly captioned "not officially supported or documented, and could change in future releases without providing backwards compatibility" [S13].

What actually runs shell commands and writes files, read directly:

- **Shell (`/run` / `!`, and `--lint-cmd`/`--test-cmd`).** `Commands.cmd_run` (`aider/commands.py:1013-1053`) calls `run_cmd(args, ..., cwd=self.coder.root)` (`aider/run_cmd.py`) immediately, with no confirmation before execution. `run_cmd` picks `pexpect` on POSIX-with-a-tty or `run_cmd_subprocess` otherwise (all of Windows, always) [S14 run_cmd.py:1-13,35-51]. On Windows it detects a PowerShell parent and prefixes `powershell -Command <command>`, otherwise `cmd.exe`. `self.io.confirm_ask(...)` at `commands.py:1029` only asks whether to *paste the output back into the chat*. It fires **after** the command has already run.
- **File writes.** `InputOutput.write_text` (`aider/io.py:478-495`) is a bare `open(filename, "w").write(content)`. The only confirmation gate found is `confirm_ask("Create new file?", subject=path)` (`base_coder.py:2207`), and only for a path that isn't already tracked in the chat. It's a UX guard, not a security boundary, and is bypassed entirely by `--yes`/`--yes-always`.
- **MCP client: does not exist.** A general web search suggested Aider is an MCP client; that is **wrong for the upstream project**. A targeted source search (`gh search code "mcp_servers"` and `"class MCP"` in `Aider-AI/aider`, plus a full grep of `aider/args.py` for `mcp`) returns **zero hits** [S15]. The "Aider MCP server" projects that surfaced (`disler/aider-mcp-server`, `sengokudaikon/aider-mcp-server`) run in the opposite direction: they let an *external* MCP client (e.g. Claude Desktop) drive Aider as a tool. They do not give Aider itself an MCP client, so `doberman serve` cannot sit downstream of Aider's own tool calls.

### 2.2 Alternatives, with an honest bypass for each

| Alternative | What it covers | What still bypasses Doberman |
|---|---|---|
| **Python monkeypatch launcher:** a small script that `import`s `aider.io` and `aider.run_cmd` before calling Aider's real entrypoint, and replaces `InputOutput.write_text` / `run_cmd` with wrapped versions that call the spine first | Every file write and every `/run`/lint/test shell command, since both funnel through exactly those two functions today | Any Aider release that renames/restructures these internals silently un-protects the install (Aider explicitly reserves the right to do this [S13]); needs a version pin + CI canary against new Aider releases, same posture as the Codex adapter's version range (`SUPPORTED_CODEX_RANGE` in `codex.py:57`) |
| **Wrap `git`** (PATH shim or a `pre-commit` hook in the repo) | Aider auto-commits by default, so a `pre-commit` hook sees every applied edit as a diff | Post-hoc only. The file is already written to disk (and already fed back to the LLM) before commit. `--no-auto-commits` mode never triggers it at all. Reads are invisible to git entirely |
| **PATH shim for the binaries Aider's `/run`/lint/test invoke** | The `/run`, `--lint-cmd`, `--test-cmd` surface specifically | Nothing about direct file edits, which are Aider's dominant write path and not shell-mediated at all |
| **Fork Aider** | Full control, same guarantee level as a first-party adapter | Ongoing rebase cost against every upstream release; the fork itself becomes the thing that can silently drift out of protection |
| **Third-party `aider-mcp-server` bridge + `doberman serve`** | Whatever coarse tool surface that bridge exposes (e.g., "edit these files") | Everything Aider does inside that one call: no per-file, per-command granularity. Depends on an unofficial, Aider-unaffiliated project's maintenance |

### 2.3 Effort

**T-shirt size: L, one real blocker.** The monkeypatch launcher is the only alternative that covers both shell and file-write surfaces, but it is explicitly working against unstable internals Aider does not promise to keep. The "hard blocker" is that there is no supported extension point to build on, only private implementation details.

---

## 3. Generic MCP / stdio bridge

### 3.1 What `doberman serve` already covers

Read directly (`src/doberman/proxy/serve.py`, `src/doberman/proxy/mcp_proxy.py`, `docs/SETUP.md:261-313`):

- `doberman serve -- <any stdio MCP server command>` spawns that command via `mcp.stdio_client` and re-exposes it to the agent as a single Doberman-fronted MCP server over the agent's own stdio channel (`serve.py:42-85`).
- `build_proxy_server()` forwards `tools/list` unchanged and routes **every** `tools/call` through `executor.decide_and_execute`: "there is no path around it" (`mcp_proxy.py:1-29,62-76`).
- This already is host-agnostic and server-agnostic: it works for Claude Code, Claude Desktop, Cursor, Codex, or *any* MCP client, in front of *any* stdio MCP server, per `docs/SETUP.md:261-313` (`claude mcp add doberman -- doberman serve -- <server>`, and the same `mcpServers` JSON shape for Cursor/Codex/Claude Desktop).
- AUTH prompts route through a dashboard → MCP elicitation → GUI → TTY fallback chain that never touches the agent's own stdout (`serve.py:9-21`).

**In substance, this already is "a generic MCP / stdio bridge."** It is not scoped to one host; it is scoped to one *transport* (stdio) and one downstream server per invocation.

### 3.2 What a "generic bridge" would still add

1. **HTTP / Streamable-HTTP / SSE downstream transport.** `serve.py` only builds a `StdioServerParameters` and calls `stdio_client`; there is no code path using `mcp.client.streamable_http` or `mcp.client.sse`. Verified these exist and are already importable from the `mcp` package Doberman depends on (`pip show mcp` → v1.27.2; `from mcp.client.streamable_http import streamablehttp_client` and `from mcp.client.sse import sse_client` both import cleanly in this environment). A remote/cloud-hosted MCP server that only speaks Streamable HTTP (increasingly the default per the MCP spec's 2026-07-28 revision toward a stateless HTTP-first core [S16]) cannot be fronted by Doberman today.
2. **Multiple downstream servers behind one Doberman process.** Today, N MCP servers means N separate `doberman serve -- <server>` invocations (one per agent config entry). This already works from the agent's point of view, so it is a smaller gap than #1: it's an ergonomics/observability question (one shared decision log vs. N), not a coverage gap.
3. **Client-side wrap.** Everything above is Doberman acting as the *server* to the agent. A "client-side" route (patching an agent's own MCP client library so it calls the spine before dispatching, independent of which transport the real server speaks) doesn't exist and isn't implied by anything in `proxy/` today; it would be a different architecture, closer to the Aider monkeypatch idea than to `serve.py`.

### 3.3 Is #202's bullet already satisfied?

**Mostly yes for the "stdio bridge" half.** That is exactly what `doberman serve` is, and it already guards "any MCP server," which is the broadest part of the ask. **Not yet for the "generic" half** if "generic" is read to include non-stdio transports, which is where the ecosystem is visibly heading [S16]. Recommendation: treat the stdio case as done (point future askers at `doberman serve` + `docs/SETUP.md`) and, if this is wanted, scope a narrow follow-up issue specifically for `--transport http|sse` on `doberman serve`, distinct from #202.

### 3.4 Effort

**T-shirt size: S** for HTTP/SSE transport add-on (swap `stdio_client` for `streamablehttp_client`/`sse_client` behind a `--transport` flag in `cli/main.py:281-319` and `serve.py:42-52`; the SDK does the protocol work). No hard blocker. The dependency is already vendored.

---

## Ranked recommendation

1. **Generic MCP bridge (transport gap only):** smallest, best-understood diff (`S`), no blocker, and closes the most defensible reading of #202's fourth bullet. Do this first regardless of the other two.
2. **Continue CLI:** cheapest adapter to *write* (`M`, near-copy of `claude_code.py`), but gated on upstream actually wiring `firePreToolUse` into tool execution. Re-verify against the next `cn` release before starting.
3. **Aider:** real user demand, but no supported extension point exists (`L`). Only path in is a version-pinned monkeypatch against explicitly-unstable internals, so it should wait until 1 and 2 are done or someone commits to owning the version-pin maintenance.

## Sources

- S1. Issue #202 body + maintainer comment (2026-08-17, trims candidates to Aider/Cursor/Continue/generic MCP, Cursor later done separately): https://github.com/DobermanCore/Doberman-Core/issues/202
- S4. Continue CLI tool permissions: https://docs.continue.dev/cli/tool-permissions
- S6. Continue CLI hooks PR: https://github.com/continuedev/continue/pull/11029
- S7. `extensions/cli/src/hooks/hookConfig.ts`: https://github.com/continuedev/continue/blob/main/extensions/cli/src/hooks/hookConfig.ts
- S8. `extensions/cli/src/hooks/fireHook.ts` and `types.ts`: https://github.com/continuedev/continue/blob/main/extensions/cli/src/hooks/fireHook.ts
- S9. `extensions/cli/src/hooks/hookRunner.ts`: https://github.com/continuedev/continue/blob/main/extensions/cli/src/hooks/hookRunner.ts
- S10. Live code search confirming no caller of `firePreToolUse(` outside its own file (run 2026-09-03): `gh search code "firePreToolUse(" --repo continuedev/continue`; corroborated by direct reads of `extensions/cli/src/stream/streamChatResponse.helpers.ts` and `extensions/cli/src/tools/index.tsx`.
- S11. Open docs issue filed after the hooks PR, still unresolved: https://github.com/continuedev/continue/issues/11678 and https://github.com/continuedev/continue/issues/11758
- S12. Code search across `Aider-AI/aider` for "hook"/"plugin" (run 2026-09-03): `gh search code "hook"|"plugin" --repo Aider-AI/aider`.
- S13. Aider scripting docs ("not officially supported... could change... without backwards compatibility"): https://aider.chat/docs/scripting.html ; FAQ: https://aider.chat/docs/faq.html ; lint/test docs: https://aider.chat/docs/usage/lint-test.html
- S14. `aider/commands.py` (`cmd_run`, lines 1013-1053), `aider/io.py` (`write_text`, lines 478-495), `aider/coders/base_coder.py` (line 2207), `aider/run_cmd.py`: https://github.com/Aider-AI/aider (contents fetched via `gh api repos/Aider-AI/aider/contents/...`)
- S15. Code search confirming no native MCP client in Aider (run 2026-09-03): `gh search code "mcp_servers"|"class MCP" --repo Aider-AI/aider` (zero hits); `aider/args.py` grepped for `mcp` (zero hits).
- S16. MCP 2026-07-28 spec revision toward a stateless HTTP-first core: https://blog.modelcontextprotocol.io/posts/2026-07-28/
- Doberman source read directly: `src/doberman/proxy/serve.py`, `src/doberman/proxy/mcp_proxy.py`, `src/doberman/hosthooks/codex.py`, `docs/SETUP.md` (lines 255-313), `docs/ADAPTER_GUIDE.md` (full file).

## Pages that would not load / were not pursued further

- `https://aider.chat/docs/config/mcp.html`: 404. No dedicated Aider MCP-config doc page was found under any guessed slug. Source-level search (S15) settled the question instead.
- Continue's own hooks reference page under `docs.continue.dev` was not found published (per S11, still tracked as an open docs gap). Relied on source (`extensions/cli/src/hooks/`) instead of docs prose for the schema.
