# Doberman adapter for OpenClaw

Routes every [OpenClaw](https://docs.openclaw.ai) tool call through Doberman's local,
fail-closed PASS / AUTH / BLOCK decision engine before it runs — no MCP reconfiguration
needed.

## How it works

This directory is a self-contained **OpenClaw plugin** (not a hook-pack — OpenClaw's
`before_tool_call` event is only reachable from a typed plugin hook, `api.on("before_tool_call",
...)`, never from a lifecycle/command hook-pack).

1. `index.js` registers a `before_tool_call` handler. On every tool call it spawns
   `doberman hook openclaw` as a **fresh subprocess**, writes the event as JSON on stdin,
   and waits up to 10 seconds for exactly one JSON verdict on stdout.
2. The Python side (`src/doberman/hosthooks/openclaw.py`, `doberman hook openclaw` CLI
   command) normalizes the call into Doberman's `SecurityObject` model and runs it through
   the same deterministic decision path as the Claude Code hook.
3. The verdict maps back to OpenClaw's `BeforeToolCallResult`:
   - `allow` → no-op — the call proceeds.
   - `block` → `{ block: true, blockReason }` — terminal, the call never runs.
   - `auth` → `{ requireApproval: {...} }` — delegated to **OpenClaw's own** `/approve`
     flow (not Doberman's local GUI/TTY challenge — the gateway process has no
     interactive terminal of its own). An unresolved or denied approval is a deny.

**Fail-closed is the invariant.** A spawn failure, a timeout, a non-zero exit, or stdout
that doesn't parse as JSON all return `{ block: true, blockReason: "doberman unavailable -
failing closed" }`. Doberman would rather block a legitimate action than silently let one
through when it can't evaluate it.

## Install

Requires the `doberman` CLI on `PATH` **in the same environment the OpenClaw gateway
process runs in** (`pip install doberman-core` or your project's editable install).

```bash
# Link the adapter directory in place (no copy — pulling a newer Doberman
# checkout keeps the adapter current):
openclaw plugins install -l /path/to/doberman-core/adapters/openclaw

# Local/linked plugins are disabled by default until explicitly enabled:
openclaw plugins enable doberman
```

To validate the packaged shape you'd actually ship (recommended before relying on this
in a shared/production gateway):

```bash
cd /path/to/doberman-core/adapters/openclaw
npm pack --pack-destination /tmp
openclaw plugins install npm-pack:/tmp/doberman-openclaw-adapter-0.1.0.tgz --force
```

## Verify it's live (do this every time — mandatory, not optional)

OpenClaw has shipped bugs where plugin hooks silently never fire
([openclaw/openclaw#5513](https://github.com/openclaw/openclaw/issues/5513)), and a plugin
that fails to *load* is a **documented, currently-open fail-open gap at the platform
level**: OpenClaw logs the error and continues running with the plugin simply absent — every
tool call then passes through completely unguarded
([openclaw/openclaw#20914](https://github.com/openclaw/openclaw/issues/20914)). Neither
failure mode is visible from the outside unless you check.

After install, and after every OpenClaw upgrade or config change:

1. Confirm the plugin actually loaded: `openclaw plugins inspect doberman --runtime` should
   show it enabled and its hook registered. Gateway startup logs should also show
   `[doberman] interception active - before_tool_call hook registered`.
2. **Run one canary action that MUST come back blocked or gated** — e.g. ask the agent to
   run a destructive shell command against a scratch directory (`rm -rf /tmp/doberman-canary`)
   or write to a path Doberman treats as sensitive. If it executes without a block/approval
   prompt, **interception is NOT active** — stop and re-check steps 1–2 before trusting this
   adapter for anything real.

## Known limitations (this slice)

- **`web_fetch`'s argument key is a best-effort assumption**, not independently confirmed
  against OpenClaw's docs (`params.url`, inferred by convention from `web_search`'s
  confirmed `params.query`). If wrong, `web_fetch` calls always deny — safe, just overly
  strict — until corrected against a live install.
- **AUTH approval outcomes are not yet recorded** to Doberman's local decision log. Only
  BLOCK and PASS/monitor-softened outcomes are (an AUTH's eventual resolution happens
  asynchronously via OpenClaw's own `/approve` flow, outside this process's lifetime — wiring
  `onResolution` back to the log is a follow-up slice).
- **Pre-execution gating only** — this slice adds no `after_tool_call`/output scan. A read's
  *target path* is still gated the same as any other file-touching action (`.env`, keys, and
  the rest of Doberman's protected/sensitive globs are blocked or authenticated up front), but
  a read tool's *returned content* isn't vetted for leaked secrets here (unlike the Claude
  Code post-hook, which scans output after execution).
- **`cwd` is best-effort** (`process.cwd()` of the gateway process, since `before_tool_call`
  exposes no working-directory field of its own). If the gateway runs from somewhere other
  than the project root, per-repo role/policy resolution falls back to Doberman's default
  mode rather than the real project's policy.
- **No build step by design** — `index.js` is plain ESM, loaded directly by OpenClaw
  (`package.json`'s `openclaw.extensions`). If you need to extend it, keep it dependency-free
  or add a build step deliberately (and document it here).
