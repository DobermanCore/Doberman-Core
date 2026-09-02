# Setup guide

This is the complete guide to installing Doberman, wiring it to your coding agent, locking in a
recovery factor, and confirming it works. New here? The [README](../README.md) has the 30-second
version.

**Contents**

- [1. Install](#1-install)
- [2. Run `doberman setup`](#2-run-doberman-setup)
- [3. Wire it to your agent](#3-wire-it-to-your-agent)
- [4. Set a password and 2FA](#4-set-a-password-and-2fa)
- [5. Check its health](#5-check-its-health)
- [6. Watch it work](#6-watch-it-work)
- [Appendix: a stale `doberman` on PATH](#appendix-a-stale-doberman-on-path)

---

## 1. Install

```bash
pip install doberman-core
```

> **Note**
> The distribution is `doberman-core` (the bare `doberman` name on PyPI belongs to an unrelated,
> abandoned project). The import name and CLI command are unchanged: you still `import doberman`
> and run `doberman`.

Install the latest from source instead:

```bash
pip install git+https://github.com/DobermanCore/Doberman-Core.git
```

Or for development:

```bash
git clone https://github.com/DobermanCore/Doberman-Core.git
cd Doberman-Core
pip install -e ".[dev]"
```

Any of these puts `doberman` on your PATH. If it behaves oddly (an old version, a missing
command), see the [PATH appendix](#appendix-a-stale-doberman-on-path). Maintainers: see
[RELEASING.md](../RELEASING.md).

## 2. Run `doberman setup`

One command does the whole job on any host. An interactive wizard detects which agents you have
installed (Claude Code, Codex CLI, an MCP client, OpenClaw), asks which ones to guard, picks your
alertness mode, asks whether to send anonymous usage stats, tunes your guardrails, and wires each
chosen host — finishing with a doctor pass and, if you wired a hooks-based host (Claude Code or
Codex), an offer to run a scripted attack through the real engine right there so you can watch it
work:

```bash
doberman setup
```

```bash
doberman setup --yes
```

`--yes` accepts the defaults (detected hosts, or Claude Code if nothing is detected; balanced mode)
with no prompts, useful for CI or scripting. Pass `--host` (repeatable) to pick hosts explicitly,
e.g. `doberman setup --yes --host claude --host codex`. Either way, basic protection works
immediately. When the wizard finishes, [set a possession factor](#4-set-a-password-and-2fa) — it's
the first line of `doberman setup`'s own next steps.

On a different host, or want to see exactly what gets wired? The next section covers each path by
hand.

## 3. Wire it to your agent

| Your host | How Doberman attaches | Where |
|---|---|---|
| Claude Code | Hooks: gate every built-in and MCP tool call (recommended) | [`doberman setup`](#2-run-doberman-setup) or [Claude Code hooks](#claude-code-hooks) |
| Codex CLI | Hooks | `doberman setup --host codex` or `doberman install-hooks --host codex`, see [Claude Code hooks](#claude-code-hooks) |
| Claude Desktop, Cursor, any MCP client | MCP proxy: wrap your tool server | `doberman setup` prints the config; see [MCP proxy](#mcp-proxy) |
| OpenClaw | Native plugin adapter | `doberman setup` prints the pointer; see [OpenClaw](#openclaw) |

### Claude Code hooks

Hooks make Doberman gate every tool call your agent makes: built-ins (`Bash`, `Edit`, `Write`,
...) and any MCP tool, without rewiring your MCP config. The harness calls Doberman before each
tool call, and Doberman answers allow or deny. A sensitive action opens Doberman's own in-session
approval dialog (confirm or TOTP 2FA), so the agent can't bypass it by not "asking to use
Doberman".

Install with one command:

```bash
doberman install-hooks
```

```bash
doberman install-hooks --global
```

```bash
doberman install-hooks --host codex
```

`install-hooks` writes `.claude/settings.json` for this project by default, `--global` writes
`~/.claude/settings.json` for every project, and `--host codex` wires `doberman hook codex-pre`
into a Codex CLI `hooks.json` instead. Add `--dry-run` to see what would change without writing
anything. Remove hooks with `doberman uninstall-hooks` (same `--global` / `--host` flags); it
strips only Doberman's entries and leaves your other hooks untouched.

`install-hooks` is idempotent, safe to re-run, and backs up an existing `settings.json` before
writing. `doberman setup` runs it for you.

`uninstall-hooks` only strips the hook entries. The project's `.doberman/` (policy, decision
database), any `--global` hooks, and your device-wide password, 2FA, and fingerprint key are all
left in place. To remove Doberman's protection from this project entirely, run `doberman
uninstall` instead: it removes the project- and local-scope hooks and `.doberman/` in one step. It
never touches `--global` hooks or device-wide auth state, since those protect every project on the
machine. Because it deletes state, it requires your enrolled possession factor (2FA if set up,
otherwise your password) and, being irreversible, also asks you to type the project directory name
back to confirm (`--yes` skips that confirmation, never the factor check). With neither factor
enrolled it fails closed and removes nothing.
If a global (or Codex `user`-scope) hook is still installed, `doberman uninstall` also adds the
project to a device-wide exclusion list that the global hook checks first, so the project gets a
true no-op; `doberman install-hooks` there clears it again (no gate, re-arming is a strengthen).

> **Note**
> `pip uninstall doberman-core` cannot also clean up the hook entries it wrote; pip has no hook
> for that. Run `doberman uninstall-hooks` first. If you already uninstalled the package and every
> tool call now fails with `doberman: command not found`, don't edit `settings.json` by hand:
> `pip install doberman-core` again and the existing hook entries start working the moment the
> binary is back.

On Claude Code it writes this, or add it by hand:

```jsonc
// .claude/settings.json (this project) or ~/.claude/settings.json (all projects)
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Edit|Write|NotebookEdit|WebFetch|WebSearch|mcp__.*",
        "hooks": [{ "type": "command", "command": "doberman hook pre" }]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "Bash|Edit|Write|NotebookEdit|WebFetch|WebSearch|Read|Glob|Grep|mcp__.*",
        "hooks": [{ "type": "command", "command": "doberman hook post" }]
      }
    ],
    "SessionStart": [
      {
        "hooks": [{ "type": "command", "command": "doberman session-summary" }]
      }
    ]
  }
}
```

**The pre-hook.** `doberman hook pre` reads the tool call on stdin and runs Doberman's
deterministic objective floor: path confinement, destructive commands, external-destination and
secret-exfil checks, smuggled-token channels. A routine action passes silently; Doberman is
raise-only and never strips the harness's own prompts. A sensitive action opens Doberman's
approval dialog, a topmost confirm or TOTP prompt bound to that exact action. Approve it and the
call proceeds; decline it, or lose the channel, and it's denied, fail closed. A dangerous action
is blocked outright, with a redaction-safe reason.

**The post-hook.** `doberman hook post` runs after a tool executes and scans its output for
credential-like material. Output containing a recognizable credential (a known key shape, a PEM
block, a secret file's contents) is blocked from reaching the model; the secret is never echoed.
A merely high-entropy token with no known credential shape (a hash, a UUID, a base64 fragment)
passes through, since that heuristic false-positives on ordinary output, but it is still recorded
and taints the session. Taint powers a multi-step exfiltration floor: the pre-hook raises any
later egress (web, network, MCP) in a session that has already touched a secret, `ask` in
light/balanced and a hard `deny` in strict/paranoid. When an outbound value exactly matches, by
keyed-HMAC fingerprint, a secret that entered the session earlier, that confirmed read-then-send
is a hard `deny` in every mode, even light.

Both handlers fail closed and stay import-light, so they add minimal latency to each call. Every
decision lands in the same local, redacted history: `doberman log` shows PreToolUse AUTH/BLOCK
outcomes alongside PostToolUse ones, and `doberman status` reports the installed version, which
settings file(s) carry the hooks, and the last five decisions.

**Doberman protects its own hooks.** Once installed, the agent can't quietly remove them. A write
or edit to `.claude/settings.json` is blocked, and other `.claude/` changes require
authentication, so the agent can't disable enforcement by editing the harness config. This mirrors
how Doberman already hard-blocks its own `.doberman/` control plane, and it holds through the
shell too: a Bash command that writes or deletes the config, or runs `doberman uninstall-hooks`
(or `uninstall`), is blocked, not only the `Write`/`Edit` tools. The same block extends to every
posture- and auth-mutating verb (`mode`, `prefs`, `enforcement`, `2fa`, `password`, `revoke`,
`taint`, `uninstall`), while read/utility verbs (`status`, `doctor`, `log`, `scan`, `review`) stay
allowed.

### MCP proxy

Doberman is a transparent MCP proxy. Give it your existing tool server command after `--`, and it
intercepts everything in between:

```bash
# Before: agent talks directly to your tool server
npx -y @modelcontextprotocol/server-filesystem ~/my-project

# After: wrap it with Doberman
doberman serve -- npx -y @modelcontextprotocol/server-filesystem ~/my-project
```

To choose which repo's policy governs decisions (defaults to the current directory):

```bash
doberman serve --path ~/my-project -- npx -y @modelcontextprotocol/server-filesystem ~/my-project
```

Doberman communicates over stdio: it spawns your tool server as a managed subprocess and speaks
standard MCP. Your agent sees one server entry; the real tool server runs silently behind it.
Your agent's MCP client spawns `doberman serve`, not you. Typed bare into a terminal it blocks on
stdin waiting for a client to speak MCP (it prints one line saying so).

Point your agent at Doberman by replacing its existing MCP server entry with the wrapped version.

**Claude Code (CLI):**

```bash
claude mcp add doberman -- doberman serve -- npx -y @modelcontextprotocol/server-filesystem ~/my-project
```

**Claude Desktop** (`~/Library/Application Support/Claude/claude_desktop_config.json` on Mac,
`%APPDATA%\Claude\claude_desktop_config.json` on Windows):

```json
{
  "mcpServers": {
    "doberman": {
      "command": "doberman",
      "args": ["serve", "--",
               "npx", "-y", "@modelcontextprotocol/server-filesystem", "~/my-project"]
    }
  }
}
```

Cursor, Codex, or any MCP-compatible client uses the same `mcpServers` format in its own config
file; substitute your own tool server command after `--`.

The proxy protects only the tools you route through it. To gate the agent's built-in tools too
(`Bash`, `Edit`, `Write`, ...), use [Claude Code hooks](#claude-code-hooks) where your host
supports them.

### OpenClaw

[OpenClaw](https://docs.openclaw.ai) agents route through Doberman via a small local plugin
instead of a hook-pack (OpenClaw's `before_tool_call` event is only reachable from a typed plugin
hook). It spawns `doberman hook openclaw` per call, the same fail-closed, deterministic objective
floor as the Claude Code hook, and maps the verdict to OpenClaw's own primitives: `allow` is a
no-op, `block` is terminal, and `auth` delegates to OpenClaw's own `/approve` flow (the gateway has
no interactive terminal of its own for Doberman's local challenge dialog). See
[`adapters/openclaw/README.md`](../adapters/openclaw/README.md) for install steps and the
mandatory "verify it's live" canary check. OpenClaw has shipped bugs where plugin hooks silently
never fire, so that check isn't optional.

## 4. Set a password and 2FA

Doberman is raise-only: tightening is always free, but a permanent policy lowering must prove
possession of a local factor. Set the minimum factor now; TOTP enrollment is optional, but becomes
the required, stronger factor once enrolled:

```bash
doberman password set
```

```bash
doberman 2fa setup
```

Rotating or dropping TOTP both need the code you currently hold, so a lost authenticator can't be
swapped out by anyone who merely reaches your shell:

```bash
doberman 2fa setup --force
```

```bash
doberman 2fa remove
```

Too many wrong 2FA codes lock further attempts for a short, self-recovering cooldown.
`doberman 2fa reset-lockout` clears it early by proving your password instead, since a locked-out
factor can't verify itself. It never disables the rate limiter; fresh wrong codes lock it again.

Removing the last possession factor is allowed but fails closed: with neither TOTP nor a password
enrolled, every policy weakening is denied until you enroll one again.

The same enrolled factor gates one other recovery action. Reading a secret taints a session for
the rest of it, and in strict/paranoid that raises later egress to AUTH or BLOCK with no automatic
reset. If that's expected and you want the repo's egress back to the mode default, `doberman taint
clear` wipes both taint stores after the same TOTP-or-password check. It still fails closed with
neither factor enrolled, and a denied or failed check leaves everything untouched.

## 5. Check its health

One read-only self-check that answers whether Doberman is wired up and healthy: host
hooks, config, the decision database, 2FA, the enforcement dial and strictness mode, and the
fingerprint key.

```bash
doberman doctor
```

It only diagnoses (it never changes state) and exits non-zero when a critical check (hooks, the
hook command being on PATH, config, or the decision database) isn't healthy, so it's safe to gate
a script on `doberman doctor && ...`.

Optionally, map what Doberman can see:

```bash
doberman scan
```

## 6. Watch it work

### Session summary

`install-hooks` also wires a `SessionStart` hook that runs `doberman session-summary`: a
print-and-exit summary (never interactive, never blocking) of a device-global, lifetime rollup.
Every decision Doberman makes, across every repo and session on this machine, increments a tiny
counter at `~/.doberman/metrics.db`: verdict class and count only, no path, no reason code, no
per-action detail. It shows total interceptions and the PASS/AUTH/BLOCK split:

```text
+------------------------------------------+
| Doberman - session guard summary          |
| Tracking since 2026-06-14 - this device   |
|                                            |
| Interceptions   1,204                     |
| Auto-passed      1,131  ( 93.9%)          |
| Authed              58  (  4.8%)          |
| Blocked             15  (  1.2%)          |
+------------------------------------------+
```

Run it any time with `doberman session-summary`. Output is plain ASCII, so it always renders on a
legacy Windows console, and the command always exits `0` and never raises: a session summary must
never break a session start.

### Decision log and TUI

`doberman log` prints the raw redacted rows; `doberman tui` browses the same rows interactively
and adds a plain-language "why" for whichever row is highlighted, built only from that row's
already-redacted verdict, layer, and reason codes. Arrow keys navigate; press `?` first for the
full keyboard reference (`/` filter, `b`/`B`/`a` jump to the next/previous BLOCK or next AUTH,
`w`/`enter` full-screen why, `tab` switch focus, `y` copy the action id, `home`/`end`, `r` reload,
`q` quit):

```bash
pip install "doberman-core[tui]"
```

```bash
doberman tui
```

By default the "why" is a deterministic, offline template: no network call, always available.
Enrich it with a short Claude-Haiku rewrite in plainer language if you want:

```bash
pip install "doberman-core[explain]"
```

```bash
export ANTHROPIC_API_KEY=...
export DOBERMAN_EXPLAIN_LLM=1
doberman tui
```

The LLM is a narrator, never a judge: it only rewords a verdict Doberman already made from the
redacted metadata above, and it can never change a decision. It's strictly opt-in (installed,
keyed, and flagged, all three), and any failure (missing key, no network, timeout, bad response)
silently falls back to the offline template. There is no `doberman explain` command; the TUI and
`doberman log` are the only surfaces for this.

### Dashboard

```bash
pip install "doberman-core[dash]"
```

```bash
doberman dash --path .
```

A localhost-only web dashboard, off by default. It binds to `127.0.0.1` only and generates a
fresh, single-use token for that run; open the printed URL to connect, since every API call is
authenticated with that token. `--path` selects the repo to report on (default: the current
directory).

It shows a summary stats line (verdict counts, top reason codes, current mode, effective
enforcement) and a live decision feed that backfills recent decisions, then streams new ones. Both
are read-only and serve only already-redacted fields, never a raw target, argument, or secret.

An `AUTH` challenge can be answered from the dashboard instead of the terminal: it lists pending
approvals and resolves one at a time, a single-use transition, so two concurrent resolves of the
same row can never both win. The dashboard never verifies a TOTP code itself; it relays the
human's decision (and, for tiers that need one, the code) to the same auth-challenge machinery
already running in the decision path. This channel engages only while the dashboard's own
heartbeat is fresh; a stale heartbeat or an unanswered approval falls back to the next channel
(MCP elicitation, then GUI dialog, then terminal) with no added latency.

You can also switch Light/Balanced/Strict/Paranoid from the dashboard. It goes through the same
gate as `doberman mode`: raising applies immediately, and lowering prompts for the same possession
factor; with neither enrolled it fails closed. Every attempt lands in the same append-only
ledger (`doberman policy-history`).

### Run the demo

Want to see real verdicts light up the dashboard without wiring up an agent? `doberman demo` runs
a scripted attack reel, five malicious tool calls and two benign ones, through the real decision
engine (no stubs) and logs every verdict, so the dashboard's live feed lights up with genuine
PASS/AUTH/BLOCK decisions. Nothing is ever executed against a real tool or downstream server.

```bash
# Terminal 1
doberman dash --path .
```

```bash
# Terminal 2
doberman demo --path .
```

Add `--fast` to skip the pacing delay between scenarios. Each scenario prints one line (verdict,
reason codes, explanation, never the raw tool arguments or any synthetic secret used to trip a
rule), then a summary table. Exit code is `0` only if every scenario matched its expected verdict,
so `doberman demo` doubles as a smoke test of the engine itself.

## Appendix: a stale `doberman` on PATH

If `doberman` behaves unexpectedly (missing a command you just added, running an old version,
ignoring your dev install), the shell may be resolving a different `doberman` executable than the
one in your active venv. This is common with more than one install method in play: a global
`pip`, `pipx`, and one or more venvs. Nothing below modifies PATH or removes anything; it only
reports.

**List every `doberman` executable on PATH.** Each command lists every match, not only the first;
the first result is the one your shell runs.

```bash
which -a doberman   # or: command -v doberman
```

```powershell
Get-Command -All doberman
```

**Compare it against your active virtual environment.** With your intended venv activated:

```bash
python -c "import sys; print(sys.prefix)"
command -v doberman
```

If `sys.prefix` doesn't match the directory the resolved `doberman` lives in (for example, it's
not under `.venv/bin` or `.venv/Scripts`), a different install is shadowing your venv's copy.

**Check common install locations.** These only report information; they don't remove or modify
anything.

```bash
.venv/bin/pip show doberman-core   # a pip-installed copy inside a venv
```

```bash
pipx list   # every pipx-managed package and its pinned interpreter
```

**Fix it, without touching PATH.** Re-activate the intended environment in the current shell
(`source .venv/bin/activate`, or `.venv\Scripts\activate` on Windows), then re-run the list step
to confirm it now resolves first. Or invoke the venv's executable directly, bypassing PATH
resolution: `./.venv/bin/doberman --version` (`.venv\Scripts\doberman.exe --version` on Windows).
If you recently activated or deactivated an environment, open a new shell; some shells cache the
resolved path for the current session (`hash -r` in bash clears this without restarting).
