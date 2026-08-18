# Doberman - Setup Guide

The complete guide to running Doberman in front of your coding agent: install it, wire it to
your agent, verify it, and watch it work. New here? The
[README Quick Start](../README.md#quick-start) has the 30-second version.

**Contents**

- [1. Install](#1-install)
- [2. The fast path: `doberman setup`](#2-the-fast-path-doberman-setup)
- [3. Wire it to your agent](#3-wire-it-to-your-agent)
  - [Host hooks](#claude-code-hooks) - Claude Code and Codex CLI
  - [MCP proxy](#mcp-proxy) - Claude Desktop, Cursor, any MCP client
  - [OpenClaw](#openclaw)
- [4. Lock it in: password and 2FA](#4-lock-it-in-password-and-2fa)
- [5. Check it's healthy: `doberman doctor`](#5-check-its-healthy-doberman-doctor)
- [6. Watch it work](#6-watch-it-work) - session summary, log and TUI, dashboard, demo
- [Appendix: wrong or stale `doberman` on PATH](#path-troubleshooting)

---

### 1. Install

```bash
pip install doberman-core
```

> The distribution is **`doberman-core`** (the bare `doberman` name on PyPI belongs to an
> unrelated, abandoned project). The import name and CLI are unchanged - after install you
> still `import doberman` and run the `doberman` command.

Or install the latest from source:

```bash
pip install git+https://github.com/fu351/Doberman-Core.git
```

Or for development:

```bash
git clone https://github.com/fu351/Doberman-Core.git
cd Doberman-Core
pip install -e ".[dev]"
```

Either way you get the `doberman` CLI on your PATH. If `doberman` behaves oddly - an old
version, a missing command - see the [PATH appendix](#path-troubleshooting).
(Maintainers: see [`RELEASING.md`](../RELEASING.md).)

### 2. The fast path: `doberman setup`

On Claude Code, one command does the whole job. An interactive wizard picks your alertness
mode, tunes your guardrails, and wires the hooks:

```bash
doberman setup          # interactive: choose mode, guardrails, install scope
doberman setup --yes    # accept sensible defaults (balanced mode), non-interactively
```

Basic protection works immediately, out of the box. When the wizard finishes:
[set a possession factor](#4-lock-it-in-password-and-2fa), then verify with
[`doberman doctor`](#5-check-its-healthy-doberman-doctor).

On a different host, or want to see what gets wired? The next section covers each path by hand.

### 3. Wire it to your agent

Pick the row that matches your host:

| Your host | How Doberman attaches | Where |
|---|---|---|
| **Claude Code** | Hooks - gate every built-in *and* MCP tool call (recommended) | [`doberman setup`](#2-the-fast-path-doberman-setup) or [host hooks](#claude-code-hooks) |
| **Codex CLI** | Hooks | `doberman install-hooks --host codex` - [host hooks](#claude-code-hooks) |
| **Claude Desktop / Cursor / any MCP client** | MCP proxy - wrap your tool server | [MCP proxy](#mcp-proxy) |
| **OpenClaw** | Native plugin adapter | [OpenClaw](#openclaw) |

<a name="claude-code-hooks"></a>

#### Host hooks (Claude Code and Codex CLI)

Hooks make Doberman gate **every** tool call your agent makes - built-ins (`Bash`, `Edit`,
`Write`, ...) *and* any MCP tool - without rewiring your MCP config. The harness calls Doberman
before each tool call, and Doberman answers **allow / deny**. A sensitive action opens
Doberman's own in-session approval dialog (confirm / TOTP 2FA), so the agent can't bypass it by
simply not "asking to use Doberman".

Install them with one command:

```bash
doberman install-hooks               # Claude Code: writes .claude/settings.json (this project)
doberman install-hooks --global      # ~/.claude/settings.json (every project)
doberman install-hooks --host codex  # Codex CLI: wires `doberman hook codex-pre` instead
doberman install-hooks --dry-run     # show what would change, write nothing
doberman uninstall-hooks             # remove only Doberman's entries (leaves your other hooks intact)
doberman uninstall                   # remove hooks AND this project's .doberman/ (gated - see below)
```

`install-hooks` is idempotent (safe to re-run), backs up an existing `settings.json` before
writing, and never touches your other settings or hooks. `doberman setup` above runs it for you.

`uninstall-hooks` only strips the hook entries — the project's `.doberman/` (policy, decision
database), `--global` hooks, and your device-wide password/2FA/fingerprint key are all left in
place. To fully remove Doberman's protection from **this project**, use `doberman uninstall`
instead: it removes the project-scope and local-scope hooks *and* `.doberman/` in one step. It is
project-scoped only — `--global` hooks and device-wide auth state are never touched, even on
success, since those protect every project on the machine. Because it also deletes state, it is
gated the same way as `doberman taint clear` / `doberman memory reset`: it requires your enrolled
possession factor (2FA if set up, otherwise your Doberman password) and, since it's irreversible,
also asks you to type the project directory name back to confirm (skippable with `--yes`; the
factor check never is). With neither factor enrolled it fails closed and removes nothing.

> **Order matters when removing Doberman.** `pip uninstall doberman-core` has no way to also
> clean up the hook entries it wrote - pip doesn't support that. Always run
> `doberman uninstall-hooks` *first*. If you already uninstalled the package and every tool call
> now fails with `doberman: command not found`, don't edit `settings.json` by hand - just
> `pip install doberman-core` again. The hook entries were never touched, so they start working
> the moment the binary is back; run `doberman uninstall-hooks` afterward if you still want it
> gone.

On Claude Code it writes this snippet - or add it by hand:

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

**What the pre-hook does.** `doberman hook pre` reads the tool call on stdin and runs
Doberman's deterministic **objective floor**: path confinement, destructive commands,
external-destination and secret-exfil checks, smuggled-token channels. Then it decides:

- A routine action passes silently. Doberman is raise-only - it never strips the harness's
  own prompts.
- A sensitive action **opens Doberman's approval dialog**: a topmost confirm / TOTP-2FA prompt
  bound to that exact action. Approve, and that single call is allowed. Decline - or if no GUI
  or terminal channel is available - and it's denied, fail-closed.
- A dangerous action is blocked, with a redaction-safe reason.

**What the post-hook does.** `doberman hook post` runs after a tool executes and scans the
tool's **output** for credential-like material:

- Output containing a **recognizable credential** (a known key shape, a PEM block, a secret
  file's contents) is **blocked from reaching the model**. The secret is never echoed.
- A merely **high-entropy** token with no known credential shape (a hash, a UUID, a base64
  fragment) passes through - that heuristic false-positives on ordinary output - but it is
  still **recorded and taints the session**.
- Session taint powers a **multi-step exfiltration floor**: the pre-hook raises any later
  egress (web, network, MCP) in a session that has already touched a secret - `ask` in
  light/balanced, a hard `deny` in strict/paranoid. That catches read-secret-then-send-it
  exfil no single-call rule can see.
- When an outbound value *exactly* matches (by keyed-HMAC fingerprint) a secret that entered
  the session earlier, that **confirmed** read-then-send is a hard `deny` in **every** mode,
  even `light`.

Both handlers **fail closed** and are import-light, so they add minimal latency to each call.
Every decision lands in the same local, redacted history: `doberman log` shows PreToolUse
AUTH/BLOCK outcomes alongside PostToolUse ones, and `doberman status` reports the installed
version, which settings file(s) have the hooks wired in, and the last 5 recorded decisions.

**Doberman protects its own hooks.** Once installed, the agent can't quietly remove them. A
write or edit to `.claude/settings.json` (the hook-install file) is **blocked**, and other
`.claude/` changes require authentication - the agent can't disable enforcement by editing the
harness config ("firing the cop"). This mirrors how Doberman already hard-blocks its own
`.doberman/` control plane. The protection holds **through the shell** too: a Bash command that
writes or deletes the config (`echo > .claude/settings.json`, `rm -rf .doberman`) or runs
`doberman uninstall-hooks` (or `doberman uninstall`) is blocked, not just the `Write`/`Edit`
tools. The same shell-layer block extends to every posture- and auth-mutating Doberman verb -
`mode`, `prefs`, `enforcement`, `2fa`, `password`, `revoke`, `taint`, `uninstall` - treated as
control-plane tampering and blocked fail-closed, while read/utility verbs (`status`, `doctor`,
`log`, `scan`, `review`) stay allowed.

<a name="mcp-proxy"></a>

#### MCP proxy - wrap any tool server

Doberman is a transparent MCP proxy. You give it your existing tool server command after `--`,
and it intercepts everything in the middle:

```bash
# Before - agent talks directly to your tool server:
npx -y @modelcontextprotocol/server-filesystem ~/my-project

# After - wrap it with Doberman:
doberman serve -- npx -y @modelcontextprotocol/server-filesystem ~/my-project
#             ^^  the -- separator: everything after is your existing tool server command
```

To specify which repo's policy governs decisions (defaults to the current directory):

```bash
doberman serve --path ~/my-project -- npx -y @modelcontextprotocol/server-filesystem ~/my-project
```

Doberman communicates over **stdio**: it spawns your tool server as a managed subprocess and
speaks standard MCP. Your agent sees one server entry; the real tool server runs silently
behind it.

> **You don't run `doberman serve` yourself, and it doesn't start your agent.** Your agent's
> MCP client spawns it, using the config below. Typed bare into a terminal it just blocks on
> stdin waiting for a client to speak MCP, which looks like a hang; it prints one line saying so.

Then point your agent at Doberman - replace your agent's existing MCP server entry with the
Doberman-wrapped version.

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

**Cursor, Codex, or any MCP-compatible client**: use the same `mcpServers` format in your
client's MCP config file, substituting your own tool server command after `--`.

Note the proxy protects the tools you route *through* it. To gate the agent's built-in tools
too (`Bash`, `Edit`, `Write`, ...), use [host hooks](#claude-code-hooks) where your host
supports them.

<a name="openclaw"></a>

#### OpenClaw

[OpenClaw](https://docs.openclaw.ai) agents route through Doberman via a small local plugin
instead of a hook-pack (OpenClaw's `before_tool_call` event is only reachable from a typed
plugin hook). It spawns `doberman hook openclaw` per call - the same fail-closed, deterministic
objective floor as the Claude Code hook - and maps the verdict to OpenClaw's own primitives:
`allow` is a no-op, `block` is terminal, and `auth` delegates to OpenClaw's own `/approve` flow
(the gateway has no interactive terminal of its own for Doberman's local challenge dialog). See
[`adapters/openclaw/README.md`](../adapters/openclaw/README.md) for install steps and the
mandatory "verify it's live" canary check - OpenClaw has shipped bugs where plugin hooks
silently never fire, so that check isn't optional.

### 4. Lock it in: password and 2FA

Doberman is raise-only: tightening is always free, but any later *permanent* policy lowering
must prove possession of a local factor. Set the minimum factor now; TOTP enrollment is
optional, but becomes the required (stronger) factor when present:

```bash
doberman password set   # always-available minimum for mode/prefs lowerings
doberman 2fa setup      # optional TOTP; required instead of the password once enrolled
```

Rotating or dropping TOTP both need the code you currently hold, so a lost authenticator
can't be swapped out by anyone who merely reaches your shell:

```bash
doberman 2fa setup --force   # rotate to a new secret (proves the current code first)
doberman 2fa remove          # unenroll; weakenings fall back to the password afterwards
```

Removing the last possession factor is allowed but fails *closed*: with neither TOTP nor a
password enrolled, every policy weakening is denied until you enroll one again.

The same enrolled factor also gates the one other recovery action: a secret read taints a
session for the rest of it, and in strict/paranoid that raises later egress to AUTH or BLOCK
with no automatic reset. If that's expected and you want the repo's egress back to the mode
default, `doberman taint clear` wipes both taint stores after the same TOTP-or-password check.
It still fails closed with neither factor enrolled, and a denied or failed check leaves
everything untouched.

### 5. Check it's healthy: `doberman doctor`

One read-only self-check that answers *"is Doberman actually wired up and healthy?"* - host
hooks, config, the decision DB, 2FA, the enforcement dial + strictness mode, and the
fingerprint key:

```bash
doberman doctor          # prints a green/red checklist; exits non-zero if a critical check fails
```

It only diagnoses (never changes state) and exits non-zero when a critical check - hooks,
config, or the decision DB - isn't healthy, so it's safe to gate a script on
`doberman doctor && ...`.

Optionally, map what Doberman can see:

```bash
doberman scan   # discover local MCP capabilities and build a risk map
```

### 6. Watch it work

#### Session summary

`install-hooks` also wires a `SessionStart` hook that runs `doberman session-summary`: a
print-and-exit (never interactive, never blocking) summary of a **device-global, lifetime
rollup**. Every decision Doberman makes, across every repo and session on this machine,
increments a tiny counter at `~/.doberman/metrics.db` - verdict class + count only, no path,
no reason code, no per-action detail. The former `doberman dashboard` command remains as a
hidden compatibility alias. It shows total interceptions and the PASS/AUTH/BLOCK split:

```
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

Run it any time with `doberman session-summary`. Output is plain ASCII (no box-drawing runes
or emoji) so it always renders on a legacy Windows console, and the command always exits `0`
and never raises - a session summary must never break a session start.

#### Decision log and TUI

`doberman log` prints the raw redacted rows; `doberman tui` browses the same rows
interactively and adds a plain-language "why" for whichever row is highlighted - the verdict,
the decided layer, and its reason codes turned into a sentence, using only that row's
already-redacted data (never a raw path, argument, or secret). Arrow keys navigate, `r`
reloads, `q` quits:

```bash
pip install "doberman-core[tui]"   # optional extra (textual)
doberman tui
```

By default the "why" is a deterministic, offline template - no network call, always
available. You can optionally enrich it with a short Claude-Haiku rewrite in plainer language:

```bash
pip install "doberman-core[explain]"     # optional extra (anthropic)
export ANTHROPIC_API_KEY=...
export DOBERMAN_EXPLAIN_LLM=1            # opt-in; off by default
doberman tui
```

The LLM is a **narrator, never a judge**: it only rewords a verdict Doberman already made
from the redacted metadata above; it can never change a decision. It's strictly opt-in
(installed *and* keyed *and* flagged, all three), and any failure - missing key, no network,
timeout, bad response - silently falls back to the offline template, so the TUI never blocks
on it or crashes because of it. There is no `doberman explain` command; the TUI and
`doberman log` are the only surfaces for this.

#### Dashboard (preview)

```bash
pip install "doberman-core[dash]"    # optional extra: starlette + uvicorn
doberman dash --path .                # prints a URL, e.g. http://127.0.0.1:8642/?token=...
```

A localhost-only web dashboard, off by default. Binds to `127.0.0.1` only (never a public
interface) and generates a fresh, single-use token for that run - open the printed URL to
connect; every API call is authenticated with that token. `--path` selects the repo to report
on (default: the current directory).

Now live: a **summary stats line** (verdict counts, top reason codes, secret/taint event count,
current mode + effective enforcement - `GET /api/stats`) and a **scrolling live decision feed**
(`GET /api/feed`, Server-Sent Events) that backfills the most recent decisions on connect, then
streams new ones as they're recorded. Both are read-only and serve only already-redacted decision-
log fields (verdict, action type, path *class*, risk, source context, reason codes, timestamp) -
never a raw target, argument, or secret. Risk and source context matter most on actions with no
path class (e.g. a `shell_exec` PASS carries neither a path nor, usually, a reason code) - without
them that row would otherwise render with no signal beyond the verdict. `EventSource` can't set
request headers, so the feed also accepts the token as `?token=` (loopback-only + single-run
token keeps this sound).

**Interactive AUTH approve/deny.** An `AUTH` challenge can now be answered from the dashboard
instead of the terminal: `GET /api/pending` lists redacted pending approvals (action type, risk,
reason codes, human explanation, path *class* - never a raw target or secret) and
`POST /api/resolve/{id}` (body `{"decision": "approved"|"denied", "totp_code"?}`) answers one.
Resolution is a single-use, race-safe state transition (`UPDATE ... WHERE status='pending'`) -
two concurrent resolves of the same row can never both win, and a resolved/expired row 409s.
The dashboard never verifies a TOTP code itself: it only relays the human's decision (and, for
tiers that need one, the code) back to the *existing* auth-challenge machinery running in the
decision path, which performs the real verification unchanged. The channel engages only while a
dashboard's liveness heartbeat is fresh (< 5s old); a stale or missing heartbeat, or an
unanswered approval, falls back to the next channel (MCP elicitation -> GUI dialog -> terminal)
with no added latency and no denial invented on the dashboard's behalf.

**Visual polish.** Dark-by-default (a `prefers-color-scheme: light` override is available),
with color-coded PASS/AUTH/BLOCK and risk badges in the live feed and pending-approval cards, a
header bar showing the current mode + effective enforcement at a glance, and a designed empty
state before any decisions arrive - no build step, no external assets, works fully offline like
the rest of the shell.

#### Try the demo

Want to see real verdicts light up the dashboard without wiring up an agent? `doberman demo`
runs a scripted "attack reel" - five malicious tool calls and two benign ones - through the
**real** decision engine (no stubs) and logs every verdict, so the dashboard's live feed lights
up with genuine PASS/AUTH/BLOCK decisions. Nothing is ever executed against a real tool or
downstream server.

```bash
# Terminal 1
doberman dash --path .

# Terminal 2
doberman demo --path .          # add --fast to skip the pacing delay between scenarios
```

Each scenario prints one line (verdict, reason codes, explanation - never the raw tool
arguments or any synthetic secret used to trip a rule), then a summary table. Exit code is `0`
only if every scenario matched its expected verdict, so `doberman demo` doubles as a smoke test
of the engine itself.

<a name="path-troubleshooting"></a>

### Appendix: wrong or stale `doberman` on PATH

If `doberman` behaves unexpectedly - missing a command you just added, using an
old version, or ignoring changes from your dev install - the shell may be
resolving a *different* `doberman` executable than the one in your active
virtual environment. This is common when you have more than one installation
method in play (global `pip`, `pipx`, and one or more venvs).

This section only lists and compares what's already on your PATH. It does not
modify PATH, uninstall anything, or touch your environments.

**List every `doberman` executable currently resolvable.**

Run the command for your shell. Each one lists **all** matches, not just the
first - this matters because the *first* result is the one actually being run.

```powershell
# PowerShell
Get-Command -All doberman
```

```cmd
:: Command Prompt (cmd.exe)
where.exe doberman
```

```bash
# Unix-like shells (bash/zsh/etc.)
which -a doberman
# or, more portable:
command -v doberman
```

If more than one path is listed, the first one in the output is the one your
shell will actually invoke when you type `doberman`.

**Compare the resolved executable against your active virtual environment.**

With your intended venv activated, check where Python thinks it's installed
and compare it to what step 1 found.

```bash
# Unix-like shells
python -c "import sys; print(sys.prefix)"
command -v doberman
```

```powershell
# PowerShell / Command Prompt
python -c "import sys; print(sys.prefix)"
Get-Command doberman
```

If `sys.prefix` doesn't match the directory the resolved `doberman` lives in
(e.g. it's not under `.venv/bin` or `.venv/Scripts`), a different install is
shadowing your venv's copy.

**Inspect common install locations safely.**

These only report information - they don't remove or modify anything.

```bash
# Check a pip-installed copy inside a venv (Unix-like shells)
.venv/bin/pip show doberman-core
```

```powershell
# Same, on Windows
.venv\Scripts\pip show doberman-core
```

```bash
# Check a pipx-installed copy (any shell with pipx on PATH)
pipx list
```

`pipx list` shows every pipx-managed package and the interpreter it's pinned
to, including any global `doberman` install that could be shadowing your venv.

```bash
# See which python/pip your shell defaults to (Unix-like shells)
which -a python python3 pip pip3
```

```powershell
# PowerShell
Get-Command -All python, pip
```

```cmd
:: Command Prompt
where.exe python
where.exe pip
```

**Remediation (non-destructive).**

Pick whichever fits your workflow - none of these require editing PATH or
removing anything:

- **Re-activate the intended virtual environment** in the current shell
  session, then re-run step 1 to confirm it now resolves first:

  ```bash
  source .venv/bin/activate        # Unix-like shells
  .venv\Scripts\activate           # Windows (cmd or PowerShell)
  ```

- **Invoke the venv's executable explicitly**, bypassing PATH resolution
  entirely:

  ```bash
  ./.venv/bin/doberman --version        # Unix-like shells
  .venv\Scripts\doberman.exe --version  # Windows
  ```

- **Open a new shell/terminal window** if you recently activated or
  deactivated an environment - some shells cache the resolved path for the
  current session (`hash -r` in bash clears this without restarting).
