<div align="center">

<img src="https://raw.githubusercontent.com/fu351/Doberman-Core/main/logo.png" alt="Doberman logo" width="200">

# Doberman

**Adaptive Authorization & Runtime Guardrails for AI Coding Agents**

[![CI](https://github.com/fu351/Doberman-Core/actions/workflows/ci.yml/badge.svg)](https://github.com/fu351/Doberman-Core/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](./LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![Status](https://img.shields.io/badge/status-alpha-orange.svg)](#roadmap)
[![Discord](https://img.shields.io/badge/Discord-join%20the%20pack-5865F2?logo=discord&logoColor=white)](https://discord.gg/Sfy5XGNqty)

Your AI coding agent can `rm -rf` your repo, leak your API keys, or get prompt-injected into exfiltrating data, autonomously, with no undo. Doberman is the guard dog on the execution path, and it stops the dangerous call before it runs.

</div>

<p align="center">
  <img src="https://raw.githubusercontent.com/fu351/Doberman-Core/main/docs/assets/dash-demo.gif" alt="The doberman demo attack reel against the live dashboard: a secret exfiltration, a destructive rm -rf, a protected-branch force push, a smuggled-token egress and a .env read are blocked in the live feed, then a human denies a high-risk SSH-trust-file write from the pending-approvals queue" width="820">
  <br>
  <em><code>doberman demo</code> against the live dashboard (<code>doberman dash</code>): five attacks blocked as they happen, then a human denies a high-risk approval.</em>
</p>

> If it isn't on the execution path, it's advisory, not protective.

Doberman sits between the agent and its tools (a transparent **MCP proxy** or **host hook**) and turns every action into an explicit, auditable decision. Every tool call gets exactly one verdict, decided before it executes:

| Verdict | What happens |
|---|---|
| **PASS** | Routine work, straight through, zero friction. |
| **AUTH** | Sensitive, paused for your one-tap approval. |
| **BLOCK** | Dangerous, stopped cold. It never runs. |

```
AI agent ──▶ Doberman ──▶ real tools (files, shell, MCP servers, APIs)
                 └─ normalize → risk engine → PASS / AUTH / BLOCK
```

Works with Claude Code, Codex, OpenClaw, and any MCP-compatible agent. Cursor and other MCP clients connect through the [MCP proxy](#quick-start). It's open-source, local-first, and holds two guarantees: it **fails closed** (uncertainty denies) and is **raise-only** (it can tighten automatically, but never silently loosens).

<div align="center">

### [Get protected in two commands](#quick-start)  ·  [Join the pack on Discord](https://discord.gg/Sfy5XGNqty)

</div>

---

## Contents

- [Why Doberman?](#why-doberman): what it does, and the two guarantees
- [Quick Start](#quick-start): install and protect an agent in two commands
- [Verify it end-to-end](#verify-it-end-to-end): watch it front a real MCP server
- [Turn gate](#turn-gate): the optional pre-inference chokepoint
- [Benchmark](#benchmark): attack-block rate (ASR) vs. false-positive friction (FPR)
- [Write a custom Guardrail](#write-a-custom-guardrail-plugin): register your own rule as a plugin
- [Tune to your risk tolerance](#tune-to-your-risk-tolerance): strictness modes + the enforcement dial
- [Who is this for?](#who-is-this-for)
- [Roadmap](#roadmap)
- [Contributing](#contributing) · [License](#license)

---

## Why Doberman?

Prompt injection, tool poisoning, data exfiltration, and runaway agents are the defining security problems of agentic AI. Most "AI guardrails" inspect prompts and offer advice. Doberman sits **on the tool-execution path** instead, so a blocked action never runs.

Those three verdicts aren't advice a model can talk its way past. Each is enforced at the one place that counts: the instant before the call runs. Evade the model's own guardrails all you want; the action still has to clear Doberman.

**Two non-negotiable properties:**

- **Fail closed**: any error, uncertainty, or unhandled case denies the action. There is no path to a tool around the decision engine. This includes silence: an approval prompt nobody answers is bounded by a hard deadline (2 minutes for the desktop dialog, 20 minutes as the whole-challenge backstop) and resolves to a **denial**, logged distinctly as `timeout` rather than `denied`. An indefinite block is not a denial, and unattended is exactly how agents usually run.
- **Raise-only learning**: guardrails and adaptive learning can auto-tighten, never silently loosen. Every permanent policy weakening requires explicit, possession-factor-gated, audited human approval (TOTP if enrolled, otherwise the local Doberman password).

**Which guarantee holds on which host?** The [parity matrix](docs/PARITY.md) maps each protection to each host Doberman fronts (Claude Code · Codex · MCP proxy · OpenClaw). Every ✅ links to the CI test that proves it; ◻ cells are open, contributor-sized work (labeled `parity`), and the matrix is regenerated from the tests on every build, so it can't drift from what's actually proven.

---

## Quick Start

Doberman guards any **MCP-compatible** coding agent: pick your agent, run one command, and every
tool call is reviewed before it executes. The full walkthrough - every option, flag, the
dashboard, and health checks - lives in the **[Setup Guide](docs/SETUP.md)**.

```bash
pip install doberman-core
```

After installing, run `doberman --install-completion` to enable shell tab
completion.

> **Uninstalling?** Run `doberman uninstall-hooks` *before* `pip uninstall doberman-core` -
> otherwise the hook entries left in `settings.json` will keep invoking a binary that's gone,
> and every tool call fails with `doberman: command not found`. Already hit this? Just
> `pip install doberman-core` again - the existing entries are still correct and start working
> immediately, no repair needed.

| Your agent | How Doberman plugs in | Get started |
|---|---|---|
| **Claude Code** | Hooks - gate every built-in *and* MCP tool call *(recommended)* | `doberman setup` -> [guide](docs/SETUP.md#claude-code-hooks) |
| **Codex CLI** | Native PreToolUse hook *(experimental)* | `doberman install-hooks --host codex` |
| **Claude Desktop / Cursor** | MCP proxy - wrap your tool server | `doberman serve -- <your-server>` -> [guide](docs/SETUP.md#mcp-proxy) |
| **OpenClaw** | Native plugin adapter | [guide](docs/SETUP.md#openclaw) - [adapter](adapters/openclaw/README.md) |
| **Any MCP-compatible agent** | MCP proxy | [guide](docs/SETUP.md#mcp-proxy) |

**Fastest path - Claude Code:**

```bash
doberman setup      # pick a strictness mode, tune guardrails, wire the hooks
```

Doberman now reviews every tool call your agent makes. Confirm it with `doberman doctor`, or watch
real verdicts with `doberman demo`. Everything else - MCP-proxy wiring, the dashboard, TUI, scan,
and 2FA - is in the **[Setup Guide](docs/SETUP.md)**.

Verdicts are colour-coded everywhere they're shown (`BLOCK` red, `AUTH` amber, `PASS` green):
`review`, `status`, `log`, the TUI, and `demo`, which also wraps its explanations to your terminal
width. Colour is dropped automatically when output is piped or redirected, and honours
[`NO_COLOR`](https://no-color.org) when that variable is set to a non-empty value.

CLI diagnostics use one severity vocabulary: fatal failures start with `error:`, successful but
degraded or skipped work starts with `warning:`, and informational asides start with `note:`.

Add `--mcp` to `doberman scan` for a static, read-only admission check of repository MCP configs;
it reports pattern classes only and never emits raw URLs, arguments, environment values, or other
config content.

---

## Verify it end-to-end

Two ways to watch Doberman front a **real** MCP server, with no in-process test doubles anywhere in the chain.

**Interactive demo (MCP Inspector + a real filesystem server):**

```bash
npx -y @modelcontextprotocol/inspector doberman serve -- npx -y @modelcontextprotocol/server-filesystem ~/my-project
```

Open the Inspector UI and call tools through Doberman: routine reads and writes PASS straight through to the real filesystem server; a destructive call comes back as a policy error and never executes.

**End-to-end test (in a dev checkout):**

```bash
pytest tests/integration/test_serve_end_to_end.py -q
```

This spawns `doberman serve` as a real subprocess fronting a real stdio tool server ([`tests/fixtures/stdio_tool_server.py`](tests/fixtures/stdio_tool_server.py)), connects to it with a real MCP client playing the agent, and asserts the deployable chain over actual stdio:

1. the downstream's tools are re-exposed through the proxy,
2. a PASS verdict reaches the tool (the downstream's call log records it), and
3. a BLOCK verdict (`rm -rf /`) never reaches it: the call log stays empty.

That last assertion is the **chokepoint property** the whole project hangs on.

> **Note on the test fixtures:** the rest of the integration suite deliberately uses an in-process fake downstream ([`tests/fixtures/fake_tool_server.py`](tests/fixtures/fake_tool_server.py)) that records every call it executes. Recording is how the tests prove a blocked action reached nothing. It is a test fixture, not the runtime. `doberman serve` always spawns and talks to the real server you give it after `--`.

### Protocol compatibility

Doberman's proxy speaks MCP as pinned in `pyproject.toml` (`mcp>=1.27,<2`). The MCP
2026-07-28 revision (RC) removes protocol-level session identity (SEP-2575); Doberman's
cross-call protections (taint ledger, read-vs-send fingerprints, decision log) key off
repo-local identity, never the protocol session, and are regression-tested stateless
(`tests/integration/test_stateless_identity.py`). "Supports 2026-07-28" will be claimed
only once the spec finalizes and the pinned SDK adopts it.

---

## Turn gate

A **second invocation point** for the same decision engine, consulted at a host **pre-inference hook** on the user's *turn* (prompt + attached/pasted/tool-fetched content), so a flagrant turn is judged **before a single inference token is spent**. The turn gate is an **efficiency / early-warning** layer with a deliberately narrow guarantee: *no Tier-0-signature turn reaches the model*. The **action gate above remains the safety guarantee**: an attacker who evades the turn gate still meets it.

- **One engine, two invocation points.** `decide_turn` reuses the raise-only `combine`, the `Decision` audit model, and the tiered-auth challenge, adding **zero new verdict authority**. It needs no change to the action path; `turngate/` is a new adapter (sibling to the proxy), and the engine stays pure (the tier guardrails are injected). Turn verdicts append to the same redacted `decisions` log, marked `action_type='turn'`.
- **Tier 0: deterministic signatures (the only hard-stop, small by design).** `instruction_nullification`, `authority_override` (impersonation / mode-switch / "print your system prompt"), `secret_export`, and `encoded_payload`. The precision core is the **issue-vs-mention discriminator** + **origin rule**: a match in *untrusted* (pasted / tool-fetched) content blocks unconditionally (indirect injection); a *typed + issued* match blocks; a *typed + mentioned* (quoted / meta-discussion) match steps up to AUTH so a researcher discussing an attack is never hard-blocked; ambiguous → issued; code fences never exempt.
- **Tier 1: heuristic recall (AUTH-only, structurally BLOCK-incapable).** Embedded agent-directed instructions inside *pasted* text (not mere imperative mood, so tutorials don't trip it), persona override, sub-threshold obfuscation, and urgency+secrecy framing. A false positive costs one tap, not a denied prompt.
- **Stylometric co-occurrence gate.** A per-entity **prompt-style baseline** (coarse scalar buckets only: length, word shape, punctuation/case/digit density; never any text) scores each turn's style as an empirical-CDF p-value, the same calibration idea the subjective baseline uses for actions. The gate steps up **only** when an *extreme* style outlier co-occurs with a *sensitive* apparent intent (credential / destructive / external-send). It **never** escalates on style alone (people type differently tired/mobile/pasting; a device or language switch is drift, not an attack). Style-weird alone is **tagged, not gated**, and stays inert until the prompt baseline matures (the same maturity rule as the other baselines); Tier 0 is active from turn one. Known limitation: shared accounts blend typists, degrading the style signal toward noise. Co-occurrence bounds the cost at one extra tap.
- **Tag-and-pass: turn signals feed the action stage (raise-only).** Every *released* turn publishes its stylometric p-value and heuristic flags as a per-entity `TurnContext`. The action stage consumes it two ways: the subjective surprise term accepts a **bounded, non-negative** contribution (a flagged turn makes its follow-on actions score harsher; a clean turn contributes exactly nothing), and actions tracing to **flagged pasted segments** inherit `provenance: untrusted_data`, which makes the lethal-trifecta floor reachable for them. Raise-only by construction; a blocked turn publishes nothing.
- **Task-match: a user-justified destination narrows the cross-call trifecta (fire-condition precision, not a new lowering path).** A *released* turn's **typed-only** text (never pasted/tool-fetched: an indirect prompt injection can't supply its own "task justification") is scanned for registered-domain tokens and persisted under the host session id. The cross-call session correlator's `correlated_trifecta` pattern (untrusted-provenance ingress + a sensitive/secret read + a current external egress) consults these tokens: an egress to a destination the user's own prompt actually named does not fire; an egress anywhere else still does, exactly as before. No session id, no task tokens, or a task-token read failure all degrade to today's unchanged behavior. The trifecta fires exactly as if this leg did not exist.
- **Repeat-after-block escape hatch.** A near-match resubmission of a just-blocked turn is treated as deliberate human intent and routed to a challenge with proof **scaled to the block** (a Tier 0 signature → `two_factor`; a replay loop cannot produce a TOTP), the **original reason restated**. Approval is single-use; the third attempt within the TTL locks out. The cache stores only a per-entity HMAC fingerprint, a reason, a count, and an expiry, and **never the prompt**.
- **AUTH-first & graceful absence.** `BLOCK` is reserved for the obvious; everything merely suspicious asks the human. Any internal error **fails toward the human** (AUTH), never a silent pass. With no host pre-inference hook (pure MCP-proxy deployments) or `DOBERMAN_TURN_GATE=off`, the gate is simply absent and the action gate carries everything.

---

## Benchmark

A suite-agnostic harness scores Doberman as a **filter over labeled actions** and reports **ASR** (attack bypass rate) and **FPR** (benign over-block / friction). It runs the real decision engine over each labeled tool-call (Doberman is the filter, not the agent), so the gated path is deterministic and offline.

```bash
python -m tests.benchmarks.run --suite synthetic --profile both          # builtins vs plugins
python -m tests.benchmarks.run --suite synthetic --profile before_after  # without vs with Doberman
python -m tests.benchmarks.run --suite corpus --corpus                    # per-category detection FPR/TPR
```

A labeled **detection corpus** (`tests/corpus/detection_corpus.jsonl`, ~137 hand-editable rows across injection / exfiltration / secrets / destructive / encoded / benign) turns the harness into a detection-**quality** measurement: `--corpus` reports true-positive rate (with a stricter `tpr_strict` counting only hard `BLOCK`), false-positive rate, and precision **per category**. Each attack row carries a raise-only floor measured against the live engine and each benign row a false-positive guard, so a CI gate fails on any detection regression or benign over-block. Adding a labeled row is data, not code.

It reports two plugin profiles: `builtins_only` and `with_plugins` (built-ins plus any installed entry-point plugins), and their uplift. The `before_after` profile adds a **no-guardrail baseline** (the unmediated tool path, where every attack executes) so you can read the engine's effect directly as `{before, after, delta}`: how many otherwise-executing attacks it stops vs. how much benign friction it adds. A deterministic synthetic suite gates in CI; map external task suites (**AgentDojo**, AgentDyn, AgentSentry, …) onto core's types with a small adapter, see [`tests/benchmarks/README.md`](tests/benchmarks/README.md).

> Reports hold counts, verdicts, and reason codes only, never payload text. ASR is reported alongside a stricter `asr_strict`, which counts only a hard `BLOCK` as mitigation, so the number can't hide behind a looser definition.

A separate `--subjective` flag runs a distribution-separation diagnostic (Mann-Whitney AUC, not an ASR) over the adaptive subjective layer's per-suite baseline, see [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md#subjective-layer-baseline-separation-diagnostic). A `--poisoning` flag runs the cross-session baseline-poisoning eval: a gradual-drift robustness number showing an autonomous attacker cannot normalize a dangerous action within the allowed envelope (`poisoning_rate` 0) and that the lethal-trifecta floor is unpoisonable even under unlimited approvals, see [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md#cross-session-baseline-poisoning-gradual-drift-robustness).

Published results, methodology, and the reproduce commands (**failure cases before wins**) live in [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md); numbers refresh per release ([`docs/RELEASING.md`](docs/RELEASING.md)).

---

## Write a custom Guardrail (plugin)

Third-party rules register through the **`doberman.rules`** entry-point group. Core never imports your package by name: install it, and `discover_rules()` / the objective guardrail pick it up automatically.

A five-minute worked example lives at [`examples/plugin-guardrail/`](examples/plugin-guardrail/) (from a git checkout):

```bash
pip install -e ".[dev]"
pip install -e examples/plugin-guardrail
pytest examples/plugin-guardrail/tests -q
pip uninstall -y doberman-example-plugin-guardrail   # optional: restore core-only discovery
```

The tutorial rule steps up a write to `SECRETS_TODO.md` to AUTH, stays raise-only, and never puts the path or payload into its explanation. Copy the package when you need a real custom rule of your own.

> While the example is installed, core's "no plugins registered" checks will see it, that is expected. Uninstall before re-running the full core suite if you want a clean standalone environment.

### Forward the audit log (webhook sink)

Drop a `.doberman/audit_webhook.yaml` next to your policy file and every redacted decision record is also POSTed to your own log pipeline:

```yaml
url: https://logs.example.com/doberman   # HTTPS required off-loopback
auth_env: DOBERMAN_WEBHOOK_TOKEN         # optional: env var read at POST time, sent in the Authorization header
timeout_s: 3                             # optional, per-request
```

No file, no sink: the forwarder is inert by default. Delivery never touches the decision path: `emit()` hands the record to a bounded background queue and returns before any I/O, so a wedged endpoint cannot delay a decision; on overflow the oldest record is dropped and counted. Records carry the same already-redacted fields as the local log (path classes, reason codes, verdicts, HMAC fingerprints, never raw secrets), and the auth token value is read from the named env var at POST time, never stored or logged. This is a bridge to your pipeline, not a delivery guarantee. Additional sinks register through the **`doberman.audit_sinks`** entry-point group, same pattern as rules.

---

## Tune to your risk tolerance

Set a mode in `.doberman/policies.yaml` or via `doberman mode <mode>`. Every mode change made this way (the CLI dial or the setup wizard) is recorded in the append-only policy-change ledger (view it with `doberman policy-history`). Lowering strictness (paranoid → strict → balanced → light) is a **weaken** and requires confirmation plus a possession factor: **TOTP if enrolled, otherwise the local Doberman password**. If neither exists, the lowering fails closed; confirmation alone never suffices. Raising stays frictionless and auto-applies:

| Mode | Best for | Bulk-delete threshold | Step-up for unknown destinations | Step-up for behavioral anomalies | Lethal-trifecta exfil |
|---|---|---|---|---|---|
| **Light** | Exploratory / trusted environments | 100 files | No | No | AUTH |
| **Balanced** *(default)* | Everyday coding agents | 25 files | No | Yes | AUTH |
| **Strict** | Production repos, shared codebases | 10 files | Yes | Yes | **BLOCK** |
| **Paranoid** | Highly autonomous or security-critical agents | 3 files | Yes | Yes | **BLOCK** |

> Hard blocks (secret exfiltration, destructive commands, role-boundary violations, smuggled-token-channel exfiltration) are **identical in every mode**. The mode dial only affects where step-up authentication is required for ambiguous or high-risk actions.
>
> Editing **CI/CD pipeline configuration**, including GitHub Actions, GitLab CI (`.gitlab-ci.yml`), Jenkins (`Jenkinsfile`), CircleCI (`.circleci/`), or Azure Pipelines (`azure-pipelines.yml`), steps up to **authentication in every mode**: that config builds, tests, signs, and deploys the repo, so an agent rewrite is always a human-in-the-loop moment.
>
> **Default-registry package fetches** get the same Light/Balanced relaxation: a recognized package-manager fetch with no explicit URL (`pip install requests`, `pip install -r requirements.txt`, `npm install`, `yarn add`, `poetry install`, `go mod download`) passes without a prompt, because its route is the manager's default registry (pypi.org, registry.npmjs.org, …), a *stronger* signal than the unknown hosts these modes already allow. Anything that could redirect the route still steps up in every mode: an explicit URL, `--index-url`/`--registry` (attached or separated), a proxy or registry environment variable, dynamic tokens, a chained command, or the publish/upload direction. `git pull`/`git fetch` also still step up: their route is the configured remote, which static parsing cannot verify. Strict/Paranoid keep the prompt for every package fetch.
>
> **Unknown network destinations** step up to authentication only in Strict/Paranoid. Light and Balanced treat a plain unknown host (e.g. fetching a docs site or an API) as allowed. That AUTH fired on almost every web fetch and was the top source of benign prompts. This relaxes the *destination-alone* signal only: a secret leaving to **any** host is still a hard block (secrets rule + raise-only combine, every mode), and the sharper destination smells (credentials embedded in the URL, raw IP addresses, unresolvable hosts) still step up in every mode. An **out-of-scope role target** likewise steps up in Balanced/Strict/Paranoid but is relaxed in Light; a role-**blocked** target is a hard block in every mode.
>
> **Checksum-valid personal or financial data bound for an external destination**, meaning a payment card number (issuer prefix + Luhn), an IBAN (mod-97), or a dashed US SSN, steps up to **authentication in every mode**. Presence alone never escalates: a card number written to a local file is not exfiltration; the prompt fires only when the data class co-occurs with an outbound destination, mirroring the trifecta's structure. Only the class label reaches any log ("payment card number"), never the value. Free-text PII (names, addresses) and one-time auth codes are outside this structured-format rule's reach. That limit is recorded, not papered over.
>
> One escalation is mode-gated: the **lethal trifecta** (sensitive data **and** untrusted-content provenance **and** an external destination) steps up to authentication in Light/Balanced, and is a hard **BLOCK** in Strict/Paranoid. Those high-security modes refuse this serious-exfil pattern outright rather than leaving it to a confirmation prompt that alert fatigue could rubber-stamp. In Strict/Paranoid this hard block is enforced at **both** decision layers (the objective rules *and* the subjective floor), so an authentication step-up on some other signal can never mask it back down to a mere prompt.
>
> Strict/Paranoid now hard-**BLOCK** a **LOCAL hard smuggled-token channel** (previously AUTH); this is raise-only, and Light/Balanced remain unchanged at AUTH.

### Enforce / monitor / off, the enforcement dial

Orthogonal to the strictness *mode* is an **enforcement dial** (`enforce` *(default)* / `monitor` / `off`) that decides whether Doberman **acts** on a verdict or just observes:

- **`enforce`**: the normal behavior, AUTH prompts and BLOCK denies.
- **`monitor`**: a deliberate **observe mode**. The *discretionary* layer (behavioral anomalies, soft step-ups) is evaluated and **recorded** (`doberman log` / `doberman tui` show what *would* have happened), but it never blocks or prompts. Use it to try Doberman on a repo without friction, or to tune before turning it on.
- **`off`**: the discretionary layer is not evaluated.

Set it with **`doberman enforcement <enforce|monitor|off>`** (no argument prints the current state). Turning the dial *down* is confirmed, plus the strongest **enrolled** possession factor (a TOTP code if 2FA is enrolled, otherwise the local Doberman password), and recorded in the ledger (view it with `doberman policy-history`); with **neither** factor enrolled the change now **fails closed** (there is no confirm-only fallback: run `doberman password set` first, then retry). Turning it back *up* re-arms automatically, with no gate.

**In every state the objective floor stays live.** Secret exfiltration, multi-step/confirmed exfil, destructive commands, protected-path writes, role/policy blocks, and the lethal trifecta always block: `monitor`/`off` can only soften the *discretionary* verdicts, never a catastrophic action. Softening the dial is gated behind confirmation plus a possession factor (TOTP if enrolled, else the local password, fails closed if neither is enrolled), and the on-disk value is **ledger-verified** on every call, so a hand-edited `enforcement: off` in `policies.yaml` with no matching approved change is caught and clamped back to `enforce` (fail-closed).

### The built-in default role, `doberman role enable-default`

The role boundary (Feature 4) is normally **dormant** until you hand-write `.doberman/role.yaml`: with no active role the role rule simply abstains. `doberman role enable-default` opts a repo into a packaged, generic **least-privilege role for a coding assistant** instead, with no YAML required: ordinary source, config, docs, and test files anywhere in the repo classify as in-scope, while CI/CD config, `infra/**`, `migrations/**`, and any unrecognized file type step up to authentication. Paths outside the repo root are always a hard block, for every role. An explicit `.doberman/role.yaml` **always** takes precedence over the opt-in default, and turning the opt-in *off* is a **weaken**: gated behind the same possession-factor confirmation as lowering `mode`/`enforcement` (`doberman role disable-default`). With the opt-in unset, behavior is unchanged from before this existed.

### Subjective preference weights, `doberman prefs`

The adaptive layer's four SL5 "care" weights (`confidentiality`, `reversibility`, `interruption_tolerance`, `blast_radius`, each in `[0, 1]`) tune how readily *discretionary* behavioral signals step up. The objective hard-block floor never moves. Show the active vector with `doberman prefs`, set one weight with `doberman prefs <dimension> <value>`. The same permanent-lowering rule as `mode` applies: **lowering** a weight requires TOTP if enrolled, otherwise the local Doberman password; with neither factor it fails closed, and confirmation alone never suffices. **Raising** a weight is a strengthen and always applies immediately. Every attempt, approved or denied, is recorded in the append-only ledger.

### Recovering from sticky taint, `doberman taint clear`

Reading a secret taints a session for the rest of it, by design: a timed reset would just be a bypass an attacker waits out. In Strict/Paranoid that means a single legitimate secret read can raise every later egress in that repo to AUTH or BLOCK, with no in-band way to reset it. `doberman taint clear` is the explicit, human-only escape hatch: it requires an enrolled possession factor (TOTP if enrolled, otherwise the local Doberman password) and, once verified, wipes **both** taint stores for the current repo: the accumulated-taint ledger and the read-vs-send fingerprint match. There is no confirm-only path, no `--scope`/`--session` narrowing, and a denied or failed gate leaves every row untouched. Because `taint` is already a control-plane-blocked subcommand, a mediated agent can never shell out to run this itself. It only runs from your own terminal.

### MCP tool-schema rug-pull defense, `doberman tools approve`

On every proxied `tools/list`, Doberman pins a keyed-HMAC fingerprint of each tool's name, description, and input schema, then checks that pin on the live `tools/call` path. A changed contract raises the call to AUTH in Light/Balanced or BLOCK in Strict/Paranoid; raw schemas are never stored or logged. This is honestly **trust on first use**: it detects a change after first contact, not a malicious schema presented on that first contact. After reviewing the server change out-of-band, run `doberman tools approve <tool_name>` from your terminal (possession-factor required); mediated agents are blocked from invoking that weakening themselves.

### Governing learned memory, `doberman memory reset` / `doberman memory prune`

The subjective baseline and revealed-preference tables (what Doberman has learned about *this* deployment's normal behavior) are persistent, per-entity memory. Persistent agent memory is itself a poisoning vector: if it were ever trained on a compromised session, nothing short of deleting it clears the taint. `doberman memory reset` is that reliable-deletion escape hatch, gated the same way as `doberman taint clear` (an enrolled possession factor, no confirm-only path), and scoped to one entity (`--entity <id>`) or the whole repo. Deleting learned memory is raise-**safe** by construction: a colder baseline scores everything as *more* novel until it relearns, never less protected. A successful reset is recorded in the append-only ledger (`doberman policy-history`); a denied attempt leaves no ledger trace, same as `taint clear`. `doberman memory prune --older-than-days N` is the retention-limit sibling: an ungated maintenance op (not a security decision) that drops entities whose newest activity is older than `N` days, never touches the decision log, and never guesses at an entity's age from missing data. Both commands are control-plane-blocked, so a mediated agent can never shell out to run them itself.

### Friction telemetry and gated tuning, `doberman tune`

Every AUTH prompt is already in the redacted decision log; `doberman tune` turns it into a friction report: interventions per session (the headline), top AUTH reasons, approval rates by reason and by target class, and a weekly trend. Where an `(action_type, target_path_class)` pair has been approved **every single time**, at least `--min-occurrences` times (default 5), and every one of those AUTHs was a `role_out_of_scope` prompt (never a secret/exfiltration/destructive/control-plane code, that allowlist is fixed), it proposes a **standing elevation**: a narrow, time-limited, revocable PASS for that exact class. `doberman tune` never applies anything by itself, running it only reports. Accepting one (`doberman tune --accept <id>`) routes through the same possession-factor-gated weaken chokepoint as every other policy loosening (TOTP if enrolled, otherwise the local password; fails closed with neither), and the resulting grant is revocable early with `doberman revoke <elevation-id>`, same as any other role elevation.

### Fully removing a project, `doberman uninstall`

`doberman uninstall-hooks` only strips the hook entries: it never touches `.doberman/`, and needs no authentication, which means nothing stops a protected agent that reaches a shell from disabling its own security layer if it wanted to. `doberman uninstall` closes that gap: it removes both the project- and local-scope hooks *and* the project's `.doberman/` control plane (policy + decision database) in one step, gated the same way as `doberman taint clear` / `doberman memory reset`: an enrolled possession factor (TOTP if enrolled, otherwise the local password), with no confirm-only fallback and a hard fail-closed refusal if neither is enrolled. Because it's destructive and irreversible, it also asks you to type the project directory name back before proceeding (`--yes` skips that prompt; it never skips the factor check). It is deliberately **project-scoped only**: `--global` hooks and your device-wide password / 2FA / fingerprint key / `~/.doberman/metrics.db` are shared across every project Doberman protects on the machine and are never touched, even on success. `uninstall` is itself a control-plane-blocked subcommand, so a mediated agent can never shell out to run it. Same protection as `uninstall-hooks`.

That project-scoping used to leave a gap: if a global (`--global`) Claude Code hook, or a Codex `user`-scope hook, is still installed on the machine, it keeps firing for every project regardless of whether that project ever ran `uninstall` — there's no way to make the hook *file* itself skip one project (its matcher keys off tool name, not path). `doberman uninstall` now closes this too: when it detects a global/Codex-user hook is still active, it automatically adds the project to a device-wide exclusion list (`~/.doberman/excluded_projects.json`) that the global hook checks — first, before anything else — on every call, so an excluded project gets a true no-op instead of the hook silently recreating `.doberman/` there. The exclusion list itself is only ever written by this already-gated `uninstall` flow (never by a mediated agent, and never on the hot hook path), and reading it is a pure, side-effect-free check that fails closed (a missing or corrupt list means *not* excluded, i.e. protection stays on). To bring protection back, run `doberman install-hooks` in that project again — any scope, no possession factor needed, since re-arming protection is a strengthen, not a weaken. `doberman status` reports whether the current project is excluded.

### Plain or technical wording, `doberman message-tone`

The authorization prompt speaks plain English by default - *"Your agent wants to run a command: `git push --force main`. The command looked destructive. Approve this exact action?"* - so you can read a catch and decide in seconds without parsing reason codes. Prefer the detailed engineering view? `doberman message-tone technical` switches to the terse `[RISK: …] role: … reason: …` block, and `doberman message-tone human` switches back. It changes wording only: cosmetic, not possession-factor gated, and it never touches the decision, the reason codes, or what lands in the decision log.

---

## Who is this for?

- **Developers running AI coding agents** who want autonomous agents without `rm -rf` roulette.
- **Security engineers** evaluating AI agent security, MCP security, LLM tool-use sandboxing, and zero-trust architectures for agentic AI.
- **Platform teams** deploying agent fleets who need policy enforcement, audit logs, and human-in-the-loop approval for destructive actions.

---

## Roadmap <a name="roadmap"></a>

Planned and in-flight work now lives on GitHub: the **[Doberman Roadmap board](https://github.com/users/fu351/projects/5)** (current focus:
host-harness containment, cost observability, and the enterprise platform). For everything already shipped,
see the **[changelog](CHANGELOG.md)**.

### Known limitations

Doberman is **defense-in-depth, not airtight**: no single rule is a guarantee. The concrete, currently-known gaps:

- **Whole-script homoglyph confusables.** The deterministic check catches *intra-token* mixed-script confusables (e.g. `раypal`, which mixes Cyrillic and Latin). But a token rendered **entirely in one non-Latin script** that mimics a Latin word (e.g. an all-Cyrillic look-alike of `paypal`) is NFKC-stable and is **not** caught by the core deterministic check today. Closing it is planned via a perplexity/confusable detector.
- **Bare high-entropy hex.** To avoid flagging git SHAs, content/AST digests, and lockfile hashes as secrets (a noisy false positive that also poisoned the multi-step taint ledger), the generic high-entropy heuristic ignores tokens that are *entirely* hash-shaped hex (≥ 40 chars). A real secret that is bare hex with **no** surrounding credential name is therefore not stepped up by this heuristic alone; it is still caught when it carries a credential key-name (e.g. `API_KEY=…`), matches a known credential shape, or is later matched by the read-vs-send fingerprint.
- **Oversized encoded-blob detection is defense-in-depth, and evadable.** The `Base64BlobDetector` steps a *large* base64-looking argument up to `AUTH` (tolerating PEM/MIME newline wrapping), but it reasons about **shape and size only**: it never decodes the payload. It targets **bulk** file/secret dumps, not small credentials (those are the objective secrets rule's job), and an attacker can still evade it by splitting the payload across several sub-threshold arguments/calls, interleaving non-alphabet separators, or switching encodings. Raise-only `AUTH`, never a guarantee.
- **Bare-token fixture/pattern-text suppression is WEAK-path only, and marker-gated on the residual.** A bare (non-assignment) token that is regex-pattern source text being quoted (e.g. `sk-ant-[A-Za-z0-9_-]{20,}`) or an obvious hand-written fixture is not stepped up by the high-entropy heuristic alone (#73). Because a fixture marker (`EXAMPLE`/`SAMPLE`/`FAKE`/`DUMMY`) and ordered `0-9`/`a-z` filler are attacker-controllable (and for a *shapeless* secret the high-entropy heuristic is the only signal), a marker on its own is **not** trusted: the token is suppressed only when, after stripping the markers and ascending runs, the residual is too short/low-entropy to be a secret. A real key padded with `EXAMPLE` keeps a high-entropy residual and still fires, and a variable merely *named* with a marker never suppresses its value (the check runs on the RHS after the `=` split). The suppression also never touches the STRONG credential-shape path, which can still drive `secret_exfiltration`. Regex-pattern source (`[]{}\`) is suppressed unconditionally: the tokenizer charset can't produce those characters in a real token. A full live-shaped example key quoted in prose with no marker is still indistinguishable from a real one and steps up.
- **Static egress classification, not a runtime egress broker.** Doberman now reads the external destination out of **shell / package / git commands** too, not just `network_request` calls. The direct-egress verb set spans HTTP/copy tools (`curl`/`wget`/`scp`/`sftp`/`rsync`) **and** raw socket/shell channels (`nc`/`ncat`/`netcat`/`ssh`/`telnet`/`ftp`/`tftp`/`socat`), so a secret piped to `curl <host>` (or `nc host port`) is a hard **BLOCK**, and *any* such command egress (even to a trusted-looking host, or one it cannot resolve to a single route, e.g. a bare `nc host port` or `ssh -R` tunnel with no URL) steps up to **authentication**. This is **raise-only**: it never mints a new silent allow, and ambiguity fails *toward* the human. But it is a *static* parse of the command string: it can flag "this looks like egress" yet cannot prove the host it classified is the socket the process actually opens. A redirect file, `--resolve`/`--connect-to`, an `HTTP(S)_PROXY`/`ALL_PROXY` override, DNS rebinding, a URL built at runtime, `git push` to an already-configured origin, a package lifecycle script, a trusted tenant abused as a channel, or egress from a spawned child process can all still route around the static classifier. **Non-verb channels also remain uncovered:** DNS-label exfil (`dig`/`host`/`nslookup` TXT lookups), bash's built-in `/dev/tcp`, and `openssl s_client` present no recognizable egress verb, so static classification does not see them. Real containment needs a runtime egress broker (planned: the `EgressBroker` seam and its entry-point group, `doberman.egress_brokers`, now exist and are consulted on every egress-classified action. A registered broker's *retrospective* ground-truth signal, what an entity's connections actually showed a moment ago, can now **raise** a decision toward `AUTH` when it diverges from the static classification, but a broker verdict still cannot lower one or grant a `PASS` on its own). A concrete core reference broker's building blocks now exist too: a default-deny allowlist, a two-sided enforcement probe (a direct connection must fail *and* a broker-routed one must succeed), and now a real listener: a minimal, stdlib-only `asyncio` HTTP `CONNECT` forward proxy (`doberman.egress.proxy.ForwardProxy`) that enforces the allowlist at the socket, so a denied destination's upstream connection is never opened. It is **`CONNECT`-only (no SOCKS)** and has **no transparent/SNI-sniffing mode** (it can only mediate traffic explicitly routed to it), and it still ships unregistered as a `doberman.egress_brokers` entry point in core (opt-in wiring only). PASS-authority now exists (RB.4): a registered broker can let `ExternalDestinationRule` contribute `PASS` instead of its usual AUTH, but only when the broker is `PROVEN` to enforce egress **and** its verdict both allowlists **and** will itself enforce this exact destination at the socket: a bare allowlist claim from an unproven or non-enforcing broker still stays AUTH, and RB.3's route-divergence check always wins over a broker PASS. Paranoid mode (RB.5) can now escalate a non-allowlisted destination all the way to a hard BLOCK, but only under the mirror-image condition (a `PROVEN`, `will_enforce`-attesting broker), so the escalation is never a bare mode toggle pretending to be real enforcement; with no broker registered, Paranoid is unchanged from every other mode. A registered broker's retrospective connection history now also feeds a bounded, in-memory per-entity velocity check (RB.6): burst/volume/fan-out over the same recent window can **raise** a `PASS` to `AUTH` (winning even over a broker-backed `PASS`) or append a reason code onto an already-`AUTH`/`BLOCK` result, never lower one, and it is silent with no broker or no `connection_events()`.
- **Artifact digest verification (RB.7) is post-fetch and opt-in: it does not, and cannot, verify content before the fetch decision.** A `PASS` on a `network_request` action is granted *before* the fetch happens, and the RB.2b `ForwardProxy` broker is an HTTP `CONNECT` proxy that relays TLS **opaquely**: it never sees plaintext response bytes, so it cannot inspect or verify a payload pre-decision (that would require TLS MITM interception, deliberately out of scope for this feature). What Doberman does instead: at the same point the existing output secret-scan runs (after the downstream tool call returns), it compares the fetched RESULT text's sha256 digest against any pin an operator configured in `.doberman/artifact_pins.yaml`. A mismatch withholds the content from the agent; a match passes it through. **Any artifact without a configured pin is not verified at all**: this is a narrow, explicit-allowlist integrity check, not a general supply-chain guarantee, and with no pins file present behavior is completely unchanged.
- **Egress behind a flag-taking transparent wrapper steps up to AUTH: static classification is still bypassable.** When an egress command is invoked through a wrapper that takes its own flags (e.g. `sudo -u www-data curl …`, `nice -n 10 curl …`, `ionice -c 2 wget …`), the wrapper's option shifts argv so the option is misread as the command. Doberman detects the hidden command and steps it up to **authentication** when the shlex-normalized command tokens name a known egress tool, including a quote-split (`cu''rl`) or path-qualified (`/usr/bin/curl`) verb. This is **raise-only** (it never mints a new silent allow), but two honest limits remain: (1) static parsing cannot recover the *wrapped* command's host, so a wrapped secret exfiltration resolves to **AUTH, not the hard BLOCK** its un-wrapped form gets (the secret-exfil floor needs the host it cannot see); and (2) a verb obscured beyond token normalization, such as a nested shell (`sh -c '…'`), command substitution (`$(…)`), or a name assembled at runtime, can still evade the static classifier. Conversely, an egress name that appears only as an *argument to a flag-taking wrapper* (e.g. `sudo -u www-data grep curl x`, where argv-shifting makes the wrapper misread `curl` as the command) over-steps to AUTH: a deliberate fail-closed cost; a bare `grep curl x` with no wrapper parses cleanly and is not flagged. Robust containment here needs the runtime egress broker (planned).
- **The adaptive layer runs on the MCP proxy path, not the host-hook path.** The Claude Code and OpenClaw hooks run the deterministic objective guardrail only: the per-entity behavioral baseline, surprise scoring, and drift detection (`doberman.subjective`) are not consulted there. That's deliberate: a `PreToolUse` hook runs before every tool call, and importing `numpy`/`scipy`/`river` at module scope costs ~2s per call. Both hooks now share a single evaluate/record spine, so verdicts cannot drift between hosts. The hook path gives you the deterministic floor (path confinement, destructive-command detection, secret patterns, egress classification, role boundaries, the enforcement dial); adaptive escalation currently needs the proxy. Wiring the adaptive layer onto the hook path via a warm process is planned.
- **The control plane is self-protected: a mediated agent cannot disable its own leash, but a human still can.** Wherever an action routes through the decision engine, a write, delete, or read of Doberman's own state (`.doberman/`) or a host's hook-and-trust config is hard-blocked, and the same check runs against a shell command that merely *names* one of those paths, so `rm -rf .doberman` or `echo > .claude/settings.json` is caught too. The protected set now also recognizes the Codex CLI control plane (`.codex/hooks.json`, `.codex/config.toml`, and the `.codex/` plugin dirs are hard-blocked; the rest of `.codex/**` steps up to authentication), mirroring the `.claude`/`.doberman` split, so it is enforced the moment a Codex action reaches the engine. Note the front door matters: today that path covers Claude Code (hooks) and any MCP-wrapped tool server. A **Codex CLI PreToolUse adapter now exists** (`doberman hook codex-pre`; Codex's hook layer is a Claude Code compatibility shim, so it shares the same decision spine and deny shape), but its one-command installer (`install-hooks --host codex`) is the next slice, so wiring it into `~/.codex/hooks.json` is still manual for now. And the limit is honest even then: this stops the *agent*, not a *human*: someone at the keyboard can always disable a hook (e.g. Codex's own `--dangerously-bypass-hook-trust`), and a control-plane path built at runtime (from a shell variable, glob, or a `python -c` payload) is not caught by static command parsing.

---

## Contributing

Start with [CONTRIBUTING.md](CONTRIBUTING.md) for local setup, CI checks, project
invariants, and the PR workflow.

CI also runs `python scripts/check_markdown_links.py`, a deterministic offline check for
repository-local Markdown links and heading anchors. It skips external URLs and fenced code
blocks and never makes network requests.

**Come say hi.** Questions, ideas, a rule pack to share, or an attack you caught in the wild?
[**Join the pack on Discord →**](https://discord.gg/Sfy5XGNqty). It's where the roadmap gets shaped.

**Found a vulnerability or a way around a guardrail?** Please report it privately: see
[SECURITY.md](SECURITY.md). Don't open a public issue or Discord post for a security report.

---

## License

Apache-2.0. The core is genuinely standalone: no proprietary dependency, ever (CI-enforced). Each
[release](https://github.com/fu351/Doberman-Core/releases) also ships a CycloneDX SBOM listing the
exact dependency set, see [SECURITY.md](SECURITY.md#software-bill-of-materials).

---
