<div align="center">

<img src="https://raw.githubusercontent.com/DobermanCore/Doberman-Core/main/logo.png" alt="Doberman logo" width="200">

# Doberman

**Adaptive Authorization & Runtime Guardrails for AI Coding Agents**

[![CI](https://github.com/DobermanCore/Doberman-Core/actions/workflows/ci.yml/badge.svg)](https://github.com/DobermanCore/Doberman-Core/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](./LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![Status](https://img.shields.io/badge/status-alpha-orange.svg)](#roadmap)
[![Discord](https://img.shields.io/badge/Discord-join%20the%20pack-5865F2?logo=discord&logoColor=white)](https://discord.gg/Sfy5XGNqty)

Your AI coding agent can `rm -rf` your repo, leak your API keys, or get prompt-injected into exfiltrating data, autonomously, with no undo. Doberman is the guard dog on the execution path, and it stops the dangerous call before it runs.

</div>

<p align="center">
  <img src="https://raw.githubusercontent.com/DobermanCore/Doberman-Core/main/docs/assets/dash-demo.gif" alt="The doberman demo attack reel against the live dashboard: a secret exfiltration, a destructive rm -rf, a protected-branch force push, a smuggled-token egress and a .env read are blocked in the live feed, then a human denies a high-risk SSH-trust-file write from the pending-approvals queue" width="820">
  <br>
  <em><code>doberman demo</code> against the live dashboard (<code>doberman dash</code>): five attacks blocked as they happen, then a human denies a high-risk approval.</em>
</p>

> A guardrail that isn't on the execution path can only advise.

Doberman sits between the agent and its tools (a transparent **MCP proxy** or **host hook**) and turns every action into an explicit, auditable decision. Every tool call gets exactly one verdict, decided before it executes:

| Verdict | What happens |
|---|---|
| `PASS` | Routine work, straight through, zero friction. |
| `AUTH` | Sensitive, paused for your one-tap approval. |
| `BLOCK` | Dangerous, stopped cold. It never runs. |

```
AI agent ──▶ Doberman ──▶ real tools (files, shell, MCP servers, APIs)
                 └─ normalize → risk engine → PASS / AUTH / BLOCK
```

Works with Claude Code, Codex, OpenClaw, and any MCP-compatible agent. Cursor and other MCP clients connect through the [MCP proxy](#quick-start). It's open source, local first, and holds two guarantees: it fails closed (uncertainty denies) and is raise-only (it can tighten automatically, but never silently loosens).

<div align="center">

### [Get protected in two commands](#quick-start)  ·  [Join the pack on Discord](https://discord.gg/Sfy5XGNqty)

**Full docs:** [docs.trydoberman.dev](https://docs.trydoberman.dev)

</div>

---

## Contents

- [Why Doberman](#why-doberman): what it does, and the two guarantees
- [Quick start](#quick-start): install and protect an agent in two commands
- [Verify it end-to-end](#verify-it-end-to-end): watch it front a real MCP server
- [Turn gate](#turn-gate): the optional pre-inference chokepoint
- [Benchmark](#benchmark): attack-block rate vs. false-positive friction
- [Write a guardrail plugin](#write-a-guardrail-plugin): register your own rule or audit sink
- [Tune to your risk tolerance](#tune-to-your-risk-tolerance): strictness modes and the enforcement dial
- [Who is this for](#who-is-this-for)
- [Roadmap](#roadmap)
- [Contributing](#contributing) · [License](#license)

---

## Why Doberman

Most "AI guardrails" inspect prompts and offer advice, after the model has already decided. Doberman
sits on the tool-execution path instead, so a blocked action never runs, no matter how it talked its
way past the model's own guardrails first. Two properties make that a guarantee:

- **Fail closed**: any error, uncertainty, or unhandled case denies the action. There's no path to a
  tool around the decision engine. This includes silence: an approval prompt nobody answers is bounded
  by a hard deadline (2 minutes for the desktop dialog, 20 minutes as the whole-challenge backstop)
  and resolves to a denial, logged distinctly as `timeout` rather than `denied`. A hung prompt is not a
  denial, and agents usually run unattended, so the deadline matters.
- **Raise-only learning**: guardrails and adaptive learning can auto-tighten, never silently loosen.
  Every permanent policy weakening requires explicit, possession-factor-gated, audited human approval
  (TOTP if enrolled, otherwise the local Doberman password).

The [parity matrix](docs/PARITY.md) maps each protection to each host Doberman fronts (Claude Code,
Codex, MCP proxy, OpenClaw). Every checkmark links to the CI test that proves it; open cells are
contributor-sized work, and the matrix regenerates from those tests on every build, so it cannot drift
from what is proven.

---

## Quick start

Doberman guards any MCP-compatible coding agent: pick your agent, run one command, and every tool call
is reviewed before it executes. The full walkthrough (every option and flag, the dashboard, health checks)
is the [Setup guide](docs/SETUP.md).

```bash
pip install doberman-core
```

After installing, run `doberman --install-completion` to enable shell tab completion.

> **Note**
> Run `doberman uninstall-hooks` before `pip uninstall doberman-core`. Uninstalling the package first
> leaves the hook entries in `settings.json` pointing at a binary that's gone, and every tool call
> then fails with `doberman: command not found`. Already hit this? `pip install doberman-core` again;
> the existing entries are still correct and start working immediately, no repair needed. More
> recovery steps: [Recover](docs/RECOVERY.md).

| Your agent | How Doberman plugs in | Get started |
|---|---|---|
| **Claude Code** | Hooks: gates every built-in and MCP tool call *(recommended)* | `doberman setup` → [guide](docs/SETUP.md) |
| **Codex CLI** | Native PreToolUse hook *(experimental)* | `doberman install-hooks --host codex` |
| **Claude Desktop / Cursor** | MCP proxy: wraps your tool server | `doberman serve -- <your-server>` → [guide](docs/SETUP.md) |
| **OpenClaw** | Native plugin adapter | [guide](docs/SETUP.md) · [adapter](adapters/openclaw/README.md) |
| **Any MCP-compatible agent** | MCP proxy | [guide](docs/SETUP.md) |

**Fastest path (Claude Code):**

```bash
doberman setup      # pick a strictness mode, tune guardrails, wire the hooks
```

Doberman now reviews every tool call your agent makes. Confirm it with `doberman doctor`, or watch
real verdicts with `doberman demo`. MCP-proxy wiring, the dashboard, the TUI, scan, and 2FA are in the
[Setup guide](docs/SETUP.md).

---

## Verify it end-to-end

Two ways to watch Doberman front a real MCP server, with no in-process test doubles anywhere in the
chain.

**Interactive demo (MCP Inspector and a real filesystem server):**

```bash
npx -y @modelcontextprotocol/inspector doberman serve -- npx -y @modelcontextprotocol/server-filesystem ~/my-project
```

Open the Inspector UI and call tools through Doberman: routine reads and writes pass straight through
to the real filesystem server; a destructive call comes back as a policy error and never executes.

**End-to-end test (in a dev checkout):**

```bash
pytest tests/integration/test_serve_end_to_end.py -q
```

This spawns `doberman serve` as a real subprocess fronting a real stdio tool server
([`tests/fixtures/stdio_tool_server.py`](tests/fixtures/stdio_tool_server.py)), connects to it with a
real MCP client playing the agent, and asserts the deployable chain over actual stdio: the
downstream's tools are re-exposed through the proxy, a `PASS` verdict reaches the tool (the
downstream's call log records it), and a `BLOCK` verdict (`rm -rf /`) never reaches it, the call log
stays empty. That last assertion is the chokepoint property the whole project hangs on.

> **Note**
> The rest of the integration suite deliberately uses an in-process fake downstream
> ([`tests/fixtures/fake_tool_server.py`](tests/fixtures/fake_tool_server.py)) that records every call
> it executes, so the tests can prove a blocked action reached nothing. It's a test fixture, not the
> runtime. `doberman serve` always spawns and talks to the real server you give it after `--`.

Doberman's proxy speaks MCP as pinned in `pyproject.toml` (`mcp>=1.27,<2`). Its cross-call protections
(taint ledger, read-vs-send fingerprints, decision log) key off repo-local identity, never the
protocol session, and are regression-tested stateless.

---

## Turn gate

A second invocation point for the same decision engine, consulted at a host pre-inference hook on the
user's turn (prompt plus attached, pasted, or tool-fetched content), so a flagrant turn is judged
before a single inference token is spent. The turn gate is an efficiency and early-warning layer with
a deliberately narrow guarantee: no Tier-0-signature turn reaches the model. The action gate above
remains the safety guarantee: an attacker who evades the turn gate still meets it. Full mechanism,
module map, and invariants: [Turn gate](docs/TURN_GATE.md).

---

## Benchmark

A suite-agnostic harness scores Doberman as a filter over labeled actions and reports attack bypass
rate and benign over-block rate, running the real decision engine over each labeled tool call so the
gated path is deterministic and offline. A labeled detection corpus turns it into a per-category
detection-quality measurement, and CI gates on any regression. Commands, methodology, and published
results (failure cases before wins): [Benchmarks](docs/BENCHMARKS.md).

---

## Write a guardrail plugin

Third-party rules register through the `doberman.rules` entry-point group; core never imports your
package by name. A five-minute worked example lives at
[`examples/plugin-guardrail/`](examples/plugin-guardrail/), and the same entry-point pattern
(`doberman.audit_sinks`) forwards the redacted audit log to your own pipeline, for example a webhook.
Full walkthrough: [Write a guardrail plugin](docs/PLUGINS.md).

---

## Tune to your risk tolerance

Doberman ships with sane defaults, but every dial is yours to move: the strictness `mode`
(Light/Balanced/Strict/Paranoid), the `enforcement` dial (enforce/monitor/off), the opt-in default
`role`, the subjective `prefs` weights, `tune`'s friction telemetry, and `message-tone`. Lowering any
of them requires a possession factor (TOTP if enrolled, otherwise the local Doberman password) and is
recorded in the append-only policy-change ledger; raising is always frictionless. Full reference:
[Tune to your risk tolerance](docs/TUNING.md). Recovering from sticky taint, re-approving a changed
tool, resetting learned memory, or fully removing a project: [Recover](docs/RECOVERY.md).

---

## Who is this for

- **Developers running AI coding agents** who want autonomous agents without `rm -rf` roulette.
- **Security engineers** evaluating AI agent security, MCP security, LLM tool-use sandboxing, and
  zero-trust architectures for agentic AI.
- **Platform teams** deploying agent fleets who need policy enforcement, audit logs, and
  human-in-the-loop approval for destructive actions.

---

## Roadmap <a name="roadmap"></a>

Planned and in-flight work now lives on GitHub: the
**[Doberman Roadmap board](https://github.com/users/fu351/projects/5)** (current focus: host-harness
containment, subjective-layer hardening, the ambient-monitoring daemon, and the enterprise platform).
For everything already shipped, see the **[changelog](CHANGELOG.md)**.

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
- **Environment-dump detection is verb-based, not exhaustive.** `env`, `printenv`, `export`/
  `export -p`, `declare -x`/`typeset -x`, and the PowerShell `Env:` drive listing step up to
  authentication before running. Deliberately out of scope for now: a bare POSIX `set` (lists
  shell variables *and* functions, but is also extremely common as `set -e`/`set -euo pipefail`
  in scripts — flagging it bare would be a high false-positive cost for a rarely-abused vector)
  and a Windows `cmd.exe` bare `set` (same ambiguity). A literal trailing backslash (`dir
  env:\`) is not in the rule's Windows-path trigger list, so POSIX shlex parsing fails on it
  first and it falls back to the generic `opaque_command` AUTH instead — still fails upward,
  just under a different reason code; the no-backslash form (`dir env:`) is unaffected. And, as
  with every objective rule, this is static command-text classification: it cannot see what an
  *output* later contains, so a program that reads `os.environ` internally and prints it (e.g. a
  Python one-liner with no recognizable verb) is not caught here — only by the post-execution
  output scan.
- **The control plane is self-protected: a mediated agent cannot disable its own leash, but a human still can.** Wherever an action routes through the decision engine, a write, delete, or read of Doberman's own state (`.doberman/`) or a host's hook-and-trust config is hard-blocked, and the same check runs against a shell command that merely *names* one of those paths, so `rm -rf .doberman` or `echo > .claude/settings.json` is caught too. The protected set now also recognizes the Codex CLI control plane (`.codex/hooks.json`, `.codex/config.toml`, and the `.codex/` plugin dirs are hard-blocked; the rest of `.codex/**` steps up to authentication), mirroring the `.claude`/`.doberman` split, so it is enforced the moment a Codex action reaches the engine. Note the front door matters: today that path covers Claude Code (hooks) and any MCP-wrapped tool server. A **Codex CLI PreToolUse adapter now exists** (`doberman hook codex-pre`; Codex's hook layer is a Claude Code compatibility shim, so it shares the same decision spine and deny shape), and `doberman install-hooks --host codex` wires it into `~/.codex/hooks.json` (or a project-local one with `--local`) in one command. And the limit is honest even then: this stops the *agent*, not a *human*: someone at the keyboard can always disable a hook (e.g. Codex's own `--dangerously-bypass-hook-trust`), and a control-plane path built at runtime (from a shell variable, glob, or a `python -c` payload) is not caught by static command parsing.

---

## Contributing

Start with [CONTRIBUTING.md](CONTRIBUTING.md) for local setup, CI checks, project invariants, and the
PR workflow.

CI also runs `python scripts/check_markdown_links.py`, a deterministic offline check for
repository-local Markdown links and heading anchors. It skips external URLs and fenced code blocks
and never makes network requests.

**Come say hi.** Questions, ideas, a rule pack to share, or an attack you caught in the wild?
[**Join the pack on Discord →**](https://discord.gg/Sfy5XGNqty). It's where the roadmap gets shaped.

**Found a vulnerability or a way around a guardrail?** Please report it privately: see
[SECURITY.md](SECURITY.md). Don't open a public issue or Discord post for a security report.

---

## License

Apache-2.0. The core is standalone: no proprietary dependency (CI-enforced). Each
[release](https://github.com/DobermanCore/Doberman-Core/releases) also ships a CycloneDX SBOM listing the
exact dependency set, see [SECURITY.md](SECURITY.md#software-bill-of-materials).

---
