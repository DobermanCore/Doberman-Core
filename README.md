<div align="center">

# 🐕 Doberman

**An adaptive authorization layer that sits between a coding agent and its tools.**

[![CI](https://github.com/fu351/Doberman-Core/actions/workflows/ci.yml/badge.svg)](https://github.com/fu351/Doberman-Core/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](./LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![Status](https://img.shields.io/badge/status-alpha-orange.svg)](#project-status)

</div>

---

## Overview

Doberman is a security layer for AI coding agents. It sits **on the tool-execution path** — the agent talks to Doberman, and Doberman talks to the real tools (filesystem, shell, git, network, package managers) over the [Model Context Protocol](https://modelcontextprotocol.io). Every meaningful action is intercepted, normalized into a redacted, structured **security object**, and run through a risk-based decision engine that returns one of three verdicts — **allow**, **authenticate**, or **block** — before the action is ever forwarded. The guiding principle is simple: *if Doberman isn't on the execution path, it's advisory, not protective.* Doberman is built to **fail closed** (any error or uncertainty denies the action) and to be **raise-only** (guardrails may automatically tighten, never silently loosen), so an agent can never reach a tool around it and a buggy rule can never make the system less safe.

> ### Project status
> **Alpha — pre-1.0, API unstable.** The **complete MVP core (Features 1–10)** is implemented: the interception layer (1), the decision engine (2), the **objective guardrail** (3 — basic rules + the plugin seam), **agent role policy** (4 — role boundaries + the policy-source seam), **capability discovery** (5 — `doberman scan`), **policy checklist + strength modes** (6), **tiered authentication** (7 — action-specific confirm/2FA challenges, narrow/temporary role elevation, and the auth-provider seam), the **local decision log & audit** (8 — an append-only, redacted SQLite log with `doberman log`/`memory` and the audit-sink seam), the **subjective guardrail** (9 — a local workflow baseline that escalates *unusual-for-you* actions, plus the detector seam), and the **policy-drift & poisoning defense** (10 — strengthen/weaken classification, a 2FA-gated weakening chokepoint with a visible diff, an append-only change ledger, and the drift-observer seam). Doberman blocks the headline disasters (secret exfiltration, protected-path writes, catastrophic commands), turns an `AUTH` verdict into a real, action-bound challenge that releases the call only on success, escalates actions that cross the agent's role boundary **or** depart from its learned workflow, reports the agent's blast radius, offers one Light/Balanced/Strict/Paranoid dial over good defaults, records every decision to an explainable, privacy-preserving local audit trail, and ensures protection can only ever be *loosened* through an explicit, audited, 2FA-gated human approval. This is the open-source **core**; advanced/hosted capabilities live in a separate commercial edition (see the [Roadmap](#roadmap)).

---

## Table of contents

- [How it works](#how-it-works)
- [Installation](#installation)
- [Quickstart](#quickstart)
- [Features](#features)
- [Design invariants](#design-invariants)
- [Versioning](#versioning)
- [Changelog](#changelog)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [Security](#security)
- [License](#license)

---

## How it works

```
                ┌─────────────────────── Doberman ───────────────────────┐
   coding       │                                                         │     real
   agent  ──────┼──▶  normalize  ──▶  decision engine  ──▶  enforce  ─────┼──▶  tool
  (MCP client)  │   (SecurityObject)   (PASS/AUTH/BLOCK)    (chokepoint)   │   servers
                │                                              │          │
                │                                  redacted interception  │
                │                                       log (JSON)        │
                └─────────────────────────────────────────────────────────┘
```

1. **Intercept** — Doberman is an MCP *server* to the agent and an MCP *client* to the downstream tool servers. It re-exposes the downstream tools unchanged, so every `tools/call` flows through a single chokepoint.
2. **Normalize** — each call becomes an immutable, redacted `SecurityObject` (action type, target, risk, redacted arguments, fingerprints). Normalization never raises; on bad input it produces a conservative high-risk object.
3. **Decide** — the engine runs the objective guardrail first, then (if it passes) the subjective guardrail — which escalates actions that are *unusual for the learned workflow* — combining results **raise-only** into a single explainable `Decision`.
4. **Enforce** — `PASS` forwards the call; `AUTH` runs a tiered, action-specific challenge (confirm / 2FA / role elevation) and forwards only on success — after a TOCTOU re-decision — otherwise nothing is forwarded; `BLOCK` returns a "blocked by policy" error and the call is **never** forwarded. Any engine failure is itself a `BLOCK`.
5. **Log** — every action is recorded as one redacted JSON line *and* one append-only, redacted row in a local SQLite decision log (path **class**, reason codes, verdict, auth result — never a raw target, argument, or secret), correlated by a stable action id and fanned out to any registered audit sinks.

---

## Installation

Requires **Python 3.11+**.

```bash
# clone
git clone https://github.com/fu351/Doberman-Core.git
cd Doberman-Core

# create and activate a virtual environment
python -m venv .venv
# Windows:        .venv\Scripts\activate
# macOS / Linux:  source .venv/bin/activate

# install the package with dev tooling
pip install -e ".[dev]"
```

### Verify your setup

```bash
ruff check .           # lint
ruff format --check .  # format check
lint-imports           # architecture / boundary contracts
pytest                 # test suite (100% coverage gate at 80% in CI)
```

A green run means the core engine, proxy, and guardrail wiring all behave as specified.

---

## Quickstart

Doberman ships a **`doberman serve`** runtime: it runs as an MCP server to your agent and an MCP client to your
real tool server, so it sits *on* the execution path with no code changes on either side. The pattern is one line —
**instead of pointing your agent at the real MCP server, point it at `doberman serve -- <that server>`.**

```bash
# Run Doberman in front of any MCP tool server (everything after `--` is the downstream command):
doberman serve -- npx -y @modelcontextprotocol/server-filesystem /path/to/repo

# Policy, decision log, and elevations live in <repo>/.doberman — choose the repo with --path:
doberman serve --path /path/to/repo -- npx -y @modelcontextprotocol/server-filesystem /path/to/repo
```

### Connect your agent

Swap the agent's MCP server entry to launch Doberman, which then spawns the real server. The decision happens in
between; `AUTH` prompts appear on **your terminal** (with no terminal attached, an `AUTH` action is denied — fail
closed), and every decision is recorded — inspect it with `doberman log` and `doberman status`.

**Claude Code**

```bash
claude mcp add doberman -- doberman serve -- npx -y @modelcontextprotocol/server-filesystem ~/repo
```

**Claude Desktop / Cursor / Codex** (`mcpServers` block in the client's config, e.g. `claude_desktop_config.json`)

```jsonc
{
  "mcpServers": {
    "doberman": {
      "command": "doberman",
      "args": ["serve", "--",
               "npx", "-y", "@modelcontextprotocol/server-filesystem", "~/repo"]
    }
  }
}
```

That's it — your agent sees exactly the same tools, now mediated by Doberman.

For the embeddable form (build the proxy yourself and serve it over your own transport), use
[`build_proxy_server`](./src/doberman/proxy/mcp_proxy.py); for runnable wiring examples see
[`tests/integration/test_serve_end_to_end.py`](./tests/integration/test_serve_end_to_end.py) and
[`tests/integration/test_proxy_passthrough.py`](./tests/integration/test_proxy_passthrough.py).

---

## Features

### Feature 1 — Tool Mediation Layer & Normalized Action Object · `v0.1.0`

Puts Doberman physically between the agent and its tools and turns every tool call into structured, observable, redacted data.

- **MCP proxy chokepoint** — re-exposes downstream tools; every `tools/call` is forced through one decision point. Fails closed (downstream/transport errors yield a sanitized error, never a silent success or a bypass).
- **`SecurityObject` schema** — an immutable, frozen normalized action object (action type, target, risk, reversibility, source context, redacted arguments, payload fingerprints) plus a `GuardrailResult`/`Verdict`/`ReasonCode` vocabulary shared across the whole system.
- **`normalize()`** — maps raw tool calls to action types, extracts targets, and redacts secret-shaped and oversized argument values. Never raises; degrades to a conservative high-risk object on malformed input.
- **Redacted interception log** — one structured JSON line per action, correlated by a stable action id. Best-effort by contract: logging can never alter, block, or crash the execution path, and never emits raw secrets.

### Feature 2 — Decision Engine & Execution Rule · `v0.2.0`

Replaces the pass-through stub with the real control core, so every guardrail added later automatically obeys the safety rules.

- **`Guardrail` interface & `Decision` model** — a pure `(action, ctx) → GuardrailResult` contract and a frozen, always-explained `Decision` audit record.
- **Raise-only combination** — `combine()` takes the **max** verdict (`PASS < AUTH < BLOCK`), **max** risk, and the **union** of reasons. There is deliberately no code path that lowers either axis — verified by an exhaustive matrix and a randomized property test.
- **Objective-first execution rule** — objective guardrail first; a `BLOCK`/`AUTH` short-circuits (the subjective guardrail can never weaken it); a non-allowlisted subjective `BLOCK` is clamped to `AUTH`. Objective errors fail **closed** (`BLOCK`); subjective errors fail **upward** (`AUTH`).
- **Enforcement at the chokepoint** — the proxy now acts on verdicts: `PASS` forwards, `AUTH`/`BLOCK` return explanatory errors (reason codes + human explanation + action id) and **never** forward. A blocked call provably never reaches a tool; an engine failure is a `BLOCK`.

### Feature 3 — Objective Guardrail · `v0.3.0` _(in review)_

The deterministic, conservative rules for universal danger — the guardrail that protects even when everything *looks* normal — plus the plugin seam that lets premium detectors attach later.

- **Basic rules (raise-only, fail-upward):** four pure rules run on every action and combine strongest-wins:
  - **Secret leakage** — detects credential shapes (`AKIA…`, `sk-…`, `ghp_…`, PEM keys, `.env` `KEY=value`) and base64/hex-encoded carriers; secret material bound for an external destination → **BLOCK**, local secret access → **AUTH**. Two confidence tiers mean a benign high-entropy blob (a base64 asset) is never hard-blocked on encoding alone.
  - **Protected paths** — matches the **canonicalized** target (resolving `..`, symlinks, and case via one shared helper) against blocked/sensitive globs; traversal, symlink, and case bypasses are caught, and a path escaping the repo root is blocked.
  - **Destructive commands** — adversarially parses shell/git command lines (`;` `&&` `|` `$()` backticks, env prefixes, `sudo`); `rm -rf /`, disk wipes, and force-pushes to a protected branch → **BLOCK**; bulk deletes and opaque `bash -c` payloads → **AUTH** (never a guessed `PASS`).
  - **External destinations** — classifies network hosts on their **registered domain** (defeating punycode/homoglyph, `user@host`, IP-literal, and substring spoofs); unknown destinations → **AUTH**, which combines with a secret to a **BLOCK**.
- **HMAC fingerprinting** — keyed (`HMAC-SHA256`) one-way fingerprints recognize secrets without ever storing them; the local key is generated on first use, kept `0600`, and never committed or logged.
- **Plugin registry (extension point)** — additional rules/detectors are discovered via Python entry points (`doberman.rules`, `doberman.detectors`) and run alongside the built-ins. Plugins are bound by the same raise-only discipline (they can only *add* risk) and are loaded defensively — a misbehaving plugin is isolated, never crashes core, and core never imports any plugin by name. With nothing installed, only the built-ins run.
- **Redaction throughout** — no rule ever puts a raw secret, path, argument value, or match excerpt into an explanation, reason, or log; explanations describe the *rule*, fingerprints are HMAC-only. Secret detection is defense-in-depth, not claimed airtight.

### Feature 4 — Agent Role Policy & Boundaries · `v0.4.0` _(in review)_

Makes the agent's **role** the top of the local authority hierarchy: an action that crosses the role's path boundaries escalates in the **objective** layer, so it cannot be learned away and casual user intent never lowers it.

- **Built-in roles** — `frontend`, `backend`, `fullstack`, `devops`, `docs`, `test`, each declaring `allowed` / `suspicious` / `blocked` path globs (data in `roles/builtin_roles.yaml`). `blocked` wins on overlap; a target matched by no `allowed` glob is treated as out-of-scope (safe default). The active role is read from `.doberman/role.yaml` (a named built-in or an inline custom role); an unknown or malformed role falls back to the most-restrictive role.
- **Boundary matcher** — classifies a target as allowed / suspicious / blocked through the **same** canonicalizer the path rule uses, so `..` traversal, symlink, and case bypasses cannot dodge a role boundary; a path escaping the repo root is treated as blocked.
- **Cross-boundary escalation** — an out-of-scope target → **AUTH (`role_out_of_scope`)**, a role-blocked target → **BLOCK (`role_blocked_target`)**. The check lives in the objective layer; with no role configured it abstains, so role enforcement is opt-in.
- **`PolicySource` seam (extension point)** — an ordered resolver merges policy from local sources (the agent role) plus any registered via the `doberman.policy_sources` entry-point group. The merge is **raise-only across sources** (a higher-authority source can only *tighten*), so an enterprise/org policy can outrank the role — without core importing the enterprise package.

### Feature 5 — Capability Discovery & Local Risk Map · `v0.5.0` _(in review)_

A read-only onboarding scan that answers "how much power does my agent actually have?" — the missing blast-radius picture.

- **Capability enumeration** — infers capabilities from the downstream **tool list** (shell, filesystem read/write/delete, network, git, git-push, package install, env access) and a **read-only** scan of the repo's sensitive surface (`.env*`, `secrets/`, key material, `infra/`, CI workflows, migrations). Sensitive files are detected **by name/existence only — never read** — and nothing is ever written.
- **Risk rating + map** — each capability is rated (`.env`/key material → critical; shell, fs-write/delete, network, git-push, package-install → high), and `doberman scan` renders a readable risk map (capability names, risk, path-class evidence — never secrets). The scan is depth- and count-bounded so a huge or hostile repo cannot make it run unbounded.
- **`doberman` CLI** — the first command-line surface (`doberman scan`, `doberman version`), built with Typer.

### Feature 6 — Policy Checklist & Security Strength Modes · `v0.6.0` _(in review)_

Good defaults as the product: a pre-checked policy generated from role + discovery, and one strength dial instead of dozens of toggles.

- **Recommended checklist** — `recommend_policy(role, capabilities)` produces an editable `PolicyDoc` (persisted to `.doberman/policies.yaml`): core hard-blocks (always present, enabled, **non-disableable here**), plus step-ups tailored to the role and discovered capabilities (an item whose capability is absent is kept and marked N/A). `doberman review [--yes]` views/saves it; disabling a core hard-block is refused (that requires the Feature 10 flow).
- **Strength modes** — `doberman mode <light|balanced|strict|paranoid>` (default **Balanced**) tunes step-up thresholds: stricter modes step up to AUTH sooner (e.g. the bulk-delete threshold drops from 100 → 25 → 10 → 3). Modes **only move step-ups** — the hard-block **floor is identical across every mode**, and even Light keeps all core BLOCKs. An unknown mode is rejected; a corrupt stored mode fails to the strictest.
- **`doberman status`** — shows the active role, mode, and policy summary.

### Feature 7 — Tiered Authentication & Role Elevation · `v0.7.0` _(in review)_

Turns an `AUTH` verdict into a real, **action-bound** challenge whose strength scales with risk, and lets a satisfied role challenge grant a narrow, temporary permission — plus the seam for SSO/hosted approvals.

- **Auth tiers** — `select_tier` derives one of `soft_confirm → local_auth → two_factor → role_elevation` from the **already-final** risk and reason codes (strongest-wins), so a sensitive delete demands 2FA while a minor unusual edit only needs a confirm. A hard `BLOCK` is never turned into a challenge.
- **Action-specific challenge** — the prompt names the **exact** role, target, and reason ("approve THIS file", never a generic "enter 2FA"); any timeout, input error, or denial fails closed. TOTP 2FA (`doberman 2fa setup`) uses standard authenticator apps, with a ±1-step skew window, constant-time comparison, and a consecutive-failure rate limit; the secret is stored locally `0600` and never committed or logged.
- **Narrow, temporary, single-use elevation** — a satisfied `role_elevation` grants permission for **one canonical path** (never `**`), time-limited (default 15 min), and **single-use for destructive scopes**. It satisfies only the role-boundary `AUTH` for that exact target — every other rule still runs, and it **never** relaxes a hard block. Elevations persist in a local SQLite store (`.doberman/doberman.db`, `0600`, never committed); `doberman status` lists them and `doberman revoke <id>` ends one early.
- **Release after auth** — approval is bound to **one action id** (no replay), the action is **re-decided** before forwarding (TOCTOU — a flip to `BLOCK` still blocks), and only then does the call reach the tool.
- **`AuthProvider` seam (extension point)** — alternative backends (SSO/RBAC, hosted/push approvals) register via the `doberman.auth_providers` entry-point group and replace the local provider without core importing them. A provider can only **grant or deny** — never change the verdict or required tier — and if it fails, the action is denied. With nothing installed, the local provider runs and behavior is unchanged.

### Feature 8 — Local Decision Log & Audit · `v0.8.0` _(in review)_

Persists every decision to a **local, append-only, redacted** audit trail — the explainability and privacy substrate that learning and drift defense build on — plus the seam for hosted/centralized audit.

- **Local SQLite store** — `.doberman/doberman.db` (`0600`, never committed) holds the `decisions` log, a `secret_fingerprints` store, and the (initially empty) `baseline_counts`/`policy_changes` tables for Features 9–10. The schema is **structurally redaction-safe**: there is **no column** that can hold a raw secret, a raw path-to-a-secret, a full file, or an unredacted prompt — only a path **class**, reason codes, verdicts, the auth result, and ids. Secrets appear only as HMAC fingerprints.
- **Append-only writer** — one redacted row per decision (the writer only ever `INSERT`s into `decisions`); writing is best-effort and isolated, so a storage failure can never alter, block, or crash a decision that has already been enforced.
- **Plain-language views** — `doberman log [--last N]` shows the recent decision history (verdict, action type, path class, reasons, auth result); `doberman memory` shows a redaction-safe profile — verdict mix, most-touched path classes, and how many distinct secrets have been *seen* (a count only, never a value).
- **`AuditSink` seam (extension point)** — additional destinations (centralized audit, hosted monitoring, SIEM export) register via the `doberman.audit_sinks` entry-point group and receive **only the already-redacted record** the local log stores. A sink can never request raw data, and a slow or failing sink is isolated — it can never block or alter a decision. With nothing installed, only the local log runs.

### Feature 9 — Subjective Guardrail & Workflow Baseline · `v0.9.0` _(in review)_

The *second* guardrail: it learns what is normal for this repo/role/workflow and raises **unusual-for-you** actions to `AUTH`, catching context-specific anomalies even when no objective rule trips — plus the seam for advanced behavioral detection.

- **Workflow baseline (update-on-allow)** — a local store of **class-level** habits (path classes, command verbs, destination hosts — never raw paths, prompts, or secrets), in the SQLite `baseline_counts` table. It is updated **only after an action is allowed**, so a blocked or denied attempt can never train the system to accept the very thing it should escalate (raise-only learning).
- **Abnormality scorer** — scores how unusual an action is for the established baseline (a never-seen path class / destination / command is novel; a familiar one is not). **Cold start is conservative, not paranoid** — a sparse baseline yields only a mild signal for clearly-sensitive surfaces, so a fresh repo is not a storm of prompts; a new-but-benign area is a one-time `AUTH`, then normal.
- **`SubjectiveGuardrail` + mode awareness** — maps the score to `PASS`/`AUTH` by the active mode's sensitivity (Strict/Paranoid step up sooner; **Light disables** the abnormality step-up). It is **raise-only** and **cannot hard-block** (the execution rule clamps a subjective block to `AUTH`) — escalation, not paternalism — so it can never weaken an objective verdict.
- **`Detector` seam (extension point)** — advanced/behavioral (UEBA-style) detectors register via the `doberman.detectors` entry-point group and run in the subjective layer, bound by the same raise-only discipline and isolated on failure. With nothing installed, only the baseline signal runs.

### Feature 10 — Policy-Drift Detection & Poisoning Defense · `v0.10.0` _(in review)_

Makes the **raise-only** invariant enforceable over time: learning and edits may tighten freely, but any **weakening** of protection must be deliberate — classified, gated, and recorded — so protection cannot slowly erode (the policy-poisoning attack).

- **Strengthen/weaken classifier** — `classify_change(before, after)` labels a proposed change by protection rank. **Ambiguous or mixed changes classify as *weaken*** (fail safe), so a disguised weakening cannot slip through as "neutral".
- **2FA-gated weakening chokepoint** — `apply_change(...)` is the single path for a policy change: a weakening renders a Before/After **diff** and requires a **`two_factor`** confirmation, and is applied **only on approval**; strengthening/neutral changes apply automatically. A denial leaves protection unchanged.
- **Append-only change ledger** — every change — **including denied weakening attempts** (the attack signal) — is recorded immutably in the `policy_changes` table; `doberman policy-history` prints the full time-ordered history (rule, before→after, classification, how it was approved).
- **`DriftObserver` seam (extension point)** — org-wide drift monitoring / compliance tooling registers via the `doberman.drift_observers` entry-point group and receives **redacted** change events. An observer is purely observational — it can **never** approve, suppress, or alter a weakening (the 2FA gate is core and authoritative) — and a failing observer is isolated. With nothing installed, the gate and local ledger are unaffected.

---

## Design invariants

These two rules are non-negotiable and define the product:

1. **Fail closed.** On any error, uncertainty, or unhandled case, the action is **denied**. The agent must never reach a tool around Doberman.
2. **Raise-only.** Guardrails and learning may automatically *tighten*; they may **never** silently *loosen*. Any weakening must go through an explicit, human-approved path.

Internally the policy core (`engine`, `roles`, `policy`, `storage`, `learning`) is decoupled from the proxy adapter, and the public core never depends on any private/commercial package — both enforced in CI by [import-linter](https://import-linter.readthedocs.io/).

---

## Versioning

Doberman follows [Semantic Versioning](https://semver.org/) (`MAJOR.MINOR.PATCH`). While the project is pre-1.0, the public API may change between minor versions.

The version line maps to the development roadmap:

- **Each numbered Feature is a minor version** (Feature 1 → `0.1.0`, Feature 2 → `0.2.0`, …).
- **Each slice is a building block of that version** — a small, independently tested, reviewed unit of work. The slices that compose a release are listed under it in the [Changelog](#changelog).
- Releases are cut as annotated git tags (`v0.1.0`, `v0.2.0`, …) once a feature's review checkpoint passes.

---

## Changelog

This project keeps a changelog in the spirit of [Keep a Changelog](https://keepachangelog.com/).

### `v0.11.0` — Agent Integration: `doberman serve` — _Unreleased (in review)_

- **`doberman serve -- <downstream cmd>`** — a runnable stdio MCP proxy that fronts any downstream MCP tool server (MCP server to the agent, MCP client to the downstream); makes Doberman usable from Claude Code, Codex, Claude Desktop, Cursor, and any MCP client with a one-line config swap.
- **Controlling-terminal AUTH** — in serve mode an `AUTH` challenge is routed to the local terminal (`/dev/tty` / `CONIN$`/`CONOUT$`) so it never touches the agent's stdin/stdout MCP stream; with no terminal attached the action is denied (fail closed).
- Logs are pinned to **stderr** (stdout is the agent's protocol channel); the engine's repo root (`.doberman/`) is selectable with `--path`.

### `v0.10.0` — Policy-Drift Detection & Poisoning Defense — _Unreleased (in review)_

- **Slice 10.1** — strengthen/weaken/neutral change classifier (ambiguous & mixed → weaken, fail safe).
- **Slice 10.2** — `apply_change` chokepoint: a weakening requires 2FA + a rendered diff and applies only on approval; strengthen/neutral apply automatically.
- **Slice 10.3** — append-only policy-change ledger + `doberman policy-history` (records applied changes **and** denied weakening attempts).
- **Slice 10.4** — the pluggable `DriftObserver` interface (the enterprise seam; discovered via `doberman.drift_observers`; redacted events; can never override the gate).

### `v0.9.0` — Subjective Guardrail & Workflow Baseline — _Unreleased (in review)_

- **Slice 9.1** — workflow baseline store updated **on allowed actions only** (class-level habits in `baseline_counts`; blocked attempts never train it).
- **Slice 9.2** — abnormality scorer (novelty over the established baseline; conservative cold start).
- **Slice 9.3** — the `SubjectiveGuardrail` (mode-aware step-up, raise-only, can't hard-block) + the `Detector` seam (`doberman.detectors`, relocated from the objective layer to its single behavioral home).

### `v0.8.0` — Local Decision Log & Audit — _Unreleased (in review)_

- **Slice 8.1** — local SQLite schema + additive migrations (`decisions`, `secret_fingerprints`, `baseline_counts`, `policy_changes`, `elevations`; `0600`; no secret-bearing columns).
- **Slice 8.2** — append-only, redacted decision-log writer wired into the proxy (one row per decision; best-effort, never alters a verdict).
- **Slice 8.3** — `doberman log` and `doberman memory` views (classes/habits and counts only; no fingerprint values or raw secrets).
- **Slice 8.4** — the pluggable `AuditSink` interface (the enterprise seam; discovered via `doberman.audit_sinks`; sinks receive redacted records only and are isolated).

### `v0.7.0` — Tiered Authentication & Role Elevation — _Unreleased (in review)_

- **Slice 7.1** — auth-tier selection from the final decision (risk + reasons, strongest-wins; a hard block never maps to a challenge).
- **Slice 7.2** — TOTP 2FA (`doberman 2fa setup`; ±1-step skew, constant-time compare, failure rate-limit, `0600` secret, fail-closed when not enrolled).
- **Slice 7.3** — the action-specific challenge (names the exact role/target/reason; timeout/error/denial → deny).
- **Slice 7.4** — narrow/temporary/single-use role elevation persisted in local SQLite (`doberman status`/`revoke`; never lifts a hard block).
- **Slice 7.5** — release after auth: approval bound to one action id, re-decided (TOCTOU) before forwarding.
- **Slice 7.6** — the pluggable `AuthProvider` interface (the enterprise seam; discovered via `doberman.auth_providers`, defaulting to local; a provider can only grant or deny).

### `v0.6.0` — Policy Checklist & Security Strength Modes — _Unreleased (in review)_

- **Slice 6.1** — recommended policy checklist (`recommend_policy`; core hard-blocks always present, step-ups tailored to role/capabilities).
- **Slice 6.2** — `doberman review` to view/persist `.doberman/policies.yaml` (core blocks non-disableable; atomic save).
- **Slice 6.3** — Light/Balanced/Strict/Paranoid modes (`doberman mode`/`status`); thresholds tune step-ups only, the hard-block floor is mode-independent.

### `v0.5.0` — Capability Discovery & Local Risk Map — _Unreleased (in review)_

- **Slice 5.1** — read-only capability enumeration (tools + sensitive-surface scan by name; depth/count bounded; never reads secret contents).
- **Slice 5.2** — risk rating + `doberman scan` risk-map renderer + the `doberman` CLI (Typer).

### `v0.4.0` — Agent Role Policy & Boundaries — _Unreleased (in review)_

- **Slice 4.1** — built-in role definitions + schema (`allowed`/`suspicious`/`blocked` globs; `.doberman/role.yaml` active-role resolution).
- **Slice 4.2** — role-boundary matcher (shared canonicalization; blocked-wins precedence; unmatched-by-allowed → suspicious).
- **Slice 4.3** — cross-boundary escalation in the objective layer (`role_out_of_scope` → AUTH, `role_blocked_target` → BLOCK; user intent never lowers it).
- **Slice 4.4** — ordered `PolicySource` resolver with authority layering (the enterprise seam; raise-only across sources; discovered via `doberman.policy_sources`).

### `v0.3.0` — Objective Guardrail — _Unreleased (in review)_

- **Slice 3.1** — HMAC secret-fingerprinting helper (keyed, `0600` key, never logged/committed).
- **Slice 3.2** — secret-leakage detection rule (credential shapes, exfil → `BLOCK`, local → `AUTH`).
- **Slice 3.3** — protected-path rule with safe canonicalization (traversal/symlink/case bypasses caught).
- **Slice 3.4** — destructive shell/git command rule (adversarial parsing; opaque → `AUTH`).
- **Slice 3.5** — external-destination classification (registered-domain match; punycode/IP/embedded-cred spoofs flagged).
- **Slice 3.6** — encoded/indirect exfiltration checks (bounded base64/hex decode-and-rescan).
- **Slice 3.7** — `ObjectiveGuardrail` assembling all rules (raise-only combine, per-rule error isolation); wired into the proxy.
- **Slice 3.8** — entry-point plugin registry for rules/detectors (the enterprise seam; plugins can only raise risk, isolated on failure).

### `v0.2.0` — Decision Engine & Execution Rule

- **Slice 2.1** — `Guardrail` interface & frozen, always-explained `Decision` model.
- **Slice 2.2** — raise-only verdict/risk `combine()` with exhaustive + property tests.
- **Slice 2.3** — objective-first execution-rule state machine (short-circuit, subjective clamp, fail-closed / fail-upward error paths).
- **Slice 2.4** — verdict enforcement at the proxy chokepoint (blocked calls never run; engine failure → `BLOCK`).

### `v0.1.0` — Tool Mediation Layer & Normalized Action Object

- **Slice 1.1** — `SecurityObject`, `Verdict`, and reason-code schema.
- **Slice 1.2** — pass-through MCP proxy: forward tool calls through a single chokepoint.
- **Slice 1.3** — normalize tool calls into `SecurityObject` (mapping, target extraction, redaction).
- **Slice 1.4** — structured, redacted interception logging.

### `v0.0.0` — Bootstrap

- Project scaffolding, packaging, and CI (lint, format, import-boundary contracts, tests, secret scanning).

---

## Roadmap

The **MVP core (Features 1–10) is feature-complete** and in review. Beyond it, the planned (still open-source) directions are:

| Theme | What |
|-------|------|
| Stronger auth tiers | passkeys / WebAuthn as a tier above TOTP. |
| Async / remote challenges | a non-blocking approval model for hosted/remote humans. |
| More adapters | Cursor / Claude-Code / OpenAI / LangChain / terminal / browser against the decoupled core. |
| Hardening | signed (cryptographically tamper-evident) append-only logs; policy-as-code checked into the repo; a local web dashboard. |

Advanced/hosted capabilities — premium detection, centralized audit, SSO/RBAC, org policy management, compliance — live in a separate commercial edition that attaches through the core extension points (`doberman.rules` / `detectors` / `auth_providers` / `audit_sinks` / `policy_sources` / `drift_observers`) **without core ever depending on it**.

---

## Contributing

Contributions are welcome. The project is built in small, reviewable **slices**: one slice = one branch = one pull request, each shipping with its own tests and passing CI before merge. Please:

- Keep the [design invariants](#design-invariants) intact (fail closed, raise-only).
- Add tests for every change; do not weaken a test or invariant to get CI green.
- Run `ruff check . && ruff format --check . && lint-imports && pytest` locally before opening a PR.

---

## Security

Doberman is defense-in-depth, not a silver bullet — no single rule (including secret detection) is claimed to be airtight. Please do not commit secrets, keys, or raw payloads; the codebase only ever stores redacted metadata, classifications, and keyed fingerprints. To report a vulnerability, please open a private security advisory rather than a public issue.

---

## License

[Apache License 2.0](./LICENSE) — © 2026 the Doberman authors.
