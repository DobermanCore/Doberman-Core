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
> **Alpha — pre-1.0, API unstable.** The interception layer (Feature 1), the decision engine (Feature 2), and the **objective guardrail** (Feature 3 — basic rules + the plugin seam) are implemented: Doberman now actively blocks the headline disasters (secret exfiltration, protected-path writes, catastrophic commands) and steps up authentication on sensitive or unknown actions. The subjective guardrail and roles arrive in upcoming versions (see the [Roadmap](#roadmap)). This is the open-source **core**; advanced/hosted capabilities live in a separate commercial edition.

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
3. **Decide** — the engine runs the objective guardrail first, then (if it passes) the subjective guardrail, combining results **raise-only** into a single explainable `Decision`.
4. **Enforce** — `PASS` forwards the call; `AUTH` returns an "authentication required" error; `BLOCK` returns a "blocked by policy" error and the call is **never** forwarded. Any engine failure is itself a `BLOCK`.
5. **Log** — every action is recorded as one redacted JSON line, correlated by a stable action id.

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

At this stage Doberman is a **library**, not a standalone binary — you embed the proxy in front of a downstream MCP tool server. The proxy is created from an active downstream client session:

```python
from doberman.proxy.mcp_proxy import build_proxy_server

# `downstream` is an mcp.client.session.ClientSession connected to your
# real tool server. The returned MCP server re-exposes its tools and routes
# every tools/call through Doberman's decision chokepoint.
proxy = build_proxy_server(downstream)
# ...serve `proxy` to the agent over your preferred MCP transport.
```

For a complete, runnable wiring (an in-process downstream + proxy + agent client),
see [`tests/integration/test_proxy_passthrough.py`](./tests/integration/test_proxy_passthrough.py)
and [`tests/integration/test_engine_blocks_reach_no_tool.py`](./tests/integration/test_engine_blocks_reach_no_tool.py).

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

Upcoming versions add the guardrail *content* and the surfaces around the engine (capability-level summary):

| Version | Theme |
|---------|-------|
| `v0.4.0` | **Agent role policy** — built-in roles and per-repo boundary matching. |
| `v0.5.0` | **Capability discovery** — local scan and risk map. |
| `v0.6.0` | **Policy checklist & strength modes** — Light / Balanced / Strict / Paranoid. |
| `v0.7.0` | **Tiered authentication** — local confirmation, TOTP 2FA, narrow/temporary elevation. |
| `v0.8.0` | **Decision log & audit** — local redacted decision log + storage interface. |
| `v0.9.0` | **Subjective guardrail** — abnormality interface + a basic local baseline. |
| `v0.10.0` | **Policy-drift & poisoning defense** — strengthen/weaken classification, gated approvals, append-only ledger. |

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
