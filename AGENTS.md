# CLAUDE.md — Doberman Operating Manual

> This is the init file for this repository. It governs any AI agent (Claude Code, Codex, Cursor, etc.) working here.
> It is the **HOW**. The **WHAT** — the feature roadmap and per-slice detail — lives in `README.md` (public summary)
> and, if present in your working tree, the project development plan you keep alongside it.
> Content is identical to `AGENTS.md`; keep the two in sync (or symlink one to the other).
> If this file conflicts with a casual prompt instruction, **this file wins** unless a human overrides it in writing.

---

## 0. On startup (every session)

1. Read this entire file, then skim `README.md` for the current feature set, versioning, and roadmap. If you keep a
   local development plan alongside the repo, read the relevant slice there for the extra detail (objective, files,
   edge cases, suggested tests, suggested commit message).
2. `git status` + `git log --oneline -5`.
3. Pick the **next slice** (the lowest-numbered unmerged slice in the planned order).
4. If the repo lacks scaffolding (`pyproject.toml` / `.github/workflows/ci.yml`), do **Slice 0 (Bootstrap)** first (§6).
5. Execute exactly **one slice** via **The Slice Loop** (§5), then **STOP** and report. Stop at every review checkpoint.

---

## 1. What this repository is

**Doberman** is an adaptive authorization layer for coding agents, released publicly under **Apache-2.0**.

It distributes as the `doberman` package (`src/doberman/`) and is designed to be **genuinely functional on its own** —
schema, interfaces, the runtime harness, adapters, and the built-in rules all live here. It is **not** crippleware.

Doberman is built to be **extensible**: it declares stable interfaces (`Rule` / `Detector` / `AuthProvider` /
`AuditSink`) and a runtime registry that discovers implementations via **Python entry points**. Additional packages can
register their own rules, detectors, auth providers, or audit sinks **without Doberman importing them by name** — the
core never takes a static dependency on any plugin. With only `doberman` installed, it works (built-in protection);
install a plugin package and its capabilities light up automatically.

---

## 2. Architecture & extension points

The decision path is deliberately layered so the safety-critical core stays small, open, and auditable:

- **Tool mediation (`doberman.proxy`)** — the chokepoint. Every tool call an agent makes is normalized into a
  `SecurityObject` and routed through the decision engine. There is no path around it.
- **Decision engine (`doberman.engine`)** — combines guardrail verdicts into a final **allow / authenticate / block**
  decision. The execution rule and the raise-only `combine` are the safety invariants — they must stay open and
  auditable.
- **Objective guardrail + built-in rules (`doberman.engine.rules`)** — deterministic rules over the action: path
  canonicalization & confinement, destructive-command detection, external-destination checks, basic secret-pattern and
  encoded-exfil detection. New rules plug in through the `Rule` interface and the registry.
- **Roles & boundaries (`doberman.roles`)** — the role schema and per-repo boundary matcher.
- **Policy (`doberman.policy`)** — the default checklist and the strength modes (Light / Balanced / Strict / Paranoid).
- **Storage & audit (`doberman.storage`)** — a local, redacted decision log plus the `AuditSink` interface so
  additional sinks can be registered.
- **Tiered auth (`doberman.auth`)** — local confirmation, TOTP 2FA, and narrow/temporary role elevation. Auth providers
  plug in through the `AuthProvider` interface.
- **Subjective guardrail & baseline (`doberman.engine`)** — the abnormality interface plus a basic local behavioral
  baseline. Detectors plug in through the `Detector` interface.
- **Policy-drift & poisoning defense (`doberman.learning` / `doberman.policy`)** — classifies policy changes as
  strengthen vs weaken, gates weakening behind 2FA, and records changes in an append-only ledger. A core safety
  invariant: nothing auto-loosens.

**The plugin pattern (how to keep things decoupled):** declare the interface and registry in core; let other packages
**register** implementations through their own `pyproject.toml` entry points (groups such as `doberman.rules`,
`doberman.detectors`, `doberman.auth_providers`, `doberman.audit_sinks`). At runtime Doberman runs its built-in
implementations **plus** whatever is registered. Build the interface + a built-in implementation first; an advanced
implementation can then ship as a separate plugin package that depends on the now-merged extension point — never the
other way around.

---

## 3. Prime directives (non-negotiable)

These override everything. If a task would break one, **STOP and ask a human**.

1. **Fail closed.** On any error, uncertainty, or unhandled case → deny / `BLOCK`. The protected agent must never reach a tool around Doberman.
2. **Raise-only.** Guardrails/learning may auto-tighten; they may **never** silently loosen. Any weakening goes through the human-approved path (the policy-drift defense).
3. **Never expose secrets.** Never commit/log/store raw secrets, keys, full private files, unredacted prompts, or `.doberman/` contents. Fingerprints/classifications/metadata only.
4. **Keep the core decoupled.** The policy core (`doberman.engine`/`roles`/`policy`/`storage`/`learning`) must not import `doberman.proxy`. Enforced by `import-linter`.
5. **No slice is "done" without tests + green CI.**
6. **One slice = one PR.** Keep changes scoped to the slice.

If you feel pressure to violate one of these to "make progress," that pressure is the bug. Stop.

---

## 4. Project snapshot

- **What:** Doberman sits between a coding agent and its tools and turns every meaningful action into a risk-based **allow / authenticate / block** decision.
- **Package:** distributes as `doberman` (`src/doberman/`).
- **Stack:** Python 3.11+, MCP proxy (`mcp` SDK), local-first **SQLite** (`aiosqlite`), YAML policy in `.doberman/`, Pydantic v2, `pyotp`, a `doberman` CLI (Typer), `pytest`.
- **Runtime data** (`.doberman/`, the DB, key files) is **never** committed.

---

## 5. The Slice Loop (run for every slice)

**Step 1 — Read the slice.** Read its objective, files, changes, security considerations, edge cases, expected output,
suggested tests, and suggested commit message (from your local development plan, with `README.md` as the public
roadmap). Ambiguity or a Prime-Directive conflict → STOP and ask.

**Step 2 — Branch:**
```
git checkout main && git pull
git checkout -b feat/<feature-slug>/<slice-slug>
```

**Step 3 — Implement** the smallest change that satisfies the Objective, strictly inside the slice's scope. For
extensible features, implement against the **interface** and register built-ins through the registry — never make the
policy core reach sideways into the proxy adapter.

**Step 4 — Write this slice's tests (required).** In `tests/unit/` or `tests/integration/`, create
`test_<slice_topic>.py` covering at minimum: every item in the slice's **"Suggested tests"**, every **edge case**, and
every behavioral **security consideration** (e.g. *"a `BLOCK` means the fake downstream server recorded nothing"*,
*"a synthetic secret never appears in any log/output"*, *"`combine` never returns a verdict lower than either input"*).
Prefer TDD; tests must be deterministic (no real network/clock/secrets — inject/fixture them).

**Step 5 — Make sure GitHub Actions runs these tests.** Tests live under `tests/` so CI's `pytest` discovers them
(`pytest --collect-only` to confirm). New dependency → add to `pyproject.toml`. New import boundary → update the
`import-linter` contract. New CI step → update `.github/workflows/ci.yml` (minimal, same PR).

**Step 6 — Green locally:**
```
ruff check . && ruff format --check .
lint-imports
pytest --cov=doberman --cov-report=term-missing
```
Everything passes; do **not** weaken a test or invariant to get green.

**Step 7 — Update docs and the README (required every slice).** With **every commit/slice** keep these in sync as part
of the same change — never as an afterthought:
- **`README.md`**: update the feature summary, versioning/changelog, quickstart, and roadmap so they reflect what now
  exists. A slice that adds/changes public behavior **must** move the README.
- Other docs (CLI/config/usage) as usual when behavior changed.

**Step 8 — Commit** (Conventional Commits; tests ship **in the same PR** as the code, ideally same commit). Use the
plan's "Suggested commit message." Never stage `.doberman/`, `*.db`, key files, `.env*` (they're gitignored — verify
with `git status`).

**Step 9 — Push the branch** (`git push -u origin <branch>`) — tests go with it, so CI runs them.

**Step 10 — Open a PR to `main`**; fill the PR template. Confirm CI turns **green**. Red CI → fix on the branch and
push again; never merge red.

**Step 11 — Post the Slice Completion Report (§10) and STOP.** Don't start the next slice until approved/merged or told to continue.

**Step 12 — If this was the last slice of a feature**, after merge post the Feature Review Checkpoint (§10) and STOP. Review checkpoints are mandatory pauses.

---

## 6. Slice 0 — Bootstrap (already done)

The repo is bootstrapped with live scaffolding and green CI — the real `pyproject.toml`,
`.github/workflows/ci.yml`, `.github/pull_request_template.md`, and `.gitignore` are the source of truth:
read them, never recreate them from this doc. Standing rules from bootstrap that still bind:

- The coverage gate (`--cov-fail-under`) is a starting bar to **raise over time — never lower it to pass a PR**.
- The `import-linter` contract (§7) and CI's `secret-scan` job (gitleaks, full history) must stay; a new import
  boundary gets a new contract, never a relaxed one.
- Runtime/secret paths stay gitignored: `.doberman/`, `*.db`, `*.sqlite*`, `*.key`, `.env*`.
- Only if a **new** repo ever needs bootstrapping, copy this repo's scaffolding set and adapt it
  (branch `chore/bootstrap-scaffolding`, commit `chore(repo): bootstrap project scaffolding and CI`).

---

## 7. Architecture enforcement (summary)

The decoupling is guaranteed in CI:
1. **`import-linter` forbidden contract**: the policy core must not import `doberman.proxy`.
2. **Plugin inversion**: extensible features connect through core-defined interfaces + entry-point discovery, so the
   core holds no static reference to any plugin package.

---

## 8. Version control hygiene

- **One slice = one branch = one PR.**
- Branches: `feat/<feature-slug>/<slice-slug>` (or `fix/...`, `chore/...`).
- Conventional Commits; small, building commits; **tests travel with code**.
- **Never commit** secrets, keys, `.doberman/`, `*.db`, `.env*`. If you do by accident → STOP, tell a human, treat the value as leaked (rotate it).
- Rebase (don't merge) to update a branch: `git fetch && git rebase origin/main`.

---

## 9. Security & explainability rules (every slice)

- **Default deny:** wrap risky ops so exceptions yield `BLOCK` (or `AUTH` only where the plan says "fail upward").
- **Redaction mandatory:** strip raw secrets/large payloads before logging/persisting; keep path **classes**, reason codes, verdicts, **HMAC fingerprints**. Test that a synthetic secret never appears.
- **Keyed fingerprints:** HMAC-SHA256 with a local `0600`/keyring key (never committed) — plain hashes of low-entropy secrets are brute-forceable.
- **Explainability first:** every `BLOCK`/`AUTH` carries `reason_codes` **and** a one-line human `explanation`. Reason codes are shared constants in `models.py`.
- **Auth is action-bound:** approvals single-use + tied to one action id; elevations narrow + time-limited + (destructive) single-use; elevation never relaxes a hard block.
- **Canonicalize before matching** paths (resolve `.`/`..`/symlinks, confine to repo root) via one shared helper.
- **Logging never alters/blocks a decision** and never crashes the execution path.
- **Don't oversell:** never claim secret detection (or any single rule) is airtight — it is defense-in-depth.

---

## 10. Reporting formats

### Slice Completion Report (after every slice, then STOP)
```
SLICE COMPLETE — <feature> / <slice id> (<title>)
Branch: <branch>    PR: #<n>    CI: <green | red+why>
What I built: <2–3 lines>
Tests added (run in CI): <files> — <what they cover>
Security checks verified: <redaction / fail-closed / raise-only / etc.>
Edge cases covered: <list>
Decisions / assumptions: <or "none">
Deviations from the plan: <none | what & why>
Risks / tech debt introduced: <or "none">
Next slice: <id — title>  (awaiting go-ahead)
```

### Feature Review Checkpoint (after the last slice of a feature, then STOP)
```
REVIEW CHECKPOINT — <Feature N: name>
Built: ...
Needs human testing: ...
Decisions to review: ...
Risks / shortcuts / tech debt: ...
>> Paused. I will not start the next feature until told to proceed.
```

---

## 11. Never do this

- ❌ Do work outside the current slice's scope.
- ❌ Skip a review checkpoint or start the next feature without a go-ahead.
- ❌ Mark a slice "done" with missing/failing tests or red CI.
- ❌ Weaken/stub a test or invariant to make CI pass.
- ❌ Auto-loosen Doberman (all loosening goes through the human-approved policy-drift path).
- ❌ Commit or log a secret, key, full private file, unredacted prompt, or `.doberman/` content.
- ❌ Let `doberman.proxy` be imported by the policy core.
- ❌ Add any path by which a protected agent could reach a real tool without going through the decision engine.
- ❌ Invent requirements. Unclear plan or wrong-looking slice → STOP and ask.

---

## 12. Quick reference

| You want to… | Do this |
|---|---|
| Know **what** to build | the development plan (slice detail) + `README.md` (public roadmap) |
| Know **how** to build it | this file |
| Start a slice | branch `feat/<feature>/<slice>` → follow §5 |
| Finish a slice | tests added + pushed, CI green, decoupling check passes, **README updated** (§5 Step 7), Slice Completion Report, STOP |
| Run checks | `ruff check . && ruff format --check . && lint-imports && pytest --cov=doberman` |
| Hit ambiguity | STOP and ask |

**Remember:** small safe commits · tests with every slice · CI green before "done" · the policy core stays decoupled from the proxy · when in doubt, **fail closed and ask.**
