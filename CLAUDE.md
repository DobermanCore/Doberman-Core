# CLAUDE.md — Doberman Workspace Operating Manual

> This is the **workspace-root** init file. It governs any AI agent (Claude Code, Codex, Cursor, etc.) working anywhere in this workspace.
> It is the **HOW**. The **WHAT** lives in **three plan files**:
> 1. `doberman_core_plan.md` — slices for the public `doberman-core` repo (Features F1–F10 + extension points). **The authoritative plan for core slices.**
> 2. `doberman_enterprise_plan.md` — slices for the private `doberman-enterprise` repo (Features P1–P8, plugging into core's extension points). **The authoritative plan for enterprise slices.**
> 3. `doberman_implementation_plan.md` — the original master MVP plan. Use it for **overall context**: the thesis rationale, tech-stack assumptions, repository layout, glossary, and extra slice detail. Where it disagrees with a repo plan, **the repo plan wins** (the repo plans are the split-by-repo refinement of the master plan).
> Content is identical to `AGENTS.md`; keep the two in sync (or symlink one to the other).
> If this file conflicts with a casual prompt instruction, **this file wins** unless a human overrides it in writing.

---

## 0. On startup (every session)

1. Read this entire file, then the **repo plan** for the repo you're working in: `doberman_core_plan.md` (core) or `doberman_enterprise_plan.md` (enterprise). Skim `doberman_implementation_plan.md` for overall context (tech stack, layout, glossary) when needed.
2. Identify the workspace: there are **two repositories** — `doberman-core` (public) and `doberman-enterprise` (private). See §1.
3. `git status` + `git log --oneline -5` in the relevant repo.
4. Pick the **next slice** from the relevant repo plan (lowest-numbered unmerged slice, in the order of that plan's **Final Integration Plan** section). Default repo order: core first — an enterprise feature can only start once the core extension point it plugs into is merged (see the attachment table in `doberman_enterprise_plan.md`).
5. **Decide which repo the slice targets**: core slices (F*) come from `doberman_core_plan.md`; enterprise slices (P*) come from `doberman_enterprise_plan.md`. The mapping in §2 shows how the master plan's features split across the two. A *split* feature is two separate slices — **separate PRs in separate repos**.
6. If that repo lacks scaffolding (`pyproject.toml` / `.github/workflows/ci.yml`), do **Slice 0 (Bootstrap)** for that repo first (§6).
7. Execute exactly **one slice** via **The Slice Loop** (§5), then **STOP** and report. Stop at every review checkpoint.

---

## 1. Workspace & repositories

This workspace contains two repos with a hard boundary between them.

### `doberman-core` — **public, Apache-2.0**
Only put code here that can be **safely released publicly, forever**.

**Allowed:** runtime harness · SDK · policy schema · basic rule engine · adapters · examples · tests · public docs.

**Not allowed:** enterprise features · hosted/cloud code · proprietary detection logic · customer data · secrets · private deployment scripts · commercial-license code.

### `doberman-enterprise` — **private, proprietary**
**Allowed:** cloud dashboard · hosted monitoring · audit logs (centralized/compliance-grade) · enterprise policy management · org/team controls · advanced detection · premium rule packs · billing · SSO/RBAC · compliance workflows.

### Dependency direction (the hard rule)
- `doberman-enterprise` **may** depend on `doberman-core`.
- `doberman-core` **must never** depend on `doberman-enterprise`.
- Enforced in CI (§7). The public core must build, test, and run **with zero enterprise code installed**.

### When in doubt → keep it private, but keep the core useful
- If you are unsure whether a piece of **detection logic, data handling, or commercial functionality** belongs in core or enterprise, put it in **enterprise**. Public release is **irreversible**; moving code private→public later is safe.
- But the open core must be **genuinely functional on its own**, not crippleware: schema, interfaces, the runtime harness, adapters, and **basic** rules always live in core.
- If a slice would require core to know about an enterprise concept, you have the boundary wrong — STOP and ask.

---

## 2. Where each part of the master plan lives

This table maps the **master plan's** features (`doberman_implementation_plan.md`) onto the two repo plans. The headline: **the MVP is almost entirely `doberman-core`.** `doberman-enterprise` is the team/enterprise + advanced-detection layer. The split below is already baked into the repo plans — core's side of each feature is specified in `doberman_core_plan.md` (F1–F10), the enterprise side in `doberman_enterprise_plan.md` (P1–P8) — so use this table as orientation, and the repo plans as the source of truth for slices.

| Plan feature | Repo | Split? | What goes where |
|---|---|---|---|
| **F1** Tool Mediation & `SecurityObject` | `core` | no | runtime harness, MCP **adapter**, SDK, `SecurityObject` **policy schema** |
| **F2** Decision Engine & Execution Rule | `core` | no | the safety invariants (execution rule, raise-only `combine`) — must be open & auditable |
| **F3** Objective Guardrail | **both** | **yes** | core: the `Rule` **interface** + the **basic** rules (paths, commands, destinations, basic secret patterns, encoded-exfil). enterprise: **advanced detection + premium rule packs** (proprietary logic) registered via the interface |
| **F4** Agent Role Policy & Boundaries | **both** | **yes** | core: role **schema** + per-repo boundary matcher. enterprise: **enterprise policy management**, **org/team** role controls |
| **F5** Capability Discovery & Risk Map | **both** | **yes** | core: **local** scan + local risk map (CLI). enterprise: fleet **agent inventory**, hosted **risk dashboards** |
| **F6** Policy Checklist & Strength Modes | **both** | **yes** | core: default checklist + Light/Balanced/Strict/Paranoid modes. enterprise: **shared/org policy templates & defaults** |
| **F7** Tiered Auth & Role Elevation | **both** | **yes** | core: **local** confirm, TOTP 2FA, narrow/temporary elevation. enterprise: **SSO/RBAC**, hosted/push approval workflows |
| **F8** Decision Log & Audit | **both** | **yes** | core: **local, redacted decision log** + storage **interface** (needed for local explainability). enterprise: **centralized audit logs**, hosted **monitoring**, SIEM export, **compliance workflows** |
| **F9** Subjective Guardrail & Baseline | **both** | **yes** | core: the abnormality **interface** + a **basic** local baseline. enterprise: **advanced detection** (UEBA-style behavioral models) |
| **F10** Policy-Drift & Poisoning Defense | **both** | **yes** | core: the **mechanism** (classify strengthen/weaken, 2FA gate, append-only ledger) — a core safety invariant. enterprise: org-wide drift **monitoring** + **compliance reporting** |
| Examples, SDK, public docs, broad test suite | `core` | — | |
| Billing, cloud dashboard, hosted monitoring, premium rule packs, SSO/RBAC, compliance | `enterprise` | — | not in the MVP; plan Phase 4–5 |

### The interface / plugin pattern (how split features stay clean)
For every split feature, **core defines a stable interface and a runtime registry; enterprise ships packages that *register* implementations** — core never imports enterprise by name.

- Core declares an abstract `Rule` / `Detector` / `AuthProvider` / `AuditSink` (per the relevant feature) plus a registry that **loads whatever is installed via Python entry points**.
- Enterprise packages implement those interfaces and advertise them through their own `pyproject.toml` entry points (e.g. group `doberman.rules`, `doberman.detectors`, `doberman.audit_sinks`).
- At runtime Doberman runs core's basic implementations **plus** any registered plugins. With only core installed, it still works (basic protection). With enterprise installed, premium detection/audit/SSO light up.
- This is exactly the decoupling discipline the plan already mandates inside core (the policy core must not import the proxy adapter) — now extended across the repo boundary.

**Rule of thumb for a split slice:** build the **interface + basic core implementation as a `core` slice first** (from `doberman_core_plan.md`); build the **advanced/proprietary/hosted implementation as a separate `enterprise` slice** (from `doberman_enterprise_plan.md`) that depends on the now-merged core extension point. The attachment table at the top of `doberman_enterprise_plan.md` says exactly which core slice each enterprise feature needs (e.g. P3 needs core F8.4's `AuditSink`).

---

## 3. Prime directives (non-negotiable)

These override everything. If a task would break one, **STOP and ask a human**.

1. **Fail closed.** On any error, uncertainty, or unhandled case → deny / `BLOCK`. The protected agent must never reach a tool around Doberman.
2. **Raise-only.** Guardrails/learning may auto-tighten; they may **never** silently loosen. Any weakening goes through the human-approved path (Feature 10).
3. **Never expose secrets.** Never commit/log/store raw secrets, keys, full private files, unredacted prompts, customer data, or `.doberman/` contents. Fingerprints/classifications/metadata only.
4. **Respect the repo boundary.** `doberman-core` is public and Apache-2.0 — it may contain **nothing** from the "not allowed" list (§1). `doberman-core` **must never import or reference `doberman_enterprise`**. Public release is irreversible; when unsure, keep it private.
5. **No slice is "done" without tests + green CI**, in the repo it belongs to.
6. **Keep cores decoupled.** Inside `doberman-core`, the policy core (`doberman.engine`/`roles`/`policy`/`storage`/`learning`) must not import `doberman.proxy`. Enforced by `import-linter`.
7. **One slice = one PR = one repo.** Never let a single PR touch both repos.

If you feel pressure to violate one of these to "make progress," that pressure is the bug. Stop.

---

## 4. Project snapshot

- **What:** Doberman sits between a coding agent and its tools and turns every meaningful action into a risk-based **allow / authenticate / block** decision.
- **Packages:** core distributes as `doberman` (`src/doberman/`); enterprise distributes as `doberman_enterprise` (separate repo) and **depends on `doberman`**.
- **Stack:** Python 3.11+, MCP proxy (`mcp` SDK), local-first **SQLite** (`aiosqlite`), YAML policy in `.doberman/`, Pydantic v2, `pyotp`, a `doberman` CLI (Typer), `pytest`.
- **Layouts:** see "Repository layout" in `doberman_implementation_plan.md` (core layout also recapped in `doberman_core_plan.md`). Runtime data (`.doberman/`, the DB, key files) is **never** committed.

---

## 5. The Slice Loop (run for every slice)

**Step 0 — Route to a repo.** Using §2, decide the target repo. If the slice is split, work only the part for the chosen repo; the other part is its own slice/PR in the other repo. Confirm the part you put in `doberman-core` contains nothing from the §1 "not allowed" list.

**Step 1 — Read the slice** in the repo plan — `doberman_core_plan.md` for core slices (F*), `doberman_enterprise_plan.md` for enterprise slices (P*) — covering its Objective, files, changes, security considerations, edge cases, expected output, suggested tests, and suggested commit message. For extra background on a core feature, consult the matching feature in `doberman_implementation_plan.md` (the repo plan wins on any conflict). Ambiguity or a Prime-Directive conflict → STOP and ask.

**Step 2 — Branch** (in the right repo):
```
git checkout main && git pull
git checkout -b feat/<feature-slug>/<slice-slug>
```

**Step 3 — Implement** the smallest change that satisfies the Objective, strictly inside the slice's scope and the repo boundary. For split features, implement against the **interface** (core) or **register a plugin** (enterprise) — never make core import enterprise.

**Step 4 — Write this slice's tests (required).** In `tests/unit/` or `tests/integration/`, create `test_<slice_topic>.py` covering at minimum: every item in the slice's **"Suggested tests"**, every **edge case**, and every behavioral **security consideration** (e.g. *"a `BLOCK` means the fake downstream server recorded nothing"*, *"a synthetic secret never appears in any log/output"*, *"`combine` never returns a verdict lower than either input"*). For `doberman-core` slices, also confirm the **standalone** guarantee (core works with no enterprise installed). Prefer TDD; tests must be deterministic (no real network/clock/secrets — inject/fixture them).

**Step 5 — Make sure GitHub Actions runs these tests.** Tests live under `tests/` so CI's `pytest` discovers them (`pytest --collect-only` to confirm). New dependency → add to that repo's `pyproject.toml`. New import boundary → update its `import-linter` contract. New CI step → update that repo's `.github/workflows/ci.yml` (minimal, same PR).

**Step 6 — Green locally:**
```
ruff check . && ruff format --check .
lint-imports
pytest --cov=doberman --cov-report=term-missing       # (--cov=doberman_enterprise in the enterprise repo)
```
Everything passes; do **not** weaken a test or invariant to get green.

**Step 7 — Update docs** if usage/CLI/config/public behavior changed.

**Step 8 — Commit** (Conventional Commits; tests ship **in the same PR** as the code, ideally same commit). Primary commit uses the plan's "Suggested commit message." Never stage `.doberman/`, `*.db`, key files, `.env*` (they're gitignored — verify with `git status`).

**Step 9 — Push the branch** (`git push -u origin <branch>`) — tests go with it, so CI runs them.

**Step 10 — Open a PR to `main`** in that repo; fill the PR template (note the **Repo** and, for core, the **public-release safety** checkbox). Confirm CI turns **green**. Red CI → fix on the branch and push again; never merge red.

**Step 11 — Post the Slice Completion Report (§10) and STOP.** Don't start the next slice until approved/merged or told to continue.

**Step 12 — If this was the last slice of a feature**, after merge post the Feature Review Checkpoint (§10) and STOP. Review checkpoints are mandatory pauses.

---

## 6. Slice 0 — Bootstrap (per repo, only if scaffolding is missing)

Each repo gets its own scaffolding + working CI + a trivial smoke test, committed on `chore/bootstrap-scaffolding` with `chore(repo): bootstrap project scaffolding and CI`. Commit `CLAUDE.md`/`AGENTS.md` into each repo, plus that repo's plan: `doberman_core_plan.md` into `doberman-core`, `doberman_enterprise_plan.md` into `doberman-enterprise`. **Never commit `doberman_enterprise_plan.md` (or the full master plan) into the public core repo** — they describe proprietary features; the master plan stays at the workspace root (or in the private repo).

### `doberman-core` — `pyproject.toml`
```toml
[project]
name = "doberman"
version = "0.0.0"
description = "Adaptive authorization layer for coding agents (open core)"
license = { text = "Apache-2.0" }
requires-python = ">=3.11"
dependencies = ["pydantic>=2", "mcp", "aiosqlite", "pyotp", "pyyaml", "typer"]

[project.optional-dependencies]
dev = ["pytest", "pytest-asyncio", "pytest-cov", "ruff", "import-linter"]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/doberman"]

[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]
addopts = "-q"

[tool.coverage.run]
source = ["doberman"]
branch = true

[tool.ruff]
line-length = 100
target-version = "py311"
[tool.ruff.lint]
extend-select = ["I", "B", "S"]   # imports, bugbear, security

[tool.importlinter]
root_package = "doberman"

# Inside-core decoupling: policy core must not import the proxy adapter.
[[tool.importlinter.contracts]]
name = "Policy core must not depend on the proxy adapter"
type = "forbidden"
source_modules = ["doberman.engine", "doberman.roles", "doberman.policy", "doberman.storage", "doberman.learning"]
forbidden_modules = ["doberman.proxy"]

# Cross-repo boundary: the public core must never import the private enterprise package.
[[tool.importlinter.contracts]]
name = "Public core must not depend on the private enterprise package"
type = "forbidden"
source_modules = ["doberman"]
forbidden_modules = ["doberman_enterprise"]
```

### `doberman-core` — `.github/workflows/ci.yml`
```yaml
name: CI
on:
  push:
    branches: ["feat/**", "fix/**", "chore/**", "main"]
  pull_request:
    branches: ["main"]
permissions:
  contents: read
concurrency:
  group: ci-${{ github.ref }}
  cancel-in-progress: true
jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        python-version: ["3.11", "3.12"]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}
          cache: pip
      - run: python -m pip install --upgrade pip && pip install -e ".[dev]"
      - name: Standalone guarantee (no enterprise installed)
        run: pip list | grep -i doberman-enterprise && exit 1 || echo "ok: core has no enterprise dependency"
      - run: ruff check .
      - run: ruff format --check .
      - name: Architecture & repo boundaries
        run: lint-imports
      - run: pytest --cov=doberman --cov-report=term-missing --cov-fail-under=80
  secret-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: gitleaks/gitleaks-action@v2
        env: { GITHUB_TOKEN: "${{ secrets.GITHUB_TOKEN }}" }
```
> `--cov-fail-under=80` is a starting bar — raise it over time, never lower it to pass a PR.

### `doberman-core` — standalone test (commit in Slice 0)
```python
# tests/unit/test_core_is_standalone.py
import sys

def test_core_imports_with_no_enterprise_installed():
    import doberman  # must succeed with zero enterprise deps
    assert "doberman_enterprise" not in sys.modules
```

### `doberman-enterprise` — bootstrap deltas (vs core)
- `pyproject.toml`: `name = "doberman_enterprise"`, **proprietary license** (not Apache-2.0), and a dependency on core: `dependencies = ["doberman @ <git/url or version>", ...]`. Coverage `source = ["doberman_enterprise"]`.
- CI: same shape, but **install core first** and `--cov=doberman_enterprise`. Add jobs as needed (license-header check, private-registry auth). **Do not** publish artifacts publicly.
- `import-linter`: enterprise may import `doberman` (the public interfaces) freely; add any internal enterprise layering contracts you need.
- An enterprise PR may register premium rule packs / detectors via entry points — never by editing core.

### Both repos — `.gitignore`
```gitignore
.doberman/
*.db
*.sqlite
*.sqlite3
*.key
.env
.env.*
__pycache__/
*.py[cod]
.venv/
.pytest_cache/
.ruff_cache/
.coverage
htmlcov/
dist/
build/
*.egg-info/
```

### Both repos — `.github/pull_request_template.md`
```markdown
## Slice
- Repo: doberman-core | doberman-enterprise
- Feature / Slice: <id> — <title>
- Plan reference: doberman_core_plan.md | doberman_enterprise_plan.md

## What this PR does

## Tests added (run in CI)
-

## Public-release safety (doberman-core only)
- [ ] Contains nothing from the "not allowed" list: no enterprise/hosted code, no proprietary detection, no customer data, no secrets, no commercial-license code
- [ ] Core still builds/tests/runs with NO enterprise package installed

## Security checklist
- [ ] Fails closed on error / uncertainty
- [ ] No secret, full file, or unredacted prompt logged or committed
- [ ] Any guardrail/learning change is raise-only (no silent loosening)
- [ ] Every BLOCK/AUTH carries reason codes + a human explanation
- [ ] doberman-core does not import doberman_enterprise

## Edge cases covered / Deviations from plan / Risks introduced
-
```

---

## 7. Cross-repo dependency enforcement (summary)

The boundary is guaranteed three ways, all in CI:
1. **`import-linter` forbidden contract** in core: `doberman` may not import `doberman_enterprise`.
2. **Standalone install + test** in core's CI: enterprise is **not installed**, and a test asserts `import doberman` succeeds and `doberman_enterprise` is absent.
3. **Plugin inversion**: split features connect through core-defined interfaces + entry-point discovery, so core has no static reference to enterprise.

Enterprise freely depends on core (installed as the `doberman` package). Never the reverse.

---

## 8. Version control hygiene

- **One slice = one branch = one PR = one repo.** Never span both repos in a PR.
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
SLICE COMPLETE — <repo> :: <feature> / <slice id> (<title>)
Branch: <branch>    PR: #<n>    CI: <green | red+why>
What I built: <2–3 lines>
Tests added (run in CI): <files> — <what they cover>
Repo-boundary check: <core has no enterprise refs / N/A for enterprise>
Security checks verified: <redaction / fail-closed / raise-only / etc.>
Edge cases covered: <list>
Decisions / assumptions: <or "none">
Deviations from the plan: <none | what & why>
Risks / tech debt introduced: <or "none">
Next slice: <repo :: id — title>  (awaiting go-ahead)
```

### Feature Review Checkpoint (after the last slice of a feature, then STOP)
```
REVIEW CHECKPOINT — <Feature N: name>
Built (and in which repo[s]): ...
Needs human testing: ...
Decisions to review: ...
Risks / shortcuts / tech debt: ...
>> Paused. I will not start the next feature until told to proceed.
```

---

## 11. Never do this

- ❌ Put anything from the §1 "not allowed" list into **doberman-core** (enterprise/hosted code, proprietary detection, customer data, secrets, commercial-license code).
- ❌ Make **doberman-core** import or reference **doberman_enterprise**, or any enterprise concept.
- ❌ Span both repos in one PR, or do work outside the current slice's scope.
- ❌ Skip a review checkpoint or start the next feature without a go-ahead.
- ❌ Mark a slice "done" with missing/failing tests or red CI.
- ❌ Weaken/stub a test or invariant to make CI pass.
- ❌ Auto-loosen Doberman (all loosening goes through the Feature 10 human-approved path).
- ❌ Commit or log a secret, key, full private file, unredacted prompt, or `.doberman/` content.
- ❌ Let `doberman.proxy` be imported by the policy core.
- ❌ Add any path by which a protected agent could reach a real tool without going through the decision engine.
- ❌ Invent requirements. Unclear plan or wrong-looking slice → STOP and ask.

---

## 12. Quick reference

| You want to… | Do this |
|---|---|
| Know **what** to build in core | `doberman_core_plan.md` (F1–F10) |
| Know **what** to build in enterprise | `doberman_enterprise_plan.md` (P1–P8) |
| Overall context / glossary / layout | `doberman_implementation_plan.md` (master plan; repo plans win on conflict) |
| Know **how** to build it | this file |
| Decide the repo for a slice | F* → core plan, P* → enterprise plan; §2 mapping for split features; when unsure → enterprise |
| Start a slice | route to repo (§5 Step 0) → branch `feat/<feature>/<slice>` → follow §5 |
| Finish a slice | tests added + pushed, CI green, boundary checks pass, Slice Completion Report, STOP |
| Run checks (core) | `ruff check . && ruff format --check . && lint-imports && pytest --cov=doberman` |
| Hit ambiguity / boundary doubt | STOP and ask — when unsure about public vs private, keep it **private** |

**Remember:** small safe commits · tests with every slice · CI green before "done" · public core stays clean and standalone · enterprise depends on core, never the reverse · when in doubt, **fail closed and ask.**
