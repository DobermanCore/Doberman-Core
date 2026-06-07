# Doberman — `doberman-core` Implementation Plan (PUBLIC, Apache-2.0)

> **This plan is for the public core repo only.** The private/enterprise repo has its **own** plan: `doberman_enterprise_plan.md`. Do not build enterprise features here.
> Read **`CLAUDE.md`** for *how* to work (the Slice Loop, per-slice tests + CI, commit hygiene, the repo boundary). This file is *what* to build in `doberman-core`.
> **Golden rules for this repo:** everything here must be safe to release publicly forever (nothing from the workspace "not allowed" list), and **`doberman-core` must never depend on `doberman_enterprise`.** Core defines **interfaces / extension points**; the enterprise plan implements premium versions of them.

---

## Scope of this repo (recap)

- **Build here (public):** runtime harness, MCP adapter, SDK, policy **schema**, the **basic** rule engine + basic rules, local auth, the **local** redacted decision log, the basic learning baseline, the safety invariants (execution rule, raise-only, drift-gating mechanism), examples, tests, public docs.
- **Do NOT build here (goes in the enterprise plan):** premium/proprietary detection, hosted/cloud code, centralized audit, org/team & enterprise policy management, SSO/RBAC, billing, compliance workflows, customer data.
- **The public core must be genuinely useful and fully functional on its own**, with zero enterprise code installed.

## Invariants (never break — full text in `CLAUDE.md`)

1. **Fail closed** — error/uncertainty → deny/`BLOCK`.
2. **Raise-only** — guardrails/learning may auto-tighten, never silently loosen.
3. **Never expose secrets** — fingerprints/classes/metadata only.
4. **Inside-core decoupling** — `engine`/`roles`/`policy`/`storage`/`learning` must not import `proxy`.
5. **Repo boundary** — `doberman` must never import `doberman_enterprise`.

## Extension points this plan exposes for the enterprise

These are the seams the enterprise plan plugs into. Building them is part of *this* plan; they keep core useful standalone and let premium features attach without core ever importing enterprise.

| Extension point | Defined in (core feature) | Enterprise uses it for |
|---|---|---|
| **Plugin registry** (entry-point discovery) | F3 (slice 3.8) | discovering premium rule packs / detectors / sinks at runtime |
| **`Rule` / `Detector` interface** | F3, F9 | advanced & proprietary detection |
| **`PolicySource` resolver + authority layering** | F4 (slice 4.4) | enterprise/org policy that outranks the agent role |
| **`AuthProvider` interface** | F7 (slice 7.6) | SSO/RBAC, hosted/push approvals |
| **`AuditSink` interface** | F8 (slice 8.4) | centralized audit, hosted monitoring, SIEM export |
| **`DriftObserver` hook** | F10 (slice 10.4) | org-wide drift monitoring & compliance reporting |

## Tech stack & layout

Python 3.11+, MCP proxy (`mcp` SDK), local SQLite (`aiosqlite`), YAML policy in `.doberman/`, Pydantic v2, `pyotp`, a `doberman` CLI (Typer), `pytest`. Package distributes as `doberman` (`src/doberman/`). Full layout: see `CLAUDE.md` §4 and the repository-layout map.

---

# Feature 1 — Tool Mediation Layer & Normalized Action Object

## 1. Feature goal
- **What:** Put Doberman physically between the agent and its tools (agent → Doberman MCP server → downstream tool servers). Intercept every tool call, normalize it into a **security object**, route it through a decision point, and only forward if approved.
- **Why:** The spine of the product. *"If Doberman is not on the tool execution path, it is advisory, not protective."*
- **Problem solved:** there is no single place today to ask "should this be allowed?" — Feature 1 creates it.

## 2. Scope
- **Included:** the MCP proxy, the `SecurityObject` schema, `normalize()`, one decision hook (pass-through stub for now), fail-closed behavior, structured redacted logging.
- **Not included:** decision logic (F2–F3), real auth (F7), learning (F9).
- **Assumptions:** one downstream MCP tool server in MVP; a fake one is provided for tests.

## 3. Implementation slices

### Slice 1.1 — Project skeleton & `SecurityObject` schema
- **Objective:** create the package + the central data model everything depends on.
- **Files:** `pyproject.toml`, `src/doberman/__init__.py`, `src/doberman/models.py`, `tests/unit/test_models.py`.
- **Backend:** Pydantic models — `ActionType`, `SourceContext`, `Risk`, `Reversibility`, `Verdict` enums; `GuardrailResult{verdict, risk, reason_codes, explanation}`; `SecurityObject{id, ts, agent_role, action_type, tool_name, target, target_path_class, risk, source_context, reversibility, sensitive_asset, external_destination, payload_fingerprints, raw_args_redacted, metadata}`; a `ReasonCode` string-constant enum.
- **Frontend:** none.
- **Schema:** this *is* the core schema; nothing persisted yet.
- **Security:** `SecurityObject` is `frozen=True` so no layer can mutate risk downward.
- **Edge cases:** unknown `tool_name` → `ActionType.other`; missing `target` allowed.
- **Expected output:** importable, validated models.
- **Verify:** build the thesis example object in a REPL.
- **Tests:** valid build; bad enum rejected; frozen blocks assignment; defaults applied.
- **Commit:** `feat(models): add SecurityObject, Verdict, and reason-code schema`

### Slice 1.2 — Pass-through MCP proxy (the chokepoint)
- **Objective:** MCP server that forwards `tools/list` and `tools/call` to one downstream tool server.
- **Files:** `src/doberman/proxy/mcp_proxy.py`, `src/doberman/proxy/executor.py`, `tests/fixtures/fake_tool_server.py`, `tests/integration/test_proxy_passthrough.py`.
- **Backend:** fake server recording calls (`fs_write/fs_delete/shell_exec/net_get`); proxy re-exposes downstream tools; `tools/call` → `decide_and_execute(call)` which (for now) just forwards.
- **Frontend:** none (developer points agent's MCP config at Doberman).
- **Schema:** none.
- **Security:** **fail closed** — downstream unreachable or call raises → return an error; never silently succeed or expose a bypass. Exactly one route, through `decide_and_execute`.
- **Edge cases:** downstream dies mid-session; unknown tool; `tools/list` before ready.
- **Expected output:** client sees downstream tools; calls succeed and are recorded.
- **Verify:** run fake server + proxy; call `fs_write`; confirm recorded + result returned.
- **Tests:** call recorded; downstream-down → error + nothing recorded; unknown tool.
- **Commit:** `feat(proxy): forward MCP tool calls through a single chokepoint`

### Slice 1.3 — Normalize raw calls into `SecurityObject`
- **Objective:** turn each intercepted call into a `SecurityObject`.
- **Files:** `src/doberman/proxy/normalize.py`, `executor.py`, `tests/unit/test_normalize.py`.
- **Backend:** `normalize(tool_name, arguments, context) -> SecurityObject`; map tool names → `ActionType`; extract `target`; redact long/secret-shaped values in `raw_args_redacted`; default `agent_role="unknown"`, `source_context=unknown`.
- **Frontend:** none.
- **Security:** never raise on weird input → on failure produce `action_type=other, risk=high` (conservative); no raw values in logs.
- **Edge cases:** path arrays; empty shell args; relative URLs.
- **Expected output:** structured object per call.
- **Verify:** log normalized objects while exercising the fake server.
- **Tests:** name→type mapping; redaction; malformed args → safe object.
- **Commit:** `feat(proxy): normalize tool calls into SecurityObject`

### Slice 1.4 — Structured, redacted interception log
- **Objective:** record every intercepted action (verdict `PASS` for now).
- **Files:** `executor.py`, logging setup, `tests/integration/test_interception_log.py`.
- **Backend:** emit one JSON log line per action with the redacted object + stable `action.id`.
- **Security:** assert no raw secret appears; logging is best-effort and must not throw into the execution path.
- **Edge cases:** high volume → don't block execution on logging.
- **Expected output:** one JSON line per call.
- **Verify:** tail the log; confirm no secrets.
- **Tests:** valid JSON + id present; fake key value never in the log.
- **Commit:** `feat(proxy): add structured redacted interception logging`

## 4. Review checkpoint — Feature 1
- **Built:** a working MCP chokepoint; every call normalized + logged; fails closed.
- **Test:** that there is genuinely **no** path agent→tool skipping `decide_and_execute`.
- **Decisions:** MCP as the first substrate; schema completeness; redaction adequacy.
- **Risks/debt:** decision hook is a pass-through (no protection yet, only observation); naive redaction; placeholder role/source; nothing persisted.

---

# Feature 2 — Decision Engine & Execution Rule

## 1. Feature goal
- **What:** replace the stub with the orchestrator — run objective first, apply the execution rule, combine verdicts **raise-only**, return one `Decision`.
- **Why:** getting this control flow right once means every guardrail/rule added later automatically obeys the safety rules.
- **Problem solved:** prevents the class of bug where some rule *lowers* risk.

## 2. Scope
- **Included:** the execution-rule state machine; a `Guardrail` interface; verdict combination (`PASS<AUTH<BLOCK`, take the max); "skip subjective if objective ≠ PASS"; the subjective-hard-block gate; `Decision`; wiring into the proxy seam.
- **Not included:** guardrail *content* (F3 objective, F9 subjective) — use stubs here.
- **Assumptions:** guardrails are pure functions of `(SecurityObject, EvalContext) -> GuardrailResult`.

## 3. Implementation slices

### Slice 2.1 — `Guardrail` interface & `Decision` model
- **Objective:** define the contract + final decision object.
- **Files:** `src/doberman/engine/decision_engine.py`, `models.py`, `tests/unit/test_decision_models.py`.
- **Backend:** `Guardrail` Protocol with `evaluate(action, ctx) -> GuardrailResult`; `Decision{action_id, final_verdict, final_risk, objective, subjective|None, reason_codes, explanation, decided_at}`; `EvalContext` (mode, role, baseline handle — start near-empty, grow per feature).
- **Security:** `Decision` is the audit source of truth → always carries reasons; `frozen=True`.
- **Edge cases:** subjective may be `None` (skipped).
- **Expected output:** importable interface + model.
- **Verify:** construct a `Decision` in the REPL.
- **Tests:** stub satisfies Protocol; `Decision` requires reasons.
- **Commit:** `feat(engine): define Guardrail interface and Decision model`

### Slice 2.2 — Verdict ordering & raise-only combination
- **Objective:** the math behind the invariant.
- **Files:** `decision_engine.py`, `tests/unit/test_verdict_ordering.py`.
- **Backend:** order `PASS=0<AUTH=1<BLOCK=2`, `low<med<high<critical`; `combine(a, b|None)` → **max** verdict, **max** risk, **union** of reasons. No path returns lower than either input.
- **Security:** this is where the invariant lives — property test: `combine` never returns below `max(a,b)`. The most important test in the repo.
- **Edge cases:** `b is None` → return `a`.
- **Expected output:** max combination.
- **Verify:** REPL `(PASS,low)+(AUTH,high)→(AUTH,high)`.
- **Tests:** 3×3 verdict matrix; risk matrix; never-lowers property over random pairs; None passthrough.
- **Commit:** `feat(engine): add raise-only verdict and risk combination`

### Slice 2.3 — The execution-rule state machine
- **Objective:** implement the exact thesis order.
- **Files:** `decision_engine.py` (`decide(...)`), `tests/unit/test_execution_rule.py`.
- **Backend:** objective first; objective `BLOCK`→BLOCK (skip subjective); objective `AUTH`→AUTH (skip subjective); objective `PASS`→run subjective then `combine`; subjective `BLOCK` honored only if its reason is on `SUBJECTIVE_HARD_BLOCK_ALLOWLIST` (empty in MVP → clamp to AUTH); compose merged reasons + human `explanation`.
- **Security:** short-circuits guarantee subjective can't weaken an objective AUTH/BLOCK; clamp prevents over-zealous hard-blocks.
- **Edge cases:** subjective errors → treat as AUTH (fail upward); objective errors → BLOCK (fail closed).
- **Expected output:** matches the thesis table for every combination.
- **Verify:** drive with stub guardrails; compare to the table.
- **Tests:** table test mirroring the thesis; skip-subjective; clamp; both error paths.
- **Commit:** `feat(engine): implement objective-first execution rule`

### Slice 2.4 — Wire the engine into the proxy seam
- **Objective:** replace pass-through with `decide(...)` and act on the verdict.
- **Files:** `executor.py`, `tests/integration/test_engine_blocks_reach_no_tool.py`.
- **Backend:** normalize → `decide` (stub guardrails) → PASS forwards; AUTH returns "authentication required" error (real auth = F7); BLOCK returns "blocked by policy" and does **not** forward.
- **Frontend:** agent now sees explanatory errors (reason codes + explanation) on AUTH/BLOCK.
- **Security:** Doberman becomes protective — integration test: a BLOCK means the fake server recorded nothing; engine exception → BLOCK.
- **Expected output:** stub BLOCK → tool never runs; PASS → runs.
- **Verify:** set stub objective to BLOCK; confirm nothing recorded + reason returned.
- **Tests:** PASS forwards+records; BLOCK error+nothing; AUTH error+nothing; engine exception→blocked.
- **Commit:** `feat(proxy): enforce engine verdicts on the execution path`

## 4. Review checkpoint — Feature 2
- **Built:** the correct control core; verdicts enforced (blocked calls truly never run).
- **Test:** the "never lowers risk" property and the execution-rule table — line by line vs the thesis.
- **Decisions:** keep subjective-hard-block allowlist empty in MVP? fail-upward-to-AUTH vs BLOCK on subjective error?
- **Risks/debt:** guardrails still stubs; AUTH just errors; no persistence yet.

---

# Feature 3 — Objective Guardrail (basic rules + the plugin seam)

## 1. Feature goal
- **What:** the deterministic, conservative checks for **universal** danger (secret leakage, protected paths, destructive commands, unknown external destinations, encoded exfil), plus the **plugin registry** that lets extra detectors attach later.
- **Why:** protects even when everything *looks* normal; "closer to security law than preference."
- **Problem solved:** the headline disasters — leaking `.env`, `rm -rf /`, deleting protected files, force-push, repo upload to unknown endpoints.

## 2. Scope
- **Included:** the `Rule` interface; basic rules (paths, commands, destinations, basic secret patterns, encoded exfil); HMAC fingerprinting; the `ObjectiveGuardrail` (raise-only combine); the **plugin registry** so premium detectors can register via entry points.
- **Not included:** advanced/proprietary detection and premium rule packs — those live in `doberman_enterprise_plan.md` and attach through slice 3.8's registry. **Do not write proprietary detection here.**
- **Assumptions:** static policy lists come from `.doberman/policies.yaml` (built in F6; until then use built-in defaults).

## 3. Implementation slices

### Slice 3.1 — HMAC secret-fingerprint helper
- **Objective:** keyed one-way fingerprints to recognize secrets without storing them.
- **Files:** `src/doberman/storage/fingerprint.py`, `src/doberman/engine/rules/secrets.py`, `tests/unit/test_fingerprint.py`.
- **Backend:** `fingerprint(value) -> "hmac:<hex>"` = HMAC-SHA256(local_key, normalized_value); key generated on first run, stored `0600`/keyring, never committed.
- **Security:** plain hashes of low-entropy secrets are brute-forceable; HMAC defeats offline attacks; key never logged/committed (add to `.gitignore`); fail closed if key creation fails.
- **Edge cases:** empty string; oversized input (cap); unicode normalization.
- **Expected output:** stable fingerprint per (value, key); differs across keys.
- **Verify:** REPL — same value twice = identical; regenerate key → different.
- **Tests:** determinism; key-dependence; never returns plaintext; key file perms.
- **Commit:** `feat(storage): add HMAC secret fingerprinting`

### Slice 3.2 — Secret-leakage detection rule
- **Objective:** `BLOCK` clear exfiltration; `AUTH` ambiguous secret access.
- **Files:** `engine/rules/secrets.py`, `tests/unit/test_rule_secrets.py`.
- **Backend:** detect secret material (high-entropy tokens, `AKIA…/sk-…/ghp_…`, PEM, `.env` KEY=value) and secret files by path; secret content + `external_destination` → `BLOCK (secret_exfiltration)`; local secret read → `AUTH (sensitive_secret_access)`; fingerprint detected secrets into `payload_fingerprints`.
- **Security:** detection is best-effort (encoded/fragmented secrets — see 3.6); never put the secret into explanation/log — use the fingerprint; prefer AUTH over BLOCK when unsure (except the clear exfil case).
- **Edge cases:** split-across-calls secret; high-entropy non-secret (lockfile hash).
- **Expected output:** `.env`→`https://evil` = BLOCK; read `.env` = AUTH.
- **Verify:** synthetic objects mimicking the demo.
- **Tests:** prefixes detected; exfil→BLOCK; local read→AUTH; ambiguous→AUTH; secret never in output.
- **Commit:** `feat(rules): detect secret leakage and exfiltration`

### Slice 3.3 — Protected-path rule (safe canonicalization)
- **Objective:** `BLOCK` hard-blocked paths; `AUTH` sensitive paths.
- **Files:** `engine/rules/paths.py`, `tests/unit/test_rule_paths.py`.
- **Backend:** `canonicalize(path)` (resolve `.`/`..`, symlinks, confine to repo root, flag escapes); match canonical path vs `blocked`/`sensitive` globs; set `target_path_class`, `sensitive_asset`.
- **Security:** **always canonicalize before matching** (defeats `../`, symlink, case bypasses); default case-insensitive matching; never let an empty/`**` allow-pattern match everything.
- **Edge cases:** symlink loops; abs vs rel; trailing slash; batch delete → treat at the worst path.
- **Expected output:** delete `backend/auth/session.ts`→AUTH; write `.env`→BLOCK; `frontend/Button.tsx`→PASS.
- **Verify:** feed a `..` traversal + a symlink; confirm caught.
- **Tests:** traversal/symlink/case bypasses; batch escalation; benign path passes.
- **Commit:** `feat(rules): enforce protected-path policy with safe canonicalization`

### Slice 3.4 — Destructive-command rule
- **Objective:** `BLOCK` catastrophic commands; `AUTH` risky-but-recoverable.
- **Files:** `engine/rules/commands.py`, `tests/unit/test_rule_commands.py`.
- **Backend:** parse command → argv (handle quoting/chaining); pattern tables for `rm -rf /|~`, disk wipes, `git push --force` to protected branch; thresholds (e.g. >N files) from policy.
- **Security:** parsing is adversarial — handle `;`, `&&`, `|`, backticks, `$()`, env prefixes; opaque (e.g. `bash -c "<base64>"`) → escalate to AUTH, never guess PASS; never execute to analyze.
- **Edge cases:** chained destructive segment; `sudo`; `curl | sh`; glob deletes.
- **Expected output:** `rm -rf /`→BLOCK; force-push main→BLOCK; small delete→PASS; 50-file delete→AUTH.
- **Verify:** run a sample command list.
- **Tests:** catastrophic→BLOCK; chained→BLOCK; opaque→AUTH; below-threshold→PASS.
- **Commit:** `feat(rules): detect destructive shell and git commands`

### Slice 3.5 — External-destination rule
- **Objective:** `AUTH` unknown destinations (→`BLOCK` when combined with secrets).
- **Files:** `engine/rules/destinations.py`, `tests/unit/test_rule_destinations.py`.
- **Backend:** extract host; classify trusted (npm/pypi/github + allowlist) vs unknown; unknown→`AUTH (unknown_external_destination)`; set `external_destination`.
- **Security:** defeat punycode/homoglyph, `user@host`, IP-literal, embedded creds, query-param smuggling; match on registered domain, not substring.
- **Edge cases:** localhost/private IP; redirects; non-HTTP schemes.
- **Expected output:** `POST evil.example`→AUTH; npm registry→PASS.
- **Verify:** feed trusted/unknown/punycode/IP URLs.
- **Tests:** trusted vs unknown; punycode caught; substring spoof not trusted; embedded-cred URL flagged.
- **Commit:** `feat(rules): classify external network destinations`

### Slice 3.6 — Encoded-exfiltration checks
- **Objective:** catch base64/hex/URL-param/filename/commit-message carriers.
- **Files:** `engine/rules/secrets.py` (extend), `tests/unit/test_encoded_exfil.py`.
- **Backend:** bounded safe-decode of suspicious tokens, re-scan for secret patterns/fingerprints; scan commit messages, filenames, query params.
- **Security:** bounded size/recursion (no decode bomb); will not catch encryption/semantic summaries — document as defense-in-depth.
- **Edge cases:** legit base64 assets (don't BLOCK on encoding alone) — escalate only on secret match/fingerprint, esp. toward external destinations.
- **Expected output:** base64(`.env`) in a webhook body → escalated like a raw secret.
- **Verify:** base64 a fake key in a call body → escalates; base64 image → doesn't.
- **Tests:** base64/hex carriers caught; decode bounded; benign asset passes; secret-in-commit flagged.
- **Commit:** `feat(rules): detect encoded and indirect exfiltration`

### Slice 3.7 — Assemble the `ObjectiveGuardrail`
- **Objective:** run all rules, combine raise-only, expose one `Guardrail`.
- **Files:** `src/doberman/engine/objective.py`, engine wiring, `tests/unit/test_objective_guardrail.py`, `tests/integration/test_objective_demo.py`.
- **Backend:** run each rule, merge via `combine`; per-rule exception → contribute `AUTH/high (rule_error)` (fail upward).
- **Security:** a single failing rule never lets the guardrail pass.
- **Edge cases:** action tripping multiple rules → strongest wins.
- **Expected output:** the thesis demo (delete `backend/**` + upload `.env`) → BLOCK exfil, AUTH backend delete.
- **Verify:** end-to-end demo via the proxy.
- **Tests:** combination cases; per-rule error isolation; the full demo.
- **Commit:** `feat(engine): assemble objective guardrail from rules`

### Slice 3.8 — Plugin registry & rule entry points (the enterprise seam) — **EXTENSION POINT**
- **Objective:** let externally-installed packages register additional `Rule`/`Detector` implementations **without core importing them**.
- **Files:** `src/doberman/engine/registry.py`, `objective.py` (load registered rules), `tests/unit/test_registry.py`, `tests/unit/test_core_is_standalone.py` (extend).
- **Backend:** a registry that discovers plugins via Python **entry points** (groups `doberman.rules`, `doberman.detectors`); `ObjectiveGuardrail` runs built-in rules **plus** any registered ones. With nothing installed, only built-ins run.
- **Frontend:** none (CLI may list active plugins via `doberman status`).
- **Security:** plugins are subject to the same raise-only/`combine` discipline — a plugin can only *add* risk; a misbehaving/erroring plugin is isolated (`AUTH/high rule_error`) and never lowers a verdict. Core must **not** import any plugin by name.
- **Edge cases:** no plugins installed (works); duplicate registration; plugin import error (skip + log, fail safe).
- **Expected output:** a test plugin registered via entry points is invoked alongside built-ins; with it uninstalled, core behaves identically.
- **Verify:** install a tiny test-only plugin package exposing a rule; confirm it runs; uninstall; confirm core unchanged.
- **Tests:** registry discovers a fixture plugin; raise-only still holds with plugins; erroring plugin isolated; **standalone test still passes (no enterprise installed)**.
- **Commit:** `feat(engine): add entry-point plugin registry for rules and detectors`

## 4. Review checkpoint — Feature 3
- **Built:** real deterministic protection for the headline disasters; the demo works; the plugin seam exists so the enterprise can extend detection.
- **Test:** bypass-resistance of canonicalization/command-parsing/destination-classification; that plugins can only raise risk; that core still works with no plugins.
- **Decisions:** default thresholds; BLOCK-vs-AUTH bias on ambiguity; which secret patterns ship; entry-point group names.
- **Risks/debt:** secret detection intentionally imperfect (never market as airtight); static thresholds; bounded encoded-exfil.

---

# Feature 4 — Agent Role Policy & Role Boundaries (+ policy-source seam)

## 1. Feature goal
- **What:** declare the agent's role (frontend/backend/…); enforce its allowed/suspicious/blocked path boundaries; make role the **top** of the local authority hierarchy. Plus a `PolicySource` seam so higher-authority policy (enterprise/org) can be layered in later.
- **Why:** the thesis's highest authority — a frontend agent touching `backend/auth/**` escalates *even if the user casually asks*.
- **Problem solved:** over-powered agents; "in scope" vs "out of scope" becomes enforceable.

## 2. Scope
- **Included:** built-in roles; role selection; the boundary matcher; engine integration; a `PolicySource` resolver + authority-layering hook.
- **Not included:** enterprise/org/team policy *management* (enterprise plan) — core only exposes the layering seam and resolves whatever sources are registered.
- **Assumptions:** role in `.doberman/role.yaml`; built-ins in `roles/builtin_roles.yaml`; one active role per repo in MVP.

## 3. Implementation slices

### Slice 4.1 — Built-in role definitions + schema
- **Objective:** encode roles as validated data.
- **Files:** `roles/builtin_roles.yaml`, `roles/roles.py`, `config.py`, `tests/unit/test_roles_schema.py`.
- **Backend:** `RoleDefinition{name, allowed[], suspicious[], blocked[], description}`; ship `frontend/backend/fullstack/devops/docs/test`.
- **Security:** `blocked` wins on overlap; empty `allowed` = nothing implicitly in-scope (safe default).
- **Edge cases:** overlapping globs; unknown role name → most-restrictive.
- **Expected output:** built-ins load + validate.
- **Verify:** print each built-in's globs.
- **Tests:** built-ins validate; overlap precedence; invalid rejected.
- **Commit:** `feat(roles): add built-in role definitions and schema`

### Slice 4.2 — Role-boundary matcher
- **Objective:** classify a target as allowed/suspicious/blocked.
- **Files:** `roles/roles.py` (`classify`), `tests/unit/test_role_matcher.py`.
- **Backend:** reuse the F3 canonicalization; evaluate blocked→suspicious→allowed; unmatched-by-allowed → suspicious.
- **Security:** share the one canonicalization helper (no divergence).
- **Edge cases:** target outside repo; non-path actions → `unknown`.
- **Expected output:** frontend role: `frontend/x`→allowed, `backend/auth/y`→suspicious, `.env`→blocked.
- **Tests:** classification; unmatched→suspicious; precedence.
- **Commit:** `feat(roles): classify targets against role boundaries`

### Slice 4.3 — Feed role into engine + escalate cross-boundary
- **Objective:** objective escalates on boundary crossings (role beats user intent).
- **Files:** `engine/objective.py`, `decision_engine.py` (`EvalContext.role`), `tests/unit/test_role_escalation.py`.
- **Backend:** blocked→`BLOCK (role_blocked_target)`; suspicious→`AUTH (role_out_of_scope)`; load active role into `EvalContext`.
- **Frontend:** explanations state the role reason.
- **Security:** keep this in the **objective** layer so it can't be learned away; user intent never downgrades it.
- **Edge cases:** permissive custom role (log it); missing role → restrictive.
- **Expected output:** frontend agent editing `backend/auth/session.ts` → AUTH (role reason), regardless of prompt friendliness.
- **Tests:** suspicious→AUTH; blocked→BLOCK; intent doesn't lower; missing role→restrictive.
- **Commit:** `feat(engine): escalate actions that cross role boundaries`

### Slice 4.4 — `PolicySource` resolver + authority layering (the enterprise seam) — **EXTENSION POINT**
- **Objective:** resolve policy from an ordered set of **sources** with fixed precedence, so a higher-authority source (registered later by the enterprise) can outrank the agent role — without core importing enterprise.
- **Files:** `src/doberman/policy/sources.py`, engine reads resolved policy via `EvalContext`, `tests/unit/test_policy_sources.py`.
- **Backend:** a `PolicySource` interface + a resolver that merges sources by precedence: (built-in defaults) < learned preferences < **agent role** < *(registered higher-authority sources)*. Core ships only the local sources; the resolver discovers extra sources via the F3 registry (group `doberman.policy_sources`).
- **Security:** precedence is **raise-only across sources** for hard constraints — a registered source may *tighten* (e.g. enterprise hard policy outranking role) but the merge must never let a lower-authority source loosen a higher one. Core works with zero extra sources.
- **Edge cases:** conflicting sources (highest authority wins; ties → stricter); no extra sources (local behavior unchanged).
- **Expected output:** with only local sources, role is top authority; a test source registered above role correctly outranks it.
- **Verify:** register a test high-authority source that blocks a path the role allows; confirm it wins.
- **Tests:** precedence order; stricter-wins on tie; raise-only across sources; standalone behavior unchanged.
- **Commit:** `feat(policy): add ordered PolicySource resolver with authority layering`

## 4. Review checkpoint — Feature 4
- **Built:** roles as enforceable scope; cross-boundary escalation; the seam for enterprise/org policy to layer above the role later.
- **Test:** that intent never lowers a role escalation; that a higher-authority source can only tighten.
- **Decisions:** default globs per role; unmatched→suspicious; precedence ordering.
- **Risks/debt:** one role per repo; static globs; permissive custom roles possible.

---

# Feature 5 — Capability Discovery & Local Risk Map

## 1. Feature goal
- **What:** onboarding scan of the agent's powers (fs/shell/net/git/pkg/env/secret files), rendered as a local risk map.
- **Why:** valuable on its own — "developers don't know how much power they gave their agent"; informs F6 defaults.
- **Problem solved:** invisible blast radius.

## 2. Scope
- **Included:** a read-only local scan + a risk-rated `doberman scan` output.
- **Not included:** fleet inventory / hosted risk dashboards (enterprise plan).
- **Assumptions:** capabilities inferred from the downstream tool list + a read-only repo scan.

## 3. Implementation slices

### Slice 5.1 — Capability enumeration
- **Objective:** list capabilities from tools + a read-only repo scan.
- **Files:** `src/doberman/discovery/scan.py`, `tests/unit/test_discovery_scan.py`.
- **Backend:** `enumerate_capabilities(tools, repo_root) -> [Capability{name, category, present, evidence}]`; scan for `.env*`, `secrets/`, `*.pem`, `infra/`, `.github/workflows/`, `migrations/`.
- **Security:** **read-only**; never open secret-file *contents* (detect by name/existence); never write outside `.doberman/`.
- **Edge cases:** huge repos (depth/time limit); permission-denied (skip+note); no tools.
- **Expected output:** e.g. `[shell present, fs_write present, network present, dotenv_visible present, git_push present]`.
- **Verify:** run on a repo with `.env`; confirm detected without reading it.
- **Tests:** capability detection; `.env`/`secrets/` by name; depth limit; never reads secret contents.
- **Commit:** `feat(discovery): enumerate agent capabilities and sensitive surface`

### Slice 5.2 — Risk rating + rendered map (`doberman scan`)
- **Objective:** rate capabilities + render the map.
- **Files:** `discovery/scan.py`, `cli/main.py` (`doberman scan`), `tests/unit/test_risk_map.py`.
- **Backend:** rate (`.env`=critical; shell/fs-write/net/git-push=high); `render_risk_map`.
- **Frontend (CLI):** `doberman scan` prints the risk map.
- **Security:** map contains no secrets — capability names + risk only.
- **Edge cases:** all-low repo; conflicting signals → higher risk.
- **Expected output:** readable risk-rated list.
- **Verify:** run `doberman scan`.
- **Tests:** rating mapping; renderer includes all caps; critical items distinct.
- **Commit:** `feat(cli): add doberman scan with a risk map`

## 4. Review checkpoint — Feature 5
- **Built:** a local "how much power does my agent have" report.
- **Test:** never reads secret contents; never writes outside `.doberman/`.
- **Decisions:** rating calibration; auto-run on `init` vs on demand.
- **Risks/debt:** heuristic inference (note in the report).

---

# Feature 6 — Policy Checklist & Security Strength Modes

## 1. Feature goal
- **What:** generate a pre-checked policy from role + discovery; let the user review/edit; offer Light/Balanced/Strict/Paranoid modes (default Balanced).
- **Why:** good defaults are the product; one strength dial beats dozens of toggles.
- **Problem solved:** config burden + approval fatigue.

## 2. Scope
- **Included:** default policy generation; editable `.doberman/policies.yaml`; the four modes → thresholds; engine consumption.
- **Not included:** shared/org templates (enterprise plan).
- **Assumptions:** policy + mode in `.doberman/`; engine reads via `EvalContext`.

## 3. Implementation slices

### Slice 6.1 — Generate the recommended policy checklist
- **Objective:** pre-checked hard-block/step-up/allow lists from role + capabilities.
- **Files:** `policy/checklist.py`, `tests/unit/test_checklist.py`.
- **Backend:** `recommend_policy(role, capabilities) -> PolicyDoc` seeded from the thesis checklist.
- **Schema:** `PolicyDoc` + `.doberman/policies.yaml` (sections: item id, description, enabled, verdict).
- **Security:** safe-by-default (checked on); core hard-blocks always present and not removable here (full removal needs F10's flow).
- **Edge cases:** no network capability (rule present, marked N/A); custom role.
- **Expected output:** a `PolicyDoc` matching the thesis, tuned to the role.
- **Tests:** required hard-blocks present; role tailoring; items default enabled.
- **Commit:** `feat(policy): generate recommended policy checklist`

### Slice 6.2 — Review + persist via CLI
- **Objective:** view/edit/save the checklist.
- **Files:** `cli/main.py` (`doberman review`), `config.py`, `tests/integration/test_policy_review.py`.
- **Frontend (CLI):** interactive (or `--yes`) checklist; mark non-disableable items.
- **Security:** disabling a core hard-block is refused here → routed through F10; invalid save fails closed (keep prior valid file).
- **Edge cases:** concurrent edits; corrupt existing file (back up, regenerate, warn).
- **Expected output:** valid saved `policies.yaml`.
- **Verify:** toggle a step-up item; re-open; confirm persisted; try to disable a core block → refused.
- **Tests:** round-trip; core block not disableable; invalid save rejected.
- **Commit:** `feat(cli): review and persist policy checklist`

### Slice 6.3 — Security strength modes
- **Objective:** Light/Balanced/Strict/Paranoid → thresholds (default Balanced).
- **Files:** `policy/modes.py`, engine reads mode, `cli/main.py` (`doberman mode`), `tests/unit/test_modes.py`.
- **Backend:** `MODES` mapping (delete threshold, whether unusual/cross-boundary → AUTH, etc.).
- **Frontend (CLI):** `doberman mode <name>`; `doberman status` shows it.
- **Security:** modes can tighten freely but cannot loosen below the **floor** — even Light keeps all core hard-blocks; encode the floor explicitly.
- **Edge cases:** unknown mode (reject); mid-session change.
- **Expected output:** more AUTH under Strict than Light; BLOCKs identical across modes.
- **Tests:** thresholds per mode; hard-block floor identical across modes; default Balanced; unknown rejected.
- **Commit:** `feat(policy): add Light/Balanced/Strict/Paranoid modes`

## 4. Review checkpoint — Feature 6
- **Built:** good defaults + one strength dial.
- **Test:** the floor logic — no mode/toggle removes a core hard-block.
- **Decisions:** mode thresholds; which items are "core" vs tunable.
- **Risks/debt:** CLI/YAML editing only; modes coarse by design.

---

# Feature 7 — Tiered Authentication & Role Elevation (+ auth-provider seam)

## 1. Feature goal
- **What:** turn an `AUTH` verdict into a real, **action-specific** challenge (soft confirm → local auth → 2FA → role elevation), with narrow/temporary elevation. Plus an `AuthProvider` seam so SSO/hosted approvals can plug in later.
- **Why:** the thesis requires auth tied to the exact action, tiered by risk, with elevation that doesn't become permanent permission.
- **Problem solved:** makes risky actions deliberate; prevents approval fatigue + permission creep.

## 2. Scope
- **Included:** tier selection; the action-specific challenge; local confirm + TOTP; narrow/temporary/single-use elevation; releasing the action on success; an `AuthProvider` interface.
- **Not included:** SSO/RBAC, hosted/push approval workflows (enterprise plan) — they register as `AuthProvider`s.
- **Assumptions:** human is at the local CLI; TOTP set up at onboarding; the agent's call blocks while awaiting the result (synchronous in MVP).

## 3. Implementation slices

### Slice 7.1 — Auth-tier selection
- **Objective:** decide which proof an `AUTH` requires.
- **Files:** `auth/challenge.py` (`select_tier`), `tests/unit/test_auth_tier.py`.
- **Backend:** `AuthTier{soft_confirm, local_auth, two_factor, role_elevation}` mapped from final risk + reason codes; strongest tier wins.
- **Security:** derive from the **already-final** risk (so subjective escalation bumps the tier); never pick a weaker tier than warranted.
- **Edge cases:** multiple reasons → strongest; hard-block reason never reaches here.
- **Expected output:** sensitive delete→two_factor; minor unusual edit→soft_confirm.
- **Tests:** mapping per reason; strongest-wins; hard-block never maps to a challenge.
- **Commit:** `feat(auth): select authentication tier from decision`

### Slice 7.2 — TOTP 2FA helper
- **Objective:** enroll + verify TOTP.
- **Files:** `auth/totp.py`, `cli/main.py` (`doberman 2fa setup`), `tests/unit/test_totp.py`.
- **Backend:** `pyotp` secret on setup (provisioning URI/QR); verify with small skew window.
- **Schema:** store the TOTP secret in keyring/`0600` file — never in repo/logs.
- **Security:** constant-time compare; ±1 step skew; rate-limit; never log secret/codes.
- **Edge cases:** skew beyond window (clear error); not-enrolled → challenge fails closed (no no-auth fallback).
- **Expected output:** working setup + correct accept/reject.
- **Verify:** enroll in an app; current code accepted, old rejected.
- **Tests:** valid accepted; wrong/expired rejected; skew bounds; secret never logged.
- **Commit:** `feat(auth): add TOTP-based two-factor verification`

### Slice 7.3 — Present the action-specific challenge
- **Objective:** show exactly what's being approved + why; collect proof.
- **Files:** `auth/challenge.py` (`run_challenge`), `cli/main.py`, `tests/integration/test_challenge_flow.py`.
- **Backend:** render role + exact target + reason (from reason codes/explanation) + "Approve this exact action?"; collect tier-appropriate proof.
- **Frontend (CLI/TUI):** the challenge dialog.
- **Schema:** `AuthResult{approved, tier, method, at, elevation_id?}`.
- **Security:** name the **specific** action/target (never generic "enter 2FA"); time out → deny; any input error → deny (fail closed).
- **Edge cases:** walk-away timeout; explicit deny; repeated wrong code.
- **Expected output:** approve/deny tied to the action; specific prompt.
- **Verify:** trigger an AUTH; confirm prompt names the file + reason; approve and deny.
- **Tests:** prompt contains target+reason; timeout denies; wrong 2FA denies; approval=true.
- **Commit:** `feat(auth): present action-specific authentication challenge`

### Slice 7.4 — Narrow, temporary role elevation
- **Objective:** a satisfied `role_elevation` grants a tight, time-limited, single-use permission.
- **Files:** `auth/elevation.py`, `storage/db.py` (elevations), engine via `EvalContext`, `tests/unit/test_elevation.py`.
- **Backend:** `grant_elevation(scope_glob, task_id, ttl)`; `is_elevated(action, now)`; engine treats a role-only AUTH as satisfied for the covered scope (other rules still apply).
- **Frontend (CLI):** prompt states scope + duration; `doberman status` lists; `doberman revoke <id>`.
- **Schema:** `elevations(id, scope_glob, task_id, granted_at, expires_at, revoked, single_use, used)`.
- **Security:** narrow (specific glob, not `**`), temporary (short TTL), single-use for destructive scopes; **never** relaxes a hard-block; expire on TTL.
- **Edge cases:** clock skew (deny if ambiguous); overlapping elevations; attempt to elevate into a hard-block (refuse).
- **Expected output:** the one approved backend file editable for 15 min; a different backend file still AUTHs.
- **Verify:** elevate one file; edit it (pass); edit another (AUTH); wait past TTL (AUTH again).
- **Tests:** scope honored; TTL expiry; single-use; can't elevate into hard-block; revoke works.
- **Commit:** `feat(auth): add narrow, temporary role elevation`

### Slice 7.5 — Release the action after successful auth
- **Objective:** connect a satisfied challenge back to the blocked call.
- **Files:** `proxy/executor.py`, `tests/integration/test_auth_release.py`.
- **Backend:** on AUTH → `select_tier`→`run_challenge`; approved → forward + return; denied/timeout → "not authorized" + don't forward.
- **Security:** approval bound to **this** action id and consumed once (no replay/confused-deputy); re-decide before executing (TOCTOU — if now BLOCK, block).
- **Edge cases:** inputs changed during prompt (re-normalize/re-decide); downstream fails post-approval.
- **Expected output:** approved AUTH executes; denied never reaches the fake server.
- **Tests:** approval forwards+records; denial nothing; bound to one action id; re-decide-on-change.
- **Commit:** `feat(proxy): release actions only after successful authentication`

### Slice 7.6 — `AuthProvider` interface (the enterprise seam) — **EXTENSION POINT**
- **Objective:** let alternative auth backends (SSO/RBAC, hosted/push approvals) plug in **without core importing them**.
- **Files:** `src/doberman/auth/provider.py`, `challenge.py` (use the active provider), `tests/unit/test_auth_provider.py`.
- **Backend:** an `AuthProvider` interface (`authenticate(decision, tier) -> AuthResult`); a default **local** provider (CLI/TOTP from 7.1–7.3); the active provider is discovered via the F3 registry (group `doberman.auth_providers`), defaulting to local.
- **Security:** a provider can only *grant or deny* — it cannot change the verdict or the required tier; if no provider authenticates, the action is **denied** (fail closed). Core ships only the local provider.
- **Edge cases:** provider raises/times out → deny; multiple providers (configurable selection; default local).
- **Expected output:** with nothing installed, local auth runs; a test provider can be selected and is honored.
- **Verify:** register a stub provider; confirm it's used; uninstall; local auth resumes.
- **Tests:** default is local; provider can't alter tier/verdict; failure → deny; standalone unchanged.
- **Commit:** `feat(auth): add pluggable AuthProvider interface`

## 4. Review checkpoint — Feature 7
- **Built:** real tiered action-specific auth + safe elevation; the seam for SSO/hosted approvals.
- **Test:** approval bound to one action id; elevation scope/TTL/single-use; elevation never relaxes a hard-block; TOCTOU re-decision; a provider can't weaken a decision.
- **Decisions:** default TTL/single-use; challenge timeout; tier↔reason mapping.
- **Risks/debt:** synchronous/blocking model (revisit for async/remote); no passkeys yet; local secret storage must be protected.

---

# Feature 8 — Local Decision Log & Audit (+ audit-sink seam)

## 1. Feature goal
- **What:** persist every decision to a **local, append-only, redacted** log; expose a user-facing "what Doberman decided / learned" view; store fingerprints/classes/metadata — never raw secrets. Plus an `AuditSink` seam for centralized/hosted audit later.
- **Why:** explainability + privacy are core; this is also the substrate learning + drift build on.
- **Problem solved:** trust & accountability without creating a new secret-leak surface.

## 2. Scope
- **Included:** the SQLite schema; an append-only redacted writer; the fingerprint store; CLI views; an `AuditSink` interface.
- **Not included:** hosted/centralized audit, monitoring, SIEM export, compliance workflows (enterprise plan) — they register as `AuditSink`s.
- **Assumptions:** DB at `.doberman/doberman.db`; local-first.

## 3. Implementation slices

### Slice 8.1 — SQLite schema + migrations
- **Objective:** create the local DB + tables.
- **Files:** `storage/db.py`, `tests/unit/test_db_schema.py`.
- **Backend:** `aiosqlite`; tables `decisions`, `secret_fingerprints`, `baseline_counts`, `policy_changes`, `elevations`; a version table.
- **Schema:** `decisions(id, ts, action_id, agent_role, action_type, target_path_class, risk, source_context, final_verdict, decided_layer, reason_codes_json, auth_required, auth_result, elevation_id)`; `secret_fingerprints(fingerprint PK, label, first_seen, last_seen, source_path_class)`.
- **Security:** **no column** can hold a raw secret value, raw path-to-secret, full file, or unredacted prompt — make it structurally impossible; DB `0600`; `.doberman/` gitignored.
- **Edge cases:** DB locked (retry); corrupt DB (fail closed for the write, never block tool execution).
- **Expected output:** tables exist; version recorded.
- **Verify:** inspect schema with `sqlite3`.
- **Tests:** idempotent creation; no secret-bearing columns (assert column set); `0600`.
- **Commit:** `feat(storage): add local SQLite schema and migrations`

### Slice 8.2 — Append-only, redacted decision-log writer
- **Objective:** one redacted row per decision, immutably.
- **Files:** `storage/log.py`, `executor.py`, `tests/integration/test_decision_log.py`.
- **Backend:** `record_decision(decision, action)` inserts a redacted row (path class, reason codes, verdict, auth result); no `UPDATE`/`DELETE` on `decisions`.
- **Security:** never write a raw secret/full payload (fingerprints/classes only); logging failure → stderr, never raises into execution and never flips a BLOCK to PASS.
- **Edge cases:** high volume (async/batch); write fails (don't crash; the decision already happened).
- **Expected output:** one redacted row per decision.
- **Verify:** run actions; `SELECT * FROM decisions`; reasons present, no secrets.
- **Tests:** row per decision; fake secret never in any column; logging failure doesn't change verdict; no update/delete code paths.
- **Commit:** `feat(storage): write append-only redacted decision log`

### Slice 8.3 — User-facing log & memory views
- **Objective:** plain-language views.
- **Files:** `cli/main.py` (`doberman log`, `doberman memory`), `tests/integration/test_cli_views.py`.
- **Backend:** `doberman log [--last N]`; `doberman memory` prints the thesis-style learned summary from policy + baseline (not raw data).
- **Frontend (CLI):** the two views.
- **Security:** memory reads as classifications/habits, never "stored your `.env`"; test that no fingerprint/raw value is shown.
- **Edge cases:** empty history; huge history (paginate/`--last`).
- **Expected output:** readable history + plain-language profile.
- **Verify:** run both; confirm wording + no secrets.
- **Tests:** `log` shows rows+reasons; `memory` shows classes/habits only; no leakage.
- **Commit:** `feat(cli): add decision-log and learned-memory views`

### Slice 8.4 — `AuditSink` interface (the enterprise seam) — **EXTENSION POINT**
- **Objective:** let extra log destinations (centralized audit, hosted monitoring, SIEM) receive **already-redacted** decision records — without core importing them.
- **Files:** `src/doberman/storage/sinks.py`, `log.py` (fan out to registered sinks), `tests/unit/test_audit_sink.py`.
- **Backend:** an `AuditSink` interface (`emit(redacted_record)`); the local SQLite writer is the default sink; additional sinks are discovered via the F3 registry (group `doberman.audit_sinks`). Records are **redacted before** reaching any sink.
- **Security:** a sink **only receives the same redacted record** the local log stores — it can never request raw data; a failing/slow sink must not block or alter a decision (best-effort, isolated); core works with only the local sink.
- **Edge cases:** no extra sinks (local only); a sink raises (log + continue); back-pressure (don't block execution).
- **Expected output:** a test sink receives redacted records; with it removed, local logging is unaffected.
- **Verify:** register a stub sink; confirm it gets redacted records (no secrets); remove it.
- **Tests:** sink receives redacted-only records; sink failure isolated; never blocks/alters a decision; standalone unchanged.
- **Commit:** `feat(storage): add pluggable redacted AuditSink interface`

## 4. Review checkpoint — Feature 8
- **Built:** local redacted audit + explainable memory; the seam for hosted audit.
- **Test:** redaction guarantees (structural + by test); logging never alters/blocks a decision; sinks only ever see redacted records.
- **Decisions:** retention/rotation; add log signing now or as hardening.
- **Risks/debt:** append-only by convention+tests (not yet cryptographic); local-only.

---

# Feature 9 — Subjective Guardrail & Workflow Baseline (basic, + detector seam)

## 1. Feature goal
- **What:** learn what's normal for this user/project/role/workflow and **raise risk** (usually to AUTH) on abnormality. Basic, local. Advanced detectors plug in via the F3 registry.
- **Why:** the second guardrail — catches context-specific anomalies even when no objective red flag trips.
- **Problem solved:** the gap between "technically allowed" and "unusual for you."

## 2. Scope
- **Included:** the baseline store (counts, classes, buckets); the abnormality scorer; the `SubjectiveGuardrail` (PASS/AUTH, never lowers, can't hard-block in MVP); updates **on allowed actions only**; the `Detector` plug point.
- **Not included:** advanced/proprietary behavioral detection (UEBA) — enterprise plan, registered as `Detector`s.
- **Assumptions:** baseline counts in `baseline_counts`; fast-changing but bounded.

## 3. Implementation slices

### Slice 9.1 — Workflow baseline store + update-on-allow
- **Objective:** counts of normal features, updated only on allowed actions.
- **Files:** `learning/baseline.py`, post-allow hook in `executor.py`, `tests/unit/test_baseline.py`.
- **Backend:** `observe(action)` increments `path_class/command_class/destination_host/style buckets`; `frequency(key)`.
- **Schema:** `baseline_counts(feature_key PK, count, first_seen, last_seen)`.
- **Security:** **only allowed actions update** (blocked attempts can't teach "normal"); store classes/buckets, never raw prompts/paths/secrets.
- **Edge cases:** cold start (→ scorer in 9.2); cardinality blow-up (bucket aggressively).
- **Expected output:** frontend frequency rises; backend stays ~0.
- **Verify:** run frontend edits; check counts.
- **Tests:** observe increments; blocked don't update; frequency reflects counts; bounded cardinality.
- **Commit:** `feat(learning): add workflow baseline updated on allowed actions`

### Slice 9.2 — Abnormality scorer
- **Objective:** score how unusual an action is.
- **Files:** `learning/baseline.py` (`abnormality(action) -> float`), `tests/unit/test_abnormality.py`.
- **Backend:** combine rarely/never-seen path class, new destination, never-used command class, prompt-style mismatch → 0–1 with documented weights.
- **Security:** cold-start **conservative but not paranoid** (mild escalation for clearly sensitive areas; avoid approval-fatigue storms); document the rule.
- **Edge cases:** new repo; new-but-benign area (one-time AUTH then normal); noisy input.
- **Expected output:** familiar→low; first `backend/auth/**` for a frontend-pattern user→high.
- **Verify:** build a frontend baseline; score a backend edit + a new-domain upload.
- **Tests:** familiar→low, novel→high; style mismatch raises; cold-start per rule.
- **Commit:** `feat(learning): add abnormality scoring`

### Slice 9.3 — Assemble the `SubjectiveGuardrail` (+ detector plug point)
- **Objective:** turn the score (and any registered detectors) into a `GuardrailResult` after a PASS objective.
- **Files:** `engine/subjective.py`, engine wiring, `tests/unit/test_subjective_guardrail.py`, `tests/integration/test_subjective_escalation.py`.
- **Backend:** map score → verdict by the active mode's sensitivity: above threshold → `AUTH (unusual_for_workflow + signal)`, else PASS; run any registered `Detector`s (F3 registry, group `doberman.detectors`) and `combine` raise-only.
- **Frontend:** explanations say "unusual for your workflow" + the signal.
- **Security:** subjective **cannot lower** risk and **cannot hard-block** in MVP (clamped to AUTH); detectors are bound by the same raise-only rule; never runs when objective already said AUTH/BLOCK.
- **Edge cases:** score at threshold (define inclusive/exclusive); Light vs Paranoid thresholds; no detectors installed (basic behavior).
- **Expected output:** unusual backend edit / force-push-instead-of-PR / formal-urgent-credential-export input → AUTH with a clear reason.
- **Verify:** frontend baseline → unusual backend edit → AUTH; normal frontend edit → PASS.
- **Tests:** above→AUTH, below→PASS; mode changes threshold; reason names the signal; never lowers an objective verdict; works with zero detectors.
- **Commit:** `feat(engine): add subjective guardrail with detector plug point`

## 4. Review checkpoint — Feature 9
- **Built:** context-aware escalation; the seam for advanced detection.
- **Test:** subjective only ever raises; blocked attempts never teach the baseline; cold-start doesn't storm; detectors can't lower risk; core works with no detectors.
- **Decisions:** scorer weights + per-mode thresholds; cold-start policy; privacy-safe style features.
- **Risks/debt:** coarse style modeling; heuristic scorer (calibrate before claiming low false positives).

---

# Feature 10 — Policy-Drift Detection & Poisoning Defense (+ observer seam)

## 1. Feature goal
- **What:** detect policy **weakening** over time; require strong auth + a diff before any weakening; record every change in an append-only ledger. Plus a `DriftObserver` seam for org-wide monitoring later.
- **Why:** the thesis flags policy poisoning as a top weakness; learning must never silently weaken safety.
- **Problem solved:** the slow-boil attack and accidental erosion of protection.

## 2. Scope
- **Included:** the strengthen/weaken classifier; the strong-auth gate + diff; the append-only ledger; a `DriftObserver` hook.
- **Not included:** org-wide drift monitoring + compliance reporting (enterprise plan) — they register as `DriftObserver`s.
- **Assumptions:** all policy/baseline changes route through one `apply_change` chokepoint.

## 3. Implementation slices

### Slice 10.1 — Change classifier (strengthen vs weaken)
- **Objective:** classify a proposed change.
- **Files:** `policy/drift.py` (`classify_change(before, after)`), `tests/unit/test_drift_classify.py`.
- **Backend:** weakening transitions (hard_block→auth, auth→allow, protected→normal, unknown_dest→trusted, new routine command class, external-upload-normal, role expansion, secret-access-accepted); strengthening = reverse.
- **Security:** **ambiguous/mixed → Weaken** (fail safe → gate it).
- **Edge cases:** mixed change → Weaken; no-op → Neutral.
- **Expected output:** `backend/** auth→allow` = Weaken; `allow→auth` = Strengthen.
- **Tests:** each weakening transition; reverses; ambiguous→Weaken; mixed→Weaken; no-op→Neutral.
- **Commit:** `feat(policy): classify policy changes as strengthen or weaken`

### Slice 10.2 — Gate weakening behind strong auth + a diff
- **Objective:** every weakening requires 2FA, shown as a diff.
- **Files:** `policy/drift.py` (`apply_change`), uses `auth/challenge.py`, `tests/integration/test_drift_gate.py`.
- **Backend:** single chokepoint `apply_change(before, after, reason)`; Weaken → render Before/After/Reason + require `two_factor`; only on approval write; Strengthen/Neutral apply (still logged).
- **Frontend (CLI):** the diff + 2FA prompt.
- **Security:** **no other path writes policy** (audit for direct writes); "approved N times → make silent" is itself a weakening → goes through here; deny → unchanged.
- **Edge cases:** user denies; repeated attempts (log each); disguised weakening (mixed→Weaken covers it).
- **Expected output:** relaxing `backend/**` auth→allow shows a diff + demands 2FA.
- **Verify:** attempt weaken (diff+2FA; approve→applied, deny→unchanged); attempt strengthen (applies).
- **Tests:** weaken requires 2FA; denial unchanged; strengthen/neutral apply; no write outside `apply_change`.
- **Commit:** `feat(policy): gate policy weakening behind 2FA and a diff`

### Slice 10.3 — Append-only policy-change ledger
- **Objective:** record every change (attempted + applied) immutably.
- **Files:** `policy/drift.py`, `storage/db.py` (`policy_changes`), `cli/main.py` (`doberman policy-history`), `tests/integration/test_policy_ledger.py`.
- **Backend:** insert a row on every `apply_change` and on denials; `doberman policy-history` prints it.
- **Schema:** `policy_changes(id, ts, rule_id, from_state, to_state, classification, reason, approval_method, approved, approved_by)`.
- **Security:** append-only; the anti-contradiction ledger; redacted.
- **Edge cases:** onboarding churn (expected); denied attempts must be recorded (the attack signal).
- **Expected output:** complete time-ordered history incl. denials.
- **Verify:** make changes (some denied); `doberman policy-history` shows all.
- **Tests:** applied + denied recorded; append-only; ordered render.
- **Commit:** `feat(policy): add append-only policy-change ledger`

### Slice 10.4 — `DriftObserver` hook (the enterprise seam) — **EXTENSION POINT**
- **Objective:** emit **redacted** drift events to registered observers (org-wide monitoring, compliance reporting) — without core importing them.
- **Files:** `src/doberman/policy/drift.py` (notify observers), `engine/registry.py` (group `doberman.drift_observers`), `tests/unit/test_drift_observer.py`.
- **Backend:** a `DriftObserver` interface (`on_change(redacted_change_event)`); fan out every classified change (incl. denials) to registered observers; local ledger is unaffected.
- **Security:** observers receive **redacted** events only; an observer can **never** approve or suppress a weakening (the 2FA gate is core and authoritative); a failing observer is isolated and never blocks the gate; core works with none.
- **Edge cases:** no observers (local only); observer raises (log + continue).
- **Expected output:** a test observer receives redacted drift events; removing it leaves the gate + ledger intact.
- **Verify:** register a stub observer; trigger a change; confirm it's notified (redacted) and the gate still controls the outcome.
- **Tests:** observer notified (redacted); observer can't alter the gate outcome; failure isolated; standalone unchanged.
- **Commit:** `feat(policy): add redacted DriftObserver hook`

## 4. Review checkpoint — Feature 10
- **Built:** learning/edits can tighten freely but only loosen via 2FA-gated, audited approval; the seam for org-wide drift monitoring.
- **Test:** **no** code writes policy outside `apply_change`; ambiguous → gated; denials logged; observers can't override the gate.
- **Decisions:** which transitions are core-weakening; cooling-off for severe weakenings.
- **Risks/debt:** heuristic classification (keep ambiguous→Weaken); ledger append-only by convention until signing (hardening).

---

# Final Integration Plan — `doberman-core`

## Recommended order
F1 → F2 → F3 → F4 → F5 → F6 → F7 → F8 → F9 → F10 (build extension-point slices 3.8/4.4/7.6/8.4/9.3/10.4 *within* their features, after the local behavior works).

## Dependencies
- Everything depends on **F1** (security object + chokepoint) and **F2** (engine + invariant).
- **F3** builds the HMAC helper (reused by F8) and the **plugin registry** (reused by F4.4, F7.6, F8.4, F9.3, F10.4).
- **F6** consumes **F4** (role) and **F5** (capabilities); engine reads its output.
- **F7** consumes the `Decision`; shares the elevations table with **F8**.
- **F8** is the storage substrate; **F9** uses `baseline_counts`; **F10** uses `policy_changes` + F7's 2FA.
- **Wiring invariant:** the policy core must not import `proxy`; `doberman` must not import `doberman_enterprise` — both enforced by `import-linter` + the standalone test.

## Minimal viable version (ship this)
**F1 → F2 → F3 → F4 → F7**, plus a minimal **F6** (default policy + Balanced mode, skip interactive editing) and a minimal **F8** (write the redacted decision log). Delivers the thesis demo: malicious GitHub issue → **block** `.env` exfiltration, **step-up auth** on the backend deletion, blocked actions provably never reach tools. Build the extension-point slices once the corresponding local feature is solid.

## Nice-to-have extensions (still public)
Full F9/F10; passkeys/WebAuthn as a stronger tier; async/remote challenge model; more adapters (Cursor/Claude-Code/OpenAI/LangChain/terminal/browser) against the decoupled core; a local web dashboard; signed append-only logs; policy-as-code checked into the repo.

## Risks & failure modes
Bypass = total failure (re-test "no path skips the engine"); approval fatigue (calibrate modes/defaults); secret-detection gaps (never oversell); policy poisoning (F10; never write policy outside `apply_change`); false confidence (position as adaptive authorization); privacy footgun (the F8 redaction tests are load-bearing); TOCTOU races (re-decide before release).

## Production hardening checklist (core)
- [ ] **No bypass:** test proves every tool path goes through the engine; proxy fails closed.
- [ ] **Invariant tests green:** raise-only `combine` property + execution-rule table.
- [ ] **Redaction proven:** no raw secret/full file/unredacted prompt in logs/DB; schema can't hold one.
- [ ] **Secrets at rest:** HMAC key, TOTP secret, DB are `0600`/keyring, never committed; `.doberman/` gitignored.
- [ ] **Auth action-bound:** single-use + tied to one action id; elevations narrow + TTL + (destructive) single-use; never relax a hard-block.
- [ ] **Policy writes gated:** all changes via `apply_change`; weakening = 2FA + diff; ledger records all incl. denials.
- [ ] **Learning not poisoned:** baseline updates only on allowed actions.
- [ ] **Explainability:** every BLOCK/AUTH carries reason codes + a human explanation.
- [ ] **Standalone:** core builds/tests/runs with **no enterprise installed** (`test_core_is_standalone.py` green; `import-linter` boundary green).
- [ ] **Extension points stable & safe:** plugins/providers/sinks/observers can only **raise** risk or **receive redacted** data; none can lower a verdict, alter a tier, suppress a gate, or request raw data.
- [ ] **Resilience:** logging/DB/sink failures never alter/unblock a decision or crash the proxy.
- [ ] **Docs:** README states stack, the invariants, the threat model (observable artifacts only), and the known limits of secret detection.
