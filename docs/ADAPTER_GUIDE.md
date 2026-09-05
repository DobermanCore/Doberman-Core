# Host adapter guide

This page documents how Doberman plugs into a coding-agent host through the host's own hook (a
callback the host runs at a fixed point in a tool call, such as just before it runs). It describes
the pattern shared by its two stable integrations, so a third adapter does not have to
reverse-engineer both from scratch. A third, experimental Codex CLI adapter
(`src/doberman/hosthooks/codex.py`) follows the same pre-call pattern through the same spine and is
a useful extra reference, though not documented here.

| Integration | Host surface | Doberman entry | Language |
|-------------|--------------|----------------|----------|
| Claude Code | `PreToolUse` / `PostToolUse` settings hooks | `doberman hook pre` / `doberman hook post` | Python (`src/doberman/hosthooks/claude_code.py`) |
| OpenClaw | `before_tool_call` plugin hook | `doberman hook openclaw` (spawned per call) | JS bridge (`adapters/openclaw/index.js`) + Python (`src/doberman/hosthooks/openclaw.py`) |

Both integrations:

1. Intercept a tool call before it runs (and Claude Code also after).
2. Normalize the host-specific call into a `SecurityObject`.
3. Run the shared decision spine.
4. Map the verdict back into whatever the host uses to allow, prompt, or deny.

Nothing here changes either adapter. It only documents them.

---

## Hook lifecycle

### Pre-call (gate the action)

Every host adapter has a pre-call path. The shape is the same even when the host protocols
differ:

```text
host event  →  adapter stdin/payload
            →  translate tool name + args
            →  spine.evaluate_action(...)
            →  map Verdict → host allow / prompt / deny
            →  (optional) record history
```

**Claude Code.** Settings invoke `doberman hook pre`, which calls `run_pre_hook` →
`evaluate_pre` in `claude_code.py`.

- Input: harness JSON with `tool_name`, `tool_input`, `cwd`, `session_id`.
- Gating set: built-ins in `GATED_BUILTINS` plus any `mcp__*` tool. Reads and internal tools
  abstain on the pre path (`return None`); the post-hook owns output scanning for those.
- Fail-closed: missing tool name, missing required input field, or any exception all resolve to
  `permissionDecision: "deny"` via `_deny()`.

**OpenClaw.** The plugin in `adapters/openclaw/index.js` registers `api.on("before_tool_call",
...)` and, for every call, spawns a fresh `doberman hook openclaw` process (`askDoberman`). The
Python side is `run_before_tool_call_hook` → `evaluate_before_tool_call` in `openclaw.py`.

- Input (built in `index.js`): `{ tool_name, params, derived_paths, cwd, session_id }`.
- Gate-by-default: only tools in `_ABSTAIN_TOOLS` skip evaluation. Everything else is normalized
  and decided, including `read`, so sensitive paths are gated up front (this adapter has no
  post-hook).
- Fail-closed: spawn failure, timeout (`DOBERMAN_TIMEOUT_MS = 10_000`), non-zero exit, or
  unparseable stdout all resolve to `{ block: true, blockReason }` from `failClosed` in
  `index.js`. The Python side never returns silence. It always emits one JSON verdict document.

### Post-call (Claude Code only)

Claude Code also wires `doberman hook post` → `run_post_hook` → `evaluate_post` in
`claude_code.py`.

- Scans tool output for credential-like material (`secret_exfiltration`,
  `sensitive_secret_access`).
- On a hard secret hit, returns a block so the harness does not feed the tainted result back to
  the model.
- History write is best-effort and wrapped so it can never change the hook's security return
  value.

OpenClaw's current slice is **pre-execution only**. See
[`adapters/openclaw/README.md`](../adapters/openclaw/README.md) ("Known limitations").

### Shared spine

Both Python adapters stop translating at a canonical `(name, args)` pair and hand off to
`hosthooks.spine.evaluate_action`:

```text
normalize(canonical, args)           → SecurityObject
decide(action, ObjectiveGuardrail…)  → Decision
apply_taint_floor(...)               → Decision (raise-only)
acted_verdict(decision, enforcement) → Verdict actually enforced
```

On the pre-call gating path, the spine is the only place that builds a `SecurityObject` and runs
the engine. Adapters must not reimplement `decide` or invent a parallel model. The one exception
today is Claude Code's post-call output scan (`evaluate_post`), which builds its own synthetic
`SecurityObject` via `normalize()` and runs the objective guardrail directly, outside
`spine.evaluate_action`. If your host supports a post-call scan, that lighter pattern is the
precedent to follow.

---

## Tool-call → `SecurityObject` normalization

### The target shape

`SecurityObject` in `src/doberman/models.py` is the normalized, redacted description of one
intercepted action. It is frozen (`model_config` / `frozen=True`) so no layer can mutate risk
downward after creation.

Key fields an adapter author cares about:

| Field | Role |
|-------|------|
| `id` | Stable action id (audit chain; `Decision.action_id` must match) |
| `ts` | Timezone-aware forensic timestamp |
| `agent_role` | Role label at decision time |
| `action_type` | `ActionType` enum (shell, network, file, …) |
| `tool_name` | Canonical tool name after remapping |
| `target` | Primary path / URL / command target when known |
| `risk` | Initial risk (engine may only raise) |
| `raw_args_redacted` | Already redacted args only; raw secrets never enter |
| `metadata` | Free-form; spine puts unredacted args under `EvalContext.metadata["raw_arguments"]` for the objective rules (in-memory only, never logged as part of the object) |

`normalize()` in `src/doberman/proxy/normalize.py` is the single constructor path. Adapters
translate the host call into `(canonical_name, args_dict)` and call `normalize` (via the spine).
They do not instantiate `SecurityObject` directly for the decision path.

### Host → canonical translation

Each adapter owns a small rename table so host tool names land on names `normalize` already
understands.

**Claude Code.** `to_normalize_input(tool_name, tool_input)` in `claude_code.py`:

- Looks up `_BUILTIN_TOOL` (for example `Bash` → shell, `Write`/`Edit` → file write with
  `file_path` renamed to the key `normalize` expects, `WebFetch` → `http_request`, and so on).
- Unknown / `mcp__*` tools pass through with their original name and args so generic MCP (Model
  Context Protocol, the standard tools use to expose themselves to an agent) handling applies.
- Required fields (`_REQUIRED_FIELD`) are checked before normalize: a gated built-in with a
  missing target fails closed rather than abstaining.

**OpenClaw.** `to_normalize_input(tool_name, params, derived_paths)` in `openclaw.py`:

- Applies `_CANONICAL_RENAME`.
- For `file_write` without a path key, fills `path` from OpenClaw's host-derived `derivedPaths`
  when present (the patch envelope has no natural path field).
- Same required-field fail-closed pattern for tools it can identify.

After translation, both call:

```python
result = spine.evaluate_action(
    canonical, args, cwd=payload.get("cwd"), raw_session_id=payload.get("session_id")
)
# result.action is the SecurityObject
# result.decision is the Decision
# result.acted is the Verdict the adapter must enforce
```

---

## Verdict enforcement

Doberman's internal verdict is always one of `Verdict.PASS` / `AUTH` / `BLOCK` (`models.py`).
Adapters map that onto the host's permission model. Doberman is raise-only: a `PASS` never
removes friction the host would have applied on its own; `AUTH` and `BLOCK` only add friction.

### Claude Code (`evaluate_pre`)

| `result.acted` | Host response | Mechanism |
|----------------|---------------|-----------|
| `PASS` | Abstain | Return `None` (print nothing on stdout; harness proceeds) |
| `AUTH` | Allow or deny this call | `_resolve_auth` → Doberman's own GUI/TTY challenge (`hookio.resolve_auth`); approved → `permissionDecision: "allow"`, otherwise `"deny"` |
| `BLOCK` | Deny | `_decision_payload` → `permissionDecision: "deny"` with a redaction-safe reason |
| Any error / unidentifiable call | Deny | `_deny()` |

CLI wiring: `doberman hook pre` / `post` in `src/doberman/cli/main.py` set up encode-safe stdio
and call `run_pre_hook` / `run_post_hook`. Install with `doberman install-hooks` (writes Claude
Code `settings.json` scopes).

### OpenClaw (Python verdict → JS host result)

Python (`evaluate_before_tool_call`) always returns a JSON object:

| Internal | Python stdout | JS `toHookResult` (`index.js`) |
|----------|---------------|--------------------------------|
| `PASS` | `{"verdict": "allow"}` | `{}` (no-op; raise-only) |
| `AUTH` | `{"verdict": "auth", title, description, severity, timeout_ms}` | `{ requireApproval: { …, allowedDecisions: ["allow-once", "deny"] } }` (**OpenClaw's** `/approve` flow, not Doberman's local challenge) |
| `BLOCK` | `{"verdict": "block", "reason": "…"}` | `{ block: true, blockReason }` |
| Transport / parse failure | (no valid document) | `failClosed(...)` returns block |

Important differences from Claude Code:

- Silence is **not** allow. The JS bridge treats null/timeout as block.
- AUTH is delegated to the host gateway (no interactive terminal in the gateway process).
  Approval outcomes are not yet written back to Doberman's decision log, documented in
  [`adapters/openclaw/README.md`](../adapters/openclaw/README.md).
- There is no post-call output scan in this slice.

CLI wiring: `doberman hook openclaw` → `run_before_tool_call_hook`.

---

## Checklist for a third adapter

1. **Find the host's pre-tool (and optionally post-tool) interception point.** Prefer an official
   hook/plugin API over monkey-patching.
2. **Write a thin translator** from the host payload to `(canonical_name, args)`. Keep rename
   tables next to the adapter, not in `normalize`.
3. **Call `spine.evaluate_action`** (or an equivalent that ends in `normalize` + `decide`). Do
   not fork a second decision engine.
4. **Map `result.acted`** to the host's allow / prompt / deny primitives. Fail closed on anything
   unidentifiable.
5. **Never put secrets into `SecurityObject.raw_args_redacted` or into reasons echoed to the
   host.** Build reasons from `Decision.explanation` and `reason_codes` only (see
   `_format_reason` in `openclaw.py` and `hookio.decision_payload` for Claude Code).
6. **Keep the hot path light.** Host hooks run on every tool call, so `claude_code.py`
   deliberately avoids importing `proxy.executor` / the subjective stack so startup cost stays
   off the critical path.
7. **Prove interception with a canary.** This matters especially when the host can fail open on
   plugin load (OpenClaw's documented gap): a destructive canary that must block is the only
   reliable liveness check.

### Reference files

| Concern | File |
|---------|------|
| `SecurityObject` / `Verdict` / `Decision` | `src/doberman/models.py` |
| Shared decide path | `src/doberman/hosthooks/spine.py` |
| Normalization | `src/doberman/proxy/normalize.py` |
| Claude Code pre/post | `src/doberman/hosthooks/claude_code.py` |
| OpenClaw Python | `src/doberman/hosthooks/openclaw.py` |
| OpenClaw JS plugin | `adapters/openclaw/index.js`, `adapters/openclaw/openclaw.plugin.json` |
| OpenClaw install / canary | [`adapters/openclaw/README.md`](../adapters/openclaw/README.md) |
| CLI hook commands | `src/doberman/cli/main.py` (`hook pre` / `post` / `openclaw`) |
