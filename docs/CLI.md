# Doberman CLI reference

Entry point: `doberman` (Typer). All commands accept `--help`.

## Core commands

| Command | Purpose |
|---------|---------|
| `doberman scan` | Read-only capability risk map of the repo |
| `doberman review` | Policy checklist (optional `--yes` to save) |
| `doberman mode` | Show or set the security strength mode |
| `doberman enforcement` | Show or set the enforcement dial (`enforce` / `monitor` / `off`) |
| `doberman prefs` | Show or set the subjective preference vector (SL5) |
| `doberman role enable-default` | Opt into the built-in least-privilege default role (used when no `.doberman/role.yaml` exists) |
| `doberman role disable-default` | Opt back out (gated — a weaken) |
| `doberman status` | Current posture, hooks, taint, elevations, recent decisions |
| `doberman doctor` | Health self-check (script-friendly exit codes) |
| `doberman policy-history` | Append-only policy change ledger |
| `doberman log` | Decision log (redacted) |
| `doberman memory` | Aggregated class counts (no secrets) |
| `doberman memory reset` | Wipe learned behavioral memory for this repo (gated; needs a possession factor) |
| `doberman memory prune` | Drop stale entities' learned memory past a retention window (ungated maintenance) |
| `doberman tui` | Interactive decision log with plain-language "why" panel (needs the `[tui]` extra) |
| `doberman dash` | Localhost-only dashboard (preview) |
| `doberman demo` | Scripted attack reel through the real decision engine |
| `doberman revoke` | Revoke an active role elevation by id |
| `doberman tune` | Friction report (interventions/session, top AUTH reasons, approval rates, trend) plus gated standing-elevation proposals; `--accept <id>` grants one |
| `doberman setup` | First-run wizard (posture + Claude Code hooks) |
| `doberman install-hooks` | Wire host hooks (Claude Code by default; `--host codex` for Codex CLI) |
| `doberman uninstall-hooks` | Remove host hooks (Claude Code by default; `--host codex` for Codex CLI) |
| `doberman serve` | MCP stdio proxy in front of a downstream tool server |
| `doberman version` | Print the installed Doberman version |
| `doberman session-summary` | Print the device-global session-guard summary and exit |

Global option: `doberman --version` / `-V` also prints the version and exits.

## Output conventions

Human-readable diagnostics use one severity vocabulary: `error:` means the command failed and
returned a non-zero exit code, `warning:` means the command succeeded but skipped or degraded
something, and `note:` marks a purely informational aside. Machine-readable flags keep their
documented schemas and do not add these prefixes.

## Auth enrollment

Security-posture commands used by [SETUP.md](SETUP.md). Group entry points also appear in `doberman --help`.

| Command | Purpose |
|---------|---------|
| `doberman 2fa setup` | Enroll TOTP two-factor; print provisioning URI |
| `doberman 2fa remove` | Remove TOTP enrollment (proves possession of the factor) |
| `doberman 2fa reset-lockout` | Clear TOTP lockout early (proves password possession) |
| `doberman password set` | Set or rotate the local password possession factor |

## Session taint recovery

| Command | Purpose |
|---------|---------|
| `doberman taint clear` | Clear this repo's sticky session taint (gated; needs a possession factor) |

## Host hooks

Low-level harness integration (also installed via `install-hooks` / `setup`).

| Command | Purpose |
|---------|---------|
| `doberman hook pre` | Claude Code PreToolUse — gate one tool call |
| `doberman hook codex-pre` | Codex CLI PreToolUse — gate one tool call (same decision spine as `hook pre`) |
| `doberman hook post` | Claude Code PostToolUse — scan output for secrets; record history |
| `doberman hook openclaw` | OpenClaw `before_tool_call` plugin hook — gate one tool call |

## Machine-readable flags

| Flag | Commands | Notes |
|------|----------|-------|
| `--json` | `status`, `scan`, `doctor`, `policy-history`, `tune` | One JSON document on stdout |
| `--jsonl` | `log` | One redacted decision object per line (empty if none) |
| `--quiet` / `-q` | `scan` | No human map; exit code preserved |
| `--path` / `-p` | most commands | Repository root (default `.`) |

When both are passed, `--json` wins over `--quiet`: machine-readable JSON is still emitted.

### `doberman scan --json` schema

```json
{
  "version": 1,
  "path": ".",
  "capabilities": [
    {
      "name": "shell",
      "category": "tool",
      "present": true,
      "risk": "high",
      "evidence": ["…path classes or tool names, never file contents…"]
    }
  ]
}
```

Capabilities are sorted by `(category, name)` for deterministic output.

Each capability's `evidence` list is capped at **10** entries in discovery. The human-readable risk map shows only the first **3** of those entries per capability — so `doberman scan` and `doberman scan --json` can legitimately differ in how much evidence they display for the same capability.

### `doberman doctor --json`

Emits `{version, path, ok, checks[], critical_failures[]}`. Exit code is still non-zero when critical checks fail.

### `doberman log --jsonl`

Emits one redacted JSON object per decision line (newest first). Columns are an allowlist of already-redacted fields (`ts`, `final_verdict`, `action_type`, `target_path_class`, `reason_codes`, `auth_result`, plus `id` / `agent_role` / `risk` when present). Empty output when there are no rows.

## JSON output conventions

All five machine-readable modes (`status --json`, `scan --json`, `doctor --json`,
`policy-history --json`, `log --jsonl`) share one contract. Understanding it once covers every
command.

### Flag naming

- **`--json`** (`status`, `scan`, `doctor`, `policy-history`, `tune`) — emits **one JSON document** on
  stdout: a single JSON object or array that can be piped directly into `jq`,
  `python -m json.tool`, or any JSON-aware tool.
- **`--jsonl`** (`log`) — emits **one JSON object per line** (JSON Lines / NDJSON). Each line is
  independently parseable; an empty result set produces empty stdout, not `[]`. This shape suits
  streaming consumers and `while read line` shell loops.

The two shapes are genuinely different and the flag names make the difference explicit:
`--json` → one document, `--jsonl` → one object per line.

### Stdout purity

When a machine-readable flag is active, **stdout contains JSON and nothing else**. Rich tables,
headings, progress spinners, and `note:` / `warning:` lines are suppressed or redirected to
stderr. Scripts must read only stdout; humans can read stderr.

### Redaction guarantee

JSON output never contains raw file paths, file contents, argument values, environment variables,
secrets, or prompt text. It contains only what the human view already shows — path *classes*
(`*.env`, `backend/auth/*.ts`), reason-code enumerations, risk levels, and verdicts — because
both modes draw from the same already-redacted data source.

### Determinism guarantee

All `--json` documents have **deterministic key ordering** (`sort_keys=True`) and **compact
separators** (`","` / `":"`). Two invocations on identical state produce byte-for-byte identical
output. `--jsonl` produces deterministic per-line objects with the same key ordering; line order
follows the command's documented row order (newest-first for `log`).

### Exit codes

Machine-readable flags do not change exit semantics. `doctor --json` still exits non-zero when
critical checks fail. `scan --json` still exits zero even when high-risk capabilities are present
(the human `--quiet` behavior). Scripts must check the exit code independently of parsing the
JSON payload.

### `doberman policy-history --json` schema

Emits a JSON array of ledger rows, newest first — the same redacted dicts the human view reads:
`ts`, `rule_id`, `from_state`, `to_state`, `classification` (strengthen / weaken / neutral),
`reason` (redacted at write time), `approval_method`, `approved` (denied weakening attempts are
recorded too — the poisoning signal), and `approved_by`. No raw policy contents, secrets, or file
paths appear.

### `doberman tune --json`

Emits `{version, decisions, sessions, unsessioned_decisions, interventions, interventions_per_session, top_auth_reason_codes, approval_rate_by_reason, approval_rate_by_target, trend, proposals}`. Deterministic across identical inputs (`sort_keys=True`); considers the most recent `--last` decisions (default 2000). A proposal is `{id, kind, action_type, target_path_class, occurrences, approval_rate, reason_codes, ttl_days, what_would_loosen, why}` — emitted only when an `(action_type, target_path_class)` group has at least `--min-occurrences` (default 5) AUTH rows, **all** approved, a narrow non-whole-tree path class, and reason codes that are a non-empty subset of `{role_out_of_scope}` (the only code a standing elevation may ever cover). `doberman tune` never applies a proposal itself. `doberman tune --accept <id>` recomputes proposals from the same `--last`/`--min-occurrences`, rejects an unknown/stale id (exit 1), then routes the accepted one through the same possession-factor-gated weaken chokepoint every other policy loosening uses (TOTP if enrolled, else the local password; fails closed with neither) before granting a revocable, time-limited elevation (`doberman revoke <elevation-id>` reverses it early).

## Examples

```bash
doberman scan --path . | less
doberman scan --json | jq '.capabilities[] | select(.present)'
doberman scan --quiet; echo $?
doberman doctor --json | jq .ok
doberman policy-history --json | jq 'length'
doberman log --jsonl | jq -c 'select(.final_verdict=="block")'
doberman tune --json | jq '.proposals'
doberman 2fa setup
doberman password set
doberman setup
```

See also [SETUP.md](SETUP.md) and the root README.
