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
| `doberman status` | Current posture, hooks, taint, elevations, recent decisions |
| `doberman doctor` | Health self-check (script-friendly exit codes) |
| `doberman policy-history` | Append-only policy change ledger |
| `doberman log` | Decision log (redacted) |
| `doberman memory` | Aggregated class counts (no secrets) |
| `doberman tui` | Interactive decision log with plain-language "why" panel |
| `doberman dash` | Localhost-only dashboard (preview) |
| `doberman demo` | Scripted attack reel through the real decision engine |
| `doberman revoke` | Revoke an active role elevation by id |
| `doberman setup` | First-run wizard (posture + Claude Code hooks) |
| `doberman install-hooks` | Wire Claude Code host hooks |
| `doberman uninstall-hooks` | Remove Claude Code host hooks |
| `doberman serve` | MCP stdio proxy in front of a downstream tool server |
| `doberman version` | Print the installed Doberman version |
| `doberman session-summary` | Print the device-global session-guard summary and exit |

Global option: `doberman --version` / `-V` also prints the version and exits.

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
| `--json` | `scan`, `doctor`, `policy-history` | One JSON document on stdout |
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

## Examples

```bash
doberman scan --path . | less
doberman scan --json | jq '.capabilities[] | select(.present)'
doberman scan --quiet; echo $?
doberman doctor --json | jq .ok
doberman policy-history --json | jq 'length'
doberman log --jsonl | jq -c 'select(.final_verdict=="block")'
doberman 2fa setup
doberman password set
doberman setup
```

See also [SETUP.md](SETUP.md) and the root README.
