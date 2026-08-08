# Doberman CLI reference

Entry point: `doberman` (Typer). All commands accept `--help`.

## Core commands

| Command | Purpose |
|---------|---------|
| `doberman scan` | Read-only capability risk map of the repo |
| `doberman review` | Policy checklist (optional `--yes` to save) |
| `doberman mode` | Strictness dial |
| `doberman status` | Current posture + elevations |
| `doberman doctor` | Health self-check (script-friendly exit codes) |
| `doberman policy-history` | Append-only policy change ledger |
| `doberman log` | Decision log (redacted) |
| `doberman memory` | Aggregated class counts (no secrets) |
| `doberman install-hooks` | Wire Claude Code host hooks |
| `doberman serve` | MCP stdio proxy |

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
```

See also [SETUP.md](SETUP.md) and the root README.
