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
| `--jsonl` | `log` | One JSON object per decision line on stdout |
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

JSON `evidence` arrays may include up to 10 path-class or tool-name entries per capability
(`scan.py` caps at 10). The human-readable risk map shows at most 3 of those same entries,
so `doberman scan` and `doberman scan --json` can legitimately differ in how many evidence
items appear for a capability.

### `doberman doctor --json`

Emits `{version, path, ok, checks[], critical_failures[]}`. Exit code is still non-zero when critical checks fail.

## Examples

```bash
doberman scan --path . | less
doberman scan --json | jq '.capabilities[] | select(.present)'
doberman scan --quiet; echo $?
doberman doctor --json | jq .ok
doberman policy-history --json | jq 'length'
doberman log --jsonl | head -n 5
```

See also [SETUP.md](SETUP.md) and the root README.
