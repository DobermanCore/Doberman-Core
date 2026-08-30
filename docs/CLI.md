# Doberman CLI reference

The `doberman` command (built with Typer) is how you check status, tune posture, recover from a lockout, and wire Doberman into a host. Every command and subcommand below accepts `--help`. This page groups them by what you use them for, then documents the JSON contract and exit codes that scripts can rely on.

## Core commands

Day-to-day posture, status, and review commands.

| Command | Purpose | Key flags |
|---------|---------|-----------|
| `doberman scan` | Read-only risk map of the repo's capabilities and sensitive surface. | `--path`/`-p`, `--quiet`/`-q`, `--json`, `--mcp` |
| `doberman review` | Show the recommended policy checklist; save it with `--yes`. | `--path`/`-p`, `--yes`/`-y` |
| `doberman mode [NAME]` | Show or set the security strength mode (light/balanced/strict/paranoid). | `--path`/`-p` |
| `doberman enforcement [STATE]` | Show or set the enforcement dial (enforce/monitor/off). | `--path`/`-p` |
| `doberman prefs [DIMENSION] [VALUE]` | Show or set the subjective preference vector. | `--path`/`-p` |
| `doberman egress-velocity [KNOB] [VALUE]` | Show or set the egress-velocity thresholds (`burst`, `volume-bytes`, `fanout`). Lowering a threshold is frictionless; raising one is gated. | `--path`/`-p` |
| `doberman message-tone [TONE]` | Show or set the AUTH challenge tone (human/technical). Cosmetic display only; it changes nothing about what is evaluated or logged. | `--path`/`-p` |
| `doberman role enable-default` | Turn on the built-in, opt-in least-privilege default role. | `--path`/`-p` |
| `doberman role disable-default` | Turn the default role off. A weaken, so it is gated. | `--path`/`-p` |
| `doberman status` | Active role, mode, policy summary, hook install state, taint state, and recent decisions. | `--path`/`-p`, `--json` |
| `doberman doctor` | Read-only health self-check; exits non-zero if a critical check fails. | `--path`/`-p`, `--json` |
| `doberman policy-history` | Append-only policy-change ledger, newest first. | `--last`/`-n`, `--path`/`-p`, `--json` |
| `doberman log` | Recent redacted decision log, newest first. | `--last`/`-n`, `--path`/`-p`, `--jsonl` |
| `doberman decision-log-prune` | Delete resolved decisions by age and/or retained-row budget. Never touches pending AUTH rows or the policy-change ledger. | `--older-than-days`, `--max-rows`, `--path`/`-p` |
| `doberman tui` | Interactive decision log with a plain-language "why" panel. Needs the `tui` extra. | `--path`/`-p` |
| `doberman dash` | Localhost-only dashboard: live decision feed, stats, and an AUTH approve/deny queue. Needs the `dash` extra. | `--port`, `--path`/`-p` |
| `doberman demo` | Scripted attack reel through the real decision engine. Nothing runs against a real tool or downstream server. | `--path`/`-p`, `--mode`, `--fast`, `--quiet`/`-q` |
| `doberman revoke ELEVATION_ID` | Revoke an active role elevation by id (see `doberman status`). | `--path`/`-p` |
| `doberman tune` | Friction report (interventions per session, top AUTH reasons) plus gated standing-elevation proposals. | `--path`/`-p`, `--json`, `--last`, `--min-occurrences`, `--accept` |
| `doberman memory` | Learned-memory profile: decision counts, verdict mix, most-touched path classes. Never shows a fingerprint value or raw secret. | `--path`/`-p`, `--json` |
| `doberman approvals status` | Show whether exact-action approval memory is enabled, its TTL, and the live-entry count. Never prints fingerprints. | `--path`/`-p` |
| `doberman approvals clear` | Clear every approval-memory entry for this repo. This is an ungated strengthening. | `--path`/`-p` |
| `doberman approvals ttl SECONDS` | Set approval-memory TTL in `0..900`; `0` disables it. Raising is possession-factor gated; lowering is ungated. | `--path`/`-p` |
| `doberman setup` | First-run wizard: pick a security posture and wire Claude Code hooks. | `--yes`/`-y`, `--mode`/`-m`, `--global`/`-g`, `--path`/`-p` |
| `doberman telemetry on` | Opt in to anonymous CLI usage counts. | none |
| `doberman telemetry off` | Opt out after one final best-effort disabled event. | none |
| `doberman telemetry status` | Show effective state, the random distinct id, and active kill switches. | none |
| `doberman session-summary` | Print the device-global session-guard summary and exit. Always exits 0; never blocks a session. | none |
| `doberman serve` | Run Doberman as an MCP proxy in front of a downstream MCP tool server. | `--path`/`-p` |
| `doberman version` | Print the installed Doberman version. `doberman --version` / `-V` does the same. | none |

## Auth enrollment

Security-posture commands used by [the setup guide](SETUP.md). These groups also appear in `doberman --help`.

| Command | Purpose | Key flags |
|---------|---------|-----------|
| `doberman 2fa setup` | Enroll TOTP two-factor and print the provisioning URI for your authenticator app. | `--force` (rotate an existing secret) |
| `doberman 2fa remove` | Remove TOTP enrollment. Requires your current 2FA code; not delegable to the password. | none |
| `doberman 2fa reset-lockout` | Clear an early TOTP lockout. Gated on your password, since a locked-out factor cannot verify itself. | none |
| `doberman 2fa methods list` | List approval methods (biometric/push), whether each is available here, and which are enabled. | none |
| `doberman 2fa methods enable <name>` | Enable an approval method (opt-in) so a tap replaces the 2FA code when available; TOTP stays as the fallback. | none |
| `doberman 2fa methods disable <name>` | Disable an approval method; 2FA falls back to the next enabled method or to TOTP. | none |
| `doberman 2fa methods status` | Show which proof the next 2FA challenge would use — an approval method, or the TOTP code. | none |
| `doberman password set` | Set or rotate the local password possession factor. | `--force` (rotate after proving the current password) |

Note that the `2fa` subcommands take no `--path`: TOTP enrollment is a device-wide factor, not a per-repo one.

## Recovery

Gated recovery actions for a stuck or compromised state. Each requires an enrolled possession factor (a 2FA code if enrolled, otherwise your Doberman password); with neither enrolled, the command fails closed.

| Command | Purpose | Key flags |
|---------|---------|-----------|
| `doberman taint clear` | Clear this repo's sticky session taint. No timer; this is the only escape hatch. | `--path`/`-p` |
| `doberman tools approve TOOL_NAME` | Approve a changed MCP tool fingerprint after possession-factor verification. | `--path`/`-p` |
| `doberman memory reset` | Wipe learned behavioral memory for this repo. Raise-safe by construction: a colder baseline scores everything as more novel, never less protected. | `--entity`, `--path`/`-p` |
| `doberman memory prune` | Drop stale entities' learned memory past a retention window. A maintenance operation, so it is not gated. | `--older-than-days` (required), `--path`/`-p` |
| `doberman uninstall` | Remove Doberman from one project, or use `--global` for ordered machine-wide removal: all writable hooks, project and device state, enrolled factors, then the pip/pipx package. Codex plugin hooks remain under `codex plugin` control. | `--path`/`-p`, `--yes`/`-y`, `--dry-run`, `--global`/`-g`, `--keep-package` |

## Host hooks

Wiring commands plus the low-level per-host handlers they install.

| Command | Purpose | Key flags |
|---------|---------|-----------|
| `doberman install-hooks` | Wire Doberman's hooks into a host so every tool call is gated before it runs. Idempotent. | `--global`/`-g`, `--local`, `--host`, `--path`/`-p`, `--dry-run` |
| `doberman uninstall-hooks` | Remove Doberman's hooks from a host. Every other setting is left untouched. | `--global`/`-g`, `--local`, `--host`, `--path`/`-p`, `--dry-run` |
| `doberman hook pre` | Claude Code PreToolUse hook: gate one tool call (allow/ask/deny). Reads the hook payload as JSON on stdin. | none |
| `doberman hook post` | Claude Code PostToolUse hook: scan tool output for secrets and record history. | none |
| `doberman hook openclaw` | OpenClaw `before_tool_call` plugin hook: gate one tool call. Always writes exactly one JSON verdict, unlike the Claude Code hooks above. | none |
| `doberman hook codex-pre` | Codex CLI PreToolUse hook: gate one tool call. Shares `hook pre`'s decision spine and deny shape. | none |

All four `hook` subcommands run only the fast deterministic objective floor, so they add minimal latency, and fail closed on any malformed input or engine error.

## Output conventions

Human-readable diagnostics use one severity vocabulary: `error:` means the command failed and returned a non-zero exit code, `warning:` means it succeeded but skipped or degraded something, and `note:` marks a purely informational aside. Machine-readable flags keep their documented schemas and never add these prefixes.

## Machine-readable output

Four flags cover every scriptable surface: `--json` (`status`, `scan`, `doctor`, `policy-history`, `tune`, `memory`) for one JSON document, `--jsonl` (`log`) for one redacted object per line, `--quiet`/`-q` (`scan`, `demo`) to suppress the human output while keeping the exit code (`demo` keeps its summary line/table, so a mismatch still fails loudly), and `--path`/`-p` (most commands) for the repository root, default `.`. When both `--json` and `--quiet` are passed to `scan`, `--json` wins.

### Flag naming

- **`--json`** emits one JSON object or array you can pipe directly into `jq` or `python -m json.tool`.
- **`--jsonl`** emits JSON Lines: each line parses independently, and an empty result set produces empty stdout, not `[]`. This shape suits streaming consumers and `while read line` shell loops.

### Stdout purity

When a machine-readable flag is active, stdout contains JSON and nothing else. Tables, headings, spinners, and `note:`/`warning:` lines are suppressed or sent to stderr instead. Scripts should read only stdout; a human reads stderr.

### Redaction guarantee

JSON output never contains a raw file path, file content, argument value, environment variable, secret, or prompt text. It contains only what the human view already shows: path *classes* (`*.env`, `backend/auth/*.ts`), reason-code names, risk levels, and verdicts, because both views draw from the same already-redacted data.

### Determinism guarantee

Every `--json` document uses deterministic key ordering (`sort_keys=True`) and compact separators. Two invocations against identical state produce byte-for-byte identical output. `--jsonl` lines are deterministic per line, in the command's documented row order (newest first for `log`).

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
      "evidence": ["path classes or tool names, never file contents"]
    }
  ]
}
```

Capabilities are sorted by `(category, name)` for deterministic output. Each capability's `evidence` list is capped at 10 entries in discovery; the human-readable risk map shows only the first 3 of those per capability, so `scan` and `scan --json` can legitimately show different amounts of evidence for the same capability.

### `doberman doctor --json`

Emits `{version, path, ok, checks[], critical_failures[]}`. `ok` is `true` only when every critical check (host hooks, hook command, config, decision DB) passed. Exit code stays non-zero when a critical check fails, even though the payload still prints.

### `doberman log --jsonl`

One redacted JSON object per decision line, newest first. Fields are an allowlist of already-redacted data: `ts`, `final_verdict`, `action_type`, `target_path_class`, `reason_codes`, `auth_result`, plus `id`, `agent_role`, and `risk` when present. Empty stdout when there are no rows.

### `doberman policy-history --json` schema

A JSON array of policy-change rows in newest-first order: each element carries the change timestamp, the changed key, the previous and new values, and the actor. No raw policy content, secret, or file path appears.

### `doberman tune --json`

Emits `{version, decisions, sessions, unsessioned_decisions, interventions, interventions_per_session, top_auth_reason_codes, approval_rate_by_reason, approval_rate_by_target, trend, proposals}`, deterministic for identical inputs and scoped to the most recent `--last` decisions (default 2000). A proposal looks like `{id, kind, action_type, target_path_class, occurrences, approval_rate, reason_codes, ttl_days, what_would_loosen, why}`; Doberman emits one only when a group has at least `--min-occurrences` (default 5) AUTH rows, all approved, a narrow non-whole-tree path class, and reason codes that are a non-empty subset of `{role_out_of_scope}`, the only code a standing elevation may cover. `doberman tune` never applies a proposal by itself. `--accept <id>` recomputes proposals from the same `--last`/`--min-occurrences`, rejects an unknown or stale id, then routes the accepted one through the same possession-factor-gated weaken chokepoint every other policy loosening uses before granting a revocable, time-limited elevation (`doberman revoke <elevation-id>` reverses it early).

## Exit codes

Every command follows a two-value convention: the same code always means the same class of failure, regardless of which command raises it.

| Code | Meaning |
|------|---------|
| `0` | The command completed normally. |
| `1` | A gate denied the change, a runtime error occurred, a required optional extra is missing, or the operation finished with errors. |
| `2` | Bad input: an argument or option value is invalid before any state is touched. |

Code `2` is reserved for input-validation failures that could be caught before any I/O or gate check runs, so a script can branch on "bad flag" versus "gate denied." Code `1` covers everything else: auth denials, runtime errors, missing optional extras, and partial-success failures.

### Per-command detail

| Command | Code | Trigger |
|---------|------|---------|
| `serve` | `2` | No downstream server command given after `--`. |
| `serve` | `1` | MCP proxy runtime error. |
| `mode` | `2` | Invalid mode name. |
| `mode` | `1` | Mode change denied by the possession-factor gate. |
| `enforcement` | `2` | Unknown enforcement state (must be `enforce`, `monitor`, or `off`). |
| `enforcement` | `1` | Enforcement change denied by the gate. |
| `role disable-default` | `1` | Disable denied by the gate. |
| `prefs` | `2` | No value given, or an invalid dimension/value. |
| `prefs` | `1` | Preference change denied by the gate. |
| `egress-velocity` | `2` | Unknown knob, missing value, or a non-positive value. |
| `egress-velocity` | `1` | Threshold change denied by the gate. |
| `doctor` | `1` | One or more critical checks failed. |
| `password set` | `1` | Passwords did not match, or enrollment failed. |
| `2fa setup` | `1` | TOTP enrollment failed. |
| `2fa remove` | `1` | Not enrolled, confirmation declined, or unenroll failed. |
| `2fa reset-lockout` | `1` | Not enrolled, no password enrolled, or an incorrect password. |
| `taint clear` | `1` | No possession factor enrolled, gate denied, or the DB clear failed. |
| `tools approve` | `1` | No possession factor enrolled, gate denied, storage failed, or no pin exists for that tool. |
| `approvals ttl` | `1` | A TTL increase was denied by the possession-factor gate. |
| `approvals ttl` | `2` | TTL is outside `0..900`. |
| `revoke` | `1` | Elevation id not found, or revoke failed. |
| `tui` | `1` | The optional `textual` extra is not installed. |
| `dash` | `1` | The optional `dash` extra is not installed. |
| `demo` | `1` | Invalid mode name, or a scenario did not match its expected outcome. |
| `memory reset` | `1` | No possession factor enrolled, gate denied, or the DB reset failed. |
| `memory prune` | `1` | The DB prune operation failed. |
| `decision-log-prune` | `2` | Neither `--older-than-days` nor `--max-rows` was provided. |
| `decision-log-prune` | `1` | The DB prune operation failed. |
| `uninstall` | `1` | No possession factor enrolled, confirmation declined, name mismatch, gate denied, or some items were not removed. |

Commands not listed (`scan`, `review`, `status`, `log`, `policy-history`, `install-hooks`, `uninstall-hooks`, `session-summary`, `version`, `memory`, `setup`, `hook pre`/`post`/`openclaw`/`codex-pre`) exit `0` on success and rely on Typer's default handler to return `1` on an unhandled exception; they have no `typer.Exit(code=...)` call sites of their own.

### Collision audit

`grep -n "typer.Exit(code=" src/doberman/cli/main.py` returns 45 call sites: 6 use `code=2` (all input-validation rejections, checked before any gate runs) and 39 use `code=1`. No command uses both codes for the same logical condition, and no two commands use the same code for contradictory meanings. This section documents the count; it changes no exit-code value.

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

See also [the setup guide](SETUP.md) and the root README.
