# Seeding the per-entity baseline, `doberman memory seed`

The subjective layer's per-entity streaming baseline, its running profile of what counts as normal
for that entity (see [TUNING.md](TUNING.md) and [RECOVERY.md](RECOVERY.md)), starts every deployment
cold: until an entity crosses `K_OBSERVATIONS` allowed actions, its surprise score blends with a
conservative peer/global prior instead of its own history. `doberman memory seed --from <file>` lets
an operator warm their own baseline from traces they already have (a prior decision log, an
allow-listed workflow capture) before live traffic starts. That way a fresh install isn't scoring on
the least-sharp version of the adaptive layer exactly when it's most likely to be evaluated.

Seeding replays each trace through the exact same `observe()` path the live proxy calls. There is no
separate learning code. Seeding and live warming can never diverge.

```
doberman memory seed --from traces.jsonl [--path .] [--now 2026-06-09T00:00:00Z] [--json]
```

- `--from`: path to a JSONL trace file (format below). Required.
- `--path`: repository root whose baseline gets seeded (default `.`).
- `--now`: ISO-8601 timestamp every seeded row is stamped with (default: current UTC). Passing an
  explicit value makes a run byte-for-byte reproducible.
- `--json`: emit the summary as one compact JSON document instead of the human view.

> **Naming note.** An earlier proposal suggested a standalone `doberman baseline seed` verb. It
> lives under the existing `memory` group instead: `memory reset`/`memory prune` already own these
> same tables, and a separate one-verb `baseline` group would split that surface across two command
> groups for no operator benefit.

## The four hard invariants

- **Allowed-only.** Only a `PASS`/`allowed: true` trace teaches the baseline. That's the same rule
  the live path enforces. A blocked/denied or malformed trace anywhere in the file refuses the
  **whole file**. Nothing is observed. A partially-seeded baseline would be unauditable (the operator
  can't tell which rows landed), so this is whole-file, not best-effort.
- **Raise-only.** Seeding only calls `observe()`. It cannot lower a verdict and never touches
  `policies.yaml`, the strictness mode, or the `policy_changes` ledger. It can only warm the surprise
  baseline, exactly like any other allowed action would.
- **Redaction.** The seed summary carries an entity-id prefix, counts, and booleans only. A refused
  file's error names the 1-based line numbers of the bad rows, **never** their content. Row content
  itself only ever reaches `observe()`, which stores classes and keyed HMAC (hash tied to a secret
  key) fingerprints, the same redaction discipline the live path uses.
- **Deterministic + local.** No network calls. The only clock read is the injected `--now`. Every row
  in one run shares that single stamp, so two runs with the same `--now` produce identical
  `last_touched` values.

## The HST limit

The baseline's Half-Space-Trees anomaly model is **process-lifetime only**: it is never persisted to
or rehydrated from the database (`baseline.py`'s in-process `_HST_MODELS`/`_HST_LEARN_COUNTS`). A
`doberman memory seed` run is a short-lived CLI process, so any HST warm-up it produces is discarded
the moment the command exits. The next real `doberman serve`/proxy process still starts its HST cold,
regardless of what was seeded. The summary's `hst` field always reads `"in-process"` for this reason:
reporting a live learn count would describe state that seeding cannot actually deliver. Persisting the
HST across processes is out of scope for this command.

## JSONL trace format v1

One JSON object per line. Blank lines are skipped. A leading UTF-8 BOM (byte-order mark) is
tolerated. Any key outside the tables below makes that row invalid (a typo must not silently pass).

| Field | Required | Type | Notes |
| --- | --- | --- | --- |
| `verdict` | one of `verdict`/`allowed` | `"PASS"` exactly | When present, `verdict` decides. See below. |
| `allowed` | one of `verdict`/`allowed` | `true` exactly | Only consulted when `verdict` is absent. |
| `agent_role` | yes | non-empty string | Combined with the repo root into the seeded `entity_id`. |
| `action_type` | yes | an `ActionType` value | e.g. `file_write`, `shell_exec`, `network_request`. |
| `tool_name` | yes | non-empty string | The tool the trace records. |
| `target` | no | string | Class-level, REPO-RELATIVE only (e.g. `src/*.py`). See below. |
| `external_destination` | no | string | Fingerprinted (keyed HMAC) before storage, never stored raw. |
| `reversibility` | no | a `Reversibility` value | Defaults to `medium`. |
| `target_count` | no | integer ≥ 1 | Feeds the numeric volume stat (`SecurityObject.metadata["target_count"]`). |
| `algebra` | no | object | See below. Omit it to let `infer_algebra()` (the production inference) classify the row. |

**`verdict`/`allowed`.** If `verdict` is present it must be exactly `"PASS"` or the row is
invalid, no matter what `allowed` says. `allowed` never overrides a non-`PASS` verdict.
`allowed` is only consulted when `verdict` is absent, and must be exactly `true`. `verdict:
"PASS"` together with an explicit `allowed: false` is a contradiction, not a pass, and is
invalid. (There is no path where the two fields disagree and the row is still accepted.)

**`target` must be repo-relative.** The stored key is the SAME bucket the live proxy computes
(`baseline.py`'s `_path_bucket()`): the directory plus `*.ext`. But an extension-less filename
(e.g. `docker/Dockerfile`) keeps its exact name, verbatim, the same way the live path does. That
bucket is stored AS GIVEN, with no confinement of its own (the live proxy's targets are already
repo-relative by the time they reach it; a seeded trace has no such guarantee). An absolute path
(POSIX `/...`, a Windows drive `C:\`/`C:/`, or a UNC share `\\...`), a `~`-prefixed path, or any
`..` segment is refused. That refusal covers the whole file; only the line number is reported,
never the path itself. Write targets as repo-relative classes only.

`algebra`, when present, may set any subset of: `capability`, `target_class`, `destination_class`,
`blast_radius`, `provenance`, `classification_confidence`. Each is validated against its enum (an
unknown key or an out-of-range value invalidates the row).

A row missing `agent_role`/`action_type`/`tool_name`, missing both `verdict` and `allowed`, whose
verdict isn't exactly `PASS`/`true`, or that carries any key outside the tables above, is invalid and
refuses the whole file.

## Worked example

```jsonl
{"verdict": "PASS", "agent_role": "frontend", "action_type": "file_write", "tool_name": "fs_write", "target": "src/*.tsx"}
{"verdict": "PASS", "agent_role": "frontend", "action_type": "file_write", "tool_name": "fs_write", "target": "src/*.tsx"}
{"allowed": true, "agent_role": "frontend", "action_type": "shell_exec", "tool_name": "run_command", "target": "npm test"}
```

```
$ doberman memory seed --from traces.jsonl --path . --now 2026-06-09T00:00:00Z
Seeded 3 allowed-action trace(s).
  entity hmac:9f2a1b3...  +3 observation(s), total 3 (cold), HST in-process
```

A row that fails validation refuses the whole run instead:

```
$ doberman memory seed --from bad-traces.jsonl --path .
error: seed refused - 1 invalid row(s) at line(s): 2; nothing observed
```
