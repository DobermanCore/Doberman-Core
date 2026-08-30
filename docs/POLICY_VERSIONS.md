# Policy versions

Every decision Doberman makes is made under some policy: the strictness mode, the enforcement dial,
the preference weights, the egress thresholds, the active role's path globs, and the rule set of the
installed release. A **policy version** names that exact combination so a log entry can later be
matched to the policy that produced it.

## What a version is

`pv1:` followed by the SHA-256 (hex) of the canonical JSON of a snapshot with these keys:

| Key | Content | Why it is hashed |
| --- | --- | --- |
| `schema` | `1` | Lets a verifier reject a snapshot layout it does not know. |
| `engine` | `doberman.__version__` | The rule set, hard-block floor, mode thresholds, and built-in roles ship with the package; the same YAML can decide differently across releases. |
| `enforcement_effective` | `enforce` / `monitor` / `off` | The state actually acted on (ledger-verified, timer applied), not just the field on disk. |
| `doc` | `.doberman/policies.yaml` as saved, minus `message_tone` and every item `description` | Everything else in the file can change a verdict; those two cannot, so a wording change never mints a version. |
| `role` | the active role's `name`, `allowed`, `suspicious`, `blocked` globs, or `null` | Role boundaries decide out-of-scope step-ups. |

Canonical form: `json.dumps(snapshot, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`,
UTF-8 encoded. The published JSON Schema is [`schemas/policy-snapshot.v1.json`](schemas/policy-snapshot.v1.json).

Plain SHA-256 rather than Doberman's keyed HMAC on purpose: anyone holding the snapshot (an auditor,
a central verifier) can recompute the id without the local key. Nothing in a snapshot is secret; it is
configuration that already lives in `.doberman/`.

Recompute one by hand from `doberman policy-versions --show <id>` output:

```bash
doberman policy-versions --show <id> | python -c "import json,sys,hashlib; s=json.load(sys.stdin)['snapshot']; print('pv1:'+hashlib.sha256(json.dumps(s,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest())"
```

## Where versions are recorded

`.doberman/policies.db` (created `0600`, never committed, never pruned by `decision-log-prune`) holds:

- `policy_versions` — each snapshot once, with the exact bytes that were hashed and when it was first seen.
- `policy_observations` — an append-only row every time the version in force was seen to change:
  `origin` is `change` (written by every gated policy save, with `ledger_ts` pointing at the
  `policy_changes` row that authorised it) or `observed` (`doberman doctor` and
  `doberman policy-versions` record what they find, which is how a hand edit of `role.yaml` or
  `policies.yaml` enters the timeline).

The version in force at a time `T` is the latest observation at or before `T`.

## Matching

- version → content: `doberman policy-versions --show <id>` (full id or ≥ 8 hex characters).
- time → version: the observation timeline (`doberman policy-versions --json` lists each version with
  `in_force_since`).
- ledger ↔ version: an observation's `ledger_ts` equals the `ts` of the `policy-history` row that
  produced it.

## Checking

`doberman policy-versions --verify` recomputes every stored digest and compares the policy on disk with
the last recorded version. It reports `ok`, `mismatch` (stored content no longer hashes to its id: the
store was altered), or `drift` (the policy on disk is not the last recorded version: a change nobody has
observed yet, or no catalogue at all). It exits `1` on anything but `ok` and never records.

## What this does not prove

An observation records when a change was *seen*, not that nothing changed between two observations.
Stamping the version on every decision row closes that gap; until then, run `doberman doctor` (or the
listing) after any manual edit. The catalogue is observational: it never alters a verdict, and a
catalogue failure never blocks a policy save.
