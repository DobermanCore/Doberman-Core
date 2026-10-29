# Policy versions

Every decision Doberman makes is made under some policy: the strictness mode, the enforcement dial,
the preference weights, the egress (outbound data) thresholds, the active role's path globs, and the
rule set of the installed release. A **policy version** names that exact combination so a log entry
can later be matched to the policy that produced it.

## What a version is

`pv1:` followed by the SHA-256 (hex) of the canonical JSON of a snapshot with these keys:

| Key | Content | Why it is hashed |
| --- | --- | --- |
| `schema` | `1` | Lets a verifier reject a snapshot layout it does not know. |
| `engine` | `doberman.__version__` | The rule set, hard-block floor, mode thresholds, and built-in roles ship with the package. The same YAML can decide differently across releases. |
| `enforcement_effective` | `enforce` / `monitor` / `off` | The state actually acted on (ledger-verified, timer applied), not just the field on disk. |
| `doc` | `.doberman/policies.yaml` as saved, minus `message_tone` and every item `description` | Everything else in the file can change a verdict. Those two cannot, so a wording change never mints a version. |
| `role` | the active role's `name`, `allowed`, `suspicious`, `blocked` globs, or `null` | Role boundaries decide out-of-scope step-ups. |
| `resolved_policy` (optional) | the captured repo-file/plugin constraints: blocked and sensitive globs, plus source contributors | These constraints also affect the verdict. Omitted when no source contributes constraints, preserving existing version IDs. |

Canonical form: `json.dumps(snapshot, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`,
UTF-8 encoded. The published JSON Schema is [`schemas/policy-snapshot.v1.json`](schemas/policy-snapshot.v1.json).

Evaluation and stamping share the same captured resolved policy; logging never resolves sources
again. After AUTH approval, the proxy refreshes the policy and runs its BLOCK check under full
enforcement, even if the enforcement dial has changed. A BLOCK from that check carries the refreshed
snapshot with `enforcement_effective: enforce`; a row recording the original AUTH keeps its original
snapshot and resolved enforcement state.

Turn-gate decisions also retain their captured snapshot across approvals and repeat challenges.
The turn gate always applies full enforcement and stamps `enforcement_effective: enforce`.

`doberman log --jsonl` includes `policy_version`, the full ID of the exact captured snapshot once
it has committed to the catalogue. A missing snapshot, failed catalogue transaction, or demonstrated
mismatch between captured and active evaluator velocity thresholds leaves this field `null`.
Historical decisions also retain `null`; logging never reconstructs a policy from later files.
These stamping failures do not prevent decision persistence. This does not change how evaluator
thresholds are loaded or reset their history.

Plain SHA-256 rather than Doberman's keyed HMAC (a hash tied to a secret key) on purpose: anyone
holding the snapshot (an auditor, a central verifier) can recompute the id without the local key.
Nothing in a snapshot is secret. It is configuration that already lives in `.doberman/`.

Recompute one by hand from `doberman policy-versions --show <id>` output:

```bash
doberman policy-versions --show <id> | python -c "import json,sys,hashlib; s=json.load(sys.stdin)['snapshot']; print('pv1:'+hashlib.sha256(json.dumps(s,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest())"
```

## Where versions are recorded

`.doberman/policies.db` (created `0600`, never committed, never pruned by `decision-log-prune`) holds:

- `policy_versions`: each snapshot once, with the exact bytes that were hashed and when it was first seen.
- `policy_observations`: an append-only row every time the version in force was seen to change:
  `origin` is `change` (written by every gated policy save, with `ledger_ts` pointing at the
  `policy_changes` row that authorised it), `decision` (decision logging records its captured
  evaluation snapshot), or `observed` (`doberman doctor` and
  `doberman policy-versions` record what they find, which is how a hand edit of `role.yaml` or
  `policies.yaml` enters the timeline).

The version in force at a time `T` is the latest observation at or before `T`.

## Matching

- version → content: `doberman policy-versions --show <id>` (full id or ≥ 8 hex characters).
- time → version: the observation timeline (`doberman policy-versions --json` lists each version with
  `in_force_since`).
- ledger ↔ version: an observation's `ledger_ts` equals the `ts` of the `policy-history` row that
  produced it. `doberman policy-history --json` exposes that link as `to_version`, or `null` when
  no linked catalogue observation exists.

## Checking

`doberman policy-versions --verify` recomputes every stored digest and compares the policy on disk with
the last recorded version. It reports `ok`, `mismatch` (stored content no longer hashes to its id: the
store was altered), `drift` (the policy on disk is not the last recorded version: a change nobody has
observed yet, or no catalogue at all), or `unledgered` (at least one version was first introduced
without a ledger-linked policy change). Its JSON report includes an `unledgered` list of version IDs.
It exits `1` on anything but `ok`; mismatches take precedence over drift, which takes precedence over
unledgered provenance. Verification records no observations, writes no policy pins, and does not
populate or consume the runtime policy cache.

## What this does not prove

An observation records when a change was *seen*, not that nothing changed between two observations.
A stamped decision identifies the snapshot captured for its evaluation; a `null` stamp means that
snapshot is unavailable, not that a later observation proves which policy was used. The catalogue
is observational: it never alters a verdict, and a catalogue failure never blocks a policy save
or prevents a decision row from being recorded.
