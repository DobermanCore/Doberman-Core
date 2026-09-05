# Tune to your risk tolerance

Doberman ships with sane defaults, but nothing about how loud it is is fixed. This page covers the
dials: strictness mode, the enforcement dial, the opt-in default role, the subjective preference
weights, friction telemetry, and message tone.

## Strictness modes, `doberman mode`

Set a mode in `.doberman/policies.yaml` or with `doberman mode <mode>`. Every mode change made this
way (the CLI or the setup wizard) is recorded in the append-only policy-change ledger, viewable with
`doberman policy-history`. Lowering strictness (paranoid to strict to balanced to light) is a
**weaken** and requires confirmation plus a possession factor: TOTP if enrolled, otherwise the local
Doberman password. With neither enrolled, the lowering fails closed; confirmation alone never
suffices. Raising stays frictionless and applies immediately:

| Mode | Best for | Bulk-delete threshold | Step-up for unknown destinations | Step-up for behavioral anomalies | Lethal-trifecta exfil |
|---|---|---|---|---|---|
| **Light** | Exploratory / trusted environments | 100 files | No | No | AUTH |
| **Balanced** *(default)* | Everyday coding agents | 25 files | No | Yes | AUTH |
| **Strict** | Production repos, shared codebases | 10 files | Yes | Yes | `BLOCK` |
| **Paranoid** | Highly autonomous or security-critical agents | 3 files | Yes | Yes | `BLOCK` |

> Hard blocks (secret exfiltration, destructive commands, role-boundary violations, smuggled-token-channel
> exfiltration) are identical in every mode. The mode dial only changes where step-up authentication
> is required for ambiguous or high-risk actions.

A few mode-dependent behaviors worth knowing:

- **CI/CD pipeline configuration** (GitHub Actions, GitLab CI, Jenkins, CircleCI, Azure Pipelines)
  steps up to authentication in every mode: that config builds, tests, signs, and deploys the repo,
  so an agent rewrite is always a human-in-the-loop moment.
- **Default-registry package fetches** get a Light/Balanced relaxation: a recognized package-manager
  fetch with no explicit URL (`pip install requests`, `npm install`, `poetry install`, `go mod
  download`, and similar) passes without a prompt, because its route is the manager's default
  registry, a stronger signal than the unknown hosts those two modes already allow. Anything that
  could redirect the route, an explicit URL, `--index-url`/`--registry`, a proxy or registry
  environment variable, a chained command, or the publish/upload direction, still steps up in every
  mode. `git pull`/`git fetch` also still step up, since their route depends on the configured
  remote. Strict/Paranoid keep the prompt for every package fetch.
- **Unknown network destinations** step up to authentication only in Strict/Paranoid; Light and
  Balanced treat a plain unknown host as allowed (a secret leaving to any host is still a hard block
  in every mode, and sharper destination smells, embedded credentials, raw IPs, unresolvable hosts,
  still step up everywhere).
- **Checksum-valid personal or financial data** (a payment card number, an IBAN, a dashed US SSN)
  bound for an external destination steps up to authentication in every mode, but only when the data
  co-occurs with an outbound destination, not merely written locally. Only the class label ("payment
  card number") ever reaches a log, never the value.
- **The lethal trifecta** (sensitive data, untrusted-content provenance, and an external destination
  together) steps up to authentication in Light/Balanced and is a hard `BLOCK` in Strict/Paranoid, at
  both decision layers, so a step-up on some other signal can never mask it back down.
- **A local hard smuggled-token channel** is a hard `BLOCK` in Strict/Paranoid and stays AUTH in
  Light/Balanced.

## Enforce, monitor, or off, `doberman enforcement`

Orthogonal to strictness mode is the enforcement dial (`enforce` *(default)* / `monitor` / `off`),
which decides whether Doberman *acts* on a verdict or only observes:

- **`enforce`**: the normal behavior, AUTH prompts and BLOCK denies.
- **`monitor`**: the discretionary layer (behavioral anomalies, soft step-ups) is evaluated and
  recorded (`doberman log` / `doberman tui` show what would have happened) but never blocks or
  prompts. Use it to try Doberman on a repo without friction, or to tune before turning it on.
- **`off`**: the discretionary layer isn't evaluated at all.

Set it with `doberman enforcement <enforce|monitor|off>`; no argument prints the current state.
Turning the dial down is gated the same way as lowering mode: confirmation plus the strongest
enrolled possession factor, recorded in the ledger; with neither factor enrolled the change fails
closed. Turning it back up re-arms automatically, no gate.

The objective floor stays live in every state. Secret exfiltration, destructive commands, protected-path
writes, role/policy blocks, and the lethal trifecta always block regardless of the dial; `monitor`/`off`
only softens the discretionary verdicts. The on-disk value is ledger-verified on every call, so a
hand-edited `enforcement: off` in `policies.yaml` with no matching approved change is caught and
clamped back to `enforce`.

## The built-in default role, `doberman role enable-default`

The role boundary is normally dormant until you hand-write `.doberman/role.yaml`; with no active role
the role rule abstains. `doberman role enable-default` opts a repo into a packaged, generic
least-privilege role for a coding assistant instead, no YAML required: ordinary source, config, docs,
and test files anywhere in the repo classify as in-scope, while CI/CD config, `infra/**`,
`migrations/**`, and any unrecognized file type step up to authentication. Paths outside the repo
root are always a hard block, for every role. An explicit `.doberman/role.yaml` always takes
precedence over the opt-in default. Turning the opt-in off (`doberman role disable-default`) is a
weaken, gated behind the same possession-factor confirmation as lowering mode or enforcement.

## Subjective preference weights, `doberman prefs`

The adaptive layer's four "care" weights, `confidentiality`, `reversibility`,
`interruption_tolerance`, and `blast_radius`, each in `[0, 1]`, tune how readily discretionary
behavioral signals step up. The objective hard-block floor never moves. Show the active vector with
`doberman prefs`, set one weight with `doberman prefs <dimension> <value>`. The same lowering rule as
mode applies: lowering a weight requires TOTP if enrolled, otherwise the local Doberman password,
with neither it fails closed. Raising a weight is a strengthen and always applies immediately. Every
attempt, approved or denied, is recorded in the append-only ledger.

## Friction telemetry and gated tuning, `doberman tune`

Every AUTH prompt is already in the redacted decision log; `doberman tune` turns it into a friction
report: interventions per session, top AUTH reasons, approval rates by reason and by target class,
and a weekly trend. Where an `(action_type, target_path_class)` pair has been approved every single
time, at least `--min-occurrences` times (default 5), and every one of those AUTHs was a
`role_out_of_scope` prompt (never a secret/exfiltration/destructive/control-plane code, that
allowlist is fixed), it proposes a standing elevation: a narrow, time-limited, revocable PASS for
that exact class. `doberman tune` never applies anything by itself, running it only reports.
Accepting one with `doberman tune --accept <id>` routes through the same possession-factor-gated
weaken chokepoint as any other policy loosening, and the resulting grant is revocable early with
`doberman revoke <elevation-id>`.

## Approval memory (5 minutes)

After a human completes a real `local_auth` or `two_factor` proof, Doberman remembers only a keyed
HMAC fingerprint of that exact action for 300 seconds. An identical repeat still prompts; it uses
`soft_confirm` and says how many minutes ago the exact action was approved. A soft-confirm approval
never extends or chains the window. The decision, risk, and reason codes do not change, and the
decision log records `soft_confirm+memory` distinctly.

Identity includes action type, tool name, unredacted command or structured arguments, canonical
target paths, and repo root. The raw values are HMAC input only and are never retained. Host hooks
also require matching session ids when both sides have one; the raw MCP proxy has no session id and
uses repo scope, as do entries where either side lacks a session id. Missing fingerprint keys,
storage errors, missing repo roots, and tainted sessions all fall back to the full tier.

Memory never reduces authentication for file deletion, critical risk, role-boundary violations,
encoded exfiltration, opaque commands, protected paths, destructive or history-rewriting commands,
bulk operations, irreversible high-blast actions, or correlated destructive flows. Role elevation
keeps its own narrow, time-limited, single-use grant and never participates.

Use `doberman approvals status`, `doberman approvals clear`, or
`doberman approvals ttl <seconds>`. The allowed TTL is 0–900 seconds; `0` disables all reads and
writes. Raising the TTL, including enabling from 0, is a weakening and requires the existing
possession-factor gate. Lowering, disabling, and clearing are strengthenings and are ungated.

## Plain or technical wording, `doberman message-tone`

The authorization prompt speaks plain English by default, for example *"Your agent wants to run a
command: `git push --force main`. The command looked destructive. Approve this exact action?"*, so
you can read a catch and decide in seconds without parsing reason codes. Prefer the detailed
engineering view? `doberman message-tone technical` switches to the terse `[RISK: …] role: … reason:
…` block, and `doberman message-tone human` switches back. It changes wording only: cosmetic, not
possession-factor gated, and it never touches the decision, the reason codes, or what lands in the
decision log.
The command line shown is rendered from the raw arguments with credential-shaped tokens masked and
cut at 300 characters; the decision log keeps only its redacted copy.

## Recovery actions

Taint clearing, tool-pin approval, learned-memory reset and pruning, and fully removing a project all
live in the [recovery guide](RECOVERY.md).

Every gated change above is also recorded as a **policy version** (`pv1:` + a content hash) in
`.doberman/policies.db`; `doberman policy-versions` lists them and `--verify` confirms the policy on
disk is the last recorded one. See [POLICY_VERSIONS.md](POLICY_VERSIONS.md).
