# Recover

This page covers Doberman's recovery and cleanup commands: clearing sticky taint, re-approving a
changed MCP tool, resetting or pruning learned memory, and removing Doberman from a project. Every
gated command here uses the same possession-factor rule: TOTP if you've enrolled 2FA, otherwise the
local Doberman password set with `doberman password set`. With neither enrolled, the action fails
closed and nothing changes; there is no confirm-only path.

## Recovering from sticky taint, `doberman taint clear`

Reading a secret taints a session for the rest of it, by design: a timed reset would be a
bypass an attacker waits out. In Strict/Paranoid that means a single legitimate secret read can raise
every later egress in that repo to AUTH or BLOCK, with no in-band way to reset it. `doberman taint
clear` is the explicit, human-only escape hatch: it requires an enrolled possession factor and, once
verified, wipes both taint stores for the current repo, the accumulated-taint ledger and the
read-vs-send fingerprint match. There is no `--scope`/`--session` narrowing, and a denied or failed
gate leaves every row untouched. Because `taint` is a control-plane-blocked subcommand, a mediated
agent can never shell out to run this itself. It only runs from your own terminal.

## MCP tool-schema rug-pull defense, `doberman tools approve`

On every proxied `tools/list`, Doberman pins a keyed-HMAC fingerprint of each tool's name,
description, and input schema, then checks that pin on the live `tools/call` path. A changed contract
raises the call to AUTH in Light/Balanced or BLOCK in Strict/Paranoid; raw schemas are never stored
or logged. This is honestly trust on first use: it detects a change after first contact, not a
malicious schema presented on that first contact. After reviewing the server change out-of-band, run
`doberman tools approve <tool_name>` from your terminal (possession factor required); mediated agents
are blocked from invoking that weakening themselves. Approving a changed pin also resets the tool's
learned familiarity across every entity in the repo, in the same transaction as the approval: a
changed tool is a new tool, so the behavioral baseline scores it as brand-new instead of inheriting
pre-change trust. Expect a short tail of extra step-up asks while it relearns.

## Governing learned memory, `doberman memory reset` / `doberman memory prune`

The subjective baseline and revealed-preference tables, what Doberman has learned about this
deployment's normal behavior, are persistent, per-entity memory. Persistent agent memory is itself a
poisoning vector: if it were ever trained on a compromised session, nothing short of deleting it
clears the taint. `doberman memory reset` is that reliable-deletion escape hatch, gated the same way
as `doberman taint clear`, and scoped to one entity (`--entity <id>`) or the whole repo. Deleting
learned memory is raise-safe by construction: a colder baseline scores everything as more novel until
it relearns, never less protected. A successful reset is recorded in the append-only ledger
(`doberman policy-history`); a denied attempt leaves no ledger trace.

`doberman memory prune --older-than-days N` is the retention-limit sibling: an ungated maintenance op
(not a security decision) that drops entities whose newest activity is older than `N` days, never
touches the decision log, and never guesses at an entity's age from missing data. Output is counts
only, entity ids are never printed. Both commands are control-plane-blocked, so a mediated agent can
never shell out to run them itself.

## Fully removing a project, `doberman uninstall`

> **Note**
> Run `doberman uninstall-hooks` *before* `pip uninstall doberman-core`, not after. Uninstalling the
> package first leaves the hook entries in `settings.json` pointing at a binary that's gone, and every
> tool call then fails with `doberman: command not found`. Already hit this? `pip install
> doberman-core` again restores the binary; the existing hook entries are still correct and start
> working immediately, no repair needed.

`doberman uninstall-hooks` only strips the hook entries: it never touches `.doberman/`, and needs no
authentication, which means nothing stops a protected agent that reaches a shell from disabling its
own security layer if it wanted to. `doberman uninstall` closes that gap: it removes both the
project- and local-scope hooks and the project's `.doberman/` control plane (policy and decision
database) in one step, gated behind an enrolled possession factor, with no confirm-only fallback and
a hard fail-closed refusal if neither factor is enrolled. Because it's destructive and irreversible,
it also asks you to type the project directory name back before proceeding (`--yes` skips that
prompt; it never skips the factor check). It is deliberately project-scoped only: `--global` hooks
and your device-wide password, 2FA, fingerprint key, and `~/.doberman/metrics.db` are shared across
every project Doberman protects on the machine and are never touched, even on success. `uninstall` is
itself control-plane-blocked, so a mediated agent can never shell out to run it. Same protection as
`uninstall-hooks`.
