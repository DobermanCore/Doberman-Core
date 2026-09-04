# Changelog fragments

Add one file per pull request instead of editing `CHANGELOG.md` by hand.

## File name

`<PR-number>.<type>.md`, for example `476.added.md`. `<type>` is one of:

- **security** — closed a bypass, a fail-open, a leak, or a way around a gate.
- **added** — a new command, flag, rule, adapter, extension point, or document.
- **changed** — existing behavior differs now. Prefix `**Breaking:**` when the reader must do something.
- **fixed** — a defect corrected, with the user-visible symptom named.
- **docs** — docs only. Fold small doc bullets into one line.
- **removed** — something gone. Deprecations go under `changed` with the word *deprecated*.

Skip the fragment entirely for changes no user can see: refactors, test-only work, CI plumbing, typos.

## Bullet format

```
- <What changed, as the reader experiences it>; <one consequence or limit if it matters> (#<PR>[, thanks @handle])
```

One sentence, at most 25 words excluding the `(#PR...)` citation and 220 characters including it, and it
must cite its own `(#PR)`; thank an outside contributor in the same parenthesis (`#498, thanks @slegarraga`).

Example, trimmed from a 92-word draft: `doberman update` checks PyPI once and prints the upgrade command;
`doberman status` nudges when you are behind. Off under `DO_NOT_TRACK`, `CI`, or `DOBERMAN_UPDATE_CHECK=off` (#508)

`python scripts/compile_changelog.py --check` is what CI runs; it rejects a bad name or bullet before merge.
