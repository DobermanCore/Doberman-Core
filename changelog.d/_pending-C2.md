- Delete-class commands (`rm`, `del`, `erase`, `rd`, `rmdir`, `Remove-Item`) reaching an AUTH challenge
  now show a bounded, offline file/directory count for their operands, recomputed just before
  forwarding — if the filesystem changed since approval, the action re-blocks (`effect_set_diverged`)
  instead of releasing on a stale preview. Display and audit only: the count never changes a verdict.
  Proxy-only for now (see README's Known limitations).
