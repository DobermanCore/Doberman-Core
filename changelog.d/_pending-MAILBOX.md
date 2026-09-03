- **A mailbox destination no longer triggers a false "embeds credentials" prompt on every mail
  send.** `_parse_host` now recognizes a bare `local@domain` recipient (or a `mailto:` URL) — what a
  `send_email`-shaped tool passes verbatim as its destination — instead of reading the mailbox local
  part as a URL username. The recipient's domain never auto-trusts via `TRUSTED_HOSTS` either (those
  are API/registry hosts; mail to someone `@` a trusted domain is not trusted egress), so it falls
  through to the same mode-aware unknown-destination logic as any other host: Light/Balanced pass a
  plain unknown recipient, Strict/Paranoid still require authentication. Raise-only: the taint floor,
  echo tripwire, and secrets rule are unchanged — this only removes an accidental AUTH that fired on
  every mailbox destination, in every mode.
