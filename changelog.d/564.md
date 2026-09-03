- **A mailbox destination no longer triggers a false "embeds credentials" prompt on every mail
  send.** `_parse_host` now recognizes a bare `local@domain` recipient (or a `mailto:` URL) — what a
  `send_email`-shaped tool passes verbatim as its destination — instead of reading the mailbox local
  part as a URL username. Plainly: **in Light/Balanced, a send to an unrecognized recipient now goes
  through with no authentication prompt at all** (the same relaxation already applied to any other
  unknown host). The recipient's domain never auto-trusts via `TRUSTED_HOSTS` either (those are
  API/registry hosts; mail to someone `@` a trusted domain is not trusted egress), so a mailbox
  destination always falls through to the ordinary mode-aware unknown-destination logic — **in
  Strict/Paranoid, an unrecognized recipient still requires authentication**, exactly as any other
  unknown host does. A scheme-less `user:pw@host` authority (no `://`) is still read as credential
  smuggling, not mail, in every mode. Raise-only: **the secrets rule, the taint floor, and the echo
  tripwire are all unaffected by this change and still raise on mail egress when warranted** — this
  only removes an accidental AUTH that fired on every mailbox destination for the wrong reason
  ("embeds credentials"), in every mode.
