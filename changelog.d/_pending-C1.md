- **A tripwire for reused untrusted values.** A host, URL, or email seen in a `WebFetch`/`WebSearch`
  result now raises a later egress to that exact same value from allowed to authentication-required —
  closing a documented gap where an untrusted page or PR body could name a destination the agent later
  visited with no extra scrutiny. Whole-value matching only (no partial/flow analysis), bounded per
  session (5,000 values, 7-day TTL).
