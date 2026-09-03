- **A tripwire for reused untrusted values.** A host, URL, or email seen in a `WebFetch`/`WebSearch`
  result now raises a later egress to that exact same value from allowed to authentication-required —
  closing a documented gap where an untrusted page or PR body could name a destination the agent later
  visited with no extra scrutiny. Whole-value matching only (no partial/flow analysis), bounded per
  session on the hook path or per-repo entity scope on the proxy path (5,000 values per scope, 7-day
  TTL). As part of wiring this up, the proxy now correctly records `TAINT_UNTRUSTED_READ` on the first
  `WebFetch`/`WebSearch` in a session (previously a no-op there) — fail-closed, but it also means the
  five-minute exact-repeat approval memory stops applying for that entity scope once anything untrusted
  has been read, not just for the echoed value.
