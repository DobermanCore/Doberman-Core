- Added an opt-in `--replay-session` benchmark harness mode that replays each case inside a fresh,
  isolated per-case session and applies the real post-decide floors (the taint floor, the C1 untrusted-
  value echo tripwire, and the session correlator) in the exact order the proxy/host-hook spine use — the
  default stateless per-action path never exercises any of them. Every report is labeled
  `"session_replay": true/false` so the two are never confused. See `docs/BENCHMARKS.md`'s new "Session
  replay" section: the echo tripwire is expected to raise LLMail-Inject's real attack shape (a reused
  attacker address); a documented remaining gap is any consummating action with no `external_destination`
  (e.g. some MSB attack types), which none of the three floors reach.
