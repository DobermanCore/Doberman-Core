- Added three operator-supplied external suite adapters to the benchmark harness — RedCode-Exec (risky
  code execution), MSB (MCP tool-response poisoning), and LLMail-Inject (email prompt injection) —
  following the same `SuiteAdapter` contract as AgentDojo (`DOBERMAN_BENCH_REDCODE_DIR`,
  `DOBERMAN_BENCH_MSB_DIR`, `DOBERMAN_BENCH_LLMAIL_DIR`; no data vendored). See `docs/BENCHMARKS.md`'s
  new "External suites" section for the measured numbers (real runs against each operator-supplied
  checkout) and each suite's documented scope/gaps.
- RedCode-Exec's synthetic benign control set now runs through the same target/destination extraction as
  the attack side, so its FPR measures the same rule surface the attack side's ASR does (previously
  narrower); LLMail-Inject's benign set gained a second, synthetic benign-SEND case per email so FPR is
  also measured on an ordinary legitimate send, not only a read.
- Added an opt-in `--replay-session` benchmark harness mode that replays each case inside a fresh,
  isolated per-case session and applies the real post-decide floors (the taint floor, the C1 untrusted-
  value echo tripwire, and the session correlator) in the exact order the proxy/host-hook spine use — the
  default stateless per-action path never exercises any of them. Every report is labeled
  `"session_replay": true/false` so the two are never confused. See `docs/BENCHMARKS.md`'s new "Session
  replay" section: the echo tripwire is expected to raise LLMail-Inject's real attack shape (a reused
  attacker address); a documented remaining gap is any consummating action with no `external_destination`
  (e.g. some MSB attack types), which none of the three floors reach.
