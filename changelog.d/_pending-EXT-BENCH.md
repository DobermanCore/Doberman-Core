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
