- **The subjective-layer AUC diagnostic now reports a held-out-benign FPR next to the AUC, and ships a
  seeded synthetic developer-session corpus** (`--suite devsession`) large enough to clear
  `HST_WARMUP`/`K_OBSERVATIONS` so the full ensemble engages instead of running cold-start-only on
  AgentDojo's smaller warm set. FPR is computed at a fixed, documented quantile (`fpr_quantile=0.95`)
  of the warm-set score distribution — never AgentDojo, never tuned — and every report now also
  carries the `k_observations`/`hst_warmup`/`fpr_quantile` constants it was measured against. See
  [`docs/BENCHMARKS.md`](../docs/BENCHMARKS.md#subjective-layer-baseline-separation-diagnostic).
