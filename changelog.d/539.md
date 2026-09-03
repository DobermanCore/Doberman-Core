- Added an experimental, offline-only BYO-model judge (`doberman.judge.HaikuJudgeAdjudicator`,
  the `[judge]` extra) that implements the shadow-adjudicator Protocol but is not wired into
  any live decision. `tests/benchmarks/suites/judge_agreement.py` replays it over the labeled
  detection corpus to measure whether it adds any lift over the deterministic rules on the
  class-only `redacted_features()` envelope - see `docs/BENCHMARKS.md`.
