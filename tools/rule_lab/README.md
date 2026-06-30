# rule_lab — raise-only experiment loop over the benchmark harness

An autonomous-research pattern (propose → run fixed evaluator → score → memory),
scoped to the one place it fits Doberman: **tuning rules/detectors against the
benchmark harness**. It is deliberately *not* a model-training pipeline.

Everything here is orchestration only — it imports the public benchmark CLI and
**never touches `src/doberman`**. Candidates are shipped as external plugins, so
the safety-critical core stays out of the autonomous loop.

## The loop

```
builtins_only report ─▶ proposer (proposer.md) ─▶ candidate spec
                                                      │
                                  candidate-worker (own venv/worktree,
                                  candidate is the only installed plugin)
                                      1. pip install -e the candidate plugin
                                      2. python tools/rule_lab/worker.py
                                         → runs `tests.benchmarks.run --profile both`
                                      3. gate (scorer.py)
                                                      │
            ┌── REJECT ── revise hypothesis / record dead end in memory
            └── ACCEPT ── held-out validation ─▶ human review checkpoint
                                                  (Slice Loop; 2FA for any loosening)
```

## Files

| File | Role |
|------|------|
| `scorer.py` | Pure **raise-only gate**. No input approves a loosening. Unit-tested. |
| `worker.py` | Thin driver: runs the unmodified benchmark CLI, applies the gate, validates held-out. Never merges. |
| `proposer.md` | System prompt + JSON spec the proposer agent emits. |
| `tests/test_scorer.py` | The safety contract for the gate. |
| `tests/test_worker.py` | Input safeguards for worker CLI and suite splitting. |

## Run it

```bash
# unit-test the gate
pytest tools/rule_lab/tests

# evaluate the currently-installed candidate plugin (run in an isolated env where
# the candidate is the ONLY installed plugin, so --profile both isolates it)
python tools/rule_lab/worker.py --tune agentdojo --holdout synthetic
```

`--eps-fpr` is deliberately bounded to `0.0 <= eps_fpr <= 0.05`; larger
tolerance values fail before scoring so the loop cannot silently approve a
high-friction candidate. Tune and holdout suites must also be disjoint. Reusing
the same suite on both sides fails fast because it would turn held-out
validation into train-on-test.

Exit code is `0` only on `ACCEPT -> human review`, so CI / the Slice Loop can
branch on it.

## Invariants (why this is safe to automate)

- **Raise-only**: `scorer.accept` rejects any candidate that raises ASR or
  hard-blocks a benign action. The agent physically cannot route a weakening to a
  merge.
- **Core untouched**: candidates are entry-point plugins; failed ones are
  `pip uninstall`'d and leave no trace in the engine.
- **Redaction holds**: only counts/rates flow back; attack payloads never enter
  the agent context.
- **Overfit guard**: tune on one suite (e.g. `agentdojo`), validate on a held-out
  suite (e.g. `synthetic`) via the non-regression predicate. Improvement must
  survive the held-out suite. A candidate tuned and measured on the *same* suite
  is train-on-test — the held-out check, not the tune ΔASR, is the real signal.
  The worker rejects overlapping tune/holdout lists before spending benchmark
  budget.
- **Human in the loop**: the worker stops at `ACCEPT -> human review`. Merging —
  and any 2FA-gated loosening — is never autonomous.
