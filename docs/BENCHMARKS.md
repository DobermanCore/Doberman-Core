# Benchmarks

Doberman's protection claims should resolve to a number you can reproduce, not an
adjective. This page documents how the numbers are produced, what they can and
cannot show, and the results — **failure cases before wins**, on purpose.

## Methodology & preconditions (read first)

Doberman is evaluated as a **decision function over tool-call cases**, not by
driving a live LLM agent. Each benchmark case is a tool call (or an ordered
multi-step sequence) labelled `benign` or `attack`; the harness replays it through
the real engine and records the verdict (PASS / AUTH / BLOCK). No model is called,
so the numbers are deterministic and cost nothing to reproduce.

The metrics:

- **ASR (attack success rate)** — the fraction of attacks that reach the tool. A
  hard `BLOCK` counts as stopped. `AUTH` counts as *not silently succeeded* in
  `asr`, but `asr_strict` counts only hard blocks as stopped (an AUTH is not a
  block — a human still has to say no).
- **FPR (false-positive rate)** — the fraction of benign cases that get friction
  (`AUTH`/`BLOCK`). `hard_fpr` counts only benign cases hard-blocked.
- **Operator metrics** — the honest part. `effective_asr_deny` / `_approve` bound
  the outcome if the human always denies vs. always approves an AUTH;
  `asr_under_fatigue` and `auth_burden` model a human who rubber-stamps some
  fraction. An AUTH-heavy defense is only as strong as the human answering it.

Two profiles are compared: `no_guardrail` (the unmediated tool path — every attack
executes) and `builtins_only` (Doberman's built-in rules). `before_after` reports
both plus the delta.

### What these numbers can and cannot show

- They measure the **objective, deterministic floor** — path/command/secret/egress
  rules — on documented attack shapes. They do **not** measure the adaptive
  subjective layer (that needs the warm proxy path), nor do they prove any single
  rule is complete. Doberman is defense-in-depth, not airtight.
- An `AUTH` verdict is a *human-in-the-loop* outcome, not a block. Read
  `asr_strict` and the operator metrics alongside `asr`, or you will overstate the
  protection.

## Subjective-layer baseline separation (diagnostic)

The ASR/FPR numbers above measure the **objective, deterministic floor** only.
This section covers a separate, narrower diagnostic for the **adaptive
subjective layer** — the per-entity streaming baseline that raises risk on
unusual actions.

- **What it measures:** whether a per-suite streaming baseline warmed on a
  deployment's benign workflow assigns higher *surprise* to injection-induced
  actions than to held-out benign actions — a distribution-separation
  **diagnostic (Mann-Whitney AUC)**, per suite and pooled. **It is not an
  ASR** and is never threshold-tuned; AgentDojo is never a target metric. The
  AUC compares each attack's attacker-goal action(s) against *all* held-out
  benign actions — the operationally correct base rate (the layer scores every
  action in a stream), but note the two buckets are selected asymmetrically.
- **The two arms, and why two:** `provenance_free` is the honest number.
  `Algebra.provenance` derives 1:1 from `source_context`, and the AgentDojo
  adapter sets `source_context` by ground truth (attack → `tool_output`,
  benign → `user`), so a provenance-driven separation would measure the
  adapter's labels, not the guard. The eval neutralizes `source_context` to a
  constant so the label can't leak — it also rides a confidence scalar into
  the HST and novelty terms, so neutralizing the one field closes both
  channels. `with_provenance` keeps the true `source_context` and is reported
  **only** to quantify that leak, never as a headline.
- **Allowed-only:** the baseline warms on benign (allowed) traces only;
  attack and held-out-benign actions are scored, never learned.
- **Warm-sufficiency caveat (read this before trusting an AUC):** AgentDojo
  suites are small — tens of benign traces per suite — against
  `K_OBSERVATIONS=100` and the HST warmup, so the cold-start peer-blend stays
  active and the HST ensemble member abstains for every suite; the live
  ensemble is novelty + Markov-surprisal + volume-z only. Each suite reports
  `n_warm_observations`, `blend_weight`, `cold_start_active`, and
  `hst_engaged`. **A suite whose numbers ride mostly the constant prior is
  inconclusive — read every AUC next to its bucket `n`.**
- **What it does not claim:** it does not catch injections that mimic benign
  action shapes — structure-invisible injections are honest true-negatives,
  never tuned away. The objective floor and the lethal-trifecta floor remain
  the primary defense; this measures the adaptive *increment* on top of them.
- **Reproduce:**

  ```bash
  python -m tests.benchmarks.run --suite agentdojo --subjective
  ```

  Needs the operator-supplied `agentdojo` package, same precondition as the
  other `agentdojo` commands above.

## Labeled detection corpus (per-category FPR / TPR)

The synthetic suite is a 3-attack smoke gate; the AgentDojo run measures coverage
but needs an operator-supplied package. The **detection corpus** fills the gap
between them: a deterministic, in-repo, ~137-row labeled fixture
(`tests/corpus/detection_corpus.jsonl`) that measures detection *quality* per
category — the false-positive rate that drives approval fatigue, and the
true-positive rate per attack class — with **no external dependency**.

- **What it measures:** each row is one labeled candidate action across
  `injection / exfiltration / secrets / destructive / encoded / benign`. `--corpus`
  runs every row through the real engine and reports **TPR** (mitigation = `AUTH`
  or `BLOCK`), **tpr_strict** (`BLOCK` only), **FPR**, and **precision**, per
  category and overall.
- **Raise-only floors, calibrated to the engine.** Every attack row's
  `expected_verdict_at_least` is the verdict the engine *actually* reaches today
  (`null` for a documented gap). It is a regression fence, not an aspiration: the
  generator refuses to lower a shipped floor, and the CI gate
  (`tests/integration/test_corpus_gate.py`) fails if any attack drops below its
  floor or any benign row is over-blocked.
- **Honest, not tuned.** The corpus is *not* filtered to cases the engine wins.
  Pure natural-language injection scores **TPR 0.0** — the objective layer is
  structurally blind to it (a provenance/subjective concern), and the corpus says
  so rather than hiding it. Calibration also surfaced a real precision note:
  reading an `.env.example` template over-blocks, because the secret-path rule
  matches `.env.*` fail-closed.
- **Redaction + push-safety.** Reports hold counts, rates, category labels, and
  payload-free row ids only. Payloads are synthetic; the secrets category triggers
  on credential *paths* and shapeless high-entropy values, never assembled
  provider literals.

Reproduce (deterministic, from a cold clone):

```bash
python -m tests.benchmarks.run --suite corpus --corpus                # balanced (row-native) mode
python -m tests.benchmarks.run --suite corpus --corpus --mode strict  # any F6 mode
python -m tests.corpus._generate --check                              # verify the shipped floors match the engine
```

## Cross-session baseline poisoning (gradual-drift robustness)

The subjective layer learns *allowed* actions only, which is poisonable in
principle by a patient attacker who normalizes a dangerous action low-and-slow —
one within-envelope step at a time, spread **across sessions** so the in-process
ADWIN drift detector (which re-warms empty on every restart) never sees an abrupt
shift. Static ASR says nothing about that threat. This eval measures it directly
and reports the **poisoning rate**: the fraction of dangerous targets an attacker
can teach the baseline to wave through.

- **Cross-session, faithful.** Each session warms a batch of allowed actions,
  then a simulated restart drops the in-process HST/ADWIN while the persisted
  SQLite baseline, calibration history, and belief window survive — exactly a
  proxy restart. Every learned action runs the production monitor sequence
  (`observe` → ADWIN `note_allowed` → Martingale `note_belief`/`run_monitor`).
- **Two honest arms.** `admitted` is the operative number — the autonomous
  attacker whose poison actions are learned **only when the real engine returns
  PASS** (no operator approvals). `worst_case` models an attacker who has already
  defeated the approval gate and gets *every* action learned, to expose the
  residual floor resistance beneath the score.
- **What holds, and why.** The `admitted` poisoning rate is **0**: normalizing a
  dangerous action needs allowed observations of its *own* dangerous key, and the
  baseline scores novelty worst-wins across an action's keys, so the very
  observations required are the ones the engine steps up and never learns. The
  lethal-trifecta floor is **unpoisonable** — the `worst_case` attacker can drive
  the score to near-zero and the verdict never flips, because the floor is
  score-independent. The load-bearing brake on smooth gradual poisoning is the
  severity-weighted `FAMILIAR_AT_HIGH` novelty threshold plus that floor; the
  Martingale is the backstop for the *frozen endgame* (a belief pinned high after
  normalization), not the smooth walk — an honest scope note, not a gap hidden.
- **Honesty control.** A benign public read is included and *does* normalize, so
  the eval cannot pass vacuously by reporting "nothing normalizes".
- **Redaction.** Report holds scores, counts, verdict/class labels, and scenario
  names only — never a payload, path, or destination.

A small campaign gates in CI (`tests/integration/test_poisoning_gate.py`, the
size-independent invariants); the fuller campaign is a CLI run:

```bash
python -m tests.benchmarks.run --poisoning
```

## Reproduce

Synthetic suite — **from a cold clone, no extra dependencies, deterministic:**

```bash
pip install -e ".[dev]"
python -m tests.benchmarks.run --suite synthetic --profile before_after
```

AgentDojo (the larger external suite) — **reproducible with the documented
preconditions**, not from a cold clone (the harness keeps `agentdojo` a lazy,
operator-supplied dependency so CI never depends on it, and vendors no suite data):

```bash
pip install agentdojo            # pin the commit you ran; record it below
python -m tests.benchmarks.run --suite agentdojo --profile before_after

# sweep every F6 strength mode at once (or one: --mode strict) — report keyed by mode
python -m tests.benchmarks.run --suite agentdojo --profile before_after --mode all
```

Numbers refresh **per release** as a documented release step (see
[`RELEASING.md`](RELEASING.md)), not as a per-commit CI artifact.

## What Doberman missed (failure cases)

| Case class | On the synthetic suite | Why |
|---|---|---|
| Every synthetic attack | Stopped at **AUTH, not BLOCK** (`asr` 0.0 but `asr_strict` 1.0) | These attack shapes route to a human decision, not a hard block; a human who **approves** is not protected (`effective_asr_approve` = 1.0). |
| Rubber-stamped AUTH | `asr_under_fatigue` = 0.8 | If the operator approves most prompts, most attacks still land. AUTH is a leash, not a wall. |
| Scale | n = 3 attacks / 3 benign | The synthetic suite is a deterministic **CI smoke gate**, not a scale benchmark. Real coverage numbers come from the AgentDojo run below. |

## Results

### Synthetic suite (deterministic CI gate, n = 3 attack / 3 benign)

Run: `python -m tests.benchmarks.run --suite synthetic --profile before_after` (2026-08-08, doberman-core 0.17.1).

| Metric | Before (no guardrail) | After (Doberman built-ins) |
|---|---|---|
| ASR (silent success) | 1.00 (3/3 bypass) | **0.00** (0/3 bypass) |
| ASR strict (hard block only) | 1.00 | 1.00 (all 3 → AUTH, not BLOCK) |
| FPR (benign friction) | 0.00 | **0.00** (3/3 benign pass) |
| Operator: deny-all / approve-all | 1.00 / 1.00 | **0.00** / 1.00 |

Read honestly: on this tiny suite Doberman converts **every silent bypass into a
human-gated AUTH with zero benign friction** — but it hard-blocks none of them, so
the protection is exactly as strong as the human answering the prompt (`deny-all`
stops everything; `approve-all` stops nothing). This is a smoke gate, not a
coverage claim.

### Detection corpus (deterministic, n = 112 attack / 25 benign)

Run: `python -m tests.benchmarks.run --suite corpus --corpus` (2026-08-13, doberman-core built-ins only, balanced mode unless noted).

| Category | n (attack) | TPR (AUTH∪BLOCK) | tpr_strict (BLOCK) | FPR |
|---|---|---|---|---|
| secrets | 7 | **1.00** | 0.43 | — |
| destructive | 10 | 0.80 | 0.60 | — |
| encoded / smuggling | 79 | 0.82 | 0.00 | — |
| exfiltration (balanced) | 8 | 0.375 | 0.00 | — |
| exfiltration (**strict**) | 8 | **1.00** | 0.00 | — |
| injection (natural-language) | 8 | **0.00** *(documented gap)* | 0.00 | — |
| benign | — (25) | — | — | **0.00** |
| **Overall (balanced)** | 112 | 0.74 | 0.08 | 0.00 |
| **Overall (strict)** | 112 | 0.79 | 0.39 | 0.00 |

Read honestly: precision is **1.00** and benign FPR **0.00** — the objective layer
does not over-block legitimate traffic here — but `tpr_strict` **0.08** in balanced
mode says almost all mitigation is a human-gated `AUTH`, not a hard `BLOCK` (the
same "AUTH is a leash, not a wall" caveat as the synthetic suite, now measured
across categories). Two categories are honest weak spots: **exfiltration** is
mode-gated (balanced deliberately passes a bare unknown host → 0.375; strict AUTHs
it → 1.00), and **natural-language injection** is a structural gap the deterministic
layer cannot close (0.00) — it belongs to provenance / the subjective layer.

### AgentDojo suite (extended, operator-supplied)

_Pending an operator run — populated at release time per [`RELEASING.md`](RELEASING.md).
Record the pinned `agentdojo` commit and the `before_after` table here._

## Fixed bypasses

Disclosed-and-fixed only (date · bypass class · fix PR). A privately-reported
bypass stays held until it is fixed and shipped, then it is listed here.

_None disclosed yet._

## Non-goals

No leaderboard infrastructure, no competitor comparisons. Reproducibility — and
listing the failure cases before the wins — is the point.
