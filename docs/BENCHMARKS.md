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
