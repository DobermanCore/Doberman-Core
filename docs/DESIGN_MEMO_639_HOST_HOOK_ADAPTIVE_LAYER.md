# Design memo: the adaptive layer on the host-hook path (#639)

> **Status: DRAFT, awaiting maintainer sign-off. No code is written against it.** Issue #639's done-condition is
> this write-up plus a maintainer's sign-off before any implementation starts. Sections marked **Maintainer
> call** are decisions this memo recommends but does not make.

## Summary

The issue asks how to run the adaptive layer (`doberman.subjective`: per-entity baseline, surprise score,
drift detection) behind a host hook through a warm background process. Measuring it changed the answer.

1. **Almost all of the cold cost is one library, and the hook cannot use what that library does.** In a fresh
   hook process the adaptive layer's import costs 0.65 to 0.95 s on the test machine. Nearly all of it is
   `river` (which pulls in `numpy` and `scipy`). The only `river` parts the scorer uses are Half-Space Trees and
   ADWIN. Both live in process memory and start empty in every new process, and the Half-Space Trees score only
   after 250 observations *in the same process*. A per-call hook process therefore never gets a score from
   them. With `river` kept out of the import, the rest of the adaptive layer costs about 2 ms to import and
   6 ms to score.
2. **Recommendation: two stages.**
   - **Stage 1 (this issue):** run the adaptive layer *inside* the hook process, with `river` imported
     lazily, scoring from the SQLite baseline the layer already keeps. There is no background process, so
     there is no "process is down" case, and raise-only holds because nothing crosses a process boundary.
   - **Stage 2 (only if a bench shows lift):** a warm per-repo sidecar that keeps the memory-only signals
     (Half-Space Trees, ADWIN drift, turn context) alive between calls. Its answer can only add risk on top of
     stage 1. If it is down, stage 1 still decides.
3. **The four open questions** are answered in the sections below: [who owns the state](#q1-who-owns-the-state),
   [how the hook talks to the process](#q2-how-the-hook-talks-to-the-process), [what happens when it is
   down](#q3-what-happens-when-the-process-is-down), and [whether raise-only holds](#q4-does-raise-only-hold-across-the-boundary).

## What exists today

- `src/doberman/hosthooks/spine.py:113` calls `decide(action, ObjectiveGuardrail(), PASS_STUB, ctx)`. The
  subjective slot is a stub that always returns `PASS`. `hosthooks/claude_code.py:587` (the PostToolUse history
  row) does the same. These are the only two call sites.
- The MCP proxy (`proxy/executor.py`) runs the real layer. Before each decision it computes the per-entity
  surprise from the baseline (`surprise_blended`), checks the step-up budget, and passes both to
  `SubjectiveGuardrail` through `EvalContext.metadata`. After a call that really ran, it teaches the baseline
  (`_observe_allowed`). Only allowed calls teach it.
- **Where the state lives.** Everything durable is already in the per-repo SQLite database: feature counts,
  Markov transitions, running numeric statistics, the score history used for calibration, step-up budgets,
  revealed-preference feedback and Martingale beliefs. Four things live only in process memory and are
  "rebuilt empty on restart" by design: the Half-Space Trees models and ADWIN detectors
  (`subjective/baseline.py`, `subjective/drift.py`), turn contexts (`subjective/score.py`) and scope tokens
  (`subjective/revealed.py`).
- **The pattern to reuse.** The warm ambient monitor (`monitor/daemon.py`, #699, commit c906f3f) already solves
  single-instance start-up. It claims an atomic `O_CREAT | O_EXCL` lock file, uses a heartbeat to detect and
  reclaim a stale lock, and wraps every tick in its own failure boundary. It is observe-only by hard rule: it
  never learns, never prompts and never enforces. That rule is why it cannot host the scorer, which learns.
- `docs/LIMITATIONS.md` ("Behavior-learning checks only run on the MCP proxy path today") quotes about two
  seconds per call for the import. On the test machine it is under one second (next section). Both figures
  make an every-call cold import too slow.

## What was measured

**Method.** A throwaway script (kept out of the repo, like the ADR 0117 benches) started each arm as a fresh
Python process, the way a host starts a hook. Every arm evaluated the same `git status --short` shell action
through `spine.evaluate_action` against a throwaway repo root, HMAC key and config directory, so no real
Doberman state was touched. The 20 runs per arm were interleaved so machine load hit every arm equally. The
`.pyc` cache was primed first, so first-run compile time is excluded. Machine: Windows 11, 20 logical cores,
Python 3.13.16, `river` 0.26.1, `numpy` 2.5.4, `scipy` 1.18.1. Run 2 seeded a 300-observation baseline first
so scoring read real rows. Run 1 used an empty one.

The arms:

- **light:** today's hook. Import the spine and run the objective path.
- **adaptive (cold):** light, plus importing the full adaptive layer in the same process, then
  `surprise_blended` and `SubjectiveGuardrail`.
- **lite:** like adaptive, but with `river` replaced by a stub that raises if it is used. This estimates a lazy
  `river` import. The stub never fired, and `numpy` and `scipy` were never loaded.
- **warm client:** light, plus one request to a warm process that had already imported the adaptive layer,
  over a Windows named pipe (`multiprocessing.connection` with an HMAC handshake).

| Median (min to max), ms | Run 1 (empty baseline) | Run 2 (seeded baseline) |
|---|---|---|
| Whole hook process, light (today) | 486 (334 to 651) | 315 (290 to 359) |
| Whole hook process, adaptive cold | 1,604 (1,212 to 1,917) | 1,098 (1,036 to 1,199) |
| Whole hook process, lite | not run | 317 (306 to 381) |
| Whole hook process, warm client | 513 (356 to 672) | 323 (308 to 385) |
| Adaptive-layer import alone, cold | 951 (704 to 1,137) | 652 (621 to 706) |
| Adaptive-layer import alone, lite | not run | 2.0 (1.8 to 3.2) |
| Adaptive scoring, in process | 11.1 | 7.4 cold, 6.1 lite |
| Warm client: import + connect + round-trip | 7.1 + 0.6 + 12.2 | 4.9 + 0.5 + 9.3 |
| Warm, held connection, 200 requests | 12.0 (server work 11.7) | 8.1 (server work 7.9) |

A `-X importtime` profile attributes 0.84 s of the cold import to `river.anomaly`. On its own, the spine import
costs about 0.2 to 0.4 s, and every hook already pays that today.

**What the numbers say.**

- A cold import adds 0.65 to 0.95 s to every call. That is what the issue already ruled out.
- A warm round-trip adds about 10 to 20 ms, almost all of it the scoring work itself. The pipe costs under 1 ms.
- The lite path adds about 2 ms of import plus the same 6 ms of scoring as the warm path, with no second process.

**Limits.** This is one machine. A slower laptop, a cold disk or a first run without `.pyc` files will be slower,
which may explain LIMITATIONS' two seconds. Run 1 shared the machine with other work and shows more spread. The
lite arm is an estimate: the real lazy-import change has not been written, and the learning writes (below) were
not timed.

Three more caveats. The arms run a bare script, not `doberman hook pre`, so the absolute "today" figure is
understated, though the deltas between arms hold. The lite arm never imports `martingale` and never times the
budget read. The bench uses pickle `send` and `recv`, not the `send_bytes` the design proposes.

## Alternatives

| | Option | Hook latency added | Down case | Verdict |
|---|---|---|---|---|
| A | A warm per-repo process runs the **whole** adaptive layer, and the hook asks it on every call (the issue's framing) | about 10 to 20 ms | Yes: the process can crash or be killed | Workable, but the fail-closed answer for "down" is the hard part, and its best version is option B |
| **B** | **Lite in-process scoring.** Import `river` lazily and score from the SQLite baseline inside the hook | about 8 ms | None | **Recommended, stage 1** |
| C | B, plus an optional warm sidecar for the memory-only signals | B + about 10 ms when the sidecar is up | Only the extra signals | **Stage 2, gated on a lift bench** |
| D | Cold full import on every call | 0.65 to 2 s | None | Rejected: the latency #639 exists to avoid |
| E | Store the Half-Space Trees and ADWIN models in SQLite, so every hook process can load them | 0.65 s or more (`river` is still imported) plus deserialization | None | Rejected: still slow, and loading pickled models from a file an agent can reach is an unsafe-deserialization surface |
| F | Route host tools through the MCP proxy | n/a | n/a | Not possible: the hosts' built-in tools (Bash, Edit, Write) never pass through MCP |
| G | Keep the stub and keep documenting the gap | 0 | n/a | Status quo |

A falls back to B in its own design. When the warm process is unreachable, the only fallback that keeps the
adaptive layer running is to score in the hook process. A cold process starts with empty Half-Space Trees
and ADWIN models, so that fallback can only compute what B computes, and it pays 0.65 s for the import first.
B makes that fallback the normal path and drops the import cost.

What B gives up on the hook path, compared with the proxy:

- the Half-Space Trees sub-score;
- ADWIN drift-triggered refreshes;
- turn context from the turn gate. It is published into process memory, so it never reaches a separate
  per-call hook process;
- session scope tokens after an approved subjective step-up.

Every item on that list is either a signal that can only raise risk, or (scope tokens) a convenience that
lowers prompts. Losing them makes the hook path stricter or noisier, never looser. Stage 2 exists to win them
back if the bench shows they matter.

## Q1: Who owns the state

**The per-repo SQLite database stays the only owner of durable adaptive state, in both stages.** That is
already true. The proxy, the hooks (taint ledger, decision history), the dashboard and the monitor all share
that database today. The subjective tables are already keyed by a fingerprinted entity id (role plus resolved
repo root). Concurrent writers are tolerated, not serialized: the connection sets `busy_timeout`, but `observe()` is a
read-modify-write sequence (numeric statistics, transitions, bounded keys) in one deferred transaction. Parallel
hooks can lose an update or drop an `observe` on a busy database. The effect is under-counting, which makes
scoring stricter, never looser.

- **Stage 1.** The hook process reads the baseline to score and writes it to learn. It holds nothing between
  calls. Learning follows the proxy's rule: observe only on a **genuine PASS**, meaning the objective,
  subjective, taint, echo and correlator results all came back `PASS`, **and the call was actually allowed and
  ran**. A call softened to `PASS` by the `monitor` or `off` dial never teaches the baseline, and neither does
  an approved `AUTH` in v1. `observe()` states that it must only be called for actions that were allowed and
  forwarded, and the proxy also skips learning when the tool errored or the output scan or artifact gate
  fired. Learning at `PreToolUse` would break that rule: a call the human then denies at the host's own prompt,
  a call that fails, and a call whose output trips the secret scan would all teach "normal", and a class key
  goes familiar after 3 allows (10 for high severity). So **learning runs at `PostToolUse`, where the host has
  one** (Claude Code, after the output scan passes). A host without a post hook gets **no learning in v1**: it
  scores from the seed and the peer prior only. Teaching from `PreToolUse` there would be a named deviation and
  a maintainer call (Decision 3). `observe()` splits into a database part (counts, transitions, numeric
  statistics, Martingale beliefs) that the hook runs, and a memory part (Half-Space Trees learning, ADWIN)
  that only a long-lived process runs. The Martingale self-monitor (`run_monitor`, every 50 observations, needs
  `numpy` and `scipy`) moves out of the call path to a CLI or monitor step. It can only refresh, hold or flag
  for review.
- **Stage 2.** The sidecar owns **caches only**: imported libraries, Half-Space Trees and ADWIN models, and turn
  contexts. Losing them costs warm-up time and never protection, the same as restarting the proxy today. It
  writes nothing the database does not already hold. Its single-instance start-up reuses the monitor's lock
  file and heartbeat, lifted into a shared helper rather than copied. One sidecar per repo mirrors where the
  database lives. It exits after an idle period, so a developer with many repos does not keep one warm
  process per repo forever. Memory per sidecar was not measured.

## Q2: How the hook talks to the process

- **Stage 1: it does not.** Scoring runs in the hook process. That is the main reason to prefer it.
- **Stage 2:**
  - **Channel.** `multiprocessing.connection` from the standard library, measured above. On Windows that is a
    named pipe. On POSIX it is a Unix socket in a per-user `0700` runtime directory. Repo paths can exceed the
    roughly 104-character socket-path limit on macOS, so the socket goes in that runtime directory, never in
    the repo. The endpoint name is the repo's fingerprint, so no raw path appears in it.
  - **Authentication.** The handshake is mutual HMAC, with the key derived from the existing `0600`
    fingerprint key, for example HMAC(key, "warm-ipc|" + repo fingerprint). This adds no new secret file. A
    process that squats on the pipe name first cannot complete the handshake, so it cannot pose as the
    sidecar. The key sits in a `0600` file the same user can read, so the HMAC stops squatting, not the agent.
    An agent that reads the key can impersonate the sidecar, and the worst case is still "down", which stage 1
    covers. The derivation is domain-separated and collides with no existing `fingerprint()` input.
  - **Messages.** Versioned JSON through `send_bytes` and `recv_bytes`, never `send` and `recv`, which unpickle.
    One request and one reply per call. The request carries the normalized action and the raw arguments that
    the built-in detectors scan. They are held in memory only and never logged, like
    `metadata['raw_arguments']` today. The reply carries the action id, verdict, risk, reason codes,
    explanation and the score the sidecar computed.
  - **Deadline.** About 100 ms for connect plus reply, which is five to ten times the measured round-trip. A
    missed deadline counts as down (Q3).
  - **Parsing.** The hook parses the reply strictly. An unknown version, verdict or reason code, or an action id
    that does not match the request, is an error, and an error is an `AUTH` (`rule_error`). That is how
    `engine/subjective.py` already isolates a failing detector.

## Q3: What happens when the process is down

The protected agent runs as the same OS user as any Doberman process, so it can kill one with a single shell
command. "Down" therefore has to be treated as something an attacker can cause, not just a crash.

**Stage 1 has no down state.** The adaptive layer runs inside the hook process that is answering the host.
Its failures already fail upward:

- a failed surprise computation scores 1.0 (maximum caution), but only if the failure reaches
  `surprise_blended`'s own guard. `total_observations()` and the peer lookup swallow a locked or corrupt
  database themselves: the count reads as 0 and the peer novelty as 0.5. The blend then weights the entity's own
  score at 0 and returns the prior, so a database lock would loosen a mature entity's score (in Balanced, the
  sensitivity times care needed to step up doubles, from 0.343 to 0.686). The hook path must not inherit that.
  Slice 2 requires that any baseline read failure on the hook path, including the observation count and the
  peer lookup, scores 1.0, tested with a locked and a corrupt database;
- a missing `surprise` key in the metadata reads as 0.0 (`_read_surprise`), so the hook needs a wrapper that
  fails to 1.0, like the proxy's `_surprise_or_caution`, which lives in `doberman.proxy` and cannot be
  imported by the policy core;
- a failed scoring step returns `AUTH` (`subjective_guardrail_error`);
- a failing detector returns `AUTH` (`rule_error`);
- a failed budget check lets the step-up through;
- an import failure is covered only if the adaptive imports sit inside `evaluate_action`, where the adapter's
  fail-closed try catches them. `hook_pre` imports `claude_code` (and through it the spine) outside any try,
  and a module-scope import error exits non-2, which the host treats as fail-open. Slice 1 requires the
  adaptive imports inside `evaluate_action`.

**Deadline.** A timed-out hook fails open, and the pinned timeout is 660 s against a 600 s challenge. A locked
database costs up to 3 s (`busy_timeout`) per open, so surprise, count, peer and budget reads could spend about
12 s before the challenge starts. The adaptive layer gets one total deadline, for example 2 s, after which
surprise is 1.0.

The only way to switch stage 1 off is to change Doberman's install or configuration, which the existing
control-plane tamper rules cover. One gap: an agent could run `doberman hook pre` itself with a crafted
payload to teach the baseline. Hosts start the hook directly, never through a gated tool, so the fix is to add
`hook` to `_DOBERMAN_CONTROL_SUBCOMMANDS` in `engine/rules/commands.py`. That is defence in depth, not a
seal: the rule matches only a command whose first token is `doberman`, so a wrapped or renamed call gets past it.

**Stage 2, the sidecar, can be down.** The options:

| | When the sidecar is unreachable or misses its deadline | Effect of killing it | Cost |
|---|---|---|---|
| 1 | Treat it as PASS silently | Silent loss of its signals | Rejected by the issue |
| **2** | **Stage 1 still decides. Skip the sidecar's extra signals, count the miss, surface it in `doberman status`, `doctor` and the dashboard, and start a new sidecar in the background (rate-limited by the lock file)** | **The hook path drops back to stage 1, never below it, and the drop is visible** | **Nothing on the call** |
| 3 | Option 2, plus raise to `AUTH` (new reason code, for example `adaptive_unavailable`) when stage 1's sensitivity term is high | A kill turns sensitive calls into prompts until the sidecar is back | Prompts during an outage |
| 4 | Raise every call to `AUTH` while it is down | A kill becomes a prompt storm, which breeds habitual approvals | Rejected: it fails toward approval fatigue rather than toward safety |
| 5 | Cold in-process fallback with the full import | Nothing gained: a cold process has empty Half-Space Trees and ADWIN models | 0.65 s or more per call |

**Recommendation: option 2, provided stage 1 ships first.** It is not "down means PASS". The adaptive layer still
decides every call, and the only signals lost are ones whose lift has not been measured and which the hook path
has never had. **If the maintainer rejects stage 1 and builds A alone, the recommendation changes to option 3.**
Without stage 1 underneath, option 2 would be exactly the silent PASS the issue forbids. Separately, and as
defense in depth that is not airtight, agent shell commands that target Doberman's own processes (`kill`,
`pkill` or `taskkill` matching a `doberman` command line) should be classed as control-plane tamper.
`taskkill /IM python.exe` will still slip past that rule, and option 2 is what makes that acceptable.

> **Maintainer call (Q3):** option 2 (recommended, with stage 1 in place), option 3, or option 3 only for A alone.

## Q4: Does raise-only hold across the boundary

**Yes, by construction, as long as the boundary sits on the subjective slot of `decide()` and nowhere else.**

- **The verdict.** The hook process keeps everything that can produce a floor: the objective rules, the taint
  floor, the echo tripwire, the correlator and the enforcement dial. `decide()` consults the subjective result
  only after an objective `PASS`, combines it raise-only, and clamps a non-allowlisted subjective `BLOCK` to
  `AUTH`. Anything the sidecar returns enters the hook as one more `GuardrailResult` combined on top of stage
  1's, so the final verdict can never fall below what stage 1 alone would give. The worst a lying sidecar can
  do is suppress its own raise. Lying needs the key, and the result is the same as the sidecar being down,
  which Q3 covers.
- **Learning, which is where a boundary could loosen Doberman quietly:**
  - only a genuine `PASS` teaches the baseline (Q1). Softened, denied and blocked calls never do;
  - in stage 2 the sidecar learns an action only when the hook confirms a genuine `PASS` for a request the
    sidecar itself scored within a short TTL, and each confirmation is accepted once. A forged confirmation
    needs the key. A process holding the key can already write the database, so the sidecar adds no new
    privilege;
  - **no approval message crosses the boundary in v1.** On the proxy, an approved subjective step-up grants a
    session scope token and records revealed-preference feedback. Both make later step-ups less likely. A
    message saying "the human approved X" would be a loosening channel the sidecar cannot verify, because the
    challenge ran in the hook process. So the hook path skips scope tokens and revealed-preference learning
    in v1. A repeated unusual action prompts every time. That is noisier, never looser.
  - **Step-up budget.** `budget_allows_step_up` counts the entity's last 20 `decisions` rows. The hook spine
    writes no `entity_id` on its rows, and a genuine `PASS` is never recorded there. If `entity_id` were simply
    added, the window would hold 20 non-`PASS` rows, so one approved step-up would suppress subjective step-ups
    for far more than 20 actions, and each suppressed one would count as a genuine `PASS` and teach the
    baseline. **v1 hooks pass `budget_ok=True`: no budget on the hook path.** A budget needs an entity-keyed
    row per decided action, which is a later slice. In every case, a budget-suppressed step-up never teaches.
- **The dial.** The adaptive layer is discretionary under the enforcement dial (ADR 0029, ADR 0095 rule 2).
  `monitor` and `off` soften its raises on the hook path exactly as they do on the proxy.

## How ADR 0117's consultation point depends on this

ADR 0117 rule 8 consults the content-reading judge only when the combined verdict before the judge is `PASS`
*and* the subjective layer marks the call as uncertain (ADR 0095 rule 3's band). The rule says outright that the
host-hook path has no uncertain band until #639 lands, and rule 9 puts activation after it.

- **Stage 1 is what unblocks it.** The hook process computes the subjective score itself, so the band is there
  on every hook call. A warm process alone (option A) would make the band exist only while that process is up.
  Killing it would then also switch off the content arm, quietly: a second silent-loosening path, and one more
  reason to prefer B.
- **The band itself is not built on any path yet.** `SubjectiveGuardrail` returns `PASS` without exposing the
  score or the threshold it compared against. Stage 1 should record both on the decision's subjective result,
  for audit only: they must never change the verdict. The ADR 0117 activation slice then defines the band from
  them, the same way on the proxy and the hook.
- **Latency.** The judge's 1.5 s timeout would apply only to uncertain-band calls, inside the hook process.
  Stage 1's roughly 8 ms does not change ADR 0117's latency budget.

## Decisions for the maintainer

1. **Stage 1 as the implementation of #639**, with the warm sidecar deferred until a bench shows the Half-Space
   Trees, ADWIN or turn-context signals add lift on hook traffic. Recommended: yes.
2. **Q3, when the sidecar is down:** option 2 (recommended) or option 3. If stage 1 is rejected: option 3.
3. **The hook path starts teaching the baseline,** from genuine `PASS` decisions at `PostToolUse`, after the
   tool ran and the output scan passed. This is the first time a host hook writes the learned baseline. It comes
   with `hook` joining the control-plane tamper verbs (defence in depth). Hosts without a post hook do not learn
   in v1. Teaching from `PreToolUse` on those hosts would break the allowed-only rule (ADR 0028, ADR 0073), so
   it is a separate maintainer call. Recommended: post-hook learning only.
4. **No scope tokens, no revealed-preference learning and no step-up budget on the hook path in v1.** More
   prompts on repeated unusual actions, and no loosening channel. Recommended: yes.
5. **Rollout.** Every hook user would start seeing subjective step-ups at once, from cold baselines.
   Recommended: one release in shadow (record what the layer would have raised, enforce nothing), with
   `doberman memory seed` (docs/BASELINE_SEEDING.md) offered to warm baselines. Then turn it on.

## Proposed slices (after sign-off)

1. **Lazy ML imports.**
   - Import `river` only inside the Half-Space Trees and ADWIN code paths, and `numpy` and `scipy` only inside
     the Martingale monitor.
   - Split `observe()` into its database part and its memory part.
   - Import the adaptive modules inside `evaluate_action`, so an import error fails closed.
   - Test in a subprocess that `river`, `numpy` and `scipy` are not in `sys.modules` after a hook decision.
     import-linter cannot tell a lazy import from a module-level one, so a test has to hold this line.
2. **Wire the layer into both hook call sites** (`spine.py:113`, `claude_code.py:587`) in shadow mode. Record
   the score and threshold. Any baseline read failure on the hook path, including the observation count and
   the peer lookup, scores 1.0, tested with a locked and a corrupt database. Set one total adaptive deadline
   (for example 2 s, then surprise is 1.0). Wrap the metadata surprise read so a missing key fails to 1.0.
   Pass `budget_ok=True`.
3. **Learning on genuine `PASS` at `PostToolUse`,** plus `hook` in the control-plane tamper set. Time the database writes on the
   hook path.
4. **Turn enforcement on** after the shadow release. Update `docs/LIMITATIONS.md` and `docs/PARITY.md`.
5. **Stage 2 only on evidence:** a lift bench for the memory-only signals, then the sidecar (Q2 to Q4).
