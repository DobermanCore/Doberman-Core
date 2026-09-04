# Authority tiers

Doberman's guardrails span four tiers of *how* a verdict is reached. Which tier an action's evaluation
sits in decides whether it is even eligible to `BLOCK` — this page names the tiers, maps each onto the
actual code, and states plainly what is (and is not) proven about them.

**The one hard rule: `BLOCK` is earned only by a signature, glob, or discrete predicate match — never by
a continuous score crossing a threshold.** A probability, an abnormality score, or a model's confidence
can raise a verdict to `AUTH`; none of them can produce `BLOCK`. That is enforced structurally in the
subjective layer (see T2 below) and is a standing invariant for any new rule.

## T0 — signature / predicate rules (may BLOCK)

Deterministic, single-shot matches: a command pattern, a path glob, a credential shape plus an external
destination, a role/policy boundary glob. No history, no learning, no probability — the same input always
produces the same verdict. This is the only tier allowed to reach `BLOCK`, and only through
`FLOOR_HARD_BLOCKS` (`src/doberman/policy/modes.py`), the five reason codes that hard-block in every
security mode:

| Reason code | Rule | Predicate |
| --- | --- | --- |
| `secret_exfiltration` | `engine/rules/secrets.py::SecretLeakageRule` | strong credential shape or a secret-store path, **and** an external destination |
| `protected_path_blocked` | `engine/rules/paths.py::ProtectedPathRule` (also reached from `commands.py` for a control-plane-tamper command) | canonicalized target matches a `DEFAULT_BLOCKED_GLOBS` entry |
| `destructive_command` | `engine/rules/commands.py::DestructiveCommandRule` | a fixed catastrophic-command signature: recursive+force delete of a root/home target, disk-wipe, raw write to a block device, force-push to a protected branch, fork bomb |
| `role_blocked_target` | `engine/rules/role_boundary.py::RoleBoundaryRule` | target classifies as `blocked` against the active role's glob boundary — **opt-in**: abstains with no active role |
| `policy_source_blocked` | `engine/rules/policy_source.py::PolicySourceRule` | target matches a resolved policy source's `blocked_globs` — **opt-in**: abstains with neither a repo-committed `doberman.policy.yaml` nor a registered policy-source plugin |

`tests/unit/test_authority_tiers.py` keeps this table honest: every code above is proven reachable as a
`BLOCK` (three through the shipped detection corpus, `role_blocked_target`/`policy_source_blocked`
directly against their rule, since the corpus's default mapping never sets a role or a resolved policy),
and every rule's boundary is proven to be a discrete step rather than a threshold on a continuous value.

## T1 — deterministic heuristics (AUTH-capped)

Still deterministic and single-shot, but a step-up rather than a floor: bulk-delete-operand-count,
opaque/unparseable commands, sensitive (not blocked) paths, role/policy "sensitive but not blocked",
the encoded-payload and token-channel detectors, PII/data-class egress. These can escalate hard in the
strictest modes (Strict/Paranoid raise several of them from `AUTH` to `BLOCK` via `policy/modes.py`'s
mode-gated `trifecta_hard_block`/`token_channel_hard_block`/`egress_hard_block` flags — always raise-only,
mode-gated, never score-derived) but on their own, in Light/Balanced, they never exceed `AUTH`.

## T2 — statistics (AUTH-capped, structurally cannot BLOCK)

The universal subjective layer (SL7, `engine/subjective.py`): `score = (surprise × sensitivity × care)
** (1/3)` — a geometric soft-AND of three axes, each in `[0, 1]`, compared against a mode threshold.
This is the one continuous, learned/tunable signal in the decision path, and it has **no `BLOCK` literal
anywhere on its path** — `_step_up_result` always constructs `Verdict.AUTH`. Even where the whole-guardrail
reduction (`SubjectiveGuardrail.evaluate`, combining the score with detector results) could in principle
carry a `BLOCK` up from elsewhere, the execution rule
(`engine/decision_engine.py`) clamps any subjective `BLOCK` down to `AUTH` **except** `lethal_trifecta` —
which is not part of the score; it is a separate, score-independent, deterministic co-occurrence floor
(sensitive/secret target **and** untrusted/mixed provenance **and** an external destination, checked
before any score math) that only escalates to `BLOCK` in Strict/Paranoid, and only ever raises what would
otherwise be an `AUTH`. `tests/unit/test_authority_tiers.py::test_subjective_score_never_blocks_even_at_maximum_abnormality`
drives every score axis to its maximum while deliberately keeping the action out of the trifecta
co-occurrence, and confirms the result is `AUTH`.

## T3 — model / adjudicator judgment (advisory only, no BLOCK path)

The shadow adjudication seam (`engine/adjudicator.py`, ADR 0028): a pluggable second opinion that may
*observe* a decision (through `redacted_features()` — an explicit allowlist Mapping, never the raw
`SecurityObject`/`EvalContext`) and record what it would have recommended on `Decision.shadow`. It is
consulted only in the ambiguous `AUTH` step-up band (never on a floor `BLOCK` or a `PASS`), fails closed
by being ignored on any error, and its recommendation is passed to **no** part of `final_verdict`/
`final_risk` — there is no code path by which an adjudicator can raise or lower the live decision. Per
ADR 0029 ("the LLM is a narrator, not a judge") and the C6 judge slice, an opt-in advisory rung may
eventually surface the shadow recommendation to a human, but the envelope itself does not widen: no LLM
or model-derived signal reaches `BLOCK`, or even the live verdict at all, without a human choosing to act
on an advisory it read.

The shipped T3 example is `doberman/judge.py` (`HaikuJudgeAdjudicator`, PR #539): behind the optional
`[judge]` extra, off unless explicitly enabled, it sees only `redacted_features()`, maps its two-boolean
answer through a raise-only contract against the current result, and is shadow-only today — nothing
registers it into `decide()`, so it has no production caller.

## What this page does NOT claim

This is a regression guard over **today's closed rule set**, not a structural (AST/lint-level) proof that
a future rule could never add a score-derived `BLOCK` path — the reviewers who approved this slice
deliberately dropped that generic guarantee as not cheaply testable (a grep/AST linter is new tooling; a
hand-maintained call-site allowlist rots and reads stronger than it is). A new rule that introduces a
`Verdict.BLOCK` off a probability threshold will not be caught by this page or its test unless someone
adds a boundary case for it in `tests/unit/test_authority_tiers.py`.

It also does not claim uniform false-positive coverage: the shipped detection corpus
(`tests/corpus/detection_corpus.jsonl`) has no benign `shell_exec`/`git_op` row that exercises
`destructive_command`'s near-miss edge (its benign shell and git rows are read-only, build, or VCS-status
commands — none reach the delete-verb branch of `DestructiveCommandRule` at all). `tests/integration/test_corpus_gate.py`'s `fpr == 0.0` assertion is
therefore true for that code today in a vacuous sense, not because a benign delete-shaped command was
tried and passed. `tests/unit/test_authority_tiers.py`'s discrete-boundary test closes this specific gap
directly (a same-rule near-miss case, not a corpus row), but a corpus row exercising that same edge
end-to-end through the real pipeline would still be a genuine, if small, follow-up.

Adding a new `FLOOR_HARD_BLOCKS` code will fail `tests/unit/test_authority_tiers.py` until either a
corpus row proves it (if the corpus's mapping can reach the new code's rule) or a direct-rule test is
added for it (if the rule is opt-in, like the two role/policy-source codes above) — this is deliberate
teeth, not a bug: a contributor who trips it should read this page's coverage-path split, not chase a
mystery red CI run.
