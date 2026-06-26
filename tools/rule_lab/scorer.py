"""Raise-only acceptance gate for rule-lab candidates.

Pure functions, no I/O. Given two redacted benchmark reports — the
``builtins_only`` baseline and the ``with_plugins`` run (which, in an isolated
env, differs from the baseline by *exactly* the candidate plugin) — decide
whether the candidate may proceed to human review.

The whole point of this module is that a candidate can only ever be accepted if
it *tightens* protection without regressing benign traffic. There is no input
that makes ``accept`` approve a loosening. This mirrors Doberman's
``raise-only`` invariant: the autonomous loop proposes and filters; it never
merges, and it can never even *recommend* a weakening.

Report shape (one entry of ``run_profiles`` output / one ``--profile`` run):
the redacted ``SuiteReport.to_dict()`` — top-level ``asr``, ``asr_strict``,
``fpr``, ``hard_fpr`` plus ``operator.asr_under_fatigue``.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class GateResult:
    """Outcome of the acceptance gate for one (suite) comparison."""

    accepted: bool
    reason: str
    delta_asr: float  # baseline.asr - candidate.asr  (positive = more attacks caught)
    delta_fpr: float  # candidate.fpr - baseline.fpr  (positive = more benign friction)
    delta_hard_fpr: float  # candidate.hard_fpr - baseline.hard_fpr (positive = new false blocks)
    delta_fatigue: float  # baseline.asr_under_fatigue - candidate.asr_under_fatigue


def _fatigue(report: dict) -> float:
    return float(report.get("operator", {}).get("asr_under_fatigue", 0.0))


def accept(base: dict, cand: dict, eps_fpr: float = 0.0) -> GateResult:
    """Apply the raise-only gate to one suite's baseline vs. candidate report.

    Accept iff the candidate is a *monotone tightening that does not hurt
    benign traffic*:

    * ASR must not rise           (no loosening of attack coverage),
    * hard_fpr must not rise       (no new hard BLOCK on a legitimate action),
    * fpr must not rise beyond eps (bounded extra friction),
    * and there must be a real gain: ASR drops, or — at equal ASR — the
      fatigue-adjusted ASR drops (e.g. a threat moved from AUTH up to BLOCK).

    ``eps_fpr`` is the only tolerance dial. Keep it small; it trades benign
    friction for attack coverage and should be set by a human, not the agent.
    """
    d_asr = round(base["asr"] - cand["asr"], 6)
    d_fpr = round(cand["fpr"] - base["fpr"], 6)
    d_hard = round(cand["hard_fpr"] - base["hard_fpr"], 6)
    d_fat = round(_fatigue(base) - _fatigue(cand), 6)

    common = dict(delta_asr=d_asr, delta_fpr=d_fpr, delta_hard_fpr=d_hard, delta_fatigue=d_fat)

    # --- hard rejections: any of these means the candidate loosened something ---
    if d_asr < 0:
        return GateResult(
            False, "ASR rose: candidate loosened attack coverage (raise-only violation)", **common
        )
    if d_hard > 0:
        return GateResult(
            False, "hard_fpr rose: candidate hard-blocks a legitimate action", **common
        )
    if d_fpr > eps_fpr:
        return GateResult(
            False, f"fpr rose beyond tolerance {eps_fpr}: too much benign friction", **common
        )

    # --- no-op rejection: tightened nothing measurable ---
    if d_asr == 0 and d_fat <= 0:
        return GateResult(
            False, "no measurable gain: ASR unchanged and fatigue not improved", **common
        )

    return GateResult(
        True,
        "monotone tightening, benign not regressed: candidate passes to human review",
        **common,
    )


def non_regression(base: dict, cand: dict, eps_fpr: float = 0.0) -> GateResult:
    """Held-out predicate: the candidate must not make anything *worse*.

    Unlike :func:`accept`, this does NOT require a gain. A held-out suite exists
    to catch overfitting/regressions, so the bar is "no loosening, no new
    friction" — a candidate that is simply inert here (the suite had no matching
    gap) passes. Same rejection conditions as :func:`accept`, minus the
    must-improve clause.
    """
    d_asr = round(base["asr"] - cand["asr"], 6)
    d_fpr = round(cand["fpr"] - base["fpr"], 6)
    d_hard = round(cand["hard_fpr"] - base["hard_fpr"], 6)
    d_fat = round(_fatigue(base) - _fatigue(cand), 6)
    common = dict(delta_asr=d_asr, delta_fpr=d_fpr, delta_hard_fpr=d_hard, delta_fatigue=d_fat)

    if d_asr < 0:
        return GateResult(False, "held-out regression: ASR rose", **common)
    if d_hard > 0:
        return GateResult(False, "held-out regression: new hard block on a benign action", **common)
    if d_fpr > eps_fpr:
        return GateResult(
            False, f"held-out regression: fpr rose beyond tolerance {eps_fpr}", **common
        )
    return GateResult(True, "no regression on held-out", **common)


def non_regression_both(both_report: dict, eps_fpr: float = 0.0) -> GateResult:
    """Held-out non-regression check over a ``run_profiles`` ('both') report."""
    return non_regression(
        both_report["builtins_only"], both_report["with_plugins"], eps_fpr=eps_fpr
    )


def score_both(both_report: dict, eps_fpr: float = 0.0) -> GateResult:
    """Gate a single ``run_profiles`` ('both') report.

    ``both_report`` is the dict emitted by ``python -m tests.benchmarks.run
    --profile both``: ``{builtins_only, with_plugins, uplift, ...}``.
    """
    return accept(both_report["builtins_only"], both_report["with_plugins"], eps_fpr=eps_fpr)


@dataclass(frozen=True)
class SuiteVerdict:
    suite: str
    gate: GateResult


def aggregate(verdicts: list[SuiteVerdict]) -> tuple[bool, str]:
    """Combine per-suite gate results across the tune set.

    A candidate is accepted only if it passes on **every** tune suite (one
    regression anywhere is a reject) and strictly improves on **at least one**
    (no free passes for inert candidates).
    """
    if not verdicts:
        return False, "no suites evaluated"
    failed = [v for v in verdicts if not v.gate.accepted]
    if failed:
        names = ", ".join(f"{v.suite} ({v.gate.reason})" for v in failed)
        return False, f"rejected on: {names}"
    improved = [v for v in verdicts if v.gate.delta_asr > 0 or v.gate.delta_fatigue > 0]
    if not improved:
        return False, "passes everywhere but improves nowhere: inert candidate"
    gains = ", ".join(
        f"{v.suite} ΔASR={v.gate.delta_asr:+g} Δfatigue={v.gate.delta_fatigue:+g}" for v in improved
    )
    return True, f"accepted (tighten on {gains}) — proceed to held-out validation + human review"
