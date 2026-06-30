"""Candidate worker: run the fixed benchmark harness and apply the gate.

This is a thin, deterministic driver. It does NOT propose candidates and it does
NOT merge anything — it runs the *unmodified* benchmark CLI on each suite, parses
the redacted JSON, and reports the raise-only gate verdict. Merging stays a human
decision behind the Slice Loop review checkpoint.

Isolation contract
------------------
``--profile both`` compares ``builtins_only`` against ``with_plugins``. For that
delta to isolate *one* candidate, run this worker in an environment where the
candidate plugin is the ONLY installed Doberman plugin (a fresh venv / git
worktree with just the candidate ``pip install -e``'d). With several plugins
installed the delta reflects all of them — still a valid measurement, just not a
single-candidate A/B.

Only counts/rates ever cross back into this process; the harness never emits
payload text, so attack strings never enter the agent loop.

Registered suites are discovered by the harness (``agentdojo``, ``agentdyn``,
``synthetic``); pass whichever you have data for. ``injecagent`` ships only as
cached data, not a registered adapter, so it is not selectable until an adapter
is added under ``tests/benchmarks/suites/``.

Usage
-----
    python tools/rule_lab/worker.py \
        --tune agentdojo \
        --holdout synthetic \
        --eps-fpr 0.0
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from scorer import (  # noqa: E402
    SuiteVerdict,
    aggregate,
    non_regression_both,
    score_both,
    validate_eps_fpr,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


def run_suite_both(suite: str) -> dict:
    """Invoke the real benchmark CLI for one suite and return its JSON report."""
    # Fixed argv: our own interpreter running the in-repo benchmark module; only
    # the suite name varies and it is validated by the CLI's choices. Not untrusted.
    proc = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "tests.benchmarks.run", "--suite", suite, "--profile", "both"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"benchmark failed for suite {suite!r}:\n{proc.stderr.strip()}")
    return json.loads(proc.stdout)


def _eps_fpr_arg(value: str) -> float:
    try:
        eps_fpr = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid eps_fpr {value!r}") from exc
    try:
        return validate_eps_fpr(eps_fpr)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def validate_suite_split(tune: list[str], holdout: list[str]) -> None:
    """Fail fast when held-out validation would reuse a tune suite."""
    overlap = sorted(set(tune) & set(holdout))
    if overlap:
        joined = ", ".join(overlap)
        raise ValueError(f"tune and holdout suites must be disjoint; overlap: {joined}")


def evaluate(tune: list[str], holdout: list[str], eps_fpr: float) -> dict:
    """Run the tune set, apply the gate, then validate on the held-out set."""
    validate_eps_fpr(eps_fpr)
    validate_suite_split(tune, holdout)
    verdicts: list[SuiteVerdict] = []
    reports: dict[str, dict] = {}
    for suite in tune:
        report = run_suite_both(suite)
        reports[suite] = report
        verdicts.append(SuiteVerdict(suite, score_both(report, eps_fpr=eps_fpr)))

    accepted, summary = aggregate(verdicts)

    holdout_results: dict[str, dict] = {}
    holdout_ok = True
    if accepted:
        # Only spend held-out budget on candidates that already cleared the tune gate.
        for suite in holdout:
            report = run_suite_both(suite)
            # Held-out uses the non-regression predicate, NOT the must-improve gate:
            # an inert candidate here (suite had no matching gap) is fine; a
            # regression is not.
            gate = non_regression_both(report, eps_fpr=eps_fpr)
            holdout_results[suite] = {
                "accepted": gate.accepted,
                "reason": gate.reason,
                "delta_asr": gate.delta_asr,
                "delta_fpr": gate.delta_fpr,
            }
            holdout_ok = holdout_ok and gate.accepted

    final = accepted and holdout_ok
    return {
        "final_decision": "ACCEPT -> human review" if final else "REJECT",
        "tune_summary": summary,
        "tune_gates": {
            v.suite: {
                "accepted": v.gate.accepted,
                "reason": v.gate.reason,
                "delta_asr": v.gate.delta_asr,
                "delta_fpr": v.gate.delta_fpr,
                "delta_hard_fpr": v.gate.delta_hard_fpr,
                "delta_fatigue": v.gate.delta_fatigue,
            }
            for v in verdicts
        },
        "holdout_gates": holdout_results,
        "holdout_passed": holdout_ok if accepted else None,
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Rule-lab candidate worker (gate over the benchmark harness)."
    )
    p.add_argument(
        "--tune",
        nargs="+",
        default=["agentdojo"],
        help="tune suites (iterate on these)",
    )
    p.add_argument(
        "--holdout",
        nargs="+",
        default=["synthetic"],
        help="held-out suites (validate accepted candidates)",
    )
    p.add_argument(
        "--eps-fpr",
        type=_eps_fpr_arg,
        default=0.0,
        help="benign-friction tolerance (human-set; keep small)",
    )
    args = p.parse_args(argv)

    result = evaluate(args.tune, args.holdout, args.eps_fpr)
    json.dump(result, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    # Exit non-zero on reject so CI / the Slice Loop can branch on it.
    return 0 if result["final_decision"].startswith("ACCEPT") else 1


if __name__ == "__main__":
    raise SystemExit(main())
