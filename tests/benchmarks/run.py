"""CLI entry point for the benchmark harness.

Run from the repo root:

    python -m tests.benchmarks.run --suite synthetic --profile both

Prints a redacted JSON report (counts + rates + verdict/reason histograms only —
never payload text). External suites register in ``suites/__init__.py`` once
their adapter exists; see ``tests/benchmarks/README.md``.
"""

from __future__ import annotations

import argparse
import json
import sys

from .profiles import build_pipeline
from .runner import run_before_after, run_profiles, run_suite
from .suites import BUILTIN_ADAPTERS

_PROFILES = ("both", "before_after", "builtins_only", "with_plugins")
_MODES = ("light", "balanced", "strict", "paranoid")


def _run_one(adapter, profile: str, mode: str | None, session_replay: bool) -> dict:
    """Run one (profile, mode) combination and return its report dict."""
    if profile == "both":
        return run_profiles(adapter, mode=mode, session_replay=session_replay)
    if profile == "before_after":
        return run_before_after(adapter, mode=mode, session_replay=session_replay)
    load_plugins = profile == "with_plugins"
    return run_suite(
        adapter, build_pipeline(load_plugins=load_plugins), mode=mode, session_replay=session_replay
    ).to_dict()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Doberman benchmark harness (ASR/FPR).")
    parser.add_argument(
        "--suite",
        default="synthetic",
        help=f"suite to run (registered: {', '.join(sorted(BUILTIN_ADAPTERS))})",
    )
    parser.add_argument("--profile", default="both", choices=_PROFILES)
    parser.add_argument(
        "--mode",
        default=None,
        choices=[*_MODES, "all"],
        help="F6 strength-mode override; 'all' runs each mode and keys the report by "
        "mode (default: the suite's per-case mode)",
    )
    parser.add_argument(
        "--subjective",
        action="store_true",
        help="run the subjective-layer baseline-separation diagnostic instead of the "
        "ASR/FPR profile/mode path; standalone (--profile/--mode are ignored)",
    )
    parser.add_argument(
        "--corpus",
        action="store_true",
        help="run the C8 labeled-corpus detection report (per-category TPR/FPR/precision "
        "+ floor/forbidden violations) instead of the ASR/FPR path; forces --suite corpus",
    )
    parser.add_argument(
        "--poisoning",
        action="store_true",
        help="run the cross-session baseline-poisoning eval (gradual-drift robustness "
        "number) instead of the ASR/FPR path; suite-independent (--suite/--profile/--mode "
        "are ignored)",
    )
    parser.add_argument(
        "--replay-session",
        action="store_true",
        help="apply the post-decide floors (taint floor, echo tripwire, session correlator) that the "
        "proxy/host-hook spine apply after decide() returns, replaying each case inside a fresh isolated "
        "per-case session; off by default (byte-for-byte the existing stateless per-action path). "
        "Applies only to the ASR/FPR path (--profile both/before_after/builtins_only/with_plugins), not "
        "--corpus/--subjective/--poisoning.",
    )
    args = parser.parse_args(argv)

    if args.poisoning:
        from .poisoning_runner import run_poisoning_eval

        json.dump(run_poisoning_eval(), sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
        return 0

    if args.corpus:
        from .metrics import corpus_metrics
        from .suites.corpus import evaluate_corpus, load_corpus

        load_plugins = args.profile == "with_plugins"
        # The corpus rows carry their own (calibrated) mode; a concrete --mode
        # overrides it, but "all" is meaningless for a per-row report → row mode.
        mode = None if args.mode in (None, "all") else args.mode
        results = evaluate_corpus(
            load_corpus(), build_pipeline(load_plugins=load_plugins), mode=mode
        )
        json.dump(corpus_metrics(results), sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
        return 0

    adapter_cls = BUILTIN_ADAPTERS.get(args.suite)
    if adapter_cls is None:
        parser.error(
            f"unknown suite {args.suite!r}; registered: {', '.join(sorted(BUILTIN_ADAPTERS))}"
        )
    adapter = adapter_cls()

    if args.subjective:
        from .subjective_runner import run_subjective_eval

        report: dict = run_subjective_eval(adapter)
    else:
        from contextlib import nullcontext

        if args.replay_session:
            from .session_replay import isolated_process_state

            state_ctx = isolated_process_state()
        else:
            state_ctx = nullcontext()
        with state_ctx:
            if args.mode == "all":
                report = {
                    m: _run_one(adapter, args.profile, m, args.replay_session) for m in _MODES
                }
            else:
                report = _run_one(adapter, args.profile, args.mode, args.replay_session)

    json.dump(report, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
