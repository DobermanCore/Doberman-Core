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


def _run_one(adapter, profile: str, mode: str | None) -> dict:
    """Run one (profile, mode) combination and return its report dict."""
    if profile == "both":
        return run_profiles(adapter, mode=mode)
    if profile == "before_after":
        return run_before_after(adapter, mode=mode)
    load_plugins = profile == "with_plugins"
    return run_suite(adapter, build_pipeline(load_plugins=load_plugins), mode=mode).to_dict()


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
    args = parser.parse_args(argv)

    adapter_cls = BUILTIN_ADAPTERS.get(args.suite)
    if adapter_cls is None:
        parser.error(
            f"unknown suite {args.suite!r}; registered: {', '.join(sorted(BUILTIN_ADAPTERS))}"
        )
    adapter = adapter_cls()

    if args.mode == "all":
        report: dict = {m: _run_one(adapter, args.profile, m) for m in _MODES}
    else:
        report = _run_one(adapter, args.profile, args.mode)

    json.dump(report, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
