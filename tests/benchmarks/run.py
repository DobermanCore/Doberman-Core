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
from .runner import run_profiles, run_suite
from .suites import BUILTIN_ADAPTERS

_PROFILES = ("both", "builtins_only", "with_plugins")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Doberman benchmark harness (ASR/FPR).")
    parser.add_argument(
        "--suite",
        default="synthetic",
        help=f"suite to run (registered: {', '.join(sorted(BUILTIN_ADAPTERS))})",
    )
    parser.add_argument("--profile", default="both", choices=_PROFILES)
    args = parser.parse_args(argv)

    adapter_cls = BUILTIN_ADAPTERS.get(args.suite)
    if adapter_cls is None:
        parser.error(
            f"unknown suite {args.suite!r}; registered: {', '.join(sorted(BUILTIN_ADAPTERS))}"
        )
    adapter = adapter_cls()

    if args.profile == "both":
        report: dict = run_profiles(adapter)
    else:
        load_plugins = args.profile == "with_plugins"
        report = run_suite(adapter, build_pipeline(load_plugins=load_plugins)).to_dict()

    json.dump(report, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
