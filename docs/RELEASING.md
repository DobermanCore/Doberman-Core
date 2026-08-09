# Releasing Doberman-Core

The checklist for cutting a release. The goal is that every published claim
resolves to something in the repo — a test, a parity cell, or a reproducible
number — at the moment of release.

## Before tagging

1. **Green `main`.** CI green on `main`: `ruff check .`, `ruff format --check .`,
   `lint-imports`, `pytest -n auto --cov-fail-under=…`, the parity `--check` step,
   and the secret scan.
2. **Parity matrix current.** `python -m tools.parity.generate_parity --check`
   passes (CI enforces it). Every ✅ in [`PARITY.md`](PARITY.md) still resolves to
   a collected test.
3. **Refresh the benchmark numbers.** Re-run the suites per
   [`BENCHMARKS.md`](BENCHMARKS.md) and update its Results tables **in the release
   PR**:
   - Synthetic (deterministic, from a cold clone):
     `python -m tests.benchmarks.run --suite synthetic --profile before_after`.
   - AgentDojo (operator-supplied): `pip install agentdojo` at a pinned commit,
     then `python -m tests.benchmarks.run --suite agentdojo --profile before_after`.
     Record the pinned commit and the run date. Keep the raw run out of git
     (`test-logs/`); transcribe only the aggregate numbers.
   - Update the "Fixed bypasses" wall with anything disclosed-and-fixed since the
     last release.
4. **Version + changelog.** Bump `version` in `pyproject.toml`; move shipped items
   into `CHANGELOG.md`; confirm the README roadmap/versioning reflects reality.
5. **Docs sweep.** Every protection claim in the README resolves to a parity cell
   or a benchmark number (no orphan adjectives).

## Tag & publish

6. Tag the release and let CI build/publish the artifact. The public core must
   build, test, and run with **zero enterprise code installed** (the standalone
   guarantee) — CI's standalone step enforces this.

## After release

7. Confirm the published artifact installs clean (`pip install doberman-core==<v>`
   in a fresh venv) and `doberman doctor` runs.
