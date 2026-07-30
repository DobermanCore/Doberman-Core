# Contributing to Doberman

Doberman is an Apache-2.0 project for AI-agent runtime authorization. This guide
gets you from a fresh clone to the same checks CI runs. `AGENTS.md` and
`CLAUDE.md` remain the operating manual and source of truth for project
invariants.

## Local setup

```bash
git clone https://github.com/fu351/Doberman-Core.git
cd Doberman-Core
python -m venv .venv
source .venv/bin/activate  # Unix/macOS
# PowerShell: .venv\Scripts\Activate.ps1
# Command Prompt: .venv\Scripts\activate.bat
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

## Run the checks

Run these before opening a PR:

```bash
ruff check .
ruff format --check .
lint-imports
pytest --cov=doberman --cov-report=term-missing --cov-fail-under=80
```

CI also verifies that `doberman-core` builds and tests without the private
enterprise package installed, then runs the same ruff, import-linter, pytest,
and secret-scan workflow.

## Choosing targeted tests

While developing a small, focused change, you can run only the tests related to
the area you're working on for faster feedback. Before marking a pull request
ready for review, always run the complete verification suite listed above.

### Common change areas

| Change area | Suggested command |
| --- | --- |
| CLI | `pytest tests/unit/test_cli_help.py` |
| Discovery / scan | `pytest tests/unit/test_discovery_scan.py` |
| Policy / engine rules | `pytest tests/unit/test_objective_guardrail.py` |
| Storage / logging | `pytest tests/unit/test_audit_sink.py` |
| Proxy | `pytest tests/integration/test_proxy_passthrough.py` |
| Host hooks | `pytest tests/unit/test_hosthook_control_plane.py` |
| Docs-only changes | Preview the rendered Markdown when possible, then run the full verification suite before opening a PR. |

### Run a single test file

```bash
pytest tests/unit/test_discovery_scan.py
```

### Run a single test

```bash
pytest tests/unit/test_discovery_scan.py::test_scan_is_depth_bounded
```

### Run tests by keyword

```bash
pytest -k scan
```

This runs only tests whose names or node IDs match the given keyword.

### Before opening a pull request

Targeted tests are useful while iterating, but they do **not** replace the full
verification process. Before marking a pull request ready for review, run:

```bash
ruff check .
ruff format --check .
lint-imports
pytest --cov=doberman --cov-report=term-missing --cov-fail-under=80
```

## Architecture in five lines

1. A tool call enters Doberman through the MCP proxy or host-hook path.
2. The call is normalized into a `SecurityObject`.
3. The decision engine runs objective and adaptive guardrails.
4. Guardrail verdicts merge through raise-only `combine()`.
5. The execution gate returns PASS / AUTH /BLOCK: allow, authenticate, or block.

## Invariants

Every change must preserve these two safety properties:

- **Fail closed** - on any error, uncertainty, or unhandled case, deny or
  `BLOCK`; a protected agent must not reach a tool around Doberman.
- **Raise-only** - guardrails may auto-tighten, but may never silently loosen.
  Any permanent weakening goes through the human-gated policy path.

Also keep secrets out of commits, logs, fixtures, and PR examples. Redacted
metadata, classifications, and fingerprints are fine; raw secrets are not.

## Workflow

- Start from current `main` and make one focused slice per PR.
- Use the existing branch pattern: `feat/<feature>/<slice>`, `fix/...`, or
  `chore/...`.
- Use Conventional Commits, such as `fix(hosthooks): block control-plane writes`
  or `docs(contributing): add onboarding guide`.
- Tests travel with the code, and docs or README updates travel with behavior
  changes.
- Fill out the PR template, including the public-release safety and security
  checklists.
- Note any AI assistance in the PR description.

## Pick a first task

Every open issue carries a `level-1` through `level-10` label — a difficulty ladder:

| Level | What it demands |
|---|---|
| 1 | Docs/Markdown only. Needs git and a text editor, no Python. |
| 2 | Mechanical: catalogue or transcribe what the code already does. Reads Python. |
| 3 | Write a self-contained test, or add a flag following an existing sibling pattern. |
| 4 | Touches a contract (redaction, reason codes). Needs one invariant understood. |
| 5 | Multi-site change or cross-module test. Understand a subsystem, change no behaviour. |
| 6 | Tooling/CI/packaging, or a new extension example. Expect unfamiliar failures. |
| 7 | Additive engine change (new rule/detector/storage policy). Raise-only by construction. |
| 8 | Modifies existing risk classification. Needs maintainer design sign-off first. |
| 9 | Complete an extension seam: interface, registry, tests and docs. |
| 10 | New subsystem, multi-week. Design discussion before any code. |

The ladder is meant to be climbed: finish a level-N issue, and a level-(N+1) issue in the same
area is the natural next step. Where an issue depends on another, it names that prerequisite.

Commenting on an issue claims it. Level-8 and above additionally expect a design comment, agreed
with a maintainer, before any code.

Start with the
[`good first issue`](https://github.com/fu351/Doberman-Core/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)
or
[`help wanted`](https://github.com/fu351/Doberman-Core/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22)
labels to find level-1/2/3 work, or browse a specific rung directly, e.g.
[`level-1`](https://github.com/fu351/Doberman-Core/labels/level-1) (swap the number for any level
1-10). Good first PRs are usually narrow docs, tests, or guardrail hardening changes with a clear
issue to close.