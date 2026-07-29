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
# Windows PowerShell: .venv\Scripts\Activate.ps1
# Windows Command Prompt: .venv\Scripts\activate.bat
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

## Architecture in five lines

1. A tool call enters Doberman through the MCP proxy or host-hook path.
2. The call is normalized into a `SecurityObject`.
3. The decision engine runs objective and adaptive guardrails.
4. Guardrail verdicts merge through raise-only `combine()`.
5. The execution gate returns PASS / AUTH / BLOCK: allow, authenticate, or block.

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

Start with the
[`good first issue`](https://github.com/fu351/Doberman-Core/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)
or
[`help wanted`](https://github.com/fu351/Doberman-Core/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22)
labels. Good first PRs are usually narrow docs, tests, or guardrail hardening
changes with a clear issue to close.
