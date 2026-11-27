"""Live-Codex canary smoke test (W1.5).

Installs Doberman's Codex hook, asks a real ``codex exec`` to destroy a sentinel
file, and asserts the sentinel survived (the hook blocked the destructive call)
and a deny was recorded. Its whole purpose is to catch **upstream Codex API
churn** — if a new Codex release changes the hook payload/protocol so Doberman's
adapter stops firing, this goes red on a schedule instead of surfacing as a user
report.

NOT part of the hermetic CI test suite: it needs a live, authenticated Codex CLI
and network. Run from the scheduled ``codex-canary`` workflow (or by hand).

Exit codes:
  0 — PROTECTED: the sentinel survived and a deny was recorded (or the model
      never even issued the destructive call because the hook context stopped it).
  1 — PROTECTION FAILED: the sentinel was deleted — the hook did not gate the call.
  2 — INCONCLUSIVE: the sentinel survived but no deny was recorded (e.g. the model
      refused on its own, or `codex`/`doberman log` was unavailable). Not churn
      evidence; the workflow annotates rather than fails on this.
"""

from __future__ import annotations

import pathlib
import sys

from doberman.cli.codex_canary import CanaryStatus, run_codex_live_canary

SENTINEL = pathlib.Path("canary-sentinel.txt")


def main() -> int:
    outcome = run_codex_live_canary(path=".", install_hooks=True)
    if outcome.status is CanaryStatus.PROTECTED:
        print(f"CANARY GREEN: {outcome.detail}")
    elif outcome.status is CanaryStatus.FAILED:
        print(f"CANARY RED: {outcome.detail}")
    else:
        print(f"CANARY INCONCLUSIVE: {outcome.detail}")
    return outcome.exit_code


if __name__ == "__main__":
    sys.exit(main())
