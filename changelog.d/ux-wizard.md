- **`doberman setup` now has an honest end.** When the closing doctor pass finds a critical (most
  commonly `doberman` not yet on PATH), the wizard prints `-- Setup incomplete --`, skips the
  "Hooks written. Doberman activates..." claim, and exits `1` — never `complete` on top of a
  diagnostic that says tool calls go unmediated. `doberman status` marks an installed hook
  `(not on PATH)` when the same check fails.
- **Every wired host now ends on the same verification ritual.** Claude Code gets the "Verify it's
  live: ask your agent to read .env and confirm it is blocked." line Codex and the MCP proxy
  already had; the run's last two lines are that check and `doberman demo --fast`, with
  `doberman uninstall-hooks` moved just above them. A re-run whose hook files are already correct
  prints `already wired: <path>` instead of `wrote <path>`.
- **`doberman setup --dry-run`** previews the mode, the preference weights, and every file it would
  write, with nothing persisted (mirrors `install-hooks --dry-run`). `--global` now asks
  `[y/N]` before writing your real home directory (or, under `--yes`, prints the exact path first).
- **Output wraps to your terminal width** (60-120 columns) instead of printing 300+-char lines, and
  the security-mode summary, doctor severity, and section titles are colored (green/cyan/yellow/
  bright-red, NO_COLOR-respecting) instead of one shade of green.
- **Setup always reports telemetry state** in its closing summary (`Telemetry: on/off`), even when
  the one-time notice already fired on `--help`. "trifecta actions" is now glossed inline in the
  mode copy, and the wizard ends with a `Docs: docs/SETUP.md` pointer.
