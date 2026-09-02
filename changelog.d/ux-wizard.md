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
- **A run that only wired `mcp`/`openclaw` now prints `-- Setup pending --`, never `complete`.**
  Nothing is running yet until you paste the printed block into your client and restart it, so the
  header, the "Hooks written" claim, and the closing verify line all say so honestly (exit stays
  `0` - this isn't an error). `doberman demo --fast` is still offered on this path, since the demo
  runs in-process either way.
- **The optional closing demo prompt can no longer fail a succeeded setup.** A closed/exhausted
  stdin (or Ctrl-C) there now falls back to the same static `See it work: \`doberman demo --fast\``
  pointer `--yes` prints, instead of raising.
- **Telemetry gets its own `-- Telemetry --` section**, moved to run after hosts are wired and
  before the doctor pass, with a one-line explanation of what is sent - no longer wedged between
  the mode and preference-tuning prompts.
- **The incomplete path ends on the remedy, not the success epilogue.** A critical doctor finding
  now prints only `Docs:`/`Check health:` and a red close naming the failing check and the first
  sentence of its detail - Telemetry/Next step/Change-your-mind no longer print underneath a run
  that isn't actually protecting anything yet.
- **Long lines wrap consistently with the section rule** (both capped at 78 columns), a `\S+` token
  containing `\` or `/` (a Windows path, a URL) is never split mid-token, and a doctor
  remediation's continuation lines now indent under the text instead of the `- ` marker.
- **`--help` leads with "Getting started"** - every command now carries an explicit help panel, so
  the unlabeled grab-bag Typer/Rich printed first (2fa, taint, plugins, ...) is gone.
- **`doberman status` leads with a `Protected: yes` / `Protected: no - <reason>` headline** (hooks
  installed for at least one host and `doberman` resolvable on PATH).
- **`--yes --mode light` over a higher mode now says so on stdout, not just stderr** -
  `Mode: balanced (requested light; not lowered - see 'doberman mode')` survives `2>/dev/null`.
- **`setup --dry-run` writes nothing, including telemetry state** - it previews
  `[dry-run] would record telemetry consent: on/off` instead of touching `~/.doberman/telemetry.json`
  the way every other `--dry-run` command already writes nothing.
- Re-prompt errors (a mistyped host or mode choice) now print `error: ...` on stderr instead of an
  unmarked line mixed into stdout.
