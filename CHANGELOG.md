# Changelog

This file records every user-visible change to Doberman, one line per change, newest release first.
Planned work lives on the [roadmap board](https://github.com/users/fu351/projects/5); each release also
gets its own [notes on GitHub](https://github.com/DobermanCore/Doberman-Core/releases).

Not yet released: [`changelog.d/`](changelog.d/), compiled into the next version.

## v0.18.6 — 2026-09-04
Closes detection bypasses and rebuilds setup, the dashboard, and the TUI.

### Security
- The destructive-command rule now scans a command-shaped argument whatever the tool is called, closing a gap where renaming the tool avoided detection (#519)
- Every rule/detector/auth-provider plugin is opt-in by name (`doberman plugins enable <name>`); role elevation now always also asks the local provider (#520)
- A password lockout now persists to disk across restarts, with the same 15-minute cooldown TOTP already had, instead of resetting on every new CLI process (#521)
- A single-use elevation grant is now claimed atomically; a losing concurrent call is blocked instead of both being allowed through (#522)
- The destructive-command rule and the egress walker now scan both sides of a single `&`, since both `cmd.exe` and POSIX shells run both commands (#524)
- A host-namespaced MCP tool (`mcp__<server>__write_file`) now classifies by its real tool name, so path and role rules apply instead of treating it as unknown (#525)
- Password guesses are counted before the hash runs, so parallel guesses can't dodge the lockout; an unrecordable attempt is refused (#526)
- A tool call's command line is rebuilt from `command` and `args` with boundaries kept, so a list-form payload can't dodge the scanner (#527)
- `doberman setup --yes` can no longer lower the security mode or preference weights past the possession-factor gate (#530)
- The GUI auth dialog no longer lets a keypress during closing flip an expired denial into an approval (#536)
- An unanswered approval now expires within 10 minutes instead of 20, so a `two_factor` challenge nobody answered can't stay approvable past its real deadline (#545)
- Reverse shells (`nc -e`, socat `EXEC:`, an inline socket that spawns a shell) now hard-block instead of prompting; probes and plain sockets are unchanged (#570)
- A Tk auth dialog no longer changes the hook's exit code on teardown, where a denied or expired action could execute if the hook crashed (#575)
- Mail addresses obfuscated as `[at]`/`(dot)`, spaced `@`, or bare `at`/`dot` words in untrusted input now trip the echo tripwire like literal ones (#578)
- The destructive-command rule now sees through shell syntax, `sudo`/`env`/`nice`/`timeout`-style wrappers, and nested command substitutions instead of stopping at them (#580)
- Process kills (`kill`, `pkill`, `taskkill`, `Stop-Process`, `os.kill`) and interpreter one-liners that spawn a subprocess now require authentication (#580)
- Every command-scan bound now fails upward to authentication instead of skipping, and a package-manager verb hidden behind wrapper options no longer gets the implied-registry pass (#580)

### Added
- Every saved policy now gets a content-hash version in `.doberman/policies.db`; `doberman policy-versions` lists them, `--show` prints one, `--verify` checks the catalogue (#513)
- `doberman setup` now asks which hosts to guard, with detected hosts preselected, `--host` repeatable, and a doctor pass at the end (#528)
- The dashboard gets verdict/text filters, keyboard shortcuts (`/`, arrows, `a`/`d`, `?` for help), a live countdown on pending cards, and a light/dark toggle (#533)
- `doberman tui` is now a full decision browser: verdict/risk chips, a full-screen `why` view, filtering, and jump/copy keys; `doberman log --why` prints the same explanation (#534)
- `doberman setup --dry-run` now previews the mode, preferences, and every file it would write, with nothing persisted (#535)
- The GUI auth dialog is rebuilt: a bounded, expandable command panel, a severity chip for risk, and a live countdown extendable up to 10 times (#536)
- The destructive-command rule now recognizes raw-socket egress shapes (`/dev/tcp`, netcat/socat exec, `openssl s_client`, an inline socket payload) and steps them up to `AUTH` (#538)
- Added an experimental, offline-only BYO-model judge behind the `[judge]` extra; it is not wired into any live decision yet (#539)
- A new verification-integrity rule pack requires authentication for `git commit --no-verify`-style bypasses and for deleting or renaming a test file (#541)
- A new offline dependency admission gate blocks a known-malicious package name and authenticates a likely typosquat (one character off a popular name) (#543)
- A host, URL, or email seen in a `WebFetch`/`WebSearch` result now raises a later egress to that exact value from allowed to authentication-required (#547)
- A delete-class command (`rm`, `del`, `Remove-Item`, ...) reaching an AUTH challenge now shows a bounded file/directory count, and re-blocks if the filesystem changed since approval (#548)
- `install-hooks` now fingerprints its own hook registration and warns if a hook is later stripped or changed; `doberman doctor` reports intact, diverged, or untracked (#561)
- Benchmark harness gains RedCode-Exec, MSB, and LLMail-Inject suite adapters (`DOBERMAN_BENCH_*_DIR`, no data vendored); measured numbers and documented gaps live in `docs/BENCHMARKS.md` (#562)
- Opt-in `--replay-session` harness mode replays each case in an isolated session with the real post-decide floors; every report is labeled `session_replay: true/false` (#562)
- Command-shaped benchmark actions classify egress through the proxy's own destination extractor, so the harness measures shipped behavior instead of under-reporting it (#562)
- The auth dialog window now carries the Doberman mark as its icon instead of Tk's default feather (#565, thanks @thesageak)
- Experimental Cursor native-hooks adapter: `doberman hook cursor` gates Cursor's tool-use events on the same decision engine as Claude Code and Codex (#568)
- `doberman install-hooks --host cursor` wires Cursor's hooks and a session heartbeat; `doberman doctor` gets a new "Cursor hooks" check (#571)
- `doberman serve --url` now fronts a remote MCP server (Streamable HTTP or `--transport sse`) through the same policy chokepoint as a local command (#574)
- A repo-committed `doberman.policy.yaml` is now resolved on every action, so teams can review policy changes in pull requests; dropping a glob needs `doberman policy-file --accept` (#579)
- `doberman memory seed --from traces.jsonl` warms a fresh install's behavioral baseline from operator-supplied allowed-action traces (#579)
- `whole_script_confusable` flags a token written entirely in Latin-lookalike Cyrillic or Greek letters (an all-Cyrillic "paypal") and steps it up to `AUTH` (#579)
- A `doberman.cost_observers` plugin can now receive loop anomalies via an optional `on_loop_anomaly` hook (#579)
- A worked example detector plugin ships at `examples/plugin-detector/`, alongside `docs/EXTENDING.md` documenting every entry-point group (#579)

### Changed
- `doberman setup` now shows the mode in force, scopes its doctor pass to your wired hosts, and offers `doberman demo` before you leave (#530)
- Deny is now the dashboard's primary action and needs the same two-step confirm as Approve; lowering the security mode needs the same confirm gesture (#533)
- `doberman setup` now ends honestly: `-- Setup complete/pending/incomplete --` with exit codes 0/1/3, and its output wraps and colors like `doberman status`/`doctor` (#535)
- The subjective-layer benchmark diagnostic reports a held-out-benign false-positive rate next to the AUC and gains a seeded `--suite devsession` corpus that engages the full ensemble (#542)

### Fixed
- The auth dialog now shows a keyboard hint (`Tab/Arrows: switch - Enter: confirm - Esc: deny`) and grows to fit it instead of clipping (#507, thanks @thesageak)
- The dashboard's mode-change form now actually closes, and approve/deny, live-feed, and refresh failures show in the UI instead of failing silently (#533)
- An unanswered approval-memory lookup no longer hangs the hook, falling back to a prompt after 5 seconds; an aborted `setup` run reports what was written (#535)
- The GUI auth dialog now scales correctly under DPI scaling and works with screen readers (#536)
- Fixed a `doberman tui` crash on startup caused by a mount-timing race in the first row's highlight (#546)
- A mailbox destination (`local@domain`, `mailto:`) no longer triggers a false "embeds credentials" prompt on every mail send in Light/Balanced (#564)
- `doberman hook cursor` now reads stdin as raw UTF-8 bytes, so the BOM Windows `cursor-agent` emits no longer turns every hook into a deny (#571)
- `doberman hook pre` now answers Cursor-shaped payloads instead of failing closed, which had denied every Cursor shell command on machines with global hooks installed (#576)
- The test suite no longer touches your real Claude settings: every test gets a throwaway home and a guard fails the run if it changes (#577)

### Docs
- Added `docs/AUTHORITY_TIERS.md`, documenting which layer of a decision may `BLOCK` versus only step up to `AUTH` (#544)
- Added `docs/CONTROL_COVERAGE.md`, mapping Doberman's controls to the OWASP Top 10 for LLM Applications and the NIST AI RMF (#579)
- `docs/BENCHMARKS.md`: RedCode rows re-measured on `main` after the reverse-shell and command-walk hardening; in-scope ASR 0.104 → 0.010, only 7 print-only variants remain (#584)

## v0.18.5 — 2026-08-30
Decision-log retention, update nudges, and dashboard polish.

### Added
- `doberman decision-log-prune` deletes resolved rows by age or row budget; pending approvals and the policy ledger are untouched (#461, #502)
- `doberman update` checks PyPI once and prints the upgrade command; `doberman status` nudges when you are behind. Off under `DO_NOT_TRACK`, `CI`, or `DOBERMAN_UPDATE_CHECK=off` (#508)
- Dashboard: a **Copy details** action on each pending card copies the redacted fields as JSON (#498, thanks @slegarraga)
- `doberman doctor` reports the password factor and the optional dash/tui extras (#474, #475, thanks @slegarraga)
- `doberman egress-velocity [KNOB] [VALUE]` shows or sets the burst, volume, and fan-out detection thresholds (#459, thanks @Maqbool61)

### Changed
- Changelog entries now compile from a per-PR `changelog.d/` fragment instead of one shared file, so parallel PRs stop colliding (#476, thanks @slegarraga)

### Fixed
- `install-hooks --dry-run` now previews the exact command the installer writes (#463, thanks @slegarraga)
- `tune --json` output is compact like every other JSON command (#470, thanks @slegarraga)
- `doberman log` columns no longer shift for long action types like `network_request` (#472, thanks @slegarraga)
- The dashboard stats strip now updates immediately instead of lagging behind the live feed (#491)
- The dashboard header shows the real Doberman mark instead of a placeholder "D" (#490)

### Docs
- `docs/README.md` indexes every doc page (#492, #500, thanks @navaneethsankar07)

## v0.18.4 — 2026-08-27
Friction reduction, part three: tap-to-approve 2FA, repeat-approval memory, safer uninstalls, and default telemetry.

### Added
- 2FA can be approved with a Windows Hello or Touch ID tap instead of a TOTP code (`doberman 2fa methods enable`)
- `doberman demo --quiet` suppresses narration and prints only the summary line and exit code, for CI smoke tests
- `doberman doctor` flags dangling hook entries when the installed `doberman` binary is no longer on PATH
- `doberman uninstall --global` removes hooks, project state, auth factors, and the package device-wide, gated the same as any other removal
- Repeated approvals get a five-minute memory: an identical action re-prompts with a one-click confirm instead of the full auth ladder

### Changed
- **Breaking:** anonymous usage telemetry is now on by default (five allowlisted events only, no paths/prompts/secrets); opt out with `doberman telemetry off`

### Fixed
- `doberman uninstall` now actually stops protection when hooks are installed globally, not just for the current project

## v0.18.2 — 2026-08-26
Fewer spurious secret-detector prompts, opt-in telemetry, and a docs rewrite.

### Security
- Re-approving a changed tool pin now resets its learned familiarity and revokes the tool's scope tokens immediately

### Added
- Anonymous CLI telemetry is available as an opt-in (`doberman telemetry on|off|status`)
- `doberman tune` reports friction telemetry and proposes possession-gated standing-elevations (#403)
- MCP tool schemas are pinned on first use; a later mismatch requires `doberman tools approve <tool_name>` (#394)
- Card numbers, IBANs, and SSNs in an outbound payload to an external destination now require authentication (#392)
- A shell command that only dumps the environment (`env`, `printenv`, `export`, PowerShell `Env:` listing) now requires authentication (#455, thanks @QY-25123)
- OpenTelemetry `AuditSink` forwards redacted decisions to any OTLP/HTTP collector (#368, thanks @Maqbool61)
- `doberman scan --mcp` statically scans known MCP configs for risky patterns without running servers (#393)
- The dashboard can change strictness mode directly, gated like `doberman mode`; live-feed rows now show risk level and source context
- Every GitHub release now ships a CycloneDX SBOM (`sbom.json`) listing exact resolved dependencies

### Changed
- `doberman message-tone human|technical` switches auth-prompt wording between plain language and the technical format; human is now the default
- The auth dialog and dashboard are restyled onto Doberman's brand system, with a live ON GUARD/ALERT status pill and a per-project dashboard tab title
- Destination hosts in the decision log are stored as HMAC fingerprints instead of plain names

### Fixed
- The GUI auth dialog no longer silently fails to render off the main thread on macOS (#453, thanks @harshitagrawal2O)
- The secret detector no longer flags ordinary identifiers, paths, UUIDs, or build tags as leaked secrets, and fails closed if it can't evaluate
- Clicking a keyboard-highlighted auth-dialog button (Deny or Approve) now actually registers the click

### Docs
- Every page under `docs/`, the README, and `CONTRIBUTING.md` were rewritten for accuracy; new site at docs.trydoberman.dev

## v0.18.1 — 2026-08-15
A documentation fix for broken images on PyPI.

### Docs
- The README's logo and demo GIF now use absolute URLs so they render correctly on the PyPI project page

## v0.18.0 — 2026-08-15
Security-audit fixes, a new detection and role-governance layer, and CLI polish.

### Security
- The proxy output-secret gate now covers error results and structured or embedded response channels, closing a leak path (#378)
- Control-plane state (the TOTP seed, password hash) and Windows-style path separators are both now correctly recognized as protected, closing two bypasses (#379, #380)
- The lethal-trifecta floor (sensitive data, untrusted provenance, and an external destination) now also fires at the objective layer in Strict and Paranoid modes
- The destructive-command rule now recognizes PowerShell and cmd deletes (`Remove-Item`, `rmdir`, `del`, `Format-Volume`), not just POSIX `rm`/`dd`/`mkfs`
- Deleting an unrecoverable gitignored file (`*.db`, `.env`, `*.key`) now requires authentication instead of passing silently
- The dashboard no longer writes its signed session URL token to server logs (#286)

### Added
- `doberman uninstall` removes this project's hooks and `.doberman/`, gated behind your password or 2FA (#375, thanks @QY-25123)
- `doberman role enable-default` turns on a built-in least-privilege role for repos with no hand-written role file
- `doberman memory reset` and `doberman memory prune --older-than-days N` manage the learned per-entity behavioral memory
- A new detector flags suspiciously large base64-looking blobs in tool-call arguments as possible bulk exfiltration
- `doberman 2fa reset-lockout` clears the TOTP lockout early, gated on your local password (#285)
- `doberman --install-completion` enables shell tab completion (#280, thanks @slegarraga)
- `WebhookAuditSink` posts every redacted decision to your own log pipeline via `.doberman/audit_webhook.yaml` (#317, thanks @Maqbool61)
- Python 3.13 is now a supported and tested version (#328, thanks @jasperdingg)

### Changed
- An unanswered AUTH challenge is now logged and reported as a timeout rather than a denial (#281)
- `--help` now groups commands into panels, and `uninstall-hooks`/`setup` state what's left behind and how to exit (#276, #279, thanks @slegarraga)
- CLI diagnostics now use one consistent severity vocabulary: `error:`, `warning:`, `note:` (#346, thanks @floze-the-genius)

### Fixed
- The session correlator no longer flags reading a credential when the user's own earlier prompt named the destination
- `doberman doctor`'s Codex check no longer false-warns on Windows; denial messages no longer assume Claude Code under Codex

### Docs
- README and the setup guide warn that `uninstall-hooks` must run before `pip uninstall doberman-core` (#373, thanks @QY-25123)
- `docs/CLI.md` documents every CLI command including `log --jsonl`; new `docs/ADAPTER_GUIDE.md` covers writing a host adapter (#295, #297, #316, thanks @AshSgDe29071999)
- Docs confirm the MCP proxy blocks credential-carrying tool output too, not just the host hook (#374, thanks @jasperdingg)

## v0.17.1 — 2026-08-07
Bug fixes, machine-readable CLI output, and a session-taint reset command.

### Security
- An `AuthProvider` plugin raising a non-`Exception` (like `SystemExit`) no longer leaves an action neither approved nor denied; it now counts as a denial

### Added
- `doberman scan/doctor/policy-history --json` and `doberman log --jsonl` emit machine-readable output through an explicit redaction allowlist (thanks NanoRisk6)
- `doberman scan --quiet` suppresses the risk map for scripted use (thanks NanoRisk6)
- `doberman taint clear` resets sticky session taint after verifying your strongest enrolled auth factor

### Changed
- `doberman dashboard` is renamed `doberman session-summary`; the old name still works (#267)
- Verdict output is now colored (`NO_COLOR`-safe) with fixed-width labels, and AUTH prompts state their auto-deny deadline (#252, #265)
- The dashboard's Approve control now needs two clicks to confirm; Deny stays one click, and light mode meets AA contrast (#261, #268)
- The setup wizard now re-prompts on a mistyped mode instead of losing your answers (#266)

### Docs
- README states the defense-in-depth disclaimer once (#264, thanks @slegarraga); hook help now points to the real `install-hooks` command (#263, thanks @AshSgDe29071999)
- New `docs/CLI.md` command reference and `docs/REASON_CODES.md` reason-code list (thanks NanoRisk6)

## v0.17.0 — 2026-07-30
The egress-broker extension point, plus AUTH-timeout and path-matching fixes.

### Security
- An unanswered AUTH challenge now denies on a wall-clock deadline instead of hanging indefinitely
- Trailing dots and spaces in a path are now stripped before matching a protected-path rule, closing a padded-spelling bypass on Windows

### Added
- A runtime egress-broker extension point lets a forward proxy verify and enforce network destinations; dormant until a broker is registered
- `doberman 2fa remove` unenrolls TOTP
- CI/CD config protection now covers GitLab CI, Jenkins, CircleCI, and Azure Pipelines, not just GitHub Actions (#164, thanks @harshitagrawal2O)

### Changed
- The `devops` role no longer allow-lists GitHub Actions workflows; CI config edits now escalate to authentication like every other role
- CLI output is now color-coded by verdict and wraps long explanations to the terminal width

### Fixed
- The dashboard now keeps you signed in across a reload, and the 2-second poll no longer clears an in-progress TOTP entry

## v0.16.0 — 2026-07-23
Raw shell and package commands are now scanned for hidden network egress.

### Added
- Doberman now parses the raw shell, package, and git command and detects a network destination hidden inside it, even through `env` or a wrapper
- A command that both touches a session secret and reaches an external destination now hard-blocks; an ambiguous or unresolvable destination requires authentication

### Fixed
- The reported version number is now sourced from installed package metadata, so it can't drift from what's published

## v0.15.0 — 2026-07-19
First PyPI release: the turn gate, a live dashboard, and a demo reel.

### Security
- A hardening pass across 17 pull requests closed proxy and host-hook secret-redaction gaps and persisted the TOTP lockout across restarts

### Added
- The turn gate now extends per-call lethal-trifecta protection across a whole multi-step turn, with provenance inheritance and risk clamping between related actions
- `doberman dash` (`pip install "doberman-core[dash]"`) is a local dashboard with a live decision feed, verdict stats, and interactive approve/deny for AUTH prompts
- `doberman demo` runs a scripted attack reel — secret exfiltration, `rm -rf ~`, a force-push, Unicode-smuggled egress — through the real decision engine

### Docs
- New `CONTRIBUTING.md` guide for external contributors

## v0.11.0 — 2026-06-17
First public release: tool mediation, guardrails, roles, and tiered authentication.

### Added
- The decision engine mediates every tool call into an allow, authenticate, or block verdict
- Objective guardrail rules cover path confinement, destructive commands, external destinations, secret patterns, and smuggled-token channels
- A subjective guardrail layer builds adaptive per-entity behavioral baselines and flags out-of-distribution and homoglyph token signals
- Roles and repo boundaries, capability discovery, and tiered auth from a local confirm up to TOTP and scoped elevation
- A local redacted audit log and raise-only policy-drift defense
- `doberman serve` runs a stdio MCP proxy in front of any MCP server
