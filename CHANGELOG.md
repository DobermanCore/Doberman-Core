# Changelog

This file records every user-visible change to Doberman, one line per change, newest release first.
Planned work lives on the [roadmap board](https://github.com/users/fu351/projects/5); each release also
gets its own [notes on GitHub](https://github.com/DobermanCore/Doberman-Core/releases).

Not yet released: [`changelog.d/`](changelog.d/), compiled into the next version.

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
Friction reduction, part three: repeat-approval memory, safer global uninstalls, and telemetry on by default.

### Added
- `doberman demo --quiet` suppresses narration and prints only the summary line and exit code, for CI smoke tests
- `doberman doctor` flags dangling hook entries when the installed `doberman` binary is no longer on PATH
- `doberman uninstall --global` removes hooks, project state, auth factors, and the package device-wide, gated the same as any other removal
- Repeated approvals get a five-minute memory: an identical action re-prompts with a one-click confirm instead of the full auth ladder

### Changed
- **Breaking:** anonymous usage telemetry is now on by default (five allowlisted events only, no paths/prompts/secrets); opt out with `doberman telemetry off`

### Fixed
- `doberman uninstall` now actually stops protection when hooks are installed globally, not just for the current project

## v0.18.3 — 2026-08-26
Tap-to-approve two-factor authentication with Windows Hello or Touch ID.

### Added
- 2FA can be approved with a Windows Hello or Touch ID tap instead of a TOTP code (`doberman 2fa methods enable`)

## v0.18.2 — 2026-08-26
Fewer spurious secret-detector prompts, opt-in telemetry, and a docs rewrite.

### Security
- Subjective-layer hardening: re-approving a changed tool pin resets its learned familiarity, destination hosts are HMAC-fingerprinted, and a changed tool's scope tokens are revoked immediately

### Added
- Anonymous CLI telemetry is available as an opt-in (`doberman telemetry on|off|status`)
- `doberman tune` reports friction telemetry and proposes possession-gated standing-elevations (#243)
- MCP tool schemas are pinned on first use; a later mismatch requires `doberman tools approve <tool_name>` (#246)
- Card numbers, IBANs, and SSNs in an outbound payload to an external destination now require authentication (#321)
- A shell command that only dumps the environment (`env`, `printenv`, `export`, PowerShell `Env:` listing) now requires authentication (thanks @QY-25123)
- OpenTelemetry `AuditSink` forwards redacted decisions to any OTLP/HTTP collector (#245, thanks @Maqbool61)
- `doberman scan --mcp` statically scans known MCP configs for risky patterns without running servers (#240)
- The dashboard can change strictness mode directly, gated like `doberman mode`; live-feed rows now show risk level and source context
- Every GitHub release now ships a CycloneDX SBOM (`sbom.json`) listing exact resolved dependencies

### Changed
- `doberman message-tone human|technical` switches auth-prompt wording between plain language and the technical format; human is now the default
- The auth dialog and dashboard are restyled onto Doberman's brand system, with a live ON GUARD / ALERT status pill and a per-project dashboard tab title

### Fixed
- The GUI auth dialog no longer silently fails to render off the main thread on macOS (#399)
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
- CLI diagnostics now use one consistent severity vocabulary: `error:`, `warning:`, `note:` (#344)

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
- `doberman scan/doctor/policy-history --json` and `doberman log --jsonl` emit machine-readable output through an explicit redaction allowlist (#207, #208, #210, thanks @NanoRisk6)
- `doberman scan --quiet` suppresses the risk map for scripted use (#208, thanks @NanoRisk6)
- `doberman taint clear` resets sticky session taint after verifying your strongest enrolled auth factor

### Changed
- `doberman dashboard` is renamed `doberman session-summary`; the old name still works (#267)
- Verdict output is now colored (`NO_COLOR`-safe) with fixed-width labels, and AUTH prompts state their auto-deny deadline (#252, #265)
- The dashboard's Approve control now needs two clicks to confirm; Deny stays one click, and light mode meets AA contrast (#261, #268)
- The setup wizard now re-prompts on a mistyped mode instead of losing your answers (#266)

### Docs
- README states the defense-in-depth disclaimer once (#264, thanks @slegarraga); hook help now points to the real `install-hooks` command (#263, thanks @AshSgDe29071999)
- New `docs/CLI.md` command reference and `docs/REASON_CODES.md` reason-code list (#208, #209, thanks @NanoRisk6)

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
