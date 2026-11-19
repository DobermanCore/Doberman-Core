# Documentation

Use this index to find the right Doberman documentation for your task.

| Document | When to open it |
| --- | --- |
| [SETUP.md](SETUP.md) | Open this when installing Doberman, connecting it to a coding agent, setting up recovery, or confirming your installation works. |
| [CLI.md](CLI.md) | Open this when you need to find a `doberman` command, understand its options, or script against its JSON output and exit codes. |
| [REASON_CODES.md](REASON_CODES.md) | Open this when reading a Doberman decision or log and you need to understand why an action received `AUTH` or `BLOCK`. |
| [PARITY.md](PARITY.md) | Open this when checking which security guarantees are proven on each supported host and where coverage gaps remain. |
| [LIMITATIONS.md](LIMITATIONS.md) | Open this when you want the plain-language list of Doberman's known gaps: what each rule catches, what it misses, and why. |
| [CONTROL_COVERAGE.md](CONTROL_COVERAGE.md) | Open this when mapping Doberman's guardrails to the OWASP Top 10 for LLM Applications or the NIST AI RMF, e.g. for a security review or a compliance questionnaire. |
| [ADAPTER_GUIDE.md](ADAPTER_GUIDE.md) | Open this when building or understanding a coding-agent host integration and need to see how tool calls flow through Doberman's decision spine. |
| [CONNECTOR_MEMO_CURSOR.md](CONNECTOR_MEMO_CURSOR.md) | Open this when deciding whether and how to guard Cursor: the hook capability matrix, the fail-closed honesty test, and the envelope a v1 connector would use. |
| [CONNECTOR_MEMO_202_HOSTS.md](CONNECTOR_MEMO_202_HOSTS.md) | Open this before picking up the rest of #202: why the generic MCP bridge is mostly `doberman serve` already (transport gap only), why Continue CLI waits on upstream wiring, and why Aider has no supported interception surface. |
| [DESIGN_MEMO_639_HOST_HOOK_ADAPTIVE_LAYER.md](DESIGN_MEMO_639_HOST_HOOK_ADAPTIVE_LAYER.md) | Open this before working on #639: why the hook path should score the adaptive layer in process with a lazy `river` import rather than through a warm background process, with the measured cost of each, and what the issue's four open questions resolve to. Draft, awaiting sign-off. |
| [AUTHORITY_TIERS.md](AUTHORITY_TIERS.md) | Open this when you need to know which layer of a Doberman decision is allowed to `BLOCK` versus only ever step up to `AUTH`, and why. |
| [BENCHMARKS.md](BENCHMARKS.md) | Open this when evaluating Doberman's protection results, reproducing benchmark numbers, or understanding what those metrics do and do not prove. |
| [HELLO-HARDWARE-CHECKS.md](HELLO-HARDWARE-CHECKS.md) | Open this when testing the Windows Hello approval method on a real machine and recording what it does. |
| [RELEASING.md](RELEASING.md) | Open this when preparing and publishing a Doberman-Core release and verifying the required checks and evidence. |
| [ROADMAP.md](../ROADMAP.md) | Open this for a quick summary of what's planned or in progress, with a link to the full GitHub roadmap board. |
| [COMPANION-CONTRACT.md](COMPANION-CONTRACT.md) | Open this when building a local tool that reads Doberman's decision log, audit webhook, or dashboard approvals, and you need to know what stays stable. |
| [audit_otel.md](audit_otel.md) | Open this when sending Doberman's redacted decision records to an OpenTelemetry-compatible collector. |
| [PLUGINS.md](PLUGINS.md) | Open this when writing a custom guardrail rule or forwarding Doberman's redacted audit log to your own pipeline. |
| [EXTENDING.md](EXTENDING.md) | Open this when deciding which of Doberman's twelve entry-point seams (rules, detectors, policy sources, auth providers, audit sinks, and the rest) to plug a new integration into. |
| [RECOVERY.md](RECOVERY.md) | Open this when clearing sticky taint, approving a changed MCP tool, resetting learned memory, or removing Doberman from a project. |
| [BASELINE_SEEDING.md](BASELINE_SEEDING.md) | Open this when warming a fresh install's per-entity baseline from your own already-allowed traces with `doberman memory seed`. |
| [TELEMETRY.md](TELEMETRY.md) | Open this when you want to understand what anonymous usage data Doberman sends, what it never sends, or how to control telemetry. |
| [POLICY_VERSIONS.md](POLICY_VERSIONS.md) | Open this when you need to know which policy was in force at a given time, what a `pv1:` policy version id contains, or how to verify the policy catalogue. |
| [TUNING.md](TUNING.md) | Open this when adjusting Doberman's strictness, enforcement, roles, preference weights, friction settings, or message tone to match your risk tolerance. |
| [TURN_GATE.md](TURN_GATE.md) | Open this when you want to understand how Doberman inspects conversation turns before inference and how the turn gate works alongside the tool-call action gate. |