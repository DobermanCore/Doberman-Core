# Telemetry

Doberman can send anonymous usage counts: which commands and modes people use, and whether they
keep using it. Telemetry is **on by default**. The first command you run prints a one-line notice
saying so, and nothing is sent until that notice has been shown. `doberman setup` asks once on its
interactive path (default Yes). `doberman setup --yes` keeps the default and prints the notice
instead of asking. Turn it off at any time with `doberman telemetry off` or any kill switch below.
That choice is recorded and never asked again.

## What is sent

Every event includes only these fixed properties:

| Property | Value |
|---|---|
| `$process_person_profile` | `false` (PostHog does not create a person profile) |
| `$geoip_disable` | `true` (PostHog does not enrich the event from the connection IP) |
| `$lib` | `doberman-cli` |
| `version` | The installed Doberman version |
| `os` | The operating-system family, such as `windows`, `linux`, or `darwin` |
| `python` | The Python major and minor version, such as `3.11` |

The event-specific data is:

| Event | When | Extra properties |
|---|---|---|
| `telemetry_enabled` | Telemetry is enabled | None |
| `telemetry_disabled` | Telemetry is disabled; this is sent before the local flag changes | None |
| `setup_completed` | Setup finishes successfully | `mode`, `host`, `hooks_installed`, `global_install`, `source` |
| `cli_command` | A CLI command runs, except `hook`, `serve`, and `telemetry` | `command` (the command name only, such as `doctor` or `taint.clear`) |
| `usage_summary` | At most once every 24 hours, alongside a CLI command | Lifetime `total`, `pass`, `auth`, and `block` counts, plus `days_since_first_seen` |

Doberman also sends a random UUID as the event's distinct id and a UTC event timestamp. The id is
created when telemetry is first enabled. It is not derived from the machine, user, hostname, or
repository.

## What is never sent

Doberman does not send paths, file contents, prompts, tool arguments, hostnames, repository names,
reason codes, secrets, or raw decision records. It does not add an IP property. GeoIP enrichment is
disabled on every event. It also disables PostHog person profiles.

Event properties use a fixed allowlist. Values must be a string, number, boolean, or null. Strings
must be at most 64 characters and contain only letters, numbers, `_`, `.`, `+`, or `-`. An event
that fails this check is dropped.

Telemetry runs only in CLI command handling. The per-tool hook (code that runs before or after each
tool call) and MCP (Model Context Protocol) proxy paths do not call it. Sending is best-effort in a
daemon thread. A network failure does not change a command's exit code. Shutdown waits no more than
one second in total for pending sends.

## Turn it on, off, or check it

```bash
doberman telemetry on
doberman telemetry status
doberman telemetry off
```

`doberman telemetry status` says `enabled (default; ...)` until you make an explicit choice. The
interactive `doberman setup` flow asks once. The default answer is Yes.

These environment variables force telemetry off even when the local state says enabled:

- `DO_NOT_TRACK` set to any non-empty value other than `0`
- `DOBERMAN_TELEMETRY=0`, `false`, or `off`
- `CI` set to any non-empty value

`doberman telemetry status` shows active kill switches.

The consent state and random id live at `<DOBERMAN_HOME or home>/.doberman/telemetry.json`. Turning
telemetry off keeps the id stable in case it is enabled again. Delete that file to reset the id.

The PostHog project key in the client is public, like other PostHog ingestion keys. Events go to
PostHog Cloud US at `us.i.posthog.com`.
