# Cursor adapter (experimental)

Doberman guards Cursor (the IDE and the `cursor-agent` CLI) through Cursor's native
[hooks](https://cursor.com/docs/hooks): one command, `doberman hook cursor`, registered for every
gating event. Each tool call reaches Doberman **before** it runs and is answered with Cursor's
`{"permission": "allow" | "deny"}` document. The decision memo behind the design is
[`docs/CONNECTOR_MEMO_CURSOR.md`](../../docs/CONNECTOR_MEMO_CURSOR.md).

> **Status: experimental.** The adapter is built from Cursor's documentation and two staff-confirmed
> forum details, not from a live capture; `doberman install-hooks --host cursor`, the manifest
> scope, the `sessionStart` heartbeat and the `doctor` checks arrive in the next slice. Until then
> the registration below is manual.

## Register the hook

Create `.cursor/hooks.json` at the project root (or `~/.cursor/hooks.json` for every project) with
`"failClosed": true` on every entry — Cursor's own default is **fail-open** on a hook crash or
timeout, and this flag is what turns that into a deny:

```json
{
  "version": 1,
  "hooks": {
    "preToolUse":          [{ "command": "doberman hook cursor", "timeout": 60, "failClosed": true }],
    "beforeShellExecution": [{ "command": "doberman hook cursor", "timeout": 60, "failClosed": true }],
    "beforeMCPExecution":  [{ "command": "doberman hook cursor", "timeout": 60, "failClosed": true }],
    "beforeReadFile":      [{ "command": "doberman hook cursor", "timeout": 60, "failClosed": true }],
    "sessionStart":        [{ "command": "doberman hook cursor", "timeout": 10, "failClosed": false }]
  }
}
```

`timeout` is in seconds and must cover Doberman's own approval dialog: an `AUTH` verdict pops the
GUI/TTY challenge **inside** the hook, so a value shorter than the human's reaction time turns every
approval into a deny. Sixty seconds matches the approval deadline; raise it if you set a longer one.
`doberman` must be on the `PATH` Cursor launches hooks with (a `pipx` install is).

Restart Cursor after editing the file. Cursor loads hooks at startup only.

## Verify it is wired

Ask the agent to run a destructive command, for example `rm -rf /tmp/doberman-probe` after
creating that directory. The command must **not** run: Cursor shows Doberman's `user_message`
(verdict, reason codes, action id, next step) and the model receives the same line as
`agent_message`. `doberman status` shows the decision in the log. If the command ran, the hook is
not registered — check the file location, restart Cursor, and check `doberman hook cursor` on the
command line:

```bash
echo '{"hook_event_name":"beforeShellExecution","conversation_id":"c","generation_id":"g","command":"rm -rf /","cwd":"."}' | doberman hook cursor
echo "exit $?"   # -> {"permission": "deny", ...} and exit 2
```

## What is gated

| Cursor event | Doberman action | Notes |
|---|---|---|
| `preToolUse` — `Shell` | `bash` | the universal chokepoint; `command` + `cwd` |
| `preToolUse` — `Write` / `Read` / `Delete` | `file_write` / `file_read` / `file_delete` | `file_path` (also `path` / `target_file`); no path → deny |
| `preToolUse` — `Grep`, `Task`, unknown tools | generic evaluation | never abstained |
| `preToolUse` — `MCP:<tool>` | `<tool>` | same translation as the MCP proxy: a filesystem server's `write_file` maps to a file write |
| `beforeShellExecution` | `bash` | `command` + `cwd` |
| `beforeMCPExecution` | `<tool_name>` | `tool_input` is a JSON string; unparseable → deny |
| `beforeReadFile` | `file_read`, then an **output scan** of `content` | a credential in the file never reaches the model; the session is tainted and the value fingerprinted, so a later egress of it is a confirmed exfil |
| `sessionStart` | acknowledged with `{}` | heartbeat lands with the installer slice |

Verdicts: `PASS` → `{"permission": "allow"}` (explicit, exit 0). `BLOCK` → `deny` **and** exit code 2
(Cursor treats either as a block, so a lost document still blocks). `AUTH` → Doberman's own
action-bound challenge inside the hook, then allow or deny; never `ask`, because Cursor's approval
system ignores a hook's `allow` / `ask`.

Malformed input fails closed: a non-JSON or non-object payload, a missing or unknown
`hook_event_name`, a path-gated tool whose path is missing, an unparseable MCP `tool_input`, and
any engine error all deny. A leading UTF-8 BOM (which `cursor-agent` on Windows prefixes to hook
stdin — Cursor forum #168407, staff-confirmed, no fix ETA) is stripped first.

A shell or MCP call registered on both `preToolUse` and its `before*` event reaches Doberman
twice. The first channel records its answer under a keyed marker for `(conversation_id,
generation_id, action)` and the other channel replays it, so one approval never doubles. The same
channel never replays: a repeated identical action inside one generation is evaluated (and
challenged) again.

`.cursor` and `.cursor/hooks.json` are part of Doberman's control plane: writes, deletes and shell
commands naming them are hard-blocked in every host, and the rest of `.cursor/**` (rules, MCP
config) requires approval.

## Known limits

- **Doc-derived payload shapes.** Cursor's hook payloads are documented, and `Shell`'s
  `command` / `cwd` and `Write`'s `file_path` / `content` are staff-confirmed, but the adapter has
  not yet been run against a captured session. A tool whose path arrives under a spelling the
  adapter does not know is **denied**, never waved through — report it and it will be added.
- **`beforeReadFile` attachments are not gated.** Cursor sends `attachments` alongside the file;
  v1 scans `content` only.
- **`sessionStart` is acknowledged, not recorded** until the installer slice adds the heartbeat.
- **No self-check yet.** `doberman doctor` does not inspect `.cursor/hooks.json` until the installer
  slice; verify the wiring by hand (above) after every Cursor update.
- **Enterprise / Team hooks win.** Cursor merges hooks Enterprise > Team > Project > User; an
  organisation policy can remove the registration. Re-verify after a policy change.
- **Trust model.** As with every hook-based host, Cursor itself is trusted: a Cursor release that
  stops honouring `deny` or `exit 2` bypasses the adapter. The MCP proxy is the alternative for a
  process-level boundary.
