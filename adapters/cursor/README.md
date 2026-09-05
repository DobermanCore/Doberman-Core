# Cursor adapter (experimental)

Doberman guards Cursor (the IDE and the `cursor-agent` CLI) through Cursor's native
[hooks](https://cursor.com/docs/hooks) (scripts Cursor runs at a fixed point, such as before a tool
call): one command, `doberman hook cursor`, registered for every gating event. Each tool call
reaches Doberman **before** it runs and is answered with Cursor's
`{"permission": "allow" | "deny"}` document. The decision memo behind the design is
[`docs/CONNECTOR_MEMO_CURSOR.md`](../../docs/CONNECTOR_MEMO_CURSOR.md).

> **Status: experimental.** The adapter is built from Cursor's documentation and two staff-confirmed
> forum details, not from a live capture.

## Install

```bash
doberman install-hooks --host cursor              # project .cursor/hooks.json
doberman install-hooks --host cursor --global      # ~/.cursor/hooks.json (every project)
```

Then restart your Cursor session so it reloads `hooks.json`. Cursor loads hooks at startup only.
`doberman uninstall-hooks --host cursor` reverses it; the install manifest also records the write,
so a plain `doberman uninstall` cleans up the project scope too.

What it writes: every gating event carries `"failClosed": true` (Cursor's own default is
**fail-open** on a hook crash or timeout, and this flag is what turns that into a deny):

```json
{
  "version": 1,
  "hooks": {
    "preToolUse":          [{ "command": "doberman hook cursor", "timeout": 120, "failClosed": true }],
    "beforeShellExecution": [{ "command": "doberman hook cursor", "timeout": 120, "failClosed": true }],
    "beforeMCPExecution":  [{ "command": "doberman hook cursor", "timeout": 120, "failClosed": true }],
    "beforeReadFile":      [{ "command": "doberman hook cursor", "timeout": 120, "failClosed": true }],
    "sessionStart":        [{ "command": "doberman hook cursor", "timeout": 10, "failClosed": false }]
  }
}
```

`timeout` is in seconds and must cover Doberman's own approval dialog: an `AUTH` verdict pops the
GUI/TTY challenge **inside** the hook, so a value shorter than the human's reaction time turns every
approval into a deny. 120s comfortably outlasts the 90s approval window. `sessionStart` is a cosmetic
liveness heartbeat (`failClosed: false`, so a failed write never aborts a session), so its timeout is
short. `doberman` must be on the `PATH` Cursor launches hooks with (a `pipx` install is).

## Self-check

`doberman doctor`'s **"Cursor hooks"** line reports the live registration, not just "is something
installed": a weak registration (a missing gating event, or `failClosed` not `true`) is a **FAIL**;
wired but no session has called `sessionStart` back yet is a **WARN** ("open this project in Cursor
and re-run doctor"); a low timeout is a non-critical WARN. The install-integrity manifest also covers
`.cursor/hooks.json` (including `failClosed` and `timeout`, not just presence), so a hand-weakened
file is reported the next time a surviving hook runs, and by `doctor`'s "Hook integrity" check.

## Verify it is wired

Ask the agent to run a destructive command, for example `rm -rf /tmp/doberman-probe` after
creating that directory. The command must **not** run: Cursor shows Doberman's `user_message`
(verdict, reason codes, action id, next step) and the model receives the same line as
`agent_message`. `doberman status` shows the decision in the log. If the command ran, the hook is
not registered. Check the file location, restart Cursor, and check `doberman hook cursor` on the
command line:

```bash
echo '{"hook_event_name":"beforeShellExecution","conversation_id":"c","generation_id":"g","command":"rm -rf /","cwd":"."}' | doberman hook cursor
echo "exit $?"   # -> {"permission": "deny", ...} and exit 2
```

## What is gated

| Cursor event | Doberman action | Notes |
|---|---|---|
| `preToolUse` (`Shell`) | `bash` | the one chokepoint every shell command passes through; `command` + `cwd` |
| `preToolUse` (`Write` / `Read` / `Delete`) | `file_write` / `file_read` / `file_delete` | `file_path` (also `path` / `target_file`); no path → deny |
| `preToolUse` (`Grep`, `Task`, unknown tools) | generic evaluation | never abstained |
| `preToolUse` (`MCP:<tool>`) | `<tool>` | same translation as the MCP (Model Context Protocol, the standard way an agent calls external tool servers) proxy: a filesystem server's `write_file` maps to a file write |
| `beforeShellExecution` | `bash` | `command` + `cwd` |
| `beforeMCPExecution` | `<tool_name>` | `tool_input` is a JSON string; unparseable → deny |
| `beforeReadFile` | `file_read`, then an **output scan** of `content` | a credential in the file never reaches the model; the session is tainted (flagged as having touched something sensitive) and the value fingerprinted (given a keyed hash so it can be recognized again), so a later egress (the value leaving the system) is a confirmed exfiltration (data theft) |
| `sessionStart` | acknowledged with `{}` | best-effort liveness heartbeat written to `.doberman/`, read by `doberman doctor` |

Verdicts: `PASS` → `{"permission": "allow"}` (explicit, exit 0). `BLOCK` → `deny` **and** exit code 2
(Cursor treats either as a block, so a lost document still blocks). `AUTH` → Doberman's own
action-bound challenge inside the hook, then allow or deny; never `ask`, because Cursor's approval
system ignores a hook's `allow` / `ask`.

Malformed input fails closed: a non-JSON or non-object payload, a missing or unknown
`hook_event_name`, a path-gated tool whose path is missing, an unparseable MCP `tool_input`, and
any engine error all deny. A leading UTF-8 BOM (which `cursor-agent` on Windows prefixes to hook
stdin, per Cursor forum #168407, staff-confirmed, with no fix ETA) is stripped first.

A shell, MCP or read call registered on both `preToolUse` and its `before*` event reaches
Doberman twice, or three times if the Claude-compat path below is also wired. The first call
records its answer under a keyed marker for `(conversation_id, generation_id, action)`; every other
call replays it, but only the closing `before*` event consumes the marker (never a `preToolUse`
replay), so the answer survives until the last call, not just the second, and one approval never
doubles or is reused. The same channel never replays: a repeated identical action inside one
generation is evaluated (and challenged) again. A replayed `beforeReadFile` still scans the file
content; only the path decision is shared.

`.cursor` and `.cursor/hooks.json` are part of Doberman's control plane: writes, deletes and shell
commands naming them are hard-blocked in every host, and the rest of `.cursor/**` (rules, MCP
config) requires approval.

## Cursor also runs your Claude Code hooks

Cursor's **"Third Party Hooks"** setting loads Claude Code hooks straight out of the Claude settings
files and calls them with Cursor's own payload shape (event names remapped: `PreToolUse` →
`preToolUse`, `PostToolUse` → `postToolUse`, `SessionStart` → `sessionStart`, …). So on any machine
where Doberman's **global Claude Code hooks** are installed (`doberman install-hooks --global`),
`doberman hook pre` receives Cursor's `preToolUse` calls too, and now recognises and answers them
through this Cursor adapter, so a project is gated even *before* `install-hooks --host cursor` is run
there. Installing both is fine: whichever call fires first evaluates the action and every later call
(up to three total for a paired shell/MCP/read action) replays that answer (single-flight), so it is
never evaluated or challenged twice. The `SessionStart` →
`sessionStart` mapping also fires `doberman session-summary` (Claude Code's SessionStart command); it
ignores the Cursor-shaped stdin and always exits 0, so it runs harmlessly.

With only the Claude Code hooks installed (no `install-hooks --host cursor`), a Cursor `Read` is
gated by path only, with no content scan, because the content scan runs on the native `beforeReadFile`
event; installing the native hooks adds it.

## Known limits

- **Doc-derived payload shapes.** Cursor's hook payloads are documented, and `Shell`'s
  `command` / `cwd` and `Write`'s `file_path` / `content` are staff-confirmed, but the adapter has
  not yet been run against a captured session. A tool whose path arrives under a spelling the
  adapter does not know is **denied**, never waved through. Report it and it will be added.
- **`beforeReadFile` attachments are not gated.** Cursor sends `attachments` alongside the file;
  v1 scans `content` only.
- **`doberman setup` does not offer Cursor yet.** Use `install-hooks --host cursor` directly.
- **Enterprise / Team hooks win.** Cursor merges hooks Enterprise > Team > Project > User; an
  organisation policy can remove the registration. Re-verify after a policy change.
- **Trust model.** As with every hook-based host, Cursor itself is trusted: a Cursor release that
  stops honouring `deny` or `exit 2` bypasses the adapter. The MCP proxy is the alternative for a
  process-level boundary.
