# Cursor hook payload fixtures

**Shaped from documentation, not captured.** These payloads follow the field names on
https://cursor.com/docs/hooks (the common base: `conversation_id`, `generation_id`,
`hook_event_name`, `workspace_roots`, ...) plus two staff-confirmed details from the Cursor forum
(2026-07-17, thread 165962): `Shell` carries `command` / `cwd` (the docs' own example spells the
directory `working_directory`, so the adapter accepts both) and `Write` carries `file_path` +
`content`. `Read` / `Delete` / `Grep` are assumed to share the `file_path` spelling; the adapter
also accepts `path` / `target_file` and fails closed on a path-gated tool whose path it cannot find.

Ids are synthetic; `workspace_roots` / `cwd` hold a placeholder that every test overrides with
`tmp_path`. When a live capture from a real Cursor session exists, replace these files with it and
record the version here — the Codex fixtures (`../codex/README.md`) show the shape of that note.

**Update (2026-09-04, Cursor slice 3).** A live `cursor-agent` 2026.09.02 capture on Windows
established the real `preToolUse`/`Shell`, `preToolUse`/`Read`, and `sessionStart` shapes; those three
now live captured (BOM preserved, `user_email` scrubbed) in `../cursor_payloads/`, and
`test_hosthook_cursor.py` loads `pre_tool_use_shell.json` / `session_start.json` from there instead of
this folder's doc-derived `pre_shell.json` (removed). `before_shell.json`, `before_read.json`,
`before_mcp.json`, and `pre_write.json` here are still doc-derived — no live capture exists yet for
`beforeShellExecution` / `beforeReadFile` / `beforeMCPExecution` or a `Write` call.

The three captured fixtures also had this machine's real `user_email` and workspace-root path scrubbed
(`user@example.com` and `C:\Users\dev\proj` respectively) before being committed.
