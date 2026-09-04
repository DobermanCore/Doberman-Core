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
