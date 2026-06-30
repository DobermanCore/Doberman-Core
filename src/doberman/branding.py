"""Brand marker for Doberman's user-facing messages.

A small dog marker (the 🐕 emoji) prefixes the messages Doberman shows the user,
so they can tell when it is *Doberman* asking/blocking versus the host agent
(Claude Code, Cursor, …) whose prompts it interleaves with.

It is used only on the **host-hook decision channel**, which serialises via
``json.dumps`` (default ``ensure_ascii=True``): the emoji is escaped to a
``\\uXXXX`` sequence on the wire — ASCII on any stdout, never raising — and the
harness UI renders it as 🐕.

CLI / terminal output deliberately stays pure ASCII (enforced by
``tests/unit/test_cli_encode_safe.py``) so it renders cleanly on a legacy cp1252
Windows console; the emoji is intentionally *not* used there.
"""

#: The dog marker codepoint (🐕). Safe to embed in any string that is later
#: JSON-encoded with the default ``ensure_ascii=True`` (the host-hook channel).
DOG = "\U0001f415"
