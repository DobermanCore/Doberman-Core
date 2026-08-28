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

#: The Doberman mark for the local dashboard header: a 68×56 PNG (2× of the 34×28
#: CSS box), the orange "D + dog" from the project logo on a transparent
#: background, base64-encoded so ``doberman dash`` stays a single self-contained
#: HTML shell with no static-file route to protect.
DASH_MARK_PNG_B64 = (
    "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"
)
