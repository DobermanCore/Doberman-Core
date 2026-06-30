"""🐕 brand marker on the host-hook decision channel: it must reach the user (so
they know it's Doberman asking, not the host agent) and stay ASCII-safe on the
wire (the hook serialises with json.dumps default ensure_ascii=True)."""

import json
import unicodedata

from doberman.branding import DOG
from doberman.hosthooks.claude_code import _FAILSAFE_REASON, _REASON


def test_dog_is_the_dog_emoji():
    assert DOG == "\U0001f415"
    assert "DOG" in unicodedata.name(DOG)


def test_hook_decision_messages_carry_the_marker():
    # The pre/post hook reasons are the surface a user sees when Doberman asks or
    # blocks mid-session, interleaved with the host agent's own prompts.
    assert _REASON.startswith(DOG)
    assert _FAILSAFE_REASON.startswith(DOG)


def test_marker_survives_the_hook_json_ascii_roundtrip():
    # Host-hook output uses json.dumps default (ensure_ascii=True): the emoji is
    # escaped on the wire (pure ASCII — cannot raise on any stdout) and decodes
    # back to 🐕 for the harness UI.
    reason = _REASON.format(verdict="deny", explanation="x", reasons="r", action_id="a")
    wire = json.dumps({"reason": reason})
    assert DOG not in wire  # escaped on the wire → ASCII-safe, never crashes a hook
    assert json.loads(wire)["reason"].startswith(DOG)  # rendered as 🐕 to the user
