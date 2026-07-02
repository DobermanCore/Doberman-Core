"""HK.5.1: the PostToolUse hook records multi-step-exfil taint into the ledger.

These mirror the real ``doberman hook post`` process: ``evaluate_post`` is sync
and runs its taint/history writes via ``asyncio.run`` internally, so the tests
are sync too and read the ledger back with ``asyncio.run``.
"""

import asyncio

from doberman.hosthooks.claude_code import evaluate_post
from doberman.storage.db import open_db
from doberman.storage.taint import (
    TAINT_SECRET_ACCESS,
    TAINT_UNTRUSTED_READ,
    entity_scope,
    read_taint,
)

# Canonical AWS example access key — a well-known synthetic, never a real secret.
_SYNTHETIC_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"


def _post(tool_name, tool_response, cwd, *, tool_input=None, session_id="sess-1"):
    return evaluate_post(
        {
            "tool_name": tool_name,
            "tool_input": tool_input or {},
            "tool_response": tool_response,
            "cwd": str(cwd),
            "session_id": session_id,
        }
    )


def _taint(cwd, scope):
    return asyncio.run(read_taint(str(cwd), scope))


def test_webfetch_records_untrusted_read_under_session_and_entity(tmp_path):
    out = _post(
        "WebFetch", "ordinary page text", tmp_path, tool_input={"url": "https://example.com"}
    )
    assert out is None  # clean content → abstain
    assert _taint(tmp_path, "sess-1").get(TAINT_UNTRUSTED_READ) == 1
    assert _taint(tmp_path, entity_scope(str(tmp_path))).get(TAINT_UNTRUSTED_READ) == 1


def test_secret_in_output_taints_session_even_when_blocked(tmp_path):
    # A secret in a Read's output → the post-hook BLOCKs, but the session must
    # still be tainted (the secret entered context) — recorded before the block.
    out = _post(
        "Read", _SYNTHETIC_AWS_KEY, tmp_path, tool_input={"file_path": "cfg.txt"}, session_id="s2"
    )
    assert out is not None and out.get("decision") == "block"
    assert _taint(tmp_path, "s2").get(TAINT_SECRET_ACCESS) == 1
    assert _taint(tmp_path, entity_scope(str(tmp_path))).get(TAINT_SECRET_ACCESS) == 1


def test_weak_high_entropy_output_passes_but_still_taints(tmp_path):
    # Slice B (benign reads): a shapeless high-entropy token (no known credential
    # shape) is only WEAK evidence (possible_high_entropy_secret). The output scan
    # lets it THROUGH — the heuristic false-positives on hashes/UUIDs/base64 — but
    # it STILL records the session taint, so the multi-step read-then-send floor is
    # unaffected. (Contrast: the STRONG AKIA key above is still blocked.)
    token = "Xk9mQ2pL7vN4wR8tY3zA6bC1dE5fG0hJwZ7vB3nM"  # noqa: S105 — shapeless, high-entropy
    out = _post("Read", f"id: {token}", tmp_path, tool_input={"file_path": "cache.txt"}, session_id="sw")
    assert out is None  # weak-only → NOT blocked (the benign-reads fix)
    assert _taint(tmp_path, "sw").get(TAINT_SECRET_ACCESS) == 1
    assert _taint(tmp_path, entity_scope(str(tmp_path))).get(TAINT_SECRET_ACCESS) == 1


def test_block_reason_never_echoes_the_secret(tmp_path):
    out = _post(
        "Read", _SYNTHETIC_AWS_KEY, tmp_path, tool_input={"file_path": "cfg.txt"}, session_id="s3"
    )
    assert _SYNTHETIC_AWS_KEY not in out["reason"]


def test_benign_tool_records_no_taint(tmp_path):
    out = _post("Write", "wrote ok", tmp_path, tool_input={"file_path": "a.py"}, session_id="s4")
    assert out is None
    assert _taint(tmp_path, "s4") == {}


def test_hash_in_output_does_not_taint_or_block(tmp_path):
    # #56 (end-to-end): a tool output containing a git-SHA / content-hash hex is
    # benign. It must NOT block AND must NOT write a false ``secret_access`` taint —
    # a false taint is sticky, entity-scoped, and cross-session, so it would later
    # spuriously AUTH/BLOCK a legitimate egress (the taint-ledger poisoning).
    manifest = (
        '{"commit": "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678", '
        '"node": "316d28fa2542938cc69aeef1188fa340fd69b94080dc7745d06dcd1dd1932738"}'
    )
    out = _post(
        "Read", manifest, tmp_path, tool_input={"file_path": "manifest.json"}, session_id="s56"
    )
    assert out is None  # benign hashes → abstain
    assert _taint(tmp_path, "s56") == {}
    assert _taint(tmp_path, entity_scope(str(tmp_path))) == {}


def test_benign_env_placeholder_output_does_not_taint_or_block(tmp_path):
    # #56 (end-to-end): a README/config line like ``API_KEY=your_key_here`` or a
    # lowercase ``configure_token_path=/usr/local/bin`` is benign. It must NOT block
    # AND must NOT write a false ``secret_access`` taint (which would poison the
    # cross-session multi-step-exfil floor).
    output = "Setup:\n    API_KEY=your_key_here\n    configure_token_path=/usr/local/bin\n"
    out = _post("Read", output, tmp_path, tool_input={"file_path": "README.md"}, session_id="s56b")
    assert out is None
    assert _taint(tmp_path, "s56b") == {}
    assert _taint(tmp_path, entity_scope(str(tmp_path))) == {}


def test_post_history_persists_the_session_id(tmp_path):
    _post("Write", "wrote ok", tmp_path, tool_input={"file_path": "a.py"}, session_id="s5")

    async def _session_ids():
        async with open_db(str(tmp_path)) as conn:
            async with conn.execute("SELECT session_id FROM decisions") as cur:
                return [row[0] for row in await cur.fetchall()]

    assert "s5" in asyncio.run(_session_ids())


def test_missing_session_id_still_taints_entity_scope(tmp_path):
    # Older harness with no session_id: the entity scope is the backstop.
    out = _post(
        "WebFetch", "page", tmp_path, tool_input={"url": "https://example.com"}, session_id=None
    )
    assert out is None
    assert _taint(tmp_path, entity_scope(str(tmp_path))).get(TAINT_UNTRUSTED_READ) == 1
