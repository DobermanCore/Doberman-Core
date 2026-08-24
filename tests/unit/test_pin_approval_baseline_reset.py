"""H2 — approving a CHANGED tool pin forgets the tool's learned familiarity.

The rug-pull tie-in, wired at the storage seam (the only approve path):
``approve_pin`` promotes the changed fingerprint and deletes every entity's
``tool:<name>`` familiarity in ONE transaction, so a changed tool is scored as
brand-new after approval — never against pre-change history. All-entities is
load-bearing: pins are per-repo, and the cold-start peer prior pools
``baseline_counts`` across entities, so a per-entity reset would leak stale
familiarity to immature peers. An unchanged approve is a pure idempotent
promote — resetting there would be step-up fatigue on a familiar tool.
"""

from datetime import datetime, timezone

from mcp.types import Tool

from doberman.models import ActionType, Algebra, Capability, SecurityObject, TargetClass
from doberman.storage.tool_pins import approve_pin, pin_status, reconcile_pins
from doberman.subjective.baseline import frequency, novelty_score, observe, scoring_keys

_NOW = datetime(2026, 6, 9, tzinfo=timezone.utc)


def _tool(*, description: str = "Read a file") -> Tool:
    return Tool(
        name="fs_read",
        description=description,
        inputSchema={"type": "object", "properties": {"path": {"type": "string"}}},
    )


def _action(tool: str = "fs_read") -> SecurityObject:
    return SecurityObject(
        id="pin-reset-1",
        ts=_NOW,
        agent_role="frontend",
        action_type=ActionType.file_read,
        tool_name=tool,
        target="notes.txt",
        algebra=Algebra(
            capability=Capability.read,
            target_class=TargetClass.internal,
            classification_confidence=0.8,
        ),
    )


async def _seed(root: str, eid: str, action: SecurityObject, times: int) -> None:
    for _ in range(times):
        await observe(action, entity_id=eid, repo_root=root, now=_NOW)


async def test_approving_a_changed_pin_resets_every_entitys_tool_familiarity(tmp_path):
    root = str(tmp_path)
    await reconcile_pins([_tool()], repo_root=root)
    await _seed(root, "hmac:aaa", _action(), 5)
    await _seed(root, "hmac:bbb", _action(), 3)
    await _seed(root, "hmac:aaa", _action("net_post"), 4)

    # The rug pull: same name, different advertised contract.
    await reconcile_pins([_tool(description="Now also uploads the file")], repo_root=root)
    assert await pin_status("fs_read", repo_root=root) == "changed"

    assert await approve_pin("fs_read", repo_root=root) is not None
    assert await pin_status("fs_read", repo_root=root) == "ok"

    # Every entity forgets the changed tool — not just the approver's.
    assert await frequency("tool:fs_read", entity_id="hmac:aaa", repo_root=root) == 0
    assert await frequency("tool:fs_read", entity_id="hmac:bbb", repo_root=root) == 0
    # The changed tool scores as brand-new (max-over-keys raw novelty).
    assert await novelty_score(_action(), entity_id="hmac:aaa", repo_root=root) == 1.0

    # Only the per-tool signal resets: other tools and coarse algebra keys survive.
    assert await frequency("tool:net_post", entity_id="hmac:aaa", repo_root=root) == 4
    capability_key = next(k for k in scoring_keys(_action()) if k.startswith("capability:"))
    assert await frequency(capability_key, entity_id="hmac:aaa", repo_root=root) > 0


async def test_approving_an_unchanged_pin_is_a_pure_promote(tmp_path):
    root = str(tmp_path)
    await reconcile_pins([_tool()], repo_root=root)
    await _seed(root, "hmac:aaa", _action(), 5)

    assert await approve_pin("fs_read", repo_root=root) is not None

    assert await frequency("tool:fs_read", entity_id="hmac:aaa", repo_root=root) == 5


async def test_approving_a_missing_pin_returns_none_and_deletes_nothing(tmp_path):
    root = str(tmp_path)
    await _seed(root, "hmac:aaa", _action(), 5)

    assert await approve_pin("ghost_tool", repo_root=root) is None

    assert await frequency("tool:fs_read", entity_id="hmac:aaa", repo_root=root) == 5


def test_scoring_keys_still_emit_the_tool_literal():
    # approve_pin duplicates the "tool:<name>" literal in raw SQL; this pins
    # the contract so a key-format change over there cannot silently orphan it.
    assert f"tool:{_action().tool_name}" in scoring_keys(_action())
