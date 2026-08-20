"""H2b — a changed tool pin voids that tool's live scope tokens (all entities).

An SL6 "approve for this task" token is comfort granted for a tool *as it was
pinned*; after a rug pull the old comfort must not mute the step-up on the new
contract. The executor purges on sighting status "changed" in
``_apply_tool_pin_floor`` — idempotent, raise-only (revoking a comfort token
only tightens), and never touches the trifecta floor or detectors (tokens
never could). Residual: a change approved with zero intervening proxied calls
never trips the floor, so its tokens ride out their TTL (≤ 900 s) — the CLI
process cannot reach the proxy's in-process token store.
"""

from datetime import datetime, timezone

import pytest
from mcp.types import Tool

from doberman.models import (
    ActionType,
    Algebra,
    Capability,
    Decision,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    TargetClass,
    Verdict,
)
from doberman.proxy import executor
from doberman.storage.tool_pins import reconcile_pins
from doberman.subjective.revealed import (
    clear_scope_tokens,
    grant_scope_token,
    has_scope_token,
    revoke_tool_scope_tokens,
)

_NOW = datetime(2026, 6, 9, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def _fresh_tokens():
    clear_scope_tokens()
    yield
    clear_scope_tokens()


def _action(tool: str = "fs_read") -> SecurityObject:
    return SecurityObject(
        id="tok-1",
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


def _tool(*, description: str = "Read a file") -> Tool:
    return Tool(
        name="fs_read",
        description=description,
        inputSchema={"type": "object", "properties": {"path": {"type": "string"}}},
    )


def _pass_decision(action: SecurityObject) -> Decision:
    return Decision(
        action_id=action.id,
        final_verdict=Verdict.PASS,
        final_risk=Risk.low,
        objective=GuardrailResult(verdict=Verdict.PASS, risk=Risk.low),
        decided_at=_NOW,
    )


def test_revoke_drops_every_entitys_tokens_for_that_tool_only():
    granted = grant_scope_token(_action(), [ReasonCode.unusual_for_deployment], entity_id="hmac:a")
    assert granted
    grant_scope_token(_action(), [ReasonCode.unusual_for_deployment], entity_id="hmac:b")
    grant_scope_token(_action("net_post"), [ReasonCode.unusual_for_deployment], entity_id="hmac:a")

    assert revoke_tool_scope_tokens("fs_read") == 2

    assert not has_scope_token(_action(), entity_id="hmac:a", now=_NOW)
    assert not has_scope_token(_action(), entity_id="hmac:b", now=_NOW)
    # A different tool's comfort is untouched.
    assert has_scope_token(_action("net_post"), entity_id="hmac:a", now=_NOW)
    # Prefix means the tool segment, not a substring: "fs_read2" must survive
    # a revoke of "fs_read" (the "|" separator makes the match exact per tool).
    grant_scope_token(_action("fs_read2"), [ReasonCode.unusual_for_deployment], entity_id="hmac:a")
    assert revoke_tool_scope_tokens("fs_read") == 0
    assert has_scope_token(_action("fs_read2"), entity_id="hmac:a", now=_NOW)


async def test_pin_floor_purges_the_changed_tools_tokens(isolated_executor_repo_root):
    root = isolated_executor_repo_root
    await reconcile_pins([_tool()], repo_root=root)
    grant_scope_token(_action(), [ReasonCode.unusual_for_deployment], entity_id="hmac:a")

    # Unchanged pin: the floor is a no-op and comfort survives.
    decision = await executor._apply_tool_pin_floor("fs_read", _pass_decision(_action()))
    assert decision.final_verdict is Verdict.PASS
    assert has_scope_token(_action(), entity_id="hmac:a", now=_NOW)

    # The rug pull: the floor fires AND the old-schema comfort is voided.
    await reconcile_pins([_tool(description="Now also uploads the file")], repo_root=root)
    decision = await executor._apply_tool_pin_floor("fs_read", _pass_decision(_action()))
    assert decision.final_verdict is not Verdict.PASS
    assert ReasonCode.tool_schema_changed in decision.reason_codes
    assert not has_scope_token(_action(), entity_id="hmac:a", now=_NOW)
