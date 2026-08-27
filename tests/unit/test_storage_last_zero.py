"""`limit=0` means zero rows, not every row (#430).

The LIMIT clause was guarded by truthiness (`if limit`), so an explicit
"show me none" dropped the clause entirely and returned the whole table.
The documented contract on these helpers is ``None`` = unlimited and
``0`` = none; these tests pin that contract at the storage layer where
the meaning lives (every ``--last`` caller passes through here).
"""

from __future__ import annotations

from datetime import datetime, timezone

from doberman.models import (
    ActionType,
    Decision,
    GuardrailResult,
    Risk,
    SecurityObject,
    SourceContext,
    Verdict,
)
from doberman.policy.drift import read_policy_changes
from doberman.storage.db import open_db
from doberman.storage.log import read_decisions, read_decisions_since, record_decision

_NOW = datetime(2026, 7, 30, tzinfo=timezone.utc)

_INSERT_CHANGE = (
    "INSERT INTO policy_changes "
    "(ts, rule_id, from_state, to_state, classification, reason, approval_method, "
    "approved, approved_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
)


async def _seed_decision(root: str, action_id: str) -> None:
    objective = GuardrailResult(
        verdict=Verdict.PASS, risk=Risk.low, reason_codes=[], explanation="seeded"
    )
    decision = Decision(
        action_id=action_id,
        final_verdict=Verdict.PASS,
        final_risk=Risk.low,
        objective=objective,
        reason_codes=[],
        explanation="seeded",
        decided_at=_NOW,
    )
    action = SecurityObject(
        id=action_id,
        ts=_NOW,
        agent_role="cli",
        action_type=ActionType.file_read,
        tool_name="fs_read",
        target="src/main.py",
        source_context=SourceContext.user,
    )
    await record_decision(decision, action, repo_root=root)


async def _seed_decisions(root: str, n: int) -> None:
    for i in range(n):
        await _seed_decision(root, f"act-{i}")


async def _seed_policy_changes(root: str, n: int) -> None:
    async with open_db(root) as conn:
        for i in range(n):
            await conn.execute(
                _INSERT_CHANGE,
                (
                    _NOW.isoformat(),
                    f"rule-{i}",
                    "monitor",
                    "enforce",
                    "strengthening",
                    "seeded",
                    "password",
                    1,
                    "local",
                ),
            )
        await conn.commit()


async def test_read_decisions_limit_contract_zero_none_one(tmp_path):
    root = str(tmp_path)
    await _seed_decisions(root, 3)

    assert len(await read_decisions(root, limit=None)) == 3  # None: unlimited
    assert len(await read_decisions(root)) == 3  # default stays unlimited
    assert len(await read_decisions(root, limit=1)) == 1
    assert await read_decisions(root, limit=0) == []


async def test_read_decisions_since_limit_contract_zero_none_one(tmp_path):
    root = str(tmp_path)
    await _seed_decisions(root, 3)

    rows = await read_decisions_since(root, 0, limit=None)
    assert len(rows) == 3  # None: unlimited
    assert len(await read_decisions_since(root, 0)) == 3
    assert len(await read_decisions_since(root, 0, limit=1)) == 1
    assert await read_decisions_since(root, 0, limit=0) == []


async def test_read_policy_changes_limit_contract_zero_none_one(tmp_path):
    root = str(tmp_path)
    await _seed_policy_changes(root, 2)

    assert len(await read_policy_changes(root, limit=None)) == 2  # None: unlimited
    assert len(await read_policy_changes(root)) == 2
    assert len(await read_policy_changes(root, limit=1)) == 1
    assert await read_policy_changes(root, limit=0) == []
