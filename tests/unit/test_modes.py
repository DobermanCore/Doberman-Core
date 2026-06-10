"""Slice 6.3 — security strength modes.

Covers: per-mode thresholds; default Balanced; unknown mode rejected; the
strictest fallback for a garbage stored mode; the hard-block floor is identical
across modes (only step-ups move); and that stricter modes produce more AUTH.
"""

from datetime import datetime, timezone

import pytest

from doberman.engine.rules.commands import DestructiveCommandRule
from doberman.models import ActionType, EvalContext, ReasonCode, SecurityObject, Verdict
from doberman.policy.modes import (
    DEFAULT_MODE,
    FLOOR_HARD_BLOCKS,
    MODES,
    SecurityMode,
    resolve_mode,
    thresholds_for,
)

RULE = DestructiveCommandRule()
BULK_15 = "rm " + " ".join(f"f{i}" for i in range(15))  # 15 delete operands


def _run(command: str, mode: str):
    action = SecurityObject(
        id="m1",
        ts=datetime(2026, 6, 8, tzinfo=timezone.utc),
        agent_role="x",
        action_type=ActionType.shell_exec,
        tool_name="shell",
        target=command,
    )
    ctx = EvalContext(mode=mode, metadata={"raw_arguments": {"command": command}})
    return RULE.evaluate(action, ctx)


def test_default_mode_is_balanced():
    assert DEFAULT_MODE is SecurityMode.balanced


def test_thresholds_get_stricter_with_mode():
    light = thresholds_for("light").bulk_delete_threshold
    balanced = thresholds_for("balanced").bulk_delete_threshold
    strict = thresholds_for("strict").bulk_delete_threshold
    paranoid = thresholds_for("paranoid").bulk_delete_threshold
    assert light > balanced > strict > paranoid


def test_resolve_mode_is_case_insensitive():
    assert resolve_mode("STRICT") is SecurityMode.strict


def test_unknown_mode_is_rejected():
    with pytest.raises(ValueError):
        resolve_mode("turbo")


def test_garbage_mode_falls_back_to_strictest():
    assert thresholds_for("turbo") == MODES[SecurityMode.paranoid]


def test_floor_contains_the_core_hard_blocks():
    assert ReasonCode.secret_exfiltration in FLOOR_HARD_BLOCKS
    assert ReasonCode.destructive_command in FLOOR_HARD_BLOCKS
    assert ReasonCode.protected_path_blocked in FLOOR_HARD_BLOCKS


def test_more_auth_under_stricter_modes():
    # 15 operands: below Light/Balanced thresholds, at/above Strict/Paranoid.
    assert _run(BULK_15, "light").verdict is Verdict.PASS
    assert _run(BULK_15, "balanced").verdict is Verdict.PASS
    assert _run(BULK_15, "strict").verdict is Verdict.AUTH
    assert _run(BULK_15, "paranoid").verdict is Verdict.AUTH


def test_hard_block_is_identical_across_modes():
    for mode in ("light", "balanced", "strict", "paranoid"):
        result = _run("rm -rf /", mode)
        assert result.verdict is Verdict.BLOCK
        assert ReasonCode.destructive_command in result.reason_codes
