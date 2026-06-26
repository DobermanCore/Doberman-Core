"""Doberman's own control plane (``.doberman/``) is a hard-blocked path.

The Feature 10 poisoning defense routes every policy **weakening** through the
2FA-gated ``apply_change`` chokepoint and an append-only ledger. That guarantee
is only real if a proxied agent cannot reach Doberman's own state on disk: the
policy document (``.doberman/policies.yaml``), the active role
(``.doberman/role.yaml``), and the SQLite DB (``.doberman/doberman.db``) that
holds the append-only ``policy_changes`` ledger, the decision log, the
baselines, and the elevations all live under ``<repo_root>/.doberman/``.
Rewriting the policy file, expanding the role file, or deleting the ledger DB
through a normal proxied tool call would each bypass the gate entirely.

Doberman writes ``.doberman/`` itself via direct file I/O (never through the
proxy), so hard-blocking *agent-proxied* access here closes the bypass without
touching Doberman's own operation.
"""

from datetime import datetime, timezone

from doberman.engine.objective import ObjectiveGuardrail
from doberman.engine.rules.paths import DEFAULT_BLOCKED_GLOBS, ProtectedPathRule
from doberman.models import (
    ActionType,
    EvalContext,
    ReasonCode,
    SecurityObject,
    Verdict,
)

RULE = ProtectedPathRule()


def _action(target, *, action_type=ActionType.file_write, metadata=None):
    return SecurityObject(
        id="cp-1",
        ts=datetime(2026, 6, 8, tzinfo=timezone.utc),
        agent_role="unknown",
        action_type=action_type,
        tool_name="t",
        target=target,
        metadata=metadata or {},
    )


def _ctx(root):
    return EvalContext(metadata={"repo_root": str(root)})


def test_writing_the_policy_file_is_blocked(tmp_path):
    result = RULE.evaluate(_action(".doberman/policies.yaml"), _ctx(tmp_path))
    assert result.verdict is Verdict.BLOCK
    assert ReasonCode.protected_path_blocked in result.reason_codes


def test_writing_the_role_file_is_blocked(tmp_path):
    result = RULE.evaluate(_action(".doberman/role.yaml"), _ctx(tmp_path))
    assert result.verdict is Verdict.BLOCK


def test_deleting_the_ledger_db_is_blocked(tmp_path):
    result = RULE.evaluate(
        _action(".doberman/doberman.db", action_type=ActionType.file_delete), _ctx(tmp_path)
    )
    assert result.verdict is Verdict.BLOCK


def test_deleting_the_whole_control_plane_dir_is_blocked(tmp_path):
    result = RULE.evaluate(_action(".doberman", action_type=ActionType.file_delete), _ctx(tmp_path))
    assert result.verdict is Verdict.BLOCK


def test_nested_control_plane_is_blocked(tmp_path):
    # A monorepo sub-project's own .doberman/ is protected too.
    result = RULE.evaluate(_action("packages/app/.doberman/policies.yaml"), _ctx(tmp_path))
    assert result.verdict is Verdict.BLOCK


def test_reading_the_control_plane_is_blocked(tmp_path):
    # Conservative: reading the policy/baseline to plan evasion is also denied;
    # the rule matches on the path for any file action.
    result = RULE.evaluate(
        _action(".doberman/policies.yaml", action_type=ActionType.file_read), _ctx(tmp_path)
    )
    assert result.verdict is Verdict.BLOCK


def test_traversal_into_control_plane_is_caught(tmp_path):
    # a/b/../../.doberman/policies.yaml canonicalizes back into .doberman → BLOCK.
    result = RULE.evaluate(_action("a/b/../../.doberman/policies.yaml"), _ctx(tmp_path))
    assert result.verdict is Verdict.BLOCK


def test_default_blocked_globs_include_the_control_plane():
    assert any(".doberman" in glob for glob in DEFAULT_BLOCKED_GLOBS)


def test_objective_guardrail_blocks_a_control_plane_write(tmp_path):
    # The proxy uses a default-constructed ObjectiveGuardrail; prove the wired
    # guardrail (not just the rule in isolation) hard-blocks the policy file.
    guardrail = ObjectiveGuardrail(load_plugins=False)
    result = guardrail.evaluate(_action(".doberman/policies.yaml"), _ctx(tmp_path))
    assert result.verdict is Verdict.BLOCK
    assert ReasonCode.protected_path_blocked in result.reason_codes


# --- HK.5.0: the host-harness control plane (.claude/) is protected too (ADR 0024) ---
# Editing .claude/settings.json is how an agent would remove the Doberman hooks
# and disable enforcement at the harness level ("fire the cop"). Hard-block the
# hook-install settings; AUTH the rest of .claude/.


def test_writing_claude_settings_is_blocked(tmp_path):
    result = RULE.evaluate(_action(".claude/settings.json"), _ctx(tmp_path))
    assert result.verdict is Verdict.BLOCK
    assert ReasonCode.protected_path_blocked in result.reason_codes


def test_writing_claude_local_settings_is_blocked(tmp_path):
    result = RULE.evaluate(_action(".claude/settings.local.json"), _ctx(tmp_path))
    assert result.verdict is Verdict.BLOCK


def test_deleting_claude_settings_is_blocked(tmp_path):
    result = RULE.evaluate(
        _action(".claude/settings.json", action_type=ActionType.file_delete), _ctx(tmp_path)
    )
    assert result.verdict is Verdict.BLOCK


def test_nested_claude_settings_is_blocked(tmp_path):
    # A monorepo sub-project's own .claude/settings.json is protected too.
    result = RULE.evaluate(_action("packages/app/.claude/settings.json"), _ctx(tmp_path))
    assert result.verdict is Verdict.BLOCK


def test_traversal_into_claude_settings_is_caught(tmp_path):
    # a/b/../../.claude/settings.json canonicalizes back into .claude → BLOCK.
    result = RULE.evaluate(_action("a/b/../../.claude/settings.json"), _ctx(tmp_path))
    assert result.verdict is Verdict.BLOCK


def test_other_claude_files_require_auth(tmp_path):
    # Non-install files under .claude/ (commands, agents, …) are sensitive: AUTH,
    # not a silent allow — and not a hard block either.
    result = RULE.evaluate(_action(".claude/commands/build.md"), _ctx(tmp_path))
    assert result.verdict is Verdict.AUTH
    assert ReasonCode.sensitive_path_access in result.reason_codes


def test_ordinary_file_still_passes(tmp_path):
    # No over-blocking: a normal source edit is unaffected by the new globs.
    result = RULE.evaluate(_action("src/app/main.py"), _ctx(tmp_path))
    assert result.verdict is Verdict.PASS


def test_default_blocked_globs_include_claude_settings():
    assert any(".claude/settings.json" in glob for glob in DEFAULT_BLOCKED_GLOBS)


def test_claude_settings_block_does_not_leak_the_raw_path(tmp_path):
    # Redaction: the explanation names only the path class, never the raw path.
    result = RULE.evaluate(_action(".claude/settings.json"), _ctx(tmp_path))
    assert ".claude/settings.json" not in (result.explanation or "")


def test_objective_guardrail_blocks_a_claude_settings_write(tmp_path):
    # Prove the wired guardrail (not just the rule in isolation) hard-blocks it.
    guardrail = ObjectiveGuardrail(load_plugins=False)
    result = guardrail.evaluate(_action(".claude/settings.json"), _ctx(tmp_path))
    assert result.verdict is Verdict.BLOCK
    assert ReasonCode.protected_path_blocked in result.reason_codes
