"""Slice 3.3 — protected-path rule with safe canonicalization.

Covers: blocked path → BLOCK; sensitive path → AUTH; benign path → PASS;
traversal / case / root-escape bypasses are all caught; batch operations
escalate to the worst member; non-path actions abstain; over-broad ``**``
policy patterns are ignored (cannot match everything); explanation never leaks
the raw path.
"""

from datetime import datetime, timezone

from doberman.engine.rules.paths import (
    DEFAULT_BLOCKED_GLOBS,
    DEFAULT_SENSITIVE_GLOBS,
    ProtectedPathRule,
    _sanitize_globs,
)
from doberman.models import (
    ActionType,
    EvalContext,
    ReasonCode,
    SecurityObject,
    Verdict,
)

RULE = ProtectedPathRule()


def _action(target=None, *, action_type=ActionType.file_write, metadata=None):
    return SecurityObject(
        id="path-1",
        ts=datetime(2026, 6, 7, tzinfo=timezone.utc),
        agent_role="unknown",
        action_type=action_type,
        tool_name="t",
        target=target,
        metadata=metadata or {},
    )


def _ctx(root):
    return EvalContext(metadata={"repo_root": str(root)})


def test_blocked_path_is_blocked(tmp_path):
    result = RULE.evaluate(_action(".env"), _ctx(tmp_path))
    assert result.verdict is Verdict.BLOCK
    assert ReasonCode.protected_path_blocked in result.reason_codes


def test_sensitive_path_requires_auth(tmp_path):
    result = RULE.evaluate(_action("backend/auth/session.ts"), _ctx(tmp_path))
    assert result.verdict is Verdict.AUTH
    assert ReasonCode.sensitive_path_access in result.reason_codes


def test_ci_config_paths_require_auth(tmp_path):
    # Non-GitHub CI configs are sensitive (AUTH), matching GitHub Actions.
    for path in (
        ".gitlab-ci.yml",
        "Jenkinsfile",
        ".circleci/config.yml",
        "azure-pipelines.yml",
        "nested/.gitlab-ci.yml",
    ):
        result = RULE.evaluate(_action(path), _ctx(tmp_path))
        assert result.verdict is Verdict.AUTH, path
        assert ReasonCode.sensitive_path_access in result.reason_codes


def test_benign_path_passes(tmp_path):
    result = RULE.evaluate(_action("frontend/Button.tsx"), _ctx(tmp_path))
    assert result.verdict is Verdict.PASS


def test_traversal_to_blocked_path_is_caught(tmp_path):
    # a/b/../../.env canonicalizes to .env → BLOCK (not bypassed).
    result = RULE.evaluate(_action("a/b/../../.env"), _ctx(tmp_path))
    assert result.verdict is Verdict.BLOCK


def test_case_variation_of_blocked_path_is_caught(tmp_path):
    result = RULE.evaluate(_action(".ENV"), _ctx(tmp_path))
    assert result.verdict is Verdict.BLOCK


def test_path_escaping_repo_root_is_blocked(tmp_path):
    result = RULE.evaluate(_action("../../../etc/passwd"), _ctx(tmp_path))
    assert result.verdict is Verdict.BLOCK
    assert ReasonCode.protected_path_blocked in result.reason_codes


def test_nested_blocked_glob_matches_subdirectory(tmp_path):
    result = RULE.evaluate(_action("packages/app/.env.production"), _ctx(tmp_path))
    assert result.verdict is Verdict.BLOCK


def test_pem_and_key_files_blocked(tmp_path):
    assert RULE.evaluate(_action("certs/server.pem"), _ctx(tmp_path)).verdict is Verdict.BLOCK
    assert RULE.evaluate(_action("deploy/tls.key"), _ctx(tmp_path)).verdict is Verdict.BLOCK


def test_batch_delete_escalates_to_worst_member(tmp_path):
    # A batch where one member is forbidden → the whole batch BLOCKs.
    action = _action(
        action_type=ActionType.file_delete,
        target="frontend/a.tsx",
        metadata={"raw_paths": ["frontend/a.tsx", "frontend/b.tsx", ".env"]},
    )
    result = RULE.evaluate(action, _ctx(tmp_path))
    assert result.verdict is Verdict.BLOCK


def test_batch_with_only_sensitive_member_is_auth(tmp_path):
    action = _action(
        action_type=ActionType.file_delete,
        target="frontend/a.tsx",
        metadata={"raw_paths": ["frontend/a.tsx", "backend/auth/x.ts"]},
    )
    result = RULE.evaluate(action, _ctx(tmp_path))
    assert result.verdict is Verdict.AUTH


def test_non_path_action_abstains(tmp_path):
    result = RULE.evaluate(_action(target=None, action_type=ActionType.shell_exec), _ctx(tmp_path))
    assert result.verdict is Verdict.PASS


def test_explanation_does_not_contain_raw_path(tmp_path):
    distinctive_path = "backend/auth/super-distinctive-session-name.ts"
    result = RULE.evaluate(_action(distinctive_path), _ctx(tmp_path))
    assert "super-distinctive-session-name" not in result.explanation


def test_over_broad_policy_pattern_is_ignored():
    # A blocked '**' would block everything — _sanitize_globs must drop it.
    assert _sanitize_globs(["**", "*", "", "  ", ".env"]) == (".env",)


def test_empty_blocked_globs_do_not_match_everything(tmp_path):
    permissive = ProtectedPathRule(blocked_globs=["**"], sensitive_globs=[])
    # With the over-broad pattern dropped, a benign path still passes.
    result = permissive.evaluate(_action("frontend/Button.tsx"), _ctx(tmp_path))
    assert result.verdict is Verdict.PASS


def test_default_globs_are_nonempty():
    assert DEFAULT_BLOCKED_GLOBS and DEFAULT_SENSITIVE_GLOBS


def test_missing_repo_root_still_evaluates(tmp_path, monkeypatch):
    # No repo_root in context → falls back to cwd; a clearly-blocked relative
    # path still blocks.
    result = RULE.evaluate(_action(".env"), EvalContext())
    assert result.verdict is Verdict.BLOCK
