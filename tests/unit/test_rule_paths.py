"""Slice 3.3 — protected-path rule with safe canonicalization.

Covers: blocked path → BLOCK; sensitive path → AUTH; benign path → PASS;
traversal / case / root-escape bypasses are all caught; batch operations
escalate to the worst member; non-path actions abstain; over-broad ``**``
policy patterns are ignored (cannot match everything); explanation never leaks
the raw path.
"""

import sys
from datetime import datetime, timezone

import pytest

from doberman.engine.rules.paths import (
    CICD_CONFIG_GLOBS,
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


# --- CI/CD pipeline config across systems, not just GitHub Actions -----------


@pytest.mark.parametrize(
    "cicd_path",
    [
        # GitHub Actions (the original coverage — still AUTH).
        ".github/workflows/release.yml",
        "packages/app/.github/workflows/ci.yaml",
        # GitLab CI.
        ".gitlab-ci.yml",
        "services/api/.gitlab-ci.yml",
        # Jenkins (root, nested, and .suffix variants; real file is capitalized).
        "Jenkinsfile",
        "ci/Jenkinsfile",
        "Jenkinsfile.release",
        # CircleCI.
        ".circleci/config.yml",
        "sub/.circleci/config.yml",
        # Azure Pipelines.
        "azure-pipelines.yml",
        "azure-pipelines.yaml",
        "infra/azure-pipelines.yml",
    ],
)
def test_cicd_config_requires_auth(tmp_path, cicd_path):
    # Editing any CI/CD pipeline definition steps up to authentication — the
    # pipeline builds/tests/signs/deploys the repo, so an agent rewrite is a
    # human-in-the-loop moment on every supported system, not only GitHub.
    result = RULE.evaluate(_action(cicd_path), _ctx(tmp_path))
    assert result.verdict is Verdict.AUTH, cicd_path
    assert ReasonCode.sensitive_path_access in result.reason_codes


def test_cicd_config_step_up_is_raise_only_over_benign_lookalikes(tmp_path):
    # The globs are specific enough not to swallow ordinary source: a file that
    # merely mentions a CI tool's name in an unrelated path still passes.
    for benign in (
        "docs/jenkins-migration-guide.md",  # not a Jenkinsfile
        "src/circleci_client.py",  # not the .circleci/ dir
        "config/azure-pipelines-notes.txt",  # not azure-pipelines.yml
    ):
        result = RULE.evaluate(_action(benign), _ctx(tmp_path))
        assert result.verdict is Verdict.PASS, benign


def test_cicd_globs_are_part_of_the_sensitive_set():
    # The CI/CD set is folded into the default sensitive globs (raise-only:
    # these paths previously PASSed silently and now step up to AUTH).
    assert set(_sanitize_globs(CICD_CONFIG_GLOBS)) <= set(_sanitize_globs(DEFAULT_SENSITIVE_GLOBS))


@pytest.mark.parametrize(
    "padded_path",
    [
        "./.gitlab-ci.yml",
        "a/../.gitlab-ci.yml",
        "./azure-pipelines.yml",
        "a/../Jenkinsfile",
        "sub/../.circleci/config.yml",
    ],
)
def test_cicd_config_bypass_via_non_canonical_path_is_still_caught(tmp_path, padded_path):
    # A non-canonical spelling (relative-dot prefix or ``..`` traversal) must
    # still canonicalize to the real sensitive target and AUTH — proven through
    # the real ProtectedPathRule -> canonicalize() path, not a reimplemented
    # matcher.
    result = RULE.evaluate(_action(padded_path), _ctx(tmp_path))
    assert result.verdict is Verdict.AUTH, padded_path
    assert ReasonCode.sensitive_path_access in result.reason_codes


@pytest.mark.skipif(sys.platform != "win32", reason="backslash separates paths only on Windows")
@pytest.mark.parametrize("padded_path", ["a\\..\\.gitlab-ci.yml", ".\\azure-pipelines.yml"])
def test_cicd_config_backslash_separator_bypass_is_caught_on_windows(tmp_path, padded_path):
    # Windows-only: there a backslash is a real separator, so these canonicalize
    # onto the sensitive target and must AUTH. On POSIX the same string is a
    # single legal filename that never resolves to the CI config, so PASS is the
    # correct verdict there and the case simply does not apply.
    result = RULE.evaluate(_action(padded_path), _ctx(tmp_path))
    assert result.verdict is Verdict.AUTH, padded_path
    assert ReasonCode.sensitive_path_access in result.reason_codes


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
