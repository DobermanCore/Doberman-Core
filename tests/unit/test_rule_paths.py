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
    VERIFICATION_CONFIG_GLOBS,
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


def _action(target=None, *, action_type=ActionType.file_write, tool_name="t", metadata=None):
    return SecurityObject(
        id="path-1",
        ts=datetime(2026, 6, 7, tzinfo=timezone.utc),
        agent_role="unknown",
        action_type=action_type,
        tool_name=tool_name,
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


@pytest.mark.parametrize(
    "config_path",
    [
        "CODEOWNERS",
        ".github/CODEOWNERS",
        "docs/CODEOWNERS",
        "ruff.toml",
        ".ruff.toml",
        "sub/ruff.toml",
        "mypy.ini",
        ".mypy.ini",
        "sub/mypy.ini",
        ".eslintrc",
        ".eslintrc.json",
        "eslint.config.js",
        "sub/.eslintrc.yml",
    ],
)
def test_verification_config_requires_auth(tmp_path, config_path):
    # Editing (writing) governance/lint config can silently disable a check —
    # that is what the AUTH step-up guards. Explicit action_type=file_write:
    # this rule scopes VERIFICATION_CONFIG_GLOBS to mutations only (see the
    # read/other-action-type PASS tests below).
    result = RULE.evaluate(_action(config_path, action_type=ActionType.file_write), _ctx(tmp_path))
    assert result.verdict is Verdict.AUTH
    assert ReasonCode.sensitive_path_access in result.reason_codes


@pytest.mark.parametrize("config_path", ["CODEOWNERS", "ruff.toml"])
def test_verification_config_read_passes(tmp_path, config_path):
    # Agents read CODEOWNERS / lint-tool config constantly (routine lookups)
    # with no security value in gating that — only a SILENT EDIT can hide a
    # bad change from review/CI, so a plain read must PASS, not AUTH. Raising
    # on every read of these extremely common files would be pure approval
    # fatigue with no corresponding security benefit.
    result = RULE.evaluate(_action(config_path, action_type=ActionType.file_read), _ctx(tmp_path))
    assert result.verdict is Verdict.PASS


def test_verification_config_delete_requires_auth(tmp_path):
    # Deletion silences a check just as effectively as a bad edit — the other
    # mutation action type this glob set steps up on.
    result = RULE.evaluate(
        _action("CODEOWNERS", action_type=ActionType.file_delete), _ctx(tmp_path)
    )
    assert result.verdict is Verdict.AUTH
    assert ReasonCode.sensitive_path_access in result.reason_codes


def test_verification_config_other_action_type_passes(tmp_path):
    # Only file_write/file_delete are mutations for this scoped glob set — any
    # other action type (e.g. a shell command that happens to name the path)
    # abstains rather than AUTHing.
    result = RULE.evaluate(_action("CODEOWNERS", action_type=ActionType.shell_exec), _ctx(tmp_path))
    assert result.verdict is Verdict.PASS


def test_verification_config_globs_are_not_unconditionally_sensitive():
    # VERIFICATION_CONFIG_GLOBS must NOT be part of DEFAULT_SENSITIVE_GLOBS
    # (that would make every action type AUTH, defeating the read/write
    # scoping above) — it is matched separately, gated on action_type, inside
    # ProtectedPathRule. Unlike CICD_CONFIG_GLOBS (still action-type-agnostic
    # and still folded into DEFAULT_SENSITIVE_GLOBS, see the assertion below).
    assert set(_sanitize_globs(VERIFICATION_CONFIG_GLOBS)).isdisjoint(
        set(_sanitize_globs(DEFAULT_SENSITIVE_GLOBS))
    )


def test_pyproject_toml_is_not_flagged(tmp_path):
    # Deliberately excluded from VERIFICATION_CONFIG_GLOBS: edited constantly
    # for routine dependency bumps; flagging the whole file would be a
    # guaranteed high-FPR mistake (a [tool.ruff]-section-only check would need
    # to read file content, which this rule never does).
    result = RULE.evaluate(_action("pyproject.toml"), _ctx(tmp_path))
    assert result.verdict is Verdict.PASS


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


def test_cicd_config_delete_still_requires_auth(tmp_path):
    # Regression guard: CICD_CONFIG_GLOBS is NOT scoped by action_type (unlike
    # VERIFICATION_CONFIG_GLOBS above) — a delete of a CI/CD pipeline file
    # AUTHs exactly like a write, proving the new mutation-only scoping was
    # applied to VERIFICATION_CONFIG_GLOBS only and did not change CICD's
    # existing action-type-agnostic behaviour.
    result = RULE.evaluate(
        _action(".github/workflows/ci.yml", action_type=ActionType.file_delete),
        _ctx(tmp_path),
    )
    assert result.verdict is Verdict.AUTH
    assert ReasonCode.sensitive_path_access in result.reason_codes


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


# --- Trailing dot/space padding (Windows treats these as insignificant) ------


@pytest.mark.parametrize(
    "padded_path",
    [
        ".env ",
        ".env  ",
        "certs/server.pem.",
        "deploy/tls.key ",
        "packages/app/.env ",
    ],
)
def test_trailing_dot_or_space_padded_protected_path_is_blocked(tmp_path, padded_path):
    # Windows silently strips trailing dots/spaces when a file is opened, so
    # e.g. ".env " and ".env" are the same on-disk file — the matcher must
    # treat them the same.
    result = RULE.evaluate(_action(padded_path), _ctx(tmp_path))
    assert result.verdict is Verdict.BLOCK, padded_path
    assert ReasonCode.protected_path_blocked in result.reason_codes


def test_padded_directory_component_is_caught(tmp_path):
    # The padding is on a DIRECTORY component (not just the leaf filename).
    result = RULE.evaluate(_action(".circleci /config.yml"), _ctx(tmp_path))
    assert result.verdict is Verdict.AUTH
    assert ReasonCode.sensitive_path_access in result.reason_codes


def test_dot_space_normalization_is_raise_only(tmp_path):
    # Everything that already blocked/authed/passed still does.
    assert RULE.evaluate(_action(".env"), _ctx(tmp_path)).verdict is Verdict.BLOCK
    assert RULE.evaluate(_action(".ENV"), _ctx(tmp_path)).verdict is Verdict.BLOCK
    assert RULE.evaluate(_action("a/b/../../.env"), _ctx(tmp_path)).verdict is Verdict.BLOCK
    assert RULE.evaluate(_action("backend/auth/session.ts"), _ctx(tmp_path)).verdict is Verdict.AUTH
    assert RULE.evaluate(_action("frontend/Button.tsx"), _ctx(tmp_path)).verdict is Verdict.PASS


def test_interior_dot_or_space_in_benign_path_still_passes(tmp_path):
    # Only TRAILING padding is normalized; an interior dot/space is a real
    # part of a benign filename.
    assert RULE.evaluate(_action("docs/my notes.md"), _ctx(tmp_path)).verdict is Verdict.PASS
    assert RULE.evaluate(_action("src/a.b.c.ts"), _ctx(tmp_path)).verdict is Verdict.PASS


# --- test_file_removal: deleting/renaming a test file steps up to AUTH -------


@pytest.mark.parametrize(
    "test_path",
    [
        "test_auth.py",
        "tests/unit/test_auth.py",
        "auth_test.py",
        "src/auth_test.py",
        "tests/fixtures/data.json",
        "src/App.test.js",
        "src/App.spec.ts",
    ],
)
def test_test_file_delete_requires_auth(tmp_path, test_path):
    action = _action(test_path, action_type=ActionType.file_delete)
    result = RULE.evaluate(action, _ctx(tmp_path))
    assert result.verdict is Verdict.AUTH
    assert ReasonCode.test_file_removal in result.reason_codes


def test_test_file_rename_by_tool_name_requires_auth(tmp_path):
    action = _action(
        "tests/unit/test_auth.py", action_type=ActionType.file_write, tool_name="rename_file"
    )
    result = RULE.evaluate(action, _ctx(tmp_path))
    assert result.verdict is Verdict.AUTH
    assert ReasonCode.test_file_removal in result.reason_codes


def test_test_file_write_is_not_flagged(tmp_path):
    # Action-type-scoped: an ordinary edit stays PASS — only delete/rename
    # steps up. A glob-table entry here would AUTH constant traffic.
    action = _action("tests/unit/test_auth.py", action_type=ActionType.file_write)
    result = RULE.evaluate(action, _ctx(tmp_path))
    assert result.verdict is Verdict.PASS


def test_non_test_file_delete_is_not_flagged_by_this_branch(tmp_path):
    action = _action("src/app/main.py", action_type=ActionType.file_delete)
    result = RULE.evaluate(action, _ctx(tmp_path))
    assert result.verdict is Verdict.PASS


def test_verification_and_test_file_globs_never_overlap_control_plane():
    from doberman.engine.rules.paths import TEST_FILE_GLOBS, VERIFICATION_CONFIG_GLOBS

    control = set(_sanitize_globs(CICD_CONFIG_GLOBS)) | set(_sanitize_globs(DEFAULT_BLOCKED_GLOBS))
    assert control.isdisjoint(_sanitize_globs(VERIFICATION_CONFIG_GLOBS))
    assert control.isdisjoint(_sanitize_globs(TEST_FILE_GLOBS))


@pytest.mark.parametrize(
    "test_path",
    [
        "src/App.test.tsx",
        "src/App.spec.tsx",
        "src/app.test.mjs",
        "src/app.spec.mjs",
    ],
)
def test_jsx_tsx_and_mjs_test_file_delete_requires_auth(tmp_path, test_path):
    # Previously TEST_FILE_GLOBS only covered .test.js/.spec.ts shapes — a
    # .tsx/.jsx/.mjs test/spec file deleted or renamed passed silently.
    action = _action(test_path, action_type=ActionType.file_delete)
    result = RULE.evaluate(action, _ctx(tmp_path))
    assert result.verdict is Verdict.AUTH, test_path
    assert ReasonCode.test_file_removal in result.reason_codes


@pytest.mark.parametrize(
    "config_path",
    [
        "packages/a/eslint.config.mjs",
        "sub/.ruff.toml",
        "sub/.mypy.ini",
    ],
)
def test_nested_verification_config_globs_require_auth(tmp_path, config_path):
    # Previously only the bare-root forms (eslint.config.*, .ruff.toml,
    # .mypy.ini) were listed — a nested copy (a monorepo package, a
    # subdirectory) passed silently.
    result = RULE.evaluate(_action(config_path, action_type=ActionType.file_write), _ctx(tmp_path))
    assert result.verdict is Verdict.AUTH, config_path
    assert ReasonCode.sensitive_path_access in result.reason_codes


def test_test_file_rename_hint_gated_on_mutation_action_type(tmp_path):
    # The tool-name "rename"/"move" hint must not fire for a non-mutation
    # action type (e.g. a read) just because the tool happens to be named
    # "rename_file" — only file_write/file_delete are mutations here.
    action = _action(
        "tests/unit/test_auth.py", action_type=ActionType.file_read, tool_name="rename_file"
    )
    result = RULE.evaluate(action, _ctx(tmp_path))
    assert result.verdict is Verdict.PASS


def test_cicd_path_that_also_looks_like_a_test_file_stays_sensitive_path_access(tmp_path):
    # ".github/workflows/tests/ci.yml" matches BOTH the CI/CD sensitive-glob
    # set ("**/.github/workflows/**") AND the test-file glob table
    # ("**/tests/**") — the CI/CD classification must win (a delete of a
    # pipeline definition keeps its own stable reason code), not get
    # relabeled test_file_removal just because "tests" appears in the path.
    action = _action(".github/workflows/tests/ci.yml", action_type=ActionType.file_delete)
    result = RULE.evaluate(action, _ctx(tmp_path))
    assert result.verdict is Verdict.AUTH
    assert ReasonCode.sensitive_path_access in result.reason_codes
    assert ReasonCode.test_file_removal not in result.reason_codes
