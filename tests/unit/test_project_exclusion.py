"""Device-wide project exclusion list (fix for the global-hook uninstall gap).

A global (``--global``) Claude Code hook, or a Codex ``user``-scope hook, fires
for every project on the machine, with no way to make the hook *file* itself
skip one project. Before this feature, ``doberman uninstall`` in one project
did not actually stop protection there when a global hook was still installed:
the hook kept firing and silently recreated ``.doberman/`` the next time any
decision needed recording (``storage/db.py``'s ``open_db`` -> ``mkdir``).

Covers: the exclusion-list storage module in isolation (round-trip,
canonicalization, subdirectory matching, fail-closed on a malformed file); the
regression proof that an excluded project's hooks fully abstain with **no**
``.doberman/`` created, across all three host adapters; and that the exclusion
list file itself stays protected by the existing outside-repo-root path
confinement rule.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

from doberman.engine.rules.paths import ProtectedPathRule
from doberman.hosthooks import claude_code, codex
from doberman.hosthooks import spine as spine_module
from doberman.hosthooks.openclaw import evaluate_before_tool_call
from doberman.models import ActionType, EvalContext, SecurityObject, Verdict
from doberman.storage.exclusions import (
    add_exclusion,
    excluded_projects_path,
    is_excluded,
    load_excluded_projects,
    remove_exclusion,
)

# ---------------------------------------------------------------------------
# storage/exclusions.py in isolation
# ---------------------------------------------------------------------------


def test_add_then_is_excluded_round_trip(tmp_path):
    project = tmp_path / "proj"
    project.mkdir()
    assert is_excluded(str(project)) is False

    add_exclusion(str(project))

    assert is_excluded(str(project)) is True
    assert str(project.resolve()) in load_excluded_projects()


def test_remove_exclusion_reverses_it(tmp_path):
    project = tmp_path / "proj"
    project.mkdir()
    add_exclusion(str(project))
    assert is_excluded(str(project)) is True

    changed = remove_exclusion(str(project))

    assert changed is True
    assert is_excluded(str(project)) is False


def test_remove_exclusion_on_unlisted_project_is_a_noop(tmp_path):
    project = tmp_path / "proj"
    project.mkdir()
    assert remove_exclusion(str(project)) is False


def test_add_exclusion_is_idempotent(tmp_path):
    project = tmp_path / "proj"
    project.mkdir()
    add_exclusion(str(project))
    add_exclusion(str(project))
    entries = load_excluded_projects()
    assert entries.count(str(project.resolve())) == 1


def test_relative_and_trailing_slash_paths_canonicalize_the_same(tmp_path, monkeypatch):
    project = tmp_path / "proj"
    project.mkdir()
    add_exclusion(str(project) + "/")

    monkeypatch.chdir(tmp_path)
    assert is_excluded("proj") is True


def test_subdirectory_of_an_excluded_project_is_also_excluded(tmp_path):
    project = tmp_path / "proj"
    (project / "sub").mkdir(parents=True)
    add_exclusion(str(project))

    assert is_excluded(str(project / "sub")) is True


def test_sibling_project_is_not_excluded(tmp_path):
    project = tmp_path / "proj"
    project.mkdir()
    sibling = tmp_path / "proj-other"
    sibling.mkdir()
    add_exclusion(str(project))

    assert is_excluded(str(sibling)) is False


def test_missing_file_is_not_excluded_and_creates_nothing():
    assert load_excluded_projects() == []
    assert is_excluded("/anything") is False
    assert not excluded_projects_path().exists()


def test_malformed_file_fails_closed_to_not_excluded(tmp_path):
    project = tmp_path / "proj"
    project.mkdir()
    path = excluded_projects_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("not json{{{", encoding="utf-8")

    assert load_excluded_projects() == []
    assert is_excluded(str(project)) is False


def test_wrong_shaped_json_fails_closed_to_not_excluded(tmp_path):
    path = excluded_projects_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(["just", "a", "list"]), encoding="utf-8")

    assert load_excluded_projects() == []


def test_dober_home_env_isolation_is_honored(tmp_path):
    """Relies on the autouse ``isolated_device_metrics_home`` fixture (conftest.py)
    pointing ``DOBERMAN_HOME`` at a per-test tmp dir — confirms exclusions.py reuses
    that same isolation rather than touching the real ``~/.doberman/``."""
    project = tmp_path / "proj"
    project.mkdir()
    add_exclusion(str(project))
    real_home_file = Path.home() / ".doberman" / "excluded_projects.json"
    assert not real_home_file.exists()


# ---------------------------------------------------------------------------
# Regression: an excluded project's hooks fully abstain, no .doberman/ created
# ---------------------------------------------------------------------------


def _doberman_dir(cwd: str) -> Path:
    return Path(cwd) / ".doberman"


def test_claude_pre_abstains_and_creates_nothing_for_excluded_project(tmp_path):
    project = tmp_path / "proj"
    project.mkdir()
    add_exclusion(str(project))

    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "rm -rf /"},  # would BLOCK if evaluated
        "cwd": str(project),
    }
    assert claude_code.evaluate_pre(payload) is None
    assert not _doberman_dir(str(project)).exists()


def test_claude_post_abstains_and_creates_nothing_for_excluded_project(tmp_path):
    project = tmp_path / "proj"
    project.mkdir()
    add_exclusion(str(project))

    payload = {
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "echo hi"},
        "tool_response": "AKIAABCDEFGHIJKLMNOP",  # secret-shaped; would BLOCK if scanned
        "cwd": str(project),
    }
    assert claude_code.evaluate_post(payload) is None
    assert not _doberman_dir(str(project)).exists()


def test_codex_pre_abstains_and_creates_nothing_for_excluded_project(tmp_path):
    project = tmp_path / "proj"
    project.mkdir()
    add_exclusion(str(project))

    payload = {
        "session_id": "00000000-0000-0000-0000-000000000001",
        "cwd": str(project),
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "rm -rf /"},
    }
    assert codex.evaluate_pre(payload) is None
    assert not _doberman_dir(str(project)).exists()


def test_openclaw_abstains_and_creates_nothing_for_excluded_project(tmp_path):
    project = tmp_path / "proj"
    project.mkdir()
    add_exclusion(str(project))

    payload = {
        "tool_name": "exec",
        "params": {"command": "rm -rf /"},
        "cwd": str(project),
    }
    out = evaluate_before_tool_call(payload)
    assert out == {"verdict": "allow"}
    assert not _doberman_dir(str(project)).exists()


def test_spine_is_excluded_direct(tmp_path):
    project = tmp_path / "proj"
    project.mkdir()
    assert spine_module.is_excluded(str(project)) is False
    add_exclusion(str(project))
    assert spine_module.is_excluded(str(project)) is True


# ---------------------------------------------------------------------------
# Security: the exclusion list file itself stays protected by the existing
# outside-repo-root path confinement rule (no new rule needed).
# ---------------------------------------------------------------------------


def test_mediated_write_to_exclusion_file_is_blocked_by_existing_confinement(tmp_path):
    repo_root = tmp_path / "some-repo"
    repo_root.mkdir()
    target = str(excluded_projects_path())  # e.g. ~/.doberman/excluded_projects.json

    action = SecurityObject(
        id="exclusion-write-1",
        ts=datetime(2026, 6, 7, tzinfo=timezone.utc),
        agent_role="unknown",
        action_type=ActionType.file_write,
        tool_name="Write",
        target=target,
        metadata={},
    )
    ctx = EvalContext(metadata={"repo_root": str(repo_root)})

    result = ProtectedPathRule().evaluate(action, ctx)

    assert result.verdict is Verdict.BLOCK
