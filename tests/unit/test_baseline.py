"""Slices 9.1 / 9.2 — workflow baseline (update-on-allow) and abnormality scorer."""

from datetime import datetime, timezone

from doberman.learning.baseline import (
    _COLD_START_MIN,
    abnormality,
    frequency,
    observe,
    scoring_keys,
)
from doberman.models import ActionType, SecurityObject

_NOW = datetime(2026, 6, 8, tzinfo=timezone.utc)


def _file(target, action_type=ActionType.file_write, **kw):
    return SecurityObject(
        id="b-1",
        ts=_NOW,
        agent_role="frontend",
        action_type=action_type,
        tool_name="fs_write",
        target=target,
        **kw,
    )


def _net(dest):
    return SecurityObject(
        id="b-2",
        ts=_NOW,
        agent_role="frontend",
        action_type=ActionType.network_request,
        tool_name="net_get",
        target="https://x",
        external_destination=dest,
    )


async def _seed(root, action, times):
    for _ in range(times):
        await observe(action, repo_root=root, now=_NOW)


# --- keys -----------------------------------------------------------------


def test_scoring_keys_are_class_level():
    keys = scoring_keys(_file("frontend/Button.tsx"))
    assert keys == ["path_class:frontend/*.tsx"]  # filename dropped → a class
    assert scoring_keys(_net("evil.example")) == ["destination:evil.example"]
    shell = SecurityObject(
        id="s",
        ts=_NOW,
        agent_role="x",
        action_type=ActionType.shell_exec,
        tool_name="shell_exec",
        target="git push --force",
    )
    assert scoring_keys(shell) == ["command:git"]


# --- update-on-allow ------------------------------------------------------


async def test_observe_increments_only_via_allowed_actions(tmp_path):
    root = str(tmp_path)
    await _seed(root, _file("frontend/Button.tsx"), 3)
    assert await frequency("path_class:frontend/*.tsx", repo_root=root) == 3
    assert await frequency("__total__", repo_root=root) == 3
    # A class never observed has frequency 0.
    assert await frequency("path_class:backend/*.ts", repo_root=root) == 0


# --- scorer ---------------------------------------------------------------


async def test_cold_start_is_conservative(tmp_path):
    root = str(tmp_path)
    # Sparse baseline (< COLD_START_MIN): a benign edit scores 0 (no storm)...
    assert await abnormality(_file("frontend/Button.tsx"), repo_root=root) == 0.0
    # ...but a clearly sensitive surface (external destination) gets a mild signal.
    assert await abnormality(_net("evil.example"), repo_root=root) == 0.3


async def test_established_baseline_scores_familiar_low_and_novel_high(tmp_path):
    root = str(tmp_path)
    # Establish a frontend-editing habit (>= COLD_START_MIN observations).
    await _seed(root, _file("frontend/Button.tsx"), _COLD_START_MIN + 1)
    # A familiar path class is normal → low score.
    assert await abnormality(_file("frontend/Hero.tsx"), repo_root=root) == 0.0
    # A never-seen path class (first backend edit for a frontend user) → high.
    assert await abnormality(_file("backend/api.ts"), repo_root=root) == 1.0


async def test_blocked_attempts_never_train_the_baseline(tmp_path):
    root = str(tmp_path)
    # We only ever call observe() for allowed actions; a class we never observe
    # stays fully novel no matter how many times it was *attempted*.
    await _seed(root, _file("frontend/Button.tsx"), _COLD_START_MIN + 1)
    assert await abnormality(_file("backend/secrets.ts"), repo_root=root) == 1.0


async def test_one_time_auth_then_normal(tmp_path):
    root = str(tmp_path)
    await _seed(root, _file("frontend/Button.tsx"), _COLD_START_MIN + 1)
    novel = _file("infra/main.tf")
    assert await abnormality(novel, repo_root=root) == 1.0  # first time: novel
    await observe(novel, repo_root=root, now=_NOW)  # allowed once
    # Now it has been seen — still somewhat novel at freq 1, but below 1.0.
    assert await abnormality(novel, repo_root=root) < 1.0


async def test_non_class_action_scores_zero(tmp_path):
    root = str(tmp_path)
    memory_action = SecurityObject(
        id="m",
        ts=_NOW,
        agent_role="x",
        action_type=ActionType.memory_write,
        tool_name="mem",
        target=None,
    )
    assert await abnormality(memory_action, repo_root=root) == 0.0
