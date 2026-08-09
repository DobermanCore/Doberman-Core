"""Install/uninstall Doberman's Codex hook into a hooks.json (W1.2).

Mirrors ``test_install_hooks.py`` (Claude Code) for the Codex-shaped hooks.json:
idempotent merge, foreign-entry preservation, no-op remove, scope path
resolution, ``.bak`` backup on overwrite, unparseable-file error, and a
never-raising install-state report.
"""

import json
from pathlib import Path

import pytest

from doberman.hosthooks.install import load_settings, write_settings
from doberman.hosthooks.install_codex import (
    CODEX_PRE_ENTRY,
    codex_hook_install_states,
    merge_codex_hooks,
    remove_codex_hooks,
    resolve_codex_hooks_path,
)


def test_merge_adds_pretooluse_group():
    merged = merge_codex_hooks({})
    groups = merged["hooks"]["PreToolUse"]
    assert CODEX_PRE_ENTRY in groups
    assert groups[-1]["hooks"][0]["command"] == "doberman hook codex-pre"


def test_merge_is_idempotent():
    once = merge_codex_hooks({})
    twice = merge_codex_hooks(once)
    doberman_groups = [
        g
        for g in twice["hooks"]["PreToolUse"]
        if g.get("hooks", [{}])[0].get("command") == "doberman hook codex-pre"
    ]
    assert len(doberman_groups) == 1  # replaced, never duplicated


def test_merge_preserves_foreign_entries():
    existing = {
        "hooks": {
            "PreToolUse": [
                {"matcher": "Bash", "hooks": [{"type": "command", "command": "some-other-tool"}]}
            ],
            "Stop": [{"hooks": [{"type": "command", "command": "upload.sh"}]}],
        },
        "other_key": 42,
    }
    merged = merge_codex_hooks(existing)
    commands = [h["command"] for g in merged["hooks"]["PreToolUse"] for h in g["hooks"]]
    assert "some-other-tool" in commands  # foreign PreToolUse group kept
    assert "doberman hook codex-pre" in commands
    assert merged["hooks"]["Stop"][0]["hooks"][0]["command"] == "upload.sh"  # foreign event kept
    assert merged["other_key"] == 42


def test_merge_does_not_mutate_input():
    original = {"hooks": {"PreToolUse": []}}
    merge_codex_hooks(original)
    assert original == {"hooks": {"PreToolUse": []}}


def test_remove_is_noop_when_absent():
    settings = {"hooks": {"PreToolUse": [{"hooks": [{"command": "not-doberman"}]}]}}
    assert remove_codex_hooks(settings) == settings


def test_remove_strips_doberman_and_keeps_the_rest():
    merged = merge_codex_hooks({"hooks": {"PreToolUse": [{"hooks": [{"command": "keep-me"}]}]}})
    cleaned = remove_codex_hooks(merged)
    commands = [h["command"] for g in cleaned["hooks"]["PreToolUse"] for h in g["hooks"]]
    assert commands == ["keep-me"]


def test_remove_drops_empty_hooks_key():
    merged = merge_codex_hooks({})
    cleaned = remove_codex_hooks(merged)
    assert "hooks" not in cleaned  # only Doberman was present -> hooks removed entirely


def test_resolve_paths():
    user = resolve_codex_hooks_path("user", "/repo")
    assert user == Path.home() / ".codex" / "hooks.json"
    repo = resolve_codex_hooks_path("repo", "/repo")
    assert repo == Path("/repo") / ".codex" / "hooks.json"


def test_resolve_rejects_unknown_scope():
    with pytest.raises(ValueError):
        resolve_codex_hooks_path("local", "/repo")


def test_write_backs_up_existing(tmp_path):
    target = tmp_path / ".codex" / "hooks.json"
    target.parent.mkdir(parents=True)
    target.write_text('{"hooks": {}}', encoding="utf-8")
    write_settings(target, merge_codex_hooks({}))
    assert (target.with_suffix(".json.bak")).exists()  # prior content backed up
    assert "doberman hook codex-pre" in target.read_text(encoding="utf-8")


def test_unparseable_file_raises_clear_error(tmp_path):
    bad = tmp_path / "hooks.json"
    bad.write_text("NOT JSON", encoding="utf-8")
    with pytest.raises(ValueError):
        load_settings(bad)


def test_codex_hook_install_states_reports_all_scopes(tmp_path):
    (tmp_path / ".codex").mkdir()
    write_settings(tmp_path / ".codex" / "hooks.json", merge_codex_hooks({}))
    states = codex_hook_install_states(str(tmp_path))
    assert [s for s, _, _ in states] == ["user", "repo", "plugin"]
    repo = next(s for s in states if s[0] == "repo")
    assert repo[2] is True  # the repo hooks.json we just wrote is detected


def test_codex_hook_install_states_never_raises(tmp_path):
    (tmp_path / ".codex").mkdir()
    (tmp_path / ".codex" / "hooks.json").write_text("NOT JSON", encoding="utf-8")
    states = codex_hook_install_states(str(tmp_path))
    assert [s for s, _, _ in states] == ["user", "repo", "plugin"]
    repo = next(s for s in states if s[0] == "repo")
    assert repo[2] is False  # unreadable reports not-installed, never crashes


def test_round_trip_install_then_uninstall(tmp_path):
    target = tmp_path / ".codex" / "hooks.json"
    target.parent.mkdir(parents=True)
    write_settings(target, merge_codex_hooks({}))
    assert "doberman hook codex-pre" in target.read_text(encoding="utf-8")
    write_settings(target, remove_codex_hooks(load_settings(target)))
    assert "doberman hook codex-pre" not in target.read_text(encoding="utf-8")
    # File stays valid JSON after removal.
    json.loads(target.read_text(encoding="utf-8"))
