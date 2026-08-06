"""Unit tests for Feature HK.4 — doberman setup wizard.

All tests use ``tmp_path``; no real ``~/.claude`` directory or real repo
``.doberman/`` is ever touched. Every interactive test uses the CliRunner
``input`` parameter to feed stdin — the wizard must handle it without hanging.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

import doberman.cli.main as cli_module
from doberman.config import load_mode, load_preferences
from doberman.hosthooks.install import POST_COMMAND, PRE_COMMAND, _is_doberman_group

app = cli_module.app
runner = CliRunner()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _settings(tmp: Path) -> dict:
    """Load the settings.json written under <tmp>/.claude/settings.json."""
    p = tmp / ".claude" / "settings.json"
    assert p.exists(), f"settings.json not found at {p}"
    return json.loads(p.read_text(encoding="utf-8"))


def _doberman_commands(settings: dict, event: str) -> list[str]:
    """Collect all hook commands in the given event that belong to Doberman."""
    return [
        h["command"]
        for g in settings.get("hooks", {}).get(event, [])
        if _is_doberman_group(g)
        for h in g.get("hooks", [])
    ]


def _count_doberman_groups(settings: dict, event: str) -> int:
    """Count Doberman-owned matcher groups in an event."""
    return sum(1 for g in settings.get("hooks", {}).get(event, []) if _is_doberman_group(g))


# ---------------------------------------------------------------------------
# --yes (non-interactive) path
# ---------------------------------------------------------------------------


def test_yes_flag_exits_zero_and_installs_hooks(tmp_path: Path) -> None:
    """``setup --yes`` runs end-to-end, exits 0, and writes Pre + Post hooks."""
    result = runner.invoke(app, ["setup", "--yes", "--path", str(tmp_path)])
    assert result.exit_code == 0, result.output
    s = _settings(tmp_path)
    pre_cmds = _doberman_commands(s, "PreToolUse")
    post_cmds = _doberman_commands(s, "PostToolUse")
    assert PRE_COMMAND in pre_cmds, f"Pre hook missing; found {pre_cmds}"
    assert POST_COMMAND in post_cmds, f"Post hook missing; found {post_cmds}"


def test_yes_flag_sets_balanced_mode(tmp_path: Path) -> None:
    """``setup --yes`` without ``--mode`` defaults to balanced mode."""
    result = runner.invoke(app, ["setup", "--yes", "--path", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert load_mode(str(tmp_path)) == "balanced"


def test_yes_mode_strict_sets_strict(tmp_path: Path) -> None:
    """``setup --yes --mode strict`` sets mode to strict and still installs hooks."""
    result = runner.invoke(app, ["setup", "--yes", "--mode", "strict", "--path", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert load_mode(str(tmp_path)) == "strict"
    s = _settings(tmp_path)
    assert PRE_COMMAND in _doberman_commands(s, "PreToolUse")
    assert POST_COMMAND in _doberman_commands(s, "PostToolUse")


def test_yes_mode_light(tmp_path: Path) -> None:
    """``setup --yes --mode light`` sets mode to light."""
    result = runner.invoke(app, ["setup", "--yes", "--mode", "light", "--path", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert load_mode(str(tmp_path)) == "light"


def test_yes_mode_paranoid(tmp_path: Path) -> None:
    """``setup --yes --mode paranoid`` sets mode to paranoid."""
    result = runner.invoke(app, ["setup", "--yes", "--mode", "paranoid", "--path", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert load_mode(str(tmp_path)) == "paranoid"


def test_yes_mode_invalid_exits_nonzero(tmp_path: Path) -> None:
    """``setup --yes --mode bogus`` keeps the flag path's hard usage error."""
    result = runner.invoke(app, ["setup", "--yes", "--mode", "bogus", "--path", str(tmp_path)])
    assert result.exit_code == 2


def test_yes_no_prompts(tmp_path: Path) -> None:
    """With ``--yes``, setup must succeed even when stdin is empty (no prompts issued)."""
    # Runner provides no ``input`` parameter → stdin is empty bytes.
    # If any ``typer.prompt`` or ``typer.confirm`` fires, it would raise EOF and
    # the exit code would be non-zero.
    result = runner.invoke(app, ["setup", "--yes", "--path", str(tmp_path)], input="")
    assert result.exit_code == 0, result.output


def test_idempotent_double_run(tmp_path: Path) -> None:
    """Running ``setup --yes`` twice leaves exactly one Pre and one Post Doberman group."""
    runner.invoke(app, ["setup", "--yes", "--path", str(tmp_path)])
    runner.invoke(app, ["setup", "--yes", "--path", str(tmp_path)])
    s = _settings(tmp_path)
    assert _count_doberman_groups(s, "PreToolUse") == 1
    assert _count_doberman_groups(s, "PostToolUse") == 1


def test_yes_saves_preferences(tmp_path: Path) -> None:
    """``setup --yes`` persists the mode-preset preferences."""
    result = runner.invoke(app, ["setup", "--yes", "--mode", "strict", "--path", str(tmp_path)])
    assert result.exit_code == 0, result.output
    prefs = load_preferences(str(tmp_path))
    # strict preset: all weights 0.7
    assert prefs.confidentiality == pytest.approx(0.7)
    assert prefs.reversibility == pytest.approx(0.7)


# ---------------------------------------------------------------------------
# Interactive path (via CliRunner input=)
# ---------------------------------------------------------------------------


def test_interactive_balanced_project_scope(tmp_path: Path) -> None:
    """Interactive run: balanced mode, keep preset prefs, project scope.

    Input sequence (newlines terminate each prompt):
    - mode choice: "balanced"
    - tune prefs: "n"
    - global install: "n"
    """
    result = runner.invoke(
        app,
        ["setup", "--path", str(tmp_path)],
        input="balanced\nn\nn\n",
    )
    assert result.exit_code == 0, result.output
    assert "Agent profile" not in result.output
    assert "What does this agent mostly do?" not in result.output
    assert "Profile:" not in result.output
    assert load_mode(str(tmp_path)) == "balanced"
    s = _settings(tmp_path)
    assert PRE_COMMAND in _doberman_commands(s, "PreToolUse")
    assert POST_COMMAND in _doberman_commands(s, "PostToolUse")


def test_interactive_numeric_mode_choice(tmp_path: Path) -> None:
    """Mode can be selected by number; '3' => strict."""
    result = runner.invoke(
        app,
        ["setup", "--path", str(tmp_path)],
        input="3\nn\nn\n",
    )
    assert result.exit_code == 0, result.output
    assert load_mode(str(tmp_path)) == "strict"


def test_interactive_tune_prefs(tmp_path: Path) -> None:
    """Tuning prefs in interactive mode persists custom weights."""
    # Input: mode=balanced, tune=y, confidentiality=0.9, others keep defaults, global=n
    weight_inputs = "\n".join(["0.9", "", "", ""])  # conf=0.9, rest = keep default
    result = runner.invoke(
        app,
        ["setup", "--path", str(tmp_path)],
        input=f"balanced\ny\n{weight_inputs}\nn\n",
    )
    assert result.exit_code == 0, result.output
    prefs = load_preferences(str(tmp_path))
    assert prefs.confidentiality == pytest.approx(0.9)


def test_setup_reprompts_on_bad_mode(tmp_path: Path) -> None:
    """A mistyped interactive mode warns and re-prompts instead of exiting."""
    result = runner.invoke(
        app,
        ["setup", "--path", str(tmp_path)],
        input="blanced\nbalanced\nn\nn\n",
    )

    assert result.exit_code == 0, result.output
    assert "unknown mode" in result.output
    assert "try again" in result.output


def test_setup_explains_each_tuned_dimension(tmp_path: Path) -> None:
    """Each advanced tuning prompt is preceded by its plain-English meaning."""
    from doberman.hosthooks import setup as setup_helpers
    from doberman.policy.preferences import DIMENSIONS

    expected = {
        "confidentiality": "How strongly to step up for sensitive data or external destinations.",
        "reversibility": "How strongly to step up for actions that are difficult to undo.",
        "interruption_tolerance": (
            "How willing you are to be asked before risky actions; higher means more prompts."
        ),
        "blast_radius": "How strongly to step up for actions that affect many targets.",
    }
    descriptions = getattr(setup_helpers, "DIMENSION_DESCRIPTIONS", {})
    assert descriptions == expected
    assert tuple(descriptions) == DIMENSIONS

    weight_inputs = "\n".join(["", "", "", ""])
    result = runner.invoke(
        app,
        ["setup", "--path", str(tmp_path)],
        input=f"balanced\ny\n{weight_inputs}\nn\n",
    )

    assert result.exit_code == 0, result.output
    for dimension, description in expected.items():
        assert description in result.output
        assert result.output.index(description) < result.output.index(f"  {dimension} [0.50]")


def test_interactive_global_flag_overrides_prompt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With ``--global``, no scope prompt is asked; hooks go to ~/.claude but we
    redirect via monkeypatching ``resolve_settings_path`` to write under tmp_path."""
    from doberman.hosthooks import install as install_mod

    original = install_mod.resolve_settings_path

    def _patched_resolve(scope: str, project_root: str):
        # Force global scope to write under tmp_path for test isolation
        if scope == "global":
            return tmp_path / ".claude" / "settings.json"
        return original(scope, project_root)

    monkeypatch.setattr(install_mod, "resolve_settings_path", _patched_resolve)

    result = runner.invoke(
        app,
        ["setup", "--yes", "--global", "--path", str(tmp_path)],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output
    s = _settings(tmp_path)
    assert PRE_COMMAND in _doberman_commands(s, "PreToolUse")
    assert POST_COMMAND in _doberman_commands(s, "PostToolUse")


# ---------------------------------------------------------------------------
# setup.py helper unit tests
# ---------------------------------------------------------------------------


def test_parse_mode_choice_by_name() -> None:
    from doberman.hosthooks.setup import parse_mode_choice
    from doberman.policy.modes import SecurityMode

    assert parse_mode_choice("balanced") == SecurityMode.balanced
    assert parse_mode_choice("STRICT") == SecurityMode.strict
    assert parse_mode_choice("light") == SecurityMode.light
    assert parse_mode_choice("paranoid") == SecurityMode.paranoid


def test_parse_mode_choice_by_number() -> None:
    from doberman.hosthooks.setup import parse_mode_choice
    from doberman.policy.modes import SecurityMode

    modes = list(SecurityMode)
    for i, mode in enumerate(modes, start=1):
        assert parse_mode_choice(str(i)) == mode


def test_parse_mode_choice_invalid() -> None:
    from doberman.hosthooks.setup import parse_mode_choice

    with pytest.raises(ValueError):
        parse_mode_choice("ultra")
    with pytest.raises(ValueError) as exc_info:
        parse_mode_choice("9")
    assert "choose 1-4" in str(exc_info.value)
    assert str(exc_info.value).isascii()
    with pytest.raises(ValueError):
        parse_mode_choice("0")


def test_mode_menu_lines_covers_all_modes() -> None:
    from doberman.hosthooks.setup import mode_menu_lines
    from doberman.policy.modes import SecurityMode

    lines = mode_menu_lines()
    assert len(lines) == len(list(SecurityMode))
    for mode in SecurityMode:
        assert any(mode.value in line for line in lines)
