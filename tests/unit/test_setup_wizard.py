"""Unit tests for Feature HK.4 — doberman setup wizard.

All tests use ``tmp_path``; no real ``~/.claude`` directory or real repo
``.doberman/`` is ever touched. Every interactive test uses the CliRunner
``input`` parameter to feed stdin — the wizard must handle it without hanging.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

import doberman.cli.main as cli_module
from doberman.config import load_mode, load_preferences
from doberman.hosthooks.install import POST_COMMAND, PRE_COMMAND, _is_doberman_group

app = cli_module.app
runner = CliRunner()


@pytest.fixture(autouse=True)
def _doberman_on_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin `doberman` as resolvable so a healthy wired-hooks run reads as
    complete regardless of the test runner's PATH (the honest-end tests below
    override this explicitly to exercise the incomplete path)."""
    import shutil

    real_which = shutil.which
    monkeypatch.setattr(
        shutil,
        "which",
        lambda name, *a, **k: (
            "/venv/bin/doberman" if name == "doberman" else real_which(name, *a, **k)
        ),
    )


@pytest.fixture(autouse=True)
def _isolated_host_detection_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point host detection at a throwaway home so this dev machine's real
    ``~/.claude`` / ``~/.codex`` never leaks into a test's default host choice.

    Nothing is detected unless a test creates a marker under the returned dir,
    so every existing interactive input sequence below can accept the "Hosts"
    prompt's default (``claude`` only) with a leading blank line.
    """
    from doberman.hosthooks import setup as setup_helpers

    home = tmp_path / "home"
    monkeypatch.setattr(setup_helpers, "_home", lambda: home)
    return home


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


def test_yes_refuses_to_lower_mode_without_prompting(tmp_path: Path) -> None:
    """``--yes`` then ``--yes --mode light`` never opens a prompt and refuses the lowering."""
    first = runner.invoke(app, ["setup", "--yes", "--path", str(tmp_path)])
    assert first.exit_code == 0, first.output

    result = runner.invoke(app, ["setup", "--yes", "--mode", "light", "--path", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "[y/N]" not in result.output
    assert "Reason:" not in result.output
    assert "not lowered" in result.output
    # item 4 (round 4): this line now wraps through wrap_detail with a hanging
    # indent, so join across the line break only (a plain `" ".join(.split())`
    # would also collapse the "Mode:       balanced" column padding).
    joined = re.sub(r"\s*\n\s*", " ", result.output)
    assert (
        "Mode:       balanced (requested light; not lowered - a possession factor is "
        "required, run 'doberman mode light')" in joined
    )
    assert load_mode(str(tmp_path)) == "balanced"
    prefs = load_preferences(str(tmp_path))
    assert prefs.confidentiality == pytest.approx(0.5)


def test_yes_lowering_refusal_survives_2_dev_null(tmp_path: Path) -> None:
    """The refusal must be on real stdout - `2>/dev/null` cannot hide it (item 11).
    ``result.stdout`` is real stdout only (Click separates it from stderr), so
    this is exactly what a caller piping stderr to /dev/null would still see."""
    first = runner.invoke(app, ["setup", "--yes", "--path", str(tmp_path)])
    assert first.exit_code == 0, first.output

    result = runner.invoke(app, ["setup", "--yes", "--mode", "light", "--path", str(tmp_path)])
    assert result.exit_code == 0, result.output
    joined = re.sub(r"\s*\n\s*", " ", result.stdout)
    assert (
        "Mode:       balanced (requested light; not lowered - a possession factor is "
        "required, run 'doberman mode light')" in joined
    )


def test_yes_raise_over_existing_policy_applies_free(tmp_path: Path) -> None:
    """A raise (``--yes --mode strict`` over an existing balanced policy) applies with no gate."""
    first = runner.invoke(app, ["setup", "--yes", "--path", str(tmp_path)])
    assert first.exit_code == 0, first.output

    result = runner.invoke(app, ["setup", "--yes", "--mode", "strict", "--path", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert load_mode(str(tmp_path)) == "strict"
    prefs = load_preferences(str(tmp_path))
    assert prefs.confidentiality == pytest.approx(0.7)


# ---------------------------------------------------------------------------
# Interactive path (via CliRunner input=)
# ---------------------------------------------------------------------------


def test_interactive_balanced_project_scope(tmp_path: Path) -> None:
    """Interactive run: balanced mode, keep preset prefs, project scope.

    Input sequence (newlines terminate each prompt):
    - hosts: "" (default: claude only, nothing detected)
    - mode choice: "balanced"
    - telemetry consent: "n"
    - tune prefs: "n"
    - global install: "n"
    - see it work? (demo offer): "n"
    """
    result = runner.invoke(
        app,
        ["setup", "--path", str(tmp_path)],
        input="\nbalanced\nn\nn\nn\nn\n",
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
        input="\n3\nn\nn\nn\nn\n",
    )
    assert result.exit_code == 0, result.output
    assert load_mode(str(tmp_path)) == "strict"


def test_interactive_tune_prefs(tmp_path: Path) -> None:
    """Tuning prefs in interactive mode persists custom weights."""
    # Input order: hosts, mode, tune=y, confidentiality=0.9 (rest keep defaults),
    # claude scope=n, telemetry=n (Telemetry now prompts after hosts are wired),
    # demo=n.
    weight_inputs = "\n".join(["0.9", "", "", ""])  # conf=0.9, rest = keep default
    result = runner.invoke(
        app,
        ["setup", "--path", str(tmp_path)],
        input=f"\nbalanced\ny\n{weight_inputs}\nn\nn\nn\n",
    )
    assert result.exit_code == 0, result.output
    prefs = load_preferences(str(tmp_path))
    assert prefs.confidentiality == pytest.approx(0.9)


def test_setup_reprompts_on_bad_mode(tmp_path: Path) -> None:
    """A mistyped interactive mode warns and re-prompts instead of exiting."""
    result = runner.invoke(
        app,
        ["setup", "--path", str(tmp_path)],
        input="\nblanced\nbalanced\nn\nn\nn\nn\n",
    )

    assert result.exit_code == 0, result.output
    assert "unknown mode" in result.output
    assert "try again" in result.output
    # item 8: the re-prompt error gets an "error: " prefix, on stderr - not
    # glued to the prompt text with no marker.
    assert "error: unknown mode" in result.stderr
    assert "error: unknown mode" not in result.stdout


def test_host_reprompt_error_gets_error_prefix_on_stderr(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["setup", "--path", str(tmp_path)],
        # hosts: an invalid choice, then a valid one; rest as usual.
        input="bogus-host\n\nbalanced\nn\nn\nn\nn\n",
    )
    assert result.exit_code == 0, result.output
    assert "error: unknown host" in result.stderr
    assert "try again" in result.stderr


def test_demo_prompt_eof_never_fails_a_succeeded_setup(tmp_path: Path) -> None:
    """stdin closing right at the optional closing demo prompt (item 2) must
    never turn a succeeded setup into a failure - it degrades to the same
    static demo pointer `--yes` prints. item 13: a leading blank line keeps
    the fallback off the confirm prompt's own (newline-less) line, so it
    lands as its own standalone final line rather than glued to the prompt."""
    # Input order: hosts, mode, tune=n, claude scope=n, telemetry=n - then
    # stdin runs out exactly at the demo confirm (no trailing answer for it).
    result = runner.invoke(
        app,
        ["setup", "--path", str(tmp_path)],
        input="\nbalanced\nn\nn\nn",
    )
    assert result.exit_code == 0, result.output
    lines = result.output.splitlines()
    next_idx = lines.index("Next: `doberman demo --fast`")
    # The confirm's own prompt line ends in "[Y/n]: " with no newline of its
    # own; our fallback must land as its own line, not glued onto that tail.
    assert lines[next_idx - 1].endswith("[Y/n]: ")
    assert any(line.startswith("Also: ") for line in lines[next_idx:])
    assert "BLOCK" not in result.output


def test_interactive_demo_offer_declined_by_default(tmp_path: Path) -> None:
    """Answering 'n' to the closing demo offer runs nothing extra and still exits 0."""
    result = runner.invoke(
        app,
        ["setup", "--path", str(tmp_path)],
        input="\nbalanced\nn\nn\nn\nn\n",
    )
    assert result.exit_code == 0, result.output
    assert "See it work?" in result.output
    assert "BLOCK" not in result.output


def test_interactive_demo_offer_accepted_runs_real_engine(tmp_path: Path) -> None:
    """Answering 'y' to the closing demo offer runs the real scripted attack reel
    in-process and shows a real BLOCK verdict from it."""
    result = runner.invoke(
        app,
        ["setup", "--path", str(tmp_path)],
        input="\nbalanced\nn\nn\nn\ny\n",
    )
    assert result.exit_code == 0, result.output
    assert "See it work?" in result.output
    assert "BLOCK" in result.output


def test_setup_explains_each_tuned_dimension(tmp_path: Path) -> None:
    """Each advanced tuning prompt is preceded by its plain-English meaning, and
    carries a 0/1 anchor (item 9) so a bare number has a concrete referent."""
    from doberman.hosthooks import setup as setup_helpers
    from doberman.policy.preferences import DIMENSIONS

    expected = {
        "confidentiality": (
            "How strongly to step up for sensitive data or external destinations "
            "(0 = never escalate, 1 = always escalate)."
        ),
        "reversibility": (
            "How strongly to step up for actions that are difficult to undo "
            "(0 = never escalate, 1 = always escalate)."
        ),
        "interruption_tolerance": (
            "How willing you are to be asked before risky actions "
            "(0 = never ask, 1 = ask on every risky action)."
        ),
        "blast_radius": (
            "How strongly to step up for actions that affect many targets "
            "(0 = never escalate, 1 = always escalate)."
        ),
    }
    descriptions = getattr(setup_helpers, "DIMENSION_DESCRIPTIONS", {})
    assert descriptions == expected
    assert tuple(descriptions) == DIMENSIONS

    weight_inputs = "\n".join(["", "", "", ""])
    result = runner.invoke(
        app,
        ["setup", "--path", str(tmp_path)],
        input=f"\nbalanced\ny\n{weight_inputs}\nn\nn\nn\n",
    )

    assert result.exit_code == 0, result.output
    for dimension, description in expected.items():
        assert description in result.output
        # item 9: the identifier is spoken as words in the prompt itself.
        words = dimension.replace("_", " ")
        assert result.output.index(description) < result.output.index(f"  {words} (q to quit)")


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


def test_interactive_telemetry_yes_persists_and_emits_setup_event(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from doberman import telemetry

    events = []
    monkeypatch.setattr(
        telemetry,
        "capture",
        lambda event, properties=None, **_kwargs: events.append((event, properties)),
    )
    # Input order: hosts, mode, tune=n, claude scope=n, telemetry=y (Telemetry
    # now prompts after hosts are wired), demo=n.
    result = runner.invoke(
        app,
        ["setup", "--path", str(tmp_path)],
        input="\nbalanced\nn\nn\ny\nn\n",
    )

    assert result.exit_code == 0, result.output
    assert telemetry.status().enabled is True
    question = "Send anonymous usage stats to help improve Doberman? [Y/n]"
    # The full explanation now wraps onto multiple lines (item 9), so pin the
    # ordering check to its first sentence rather than the whole (now
    # possibly-split-across-lines) note.
    note = "Counts and command names only."
    assert result.output.index(note) < result.output.index(question)
    assert (
        "setup_completed",
        {
            "mode": "balanced",
            "host": "claude",
            "hooks_installed": True,
            "global_install": False,
            "source": "wizard",
        },
    ) in events


def test_interactive_telemetry_default_yes_records_the_choice(tmp_path: Path) -> None:
    from doberman import telemetry

    # Input order: hosts, mode, tune=n, claude scope=n, telemetry="" (accept
    # the Y default), demo=n.
    result = runner.invoke(
        app,
        ["setup", "--path", str(tmp_path)],
        input="\nbalanced\nn\nn\n\nn\n",
    )
    assert result.exit_code == 0, result.output
    state = telemetry.status()
    assert state.enabled is True
    assert state.consent_at is not None  # an explicit yes, not the silent default


def test_interactive_telemetry_no_persists_disabled(tmp_path: Path) -> None:
    from doberman import telemetry

    result = runner.invoke(
        app,
        ["setup", "--path", str(tmp_path)],
        input="\nbalanced\nn\nn\nn\nn\n",
    )
    assert result.exit_code == 0, result.output
    assert telemetry.status().enabled is False


def test_yes_does_not_prompt_and_keeps_the_default(tmp_path: Path) -> None:
    from doberman import telemetry

    result = runner.invoke(app, ["setup", "--yes", "--path", str(tmp_path)], input="")
    assert result.exit_code == 0, result.output
    assert "Send anonymous usage stats" not in result.output  # no question asked
    state = telemetry.status()
    assert state.enabled is True
    assert state.consent_at is None  # default kept, nothing recorded as a choice


# ---------------------------------------------------------------------------
# Host selection (HK.5)
# ---------------------------------------------------------------------------


def _codex_hooks(tmp: Path) -> dict:
    p = tmp / ".codex" / "hooks.json"
    assert p.exists(), f"hooks.json not found at {p}"
    return json.loads(p.read_text(encoding="utf-8"))


def test_yes_host_codex_writes_hooks_and_no_claude_dir(tmp_path: Path) -> None:
    """``--yes --host codex`` wires only the Codex hook — no ``.claude`` at all."""
    result = runner.invoke(app, ["setup", "--yes", "--host", "codex", "--path", str(tmp_path)])
    assert result.exit_code == 0, result.output
    hooks = _codex_hooks(tmp_path)
    commands = [h["command"] for g in hooks["hooks"]["PreToolUse"] for h in g["hooks"]]
    assert "doberman hook codex-pre" in commands
    assert not (tmp_path / ".claude").exists()


def test_yes_host_claude_and_codex_writes_both(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["setup", "--yes", "--host", "claude", "--host", "codex", "--path", str(tmp_path)],
    )
    assert result.exit_code == 0, result.output
    s = _settings(tmp_path)
    assert PRE_COMMAND in _doberman_commands(s, "PreToolUse")
    hooks = _codex_hooks(tmp_path)
    commands = [h["command"] for g in hooks["hooks"]["PreToolUse"] for h in g["hooks"]]
    assert "doberman hook codex-pre" in commands


def test_yes_detects_codex_and_wires_codex_only(
    tmp_path: Path, _isolated_host_detection_home: Path
) -> None:
    """No explicit ``--host``: a detected ``~/.codex`` (with no Claude marker) drives
    the ``--yes`` default, so only Codex is wired."""
    (_isolated_host_detection_home / ".codex").mkdir(parents=True)
    result = runner.invoke(app, ["setup", "--yes", "--path", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert not (tmp_path / ".claude").exists()
    hooks = _codex_hooks(tmp_path)
    commands = [h["command"] for g in hooks["hooks"]["PreToolUse"] for h in g["hooks"]]
    assert "doberman hook codex-pre" in commands


def test_interactive_hosts_1_2_wires_both(tmp_path: Path) -> None:
    """Choosing "1,2" at the hosts prompt wires both Claude and Codex."""
    result = runner.invoke(
        app,
        ["setup", "--path", str(tmp_path)],
        input="1,2\nbalanced\nn\nn\nn\nn\nn\n",
    )
    assert result.exit_code == 0, result.output
    s = _settings(tmp_path)
    assert PRE_COMMAND in _doberman_commands(s, "PreToolUse")
    hooks = _codex_hooks(tmp_path)
    commands = [h["command"] for g in hooks["hooks"]["PreToolUse"] for h in g["hooks"]]
    assert "doberman hook codex-pre" in commands


def test_yes_host_mcp_prints_serve_block_and_writes_no_hook_file(tmp_path: Path) -> None:
    # mcp-only is a pending run (item 7): exits 3, not 0.
    result = runner.invoke(app, ["setup", "--yes", "--host", "mcp", "--path", str(tmp_path)])
    assert result.exit_code == 3, result.output
    assert "doberman serve --" in result.output
    assert not (tmp_path / ".claude").exists()
    assert not (tmp_path / ".codex").exists()


def test_yes_host_openclaw_prints_pointer(tmp_path: Path) -> None:
    # openclaw-only is a pending run (item 7): exits 3, not 0.
    result = runner.invoke(app, ["setup", "--yes", "--host", "openclaw", "--path", str(tmp_path)])
    assert result.exit_code == 3, result.output
    assert "adapters/openclaw/README.md" in result.output
    assert not (tmp_path / ".claude").exists()
    assert not (tmp_path / ".codex").exists()


def test_yes_host_mcp_doctor_scoped_and_shows_canary(tmp_path: Path) -> None:
    """MCP-only: the hooks-only doctor checks are scoped out, and the summary
    gets its own end state + canary instead of the hooks restart banner."""
    result = runner.invoke(app, ["setup", "--yes", "--host", "mcp", "--path", str(tmp_path)])
    assert result.exit_code == 3, result.output  # mcp-only is pending (item 7)
    assert "  - Host hooks" not in result.output
    assert "  - Hook command" not in result.output
    assert "hooks n/a" in result.output
    normalized = " ".join(result.output.split())
    assert (
        "After you paste the block and restart your client: ask your agent to read "
        ".env and confirm it is blocked." in normalized
    )
    assert "activates when you restart" not in result.output


def test_yes_host_openclaw_doctor_scoped(tmp_path: Path) -> None:
    """OpenClaw-only: same doctor scoping as MCP-only (no hooks-kind host wired)."""
    result = runner.invoke(app, ["setup", "--yes", "--host", "openclaw", "--path", str(tmp_path)])
    assert result.exit_code == 3, result.output  # openclaw-only is pending (item 7)
    assert "  - Host hooks" not in result.output
    assert "  - Hook command" not in result.output
    assert "hooks n/a" in result.output
    assert "activates when you restart" not in result.output


# ---------------------------------------------------------------------------
# "Setup pending" (item 1 + 13): mcp/openclaw-only never claims "complete"
# ---------------------------------------------------------------------------


def test_mcp_only_header_is_pending_not_complete(tmp_path: Path) -> None:
    result = runner.invoke(app, ["setup", "--yes", "--host", "mcp", "--path", str(tmp_path)])
    assert result.exit_code == 3, result.output  # item 7: pending exits 3, not 0
    assert "-- Setup pending --" in result.output
    assert "-- Setup complete --" not in result.output
    assert "Hooks written." not in result.output


def test_openclaw_only_header_is_pending_not_complete(tmp_path: Path) -> None:
    result = runner.invoke(app, ["setup", "--yes", "--host", "openclaw", "--path", str(tmp_path)])
    assert result.exit_code == 3, result.output  # item 7: pending exits 3, not 0
    assert "-- Setup pending --" in result.output
    assert "-- Setup complete --" not in result.output
    assert "Hooks written." not in result.output


def test_mcp_only_still_offers_the_demo_pointer(tmp_path: Path) -> None:
    """The demo runs in-process, so it's valid to offer on the pending path too (item 13)."""
    result = runner.invoke(app, ["setup", "--yes", "--host", "mcp", "--path", str(tmp_path)])
    assert result.exit_code == 3, result.output
    assert "Next: `doberman demo --fast`" in result.output


def test_claude_host_still_gets_setup_complete(tmp_path: Path) -> None:
    """A hook-kind host wired (claude) still reads as complete, not pending."""
    result = runner.invoke(app, ["setup", "--yes", "--host", "claude", "--path", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "-- Setup complete --" in result.output
    assert "-- Setup pending --" not in result.output


def test_invalid_host_exits_2_naming_valid_hosts(tmp_path: Path) -> None:
    result = runner.invoke(app, ["setup", "--yes", "--host", "cursor", "--path", str(tmp_path)])
    assert result.exit_code == 2
    assert "claude" in result.output
    assert "codex" in result.output
    assert "mcp" in result.output
    assert "openclaw" in result.output


def test_output_contains_doctor_pass(tmp_path: Path) -> None:
    result = runner.invoke(app, ["setup", "--yes", "--path", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "Doctor:" in result.output
    # First-run warnings (no decision DB / fingerprint key yet, no TUI extra)
    # are counted, never listed as failures. (Whether a *critical* check such
    # as "Hook command" warns depends on the test runner's PATH, so only the
    # non-critical names are pinned here.)
    for first_run_warning in ("Decision DB", "Fingerprint key", "TUI extra"):
        assert f"  - {first_run_warning}" not in result.output
    assert "warning(s)" in result.output


def test_output_contains_restart_activation_hint(tmp_path: Path) -> None:
    result = runner.invoke(app, ["setup", "--yes", "--path", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "activates when you restart" in result.output


def test_restart_your_session_sentence_never_repeats_with_two_hosts(tmp_path: Path) -> None:
    """item 10: with both claude and codex wired, "restart your ... session"
    prints exactly once - the per-host restart_hint no longer duplicates it."""
    result = runner.invoke(
        app,
        ["setup", "--yes", "--host", "claude", "--host", "codex", "--path", str(tmp_path)],
    )
    assert result.exit_code == 0, result.output
    assert result.output.count("restart your") == 1
    assert "Restart your Claude Code session." not in result.output
    assert "Restart your Codex CLI session." not in result.output


def test_doctor_remediation_detail_shown(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A remaining critical is printed as '- <name>: <detail>' using doctor's own text."""
    from doberman.cli import doctor as doctor_mod

    def _fake_run_checks(path: str) -> list:
        return [
            doctor_mod.CheckResult(
                "Config",
                doctor_mod.CheckStatus.FAIL,
                "no policy saved - run `doberman setup`",
                critical=True,
            )
        ]

    monkeypatch.setattr(doctor_mod, "run_checks", _fake_run_checks)
    result = runner.invoke(app, ["setup", "--yes", "--path", str(tmp_path)])
    assert result.exit_code == 1, result.output
    assert "  - Config: no policy saved - run `doberman setup`" in result.output
    assert "-- Setup incomplete --" in result.output
    assert "-- Setup complete --" not in result.output
    assert "Hooks written. Doberman activates when you restart your session." not in result.output


def test_doctor_crash_falls_back_cleanly(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from doberman.cli import doctor as doctor_mod

    def _boom(path: str) -> list:
        raise RuntimeError("boom")

    monkeypatch.setattr(doctor_mod, "run_checks", _boom)
    result = runner.invoke(app, ["setup", "--yes", "--path", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "Doctor: could not run here; verify with `doberman doctor`" in result.output


def test_password_set_appears_in_the_also_line_when_no_factor_enrolled(tmp_path: Path) -> None:
    """item 1: the old standalone "Next step:" line is folded into the
    compact, muted "Also:" line at the end of the epilogue."""
    result = runner.invoke(app, ["setup", "--yes", "--path", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "Next step:" not in result.output
    idx = result.output.index("Also:")
    assert "doberman password set" in result.output[idx : idx + 200]


def test_enrolled_password_replaces_next_step_with_possession_factor(tmp_path: Path) -> None:
    """With a possession factor already enrolled, the password nudge is gone and
    the summary says so instead."""
    from doberman.auth import password as password_mod

    password_mod.enroll("correct horse battery staple")

    result = runner.invoke(app, ["setup", "--yes", "--path", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "Next step:" not in result.output
    assert "password set" not in result.output
    assert "Possession factor: set (password)." in result.output


# ---------------------------------------------------------------------------
# Honest end (P0): a critical from the in-wizard doctor pass must never be
# reported as "complete" with exit 0.
# ---------------------------------------------------------------------------


def _no_doberman_on_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """Undo the module's ``_doberman_on_path`` autouse shim for one test, so the
    Hook command check genuinely fails closed like a real broken install."""
    import shutil

    monkeypatch.setattr(shutil, "which", lambda name, *a, **k: None)


def test_yes_honest_incomplete_when_hook_command_critical(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _no_doberman_on_path(monkeypatch)
    result = runner.invoke(app, ["setup", "--yes", "--path", str(tmp_path)])
    assert result.exit_code == 1, result.output
    assert "-- Setup incomplete --" in result.output
    assert "-- Setup complete --" not in result.output
    assert "Hooks written. Doberman activates when you restart your session." not in result.output
    # Remediation and next steps still print - but nothing else (item 5): the
    # incomplete path ends on the remedy, not the success epilogue. Telemetry
    # consent is resolved earlier in the flow (before the doctor pass even
    # runs, round 4 item 3), so its compact summary legitimately still shows -
    # what must NOT show is anything from the success-only epilogue.
    assert "Hook command" in result.output
    assert "Check health:" in result.output
    assert "Docs:" in result.output
    assert "Also:" not in result.output
    assert "Possession factor:" not in result.output
    assert "Next step:" not in result.output
    assert "Change your mind:" not in result.output
    assert "Docs:" in result.output
    docs_idx = result.output.index("Docs:")
    health_idx = result.output.index("Check health:")
    assert docs_idx < health_idx
    normalized = " ".join(result.output.split())
    # item 8: the doctor block above already printed the full detail once;
    # the closing sentence references the critical by name only.
    assert (
        "Not protecting this repo yet: fix 'Hook command' above, then run 'doberman doctor'."
        in normalized
    )


def test_interactive_honest_incomplete_when_hook_command_critical(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _no_doberman_on_path(monkeypatch)
    result = runner.invoke(
        app,
        ["setup", "--path", str(tmp_path)],
        input="\nbalanced\nn\nn\nn\nn\n",
    )
    assert result.exit_code == 1, result.output
    assert "-- Setup incomplete --" in result.output


def test_status_flags_hook_command_not_on_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`status` reuses doctor's cheap PATH check next to `[installed]`."""
    _no_doberman_on_path(monkeypatch)
    runner.invoke(app, ["setup", "--yes", "--path", str(tmp_path)])
    result = runner.invoke(app, ["status", "--path", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "(not on PATH)" in result.output


def test_status_omits_not_on_path_hint_when_resolvable(tmp_path: Path) -> None:
    runner.invoke(app, ["setup", "--yes", "--path", str(tmp_path)])
    result = runner.invoke(app, ["status", "--path", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "(not on PATH)" not in result.output


# ---------------------------------------------------------------------------
# Verification ritual + peak-end ordering (item 2)
# ---------------------------------------------------------------------------


def test_claude_host_gets_the_same_verify_line_as_codex_and_mcp(tmp_path: Path) -> None:
    result = runner.invoke(app, ["setup", "--yes", "--host", "claude", "--path", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert (
        "Verify it's live: ask your agent to read .env and confirm it is blocked." in result.output
    )


def test_verify_and_next_precede_the_final_also_line(tmp_path: Path) -> None:
    """item 1: Verify -> Next (bold) -> Also, with Also now the closing line -
    no more seven equal-weight lines competing for attention."""
    result = runner.invoke(app, ["setup", "--yes", "--path", str(tmp_path)])
    assert result.exit_code == 0, result.output
    lines = [line for line in result.output.splitlines() if line.strip()]
    verify_idx = lines.index(
        "Verify it's live: ask your agent to read .env and confirm it is blocked."
    )
    next_idx = lines.index("Next: `doberman demo --fast`")
    also_idx = next(i for i, line in enumerate(lines) if line.startswith("Also: "))
    assert next_idx == verify_idx + 1
    assert also_idx == next_idx + 1
    # the "Also:" line is the last thing printed (it may itself wrap over a
    # couple of lines, e.g. the docs URL).
    assert all(not line.startswith(("--", "Verify", "Next:")) for line in lines[also_idx + 1 :])


def test_uninstall_hooks_pointer_moves_into_the_also_line(tmp_path: Path) -> None:
    """item 1: the standalone "Change your mind:" line is retired; the
    uninstall-hooks pointer now lives in the compact "Also:" line."""
    result = runner.invoke(app, ["setup", "--yes", "--path", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "Change your mind:  doberman uninstall-hooks" not in result.output
    idx = result.output.index("Also:")
    assert "doberman uninstall-hooks" in result.output[idx : idx + 300]


def test_rerun_with_unchanged_hooks_prints_already_wired(tmp_path: Path) -> None:
    first = runner.invoke(app, ["setup", "--yes", "--path", str(tmp_path)])
    assert first.exit_code == 0, first.output
    second = runner.invoke(app, ["setup", "--yes", "--path", str(tmp_path)])
    assert second.exit_code == 0, second.output
    settings_path = tmp_path / ".claude" / "settings.json"
    assert f"already wired: {settings_path}" in second.output
    assert f"wrote {settings_path}" not in second.output


# ---------------------------------------------------------------------------
# --dry-run (item 5)
# ---------------------------------------------------------------------------


def test_dry_run_yes_previews_and_writes_nothing(tmp_path: Path) -> None:
    result = runner.invoke(app, ["setup", "--yes", "--dry-run", "--path", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "[dry-run] would set mode: balanced" in result.output
    settings_path = tmp_path / ".claude" / "settings.json"
    assert f"[dry-run] would write: {settings_path}" in result.output
    assert not settings_path.exists()
    assert not (tmp_path / ".claude").exists()


def test_dry_run_mode_flag_previews_the_requested_mode(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["setup", "--yes", "--dry-run", "--mode", "strict", "--path", str(tmp_path)]
    )
    assert result.exit_code == 0, result.output
    assert "[dry-run] would set mode: strict" in result.output


def test_dry_run_mcp_host_has_no_file_to_write(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["setup", "--yes", "--dry-run", "--host", "mcp", "--path", str(tmp_path)]
    )
    assert result.exit_code == 0, result.output
    assert "no file written" in result.output
    assert not (tmp_path / ".claude").exists()


def test_dry_run_writes_no_telemetry_state_and_previews_the_consent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`--dry-run` means write nothing - telemetry state (distinct id,
    notice-shown) is a write like any other, so it must stay untouched, and the
    dry-run preview gets its own line for it (item 12)."""
    import os

    from doberman.storage.device_metrics import HOME_ENV

    home = os.environ[HOME_ENV]
    before = sorted(Path(home).rglob("*")) if Path(home).exists() else []

    result = runner.invoke(app, ["setup", "--yes", "--dry-run", "--path", str(tmp_path)])

    assert result.exit_code == 0, result.output
    assert "[dry-run] would record telemetry consent:" in result.output
    after = sorted(Path(home).rglob("*")) if Path(home).exists() else []
    assert after == before, f"dry-run wrote files under HOME: {set(after) - set(before)}"
    assert not (Path(home) / ".doberman" / "telemetry.json").exists()


# ---------------------------------------------------------------------------
# --global confirmation gate (item 5)
# ---------------------------------------------------------------------------


def test_global_yes_prints_exact_path_before_writing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from doberman.hosthooks import install as install_mod

    fake_home_settings = tmp_path / "fake-global" / ".claude" / "settings.json"
    original = install_mod.resolve_settings_path

    def _patched_resolve(scope: str, project_root: str):
        if scope == "global":
            return fake_home_settings
        return original(scope, project_root)

    monkeypatch.setattr(install_mod, "resolve_settings_path", _patched_resolve)

    result = runner.invoke(
        app, ["setup", "--yes", "--global", "--path", str(tmp_path)], catch_exceptions=False
    )
    assert result.exit_code == 0, result.output
    assert f"Installing globally: {fake_home_settings}" in result.output
    assert result.output.index(f"Installing globally: {fake_home_settings}") < result.output.index(
        f"wrote {fake_home_settings}"
    )
    assert fake_home_settings.exists()


def test_global_interactive_declined_falls_back_to_project_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from doberman.hosthooks import install as install_mod

    fake_home_settings = tmp_path / "fake-global" / ".claude" / "settings.json"
    original = install_mod.resolve_settings_path

    def _patched_resolve(scope: str, project_root: str):
        if scope == "global":
            return fake_home_settings
        return original(scope, project_root)

    monkeypatch.setattr(install_mod, "resolve_settings_path", _patched_resolve)

    result = runner.invoke(
        app,
        ["setup", "--global", "--path", str(tmp_path)],
        # hosts default, mode=balanced, global-confirm=n, telemetry=n, tune=n, demo=n
        input="\nbalanced\nn\nn\nn\nn\n",
    )
    assert result.exit_code == 0, result.output
    assert "Write to your real home directory now?" in result.output
    assert not fake_home_settings.exists()
    assert (tmp_path / ".claude" / "settings.json").exists()


# ---------------------------------------------------------------------------
# Telemetry gets its own section, after hosts are wired (item 4)
# ---------------------------------------------------------------------------


def test_telemetry_gets_its_own_section_after_hosts_before_doctor(tmp_path: Path) -> None:
    result = runner.invoke(app, ["setup", "--yes", "--path", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "-- Telemetry --" in result.output
    settings_path = tmp_path / ".claude" / "settings.json"
    wired_idx = result.output.index(f"wrote {settings_path}")
    telemetry_idx = result.output.index("-- Telemetry --")
    doctor_idx = result.output.index("-- Doctor --")
    assert wired_idx < telemetry_idx < doctor_idx


def test_telemetry_explanation_shows_only_when_interactive(tmp_path: Path) -> None:
    """Interactive: the full "what is sent" explanation prints before the
    question, wraps at 78 columns (item 9), and glosses "reason payloads"
    inline (item 10)."""
    result = runner.invoke(
        app,
        ["setup", "--path", str(tmp_path)],
        input="\nbalanced\nn\nn\nn\nn\n",
    )
    assert result.exit_code == 0, result.output
    normalized = " ".join(result.output.split())
    assert (
        "Counts and command names only. Never paths, prompts, secrets, or reason "
        "payloads (the structured why-blocked details)." in normalized
    )
    assert "https://github.com/DobermanCore/Doberman-Core/blob/main/docs/TELEMETRY.md" in normalized


def test_yes_telemetry_section_shows_compact_summary_not_full_explanation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`--yes` mentions telemetry at most twice per run (round 4 item 3): the
    `-- Telemetry --` section shows the compact `Telemetry: on/off` summary
    instead of the full explanation, and the `Also:` line is the only other
    mention - not a 3rd one from the full paragraph too."""
    monkeypatch.delenv("DOBERMAN_TELEMETRY", raising=False)
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("DO_NOT_TRACK", raising=False)
    result = runner.invoke(app, ["setup", "--yes", "--path", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "Counts and command names only." not in result.output
    telemetry_idx = result.output.index("-- Telemetry --")
    doctor_idx = result.output.index("-- Doctor --")
    section_body = result.output[telemetry_idx:doctor_idx]
    assert "Telemetry: on" in section_body


# ---------------------------------------------------------------------------
# Telemetry recognition (item 6)
# ---------------------------------------------------------------------------


def test_yes_summary_always_shows_telemetry_on_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # `is_enabled()` also forces off under CI/DO_NOT_TRACK (telemetry.py's
    # `_forced_off_reasons`) - clear every kill switch, not just the one this
    # test is nominally about, so this is deterministic on CI too (CI sets
    # `CI=true`, which previously made this "on" assertion fail there).
    monkeypatch.delenv("DOBERMAN_TELEMETRY", raising=False)
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("DO_NOT_TRACK", raising=False)
    result = runner.invoke(app, ["setup", "--yes", "--path", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert (
        "Telemetry: on - anonymous usage counts; `doberman telemetry off` to opt out"
        in result.output
    )


def test_yes_summary_shows_telemetry_off_when_forced_off(tmp_path: Path) -> None:
    # conftest's autouse fixture already sets DOBERMAN_TELEMETRY=0 for every test.
    result = runner.invoke(app, ["setup", "--yes", "--path", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "Telemetry: off" in result.output


def test_telemetry_summary_line_shows_even_after_help_already_marked_the_notice_seen(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("DOBERMAN_TELEMETRY", raising=False)
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("DO_NOT_TRACK", raising=False)
    from doberman import telemetry

    telemetry.first_run_notice()  # simulate: a user who read `--help` first
    result = runner.invoke(app, ["setup", "--yes", "--path", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "Telemetry: on" in result.output


# ---------------------------------------------------------------------------
# Docs pointer + copy (item 7)
# ---------------------------------------------------------------------------


def test_summary_ends_with_a_docs_pointer(tmp_path: Path) -> None:
    """item 1: the docs pointer now lives in the compact "Also:" line."""
    result = runner.invoke(app, ["setup", "--yes", "--path", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert (
        "docs: https://github.com/DobermanCore/Doberman-Core/blob/main/docs/SETUP.md"
        in result.output
    )


def test_strict_mode_glosses_trifecta_actions(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["setup", "--path", str(tmp_path)],
        input="\n3\nn\nn\nn\nn\n",
    )
    assert result.exit_code == 0, result.output
    # The strict description wraps onto a continuation line (item 6); the
    # phrase itself may straddle that wrap point, so compare whitespace-
    # normalized rather than pinning it to a single physical line.
    normalized = " ".join(result.output.split())
    assert "sensitive data + untrusted content + external destination" in normalized


def test_setup_help_has_no_raw_rst_double_backticks() -> None:
    result = runner.invoke(app, ["setup", "--help"])
    assert result.exit_code == 0, result.output
    assert "``" not in result.output


def test_install_hooks_help_has_no_raw_rst_double_backticks() -> None:
    result = runner.invoke(app, ["install-hooks", "--help"])
    assert result.exit_code == 0, result.output
    assert "``" not in result.output


def test_install_hooks_help_documents_the_host_scope_difference() -> None:
    result = runner.invoke(app, ["install-hooks", "--help"])
    assert result.exit_code == 0, result.output
    assert "mcp" in result.output and "openclaw" in result.output


# ---------------------------------------------------------------------------
# Terminal-width wrapping and the section rule (item 3)
# ---------------------------------------------------------------------------


def test_columns_60_and_200_produce_different_wrapped_output(tmp_path: Path) -> None:
    d1, d2 = tmp_path / "a", tmp_path / "b"
    d1.mkdir()
    d2.mkdir()
    narrow = runner.invoke(app, ["setup", "--yes", "--path", str(d1)], env={"COLUMNS": "60"})
    wide = runner.invoke(app, ["setup", "--yes", "--path", str(d2)], env={"COLUMNS": "200"})
    assert narrow.exit_code == 0, narrow.output
    assert wide.exit_code == 0, wide.output
    assert narrow.output != wide.output
    assert len(narrow.output.splitlines()) > len(wide.output.splitlines())


def test_section_rule_is_never_empty_for_a_long_title(monkeypatch: pytest.MonkeyPatch) -> None:
    import doberman.cli.main as cli_module

    monkeypatch.setattr(
        cli_module.shutil, "get_terminal_size", lambda fallback=(100, 24): (100, 24)
    )
    monkeypatch.delenv("NO_COLOR", raising=False)
    line = cli_module._section("MCP proxy (Cursor / Claude Desktop / other MCP client)")
    assert line.rstrip("-").rstrip() != line.rstrip()  # at least one trailing dash
    assert line.count("-") > 5


# ---------------------------------------------------------------------------
# Color (item 4)
# ---------------------------------------------------------------------------


def test_mode_style_gradient_has_four_distinct_styles() -> None:
    import doberman.cli.main as cli_module

    styles = list(cli_module._MODE_STYLE.values())
    assert len(set(styles)) == len(styles) == 4


def test_setup_output_carries_zero_ansi_under_no_color(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NO_COLOR", "1")
    result = runner.invoke(app, ["setup", "--yes", "--path", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "\x1b[" not in result.output


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
    # A long description (e.g. "strict") wraps into more than one line, so
    # this is a floor, not an exact count.
    assert len(lines) >= len(list(SecurityMode))
    for mode in SecurityMode:
        assert any(mode.value in line for line in lines)


def test_mode_menu_lines_wraps_long_descriptions_with_a_hanging_indent() -> None:
    """The `strict` description overflows a single line; its continuation(s)
    indent to the description column, never to column 0."""
    from doberman.hosthooks.setup import mode_menu_lines

    lines = mode_menu_lines()
    strict_idx = next(i for i, line in enumerate(lines) if line.lstrip().startswith("[3]"))
    next_line = lines[strict_idx + 1]
    assert next_line.startswith("                ")  # hanging indent, not column 0
    assert next_line.strip()


# ---------------------------------------------------------------------------
# Round 3: honest-end wizard polish (items 1-13)
# ---------------------------------------------------------------------------


def test_host_and_mode_menus_share_the_same_numbering_style() -> None:
    """item 9: both menus use `[N]`, not `1)` for one and `[1]` for the other."""
    from doberman.hosthooks.setup import host_menu_lines, mode_menu_lines

    assert host_menu_lines(set())[0].lstrip().startswith("[1]")
    assert mode_menu_lines()[0].lstrip().startswith("[1]")


def test_codex_host_gets_verify_line_and_already_wired_summary(tmp_path: Path) -> None:
    """item 1: Codex gets the same epilogue "Verify it's live" pointer Claude
    and mcp get, not only its own mid-wiring TRUST ritual. item 2: a re-run
    with unchanged hooks says "already wired" in the Hosts: summary too."""
    first = runner.invoke(app, ["setup", "--yes", "--host", "codex", "--path", str(tmp_path)])
    assert first.exit_code == 0, first.output
    assert (
        "Verify it's live: ask your agent to read .env and confirm it is blocked." in first.output
    )
    assert "  codex    hook written to" in first.output

    second = runner.invoke(app, ["setup", "--yes", "--host", "codex", "--path", str(tmp_path)])
    assert second.exit_code == 0, second.output
    assert "  codex    already wired:" in second.output


def test_write_and_already_wired_lines_render_bold(monkeypatch: pytest.MonkeyPatch) -> None:
    """item 2: the write is the visible event - bold when color is supported.
    Click's own ``echo()`` strips ANSI on any non-tty stream (CliRunner
    included), so - same pattern as test_cli_verdict_render.py - this is
    tested at the ``style_text`` level directly, not via captured CLI output."""
    import doberman.render as render_mod

    monkeypatch.setattr(render_mod, "supports_color", lambda: True)
    assert render_mod.style_text("wrote /tmp/x", bold=True) == "\x1b[1mwrote /tmp/x\x1b[0m"
    assert (
        render_mod.style_text("already wired: /tmp/x", bold=True)
        == "\x1b[1malready wired: /tmp/x\x1b[0m"
    )

    monkeypatch.setattr(render_mod, "supports_color", lambda: False)
    assert render_mod.style_text("wrote /tmp/x", bold=True) == "wrote /tmp/x"


def test_interactive_step_counter_appears_in_section_titles(tmp_path: Path) -> None:
    """item 3: a fully-interactive run numbers every prompt-bearing section;
    "Wiring" covers Hook installation/MCP/OpenClaw as one stage. item 7 (round
    4): the closing demo offer counts as a step too, so the denominator is 7."""
    result = runner.invoke(
        app,
        ["setup", "--path", str(tmp_path)],
        input="\nbalanced\nn\nn\nn\nn\n",
    )
    assert result.exit_code == 0, result.output
    assert "Hosts [1 of 7]" in result.output
    assert "Security mode [2 of 7]" in result.output
    assert "Preference tuning [3 of 7]" in result.output
    assert "Hook installation (Claude Code) [4 of 7]" in result.output
    assert "Telemetry [5 of 7]" in result.output
    assert "Doctor [6 of 7]" in result.output
    assert "[7 of 7]" in result.output  # the demo offer, item 7


def test_yes_run_shows_no_step_counters(tmp_path: Path) -> None:
    """item 3: `--yes` prompts for nothing, so it never shows a step counter."""
    import re

    result = runner.invoke(app, ["setup", "--yes", "--path", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert re.search(r"\[\d+ of \d+\]", result.output) is None


def test_tune_prefs_invalid_weight_reprompts_and_names_changed_dims(tmp_path: Path) -> None:
    """item 4: an invalid weight reprompts exactly like every other field
    (never a raw `could not convert string to float`), and the summary
    names exactly the dimensions that actually changed."""
    result = runner.invoke(
        app,
        ["setup", "--path", str(tmp_path)],
        input="\nbalanced\ny\nabc\n0.9\n\n\n\nn\nn\nn\n",
    )
    assert result.exit_code == 0, result.output
    assert "error: 'abc' is not a number between 0 and 1 - try again" in result.stderr
    assert "could not convert string to float" not in result.output
    assert "Prefs:      custom (tuned: confidentiality)" in result.output


def test_tune_prefs_nothing_changed_falls_back_to_preset_name(tmp_path: Path) -> None:
    """item 4: tuning through every prompt and keeping every default names
    the preset, not an empty "custom (tuned: )"."""
    result = runner.invoke(
        app,
        ["setup", "--path", str(tmp_path)],
        input="\nbalanced\ny\n\n\n\n\nn\nn\nn\n",
    )
    assert result.exit_code == 0, result.output
    assert "Prefs:      preset defaults for balanced" in result.output


def test_hosts_menu_q_aborts_cleanly(tmp_path: Path) -> None:
    """item 6: 'q' at the Hosts menu aborts cleanly, exit 1, nothing written."""
    result = runner.invoke(app, ["setup", "--path", str(tmp_path)], input="q\n")
    assert result.exit_code == 1, result.output
    assert "Aborted - nothing written." in result.stderr
    assert not (tmp_path / ".claude").exists()


def test_mode_menu_quit_aborts_cleanly(tmp_path: Path) -> None:
    """item 6: 'quit' (not just 'q') also aborts cleanly."""
    result = runner.invoke(app, ["setup", "--path", str(tmp_path)], input="\nquit\n")
    assert result.exit_code == 1, result.output
    assert "Aborted - nothing written." in result.stderr


def test_mode_menu_five_invalid_answers_aborts(tmp_path: Path) -> None:
    """item 6: five invalid answers in a row aborts rather than looping forever."""
    result = runner.invoke(
        app,
        ["setup", "--path", str(tmp_path)],
        input="\nbogus\nbogus\nbogus\nbogus\nbogus\n",
    )
    assert result.exit_code == 1, result.output
    assert "Aborted - nothing written." in result.stderr
    assert result.stderr.count("error:") == 5


def test_hosts_menu_eof_prints_the_setup_specific_abort_message(tmp_path: Path) -> None:
    """item 6: an exhausted stdin at a menu gets this wizard's own message,
    never a bare Click 'Aborted!'."""
    result = runner.invoke(app, ["setup", "--path", str(tmp_path)], input="")
    assert result.exit_code == 1, result.output
    assert "Aborted - nothing written." in result.stderr
    assert "Aborted!" not in result.output


def test_weight_tuning_q_aborts_cleanly(tmp_path: Path) -> None:
    """item 6: 'q' during weight tuning aborts the whole wizard, same as any
    other menu - it doesn't just skip the remaining dimensions. Round 4 item 1:
    by this point the mode IS already persisted, so the abort message says so
    instead of the (now false) "nothing written"."""
    result = runner.invoke(
        app,
        ["setup", "--path", str(tmp_path)],
        input="\nbalanced\ny\nq\n",
    )
    assert result.exit_code == 1, result.output
    assert (
        "Aborted - security mode balanced was already saved (no hooks written); run "
        "'doberman mode <other>' to change it, which needs your possession factor to "
        "lower." in result.stderr
    )
    assert "Aborted - nothing written." not in result.stderr
    assert load_mode(str(tmp_path)) == "balanced"
    assert not (tmp_path / ".claude").exists()


def test_doctor_critical_detail_appears_only_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """item 8: the doctor block prints a critical's detail once; the closing
    red sentence references it by name only, not a repeated/truncated copy."""
    from doberman.cli import doctor as doctor_mod

    def _fake_run_checks(path: str) -> list:
        return [
            doctor_mod.CheckResult(
                "Config",
                doctor_mod.CheckStatus.FAIL,
                "no policy saved - run `doberman setup`",
                critical=True,
            )
        ]

    monkeypatch.setattr(doctor_mod, "run_checks", _fake_run_checks)
    result = runner.invoke(app, ["setup", "--yes", "--path", str(tmp_path)])
    assert result.exit_code == 1, result.output
    assert result.output.count("no policy saved - run `doberman setup`") == 1
    normalized = " ".join(result.output.split())
    assert (
        "Not protecting this repo yet: fix 'Config' above, then run 'doberman doctor'."
        in normalized
    )


def test_invalid_host_rejects_before_the_welcome_banner(tmp_path: Path) -> None:
    """item 9: `--host vscode` is a hard usage error before any banner prints."""
    result = runner.invoke(app, ["setup", "--yes", "--host", "vscode", "--path", str(tmp_path)])
    assert result.exit_code == 2, result.output
    assert "Welcome to Doberman setup!" not in result.output
    assert "unknown host(s) vscode" in result.output


def test_blast_radius_glossed_in_tuning_copy(tmp_path: Path) -> None:
    """item 10: `blast_radius` carries an inline gloss where it's shown as a
    raw weight name, unlike the other three dimensions (already plain English)."""
    result = runner.invoke(
        app,
        ["setup", "--path", str(tmp_path)],
        input="\nbalanced\nn\nn\nn\nn\n",
    )
    assert result.exit_code == 0, result.output
    normalized = " ".join(result.output.split())
    assert "blast_radius=0.50 (actions affecting many targets)" in normalized


def test_dry_run_without_yes_and_no_tty_uses_defaults(tmp_path: Path) -> None:
    """item 12: `--dry-run` with no `--yes` and no TTY on stdin behaves like
    `--yes --dry-run` (defaults, preview, exit 0) instead of hitting EOF at
    the first prompt."""
    result = runner.invoke(app, ["setup", "--dry-run", "--path", str(tmp_path)], input="")
    assert result.exit_code == 0, result.output
    assert "stdin is not a terminal - using defaults for the preview" in result.stderr
    assert "[dry-run] would set mode: balanced" in result.output
    assert not (tmp_path / ".claude").exists()


def test_dry_run_with_yes_unaffected_by_the_non_tty_check(tmp_path: Path) -> None:
    """item 12: the non-tty note is specific to the no-`--yes` case; a plain
    `--yes --dry-run` never prints it."""
    result = runner.invoke(app, ["setup", "--yes", "--dry-run", "--path", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "stdin is not a terminal" not in result.output
    assert "stdin is not a terminal" not in result.stderr


# ---------------------------------------------------------------------------
# Round 4: honest abort, one output grammar, telemetry dedup, spacing (items 1-16)
# ---------------------------------------------------------------------------


def test_invalid_mode_rejects_before_the_welcome_banner(tmp_path: Path) -> None:
    """item 2: a bad `--mode` is a hard usage error before any banner prints,
    same as a bad `--host` already was."""
    result = runner.invoke(app, ["setup", "--yes", "--mode", "bogus", "--path", str(tmp_path)])
    assert result.exit_code == 2, result.output
    assert "Welcome to Doberman setup!" not in result.output
    assert "unknown mode" in result.output


def test_no_telemetry_flag_disables_and_persists(tmp_path: Path) -> None:
    """item 3: `--no-telemetry` skips the question entirely and persists off,
    the same outcome `doberman telemetry off` gives."""
    from doberman import telemetry

    result = runner.invoke(app, ["setup", "--yes", "--no-telemetry", "--path", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "Telemetry: off (--no-telemetry)" in result.output
    assert telemetry.status().enabled is False


def test_setup_help_never_prints_the_telemetry_notice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """item 3/10: `--help` never runs setup's own body (Click prints help and
    exits first), so the generic first-run notice must never show above the
    usage text either."""
    monkeypatch.delenv("DOBERMAN_TELEMETRY", raising=False)
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("DO_NOT_TRACK", raising=False)
    result = runner.invoke(app, ["setup", "--help"])
    assert result.exit_code == 0, result.output
    assert "sends anonymous usage counts" not in result.output
    assert "Usage:" in result.output


def test_setup_help_documents_exit_codes() -> None:
    """item 10: `setup --help` mentions all three exit codes it can raise."""
    result = runner.invoke(app, ["setup", "--help"])
    assert result.exit_code == 0, result.output
    normalized = " ".join(result.output.split())
    for code in ("0", "1", "3"):
        assert code in normalized


def test_hook_group_help_mentions_codex_alongside_claude_code() -> None:
    """item 10: the top-level `hook` group's help text names Codex CLI too,
    not just Claude Code."""
    result = runner.invoke(app, ["hook", "--help"])
    assert result.exit_code == 0, result.output
    assert "Claude Code" in result.output
    assert "Codex" in result.output


def test_wrapped_lines_stay_within_78_columns_at_columns_60(tmp_path: Path) -> None:
    """item 4: the mode/telemetry/dry-run summary lines wrap through
    `wrap_detail` like every other long line, so nothing overruns 78 columns
    at a narrow terminal - except a URL, or this test's own (environment-
    dependent) tmp_path, which `wrap_detail` deliberately never splits
    mid-token (a garbled path is worse than a long line)."""
    result = runner.invoke(app, ["setup", "--yes", "--path", str(tmp_path)], env={"COLUMNS": "60"})
    assert result.exit_code == 0, result.output
    tmp_str = str(tmp_path)
    for line in result.output.splitlines():
        if "://" in line or tmp_str in line:
            continue
        assert len(line) <= 78, line


def test_dry_run_mode_line_wraps_with_hanging_indent(tmp_path: Path) -> None:
    """item 4: the `[dry-run] would set mode: ...` line goes through
    `wrap_detail` too, at the narrowest supported width (the `[dry-run] would
    write: <path>` lines are unwrapped by design, item unrelated - exempted
    same as this test's own tmp_path elsewhere)."""
    result = runner.invoke(
        app,
        ["setup", "--yes", "--dry-run", "--path", str(tmp_path)],
        env={"COLUMNS": "60"},
    )
    assert result.exit_code == 0, result.output
    tmp_str = str(tmp_path)
    for line in result.output.splitlines():
        if tmp_str in line:
            continue
        assert len(line) <= 78, line


def test_hosts_and_mode_prompts_end_in_q_to_quit(tmp_path: Path) -> None:
    """item 5: the hosts and mode menu prompts are discoverable as quittable,
    same as the weight-tuning prompt already is."""
    result = runner.invoke(
        app,
        ["setup", "--path", str(tmp_path)],
        input="\nbalanced\nn\nn\nn\nn\n",
    )
    assert result.exit_code == 0, result.output
    assert "(numbers or names, comma-separated, or 'all') (q to quit)" in result.output
    assert "Choose a mode (name or number) (q to quit)" in result.output


def test_rerun_says_hooks_already_in_place_not_written(tmp_path: Path) -> None:
    """item 6: a re-run where every hooks-kind host was already wired must
    never claim "Hooks written." - it says "already in place" instead."""
    first = runner.invoke(app, ["setup", "--yes", "--path", str(tmp_path)])
    assert first.exit_code == 0, first.output

    second = runner.invoke(app, ["setup", "--yes", "--path", str(tmp_path)])
    assert second.exit_code == 0, second.output
    assert (
        "Hooks already in place. Doberman activates when you restart your session." in second.output
    )
    assert "Hooks written." not in second.output


def test_openclaw_only_pending_message_has_no_paste_step(tmp_path: Path) -> None:
    """item 13: OpenClaw has no paste step, unlike mcp - the pending epilogue
    names its actual remaining step instead of the mcp "paste the block"
    wording."""
    result = runner.invoke(app, ["setup", "--yes", "--host", "openclaw", "--path", str(tmp_path)])
    assert result.exit_code == 3, result.output
    normalized = " ".join(result.output.split())
    assert (
        "After you follow adapters/openclaw/README.md and restart: ask your agent to "
        "read .env and confirm it is blocked." in normalized
    )
    assert "paste the block" not in normalized


def test_mcp_and_openclaw_pending_message_prefers_mcp_wording(tmp_path: Path) -> None:
    """item 13: when both are chosen, mcp's paste step IS still real, so the
    mcp wording (not the openclaw-only one) applies."""
    result = runner.invoke(
        app,
        ["setup", "--yes", "--host", "mcp", "--host", "openclaw", "--path", str(tmp_path)],
    )
    assert result.exit_code == 3, result.output
    normalized = " ".join(result.output.split())
    assert "After you paste the block and restart your client" in normalized


def test_codex_only_verify_line_appears_exactly_once(tmp_path: Path) -> None:
    """item 14: Codex's mid-wiring TRUST ritual no longer prints its own
    "Verify it's live" line - the epilogue's is the only one."""
    result = runner.invoke(app, ["setup", "--yes", "--host", "codex", "--path", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert result.output.count("Verify it's live") == 1


def test_prompt_menu_reprompt_starts_with_a_blank_echo(monkeypatch: pytest.MonkeyPatch) -> None:
    """item 15: a bad answer's retry is preceded by a blank stdout line, so it
    never glues onto the first (un-terminated) prompt's text. Tested at the
    `_prompt_menu` level directly rather than via CliRunner: CliRunner's own
    stdin-echo simulation already inserts a newline after a fed answer, which
    would mask whether this fix's OWN newline is present - a real piped,
    non-interactive run (the case this bug affects) has no such echo."""
    from doberman.hosthooks.setup import parse_mode_choice

    answers = iter(["bogus", "balanced"])
    monkeypatch.setattr(
        cli_module.typer, "prompt", lambda text, default: next(answers), raising=True
    )
    echo_calls: list[tuple] = []
    monkeypatch.setattr(
        cli_module.typer,
        "echo",
        lambda *a, **k: echo_calls.append((a, k)),
        raising=True,
    )

    result = cli_module._prompt_menu(
        "Choose a mode (name or number)", "balanced", parse_mode_choice
    )

    assert result == cli_module.SecurityMode.balanced
    # The error for "bogus" prints first (to stderr); THEN, before the retry
    # prompt is issued, a bare blank echo (no args) separates it.
    assert echo_calls[0][1].get("err") is True
    assert echo_calls[1] == ((), {})


def test_no_double_blank_line_on_a_yes_mcp_only_run(tmp_path: Path) -> None:
    """item 11: an mcp/openclaw-only `--yes` run is exactly the path that used
    to double up a blank line twice - once right after the welcome banner
    (mcp's own section header used to always prepend a blank), and once
    between the "Hosts:" summary and the telemetry line on the pending path."""
    result = runner.invoke(app, ["setup", "--yes", "--host", "mcp", "--path", str(tmp_path)])
    assert result.exit_code == 3, result.output
    assert "\n\n\n" not in result.output


def test_no_double_blank_line_when_hosts_skipped_but_mode_interactive(tmp_path: Path) -> None:
    """item 11: `--host` given via flag (skips the Hosts menu) but the mode
    still interactive used to double the blank right before "-- Security
    mode --" (the welcome banner's own trailing blank plus the section's)."""
    result = runner.invoke(
        app,
        ["setup", "--host", "claude", "--path", str(tmp_path)],
        input="balanced\nn\nn\nn\n",
    )
    assert result.exit_code == 0, result.output
    assert "\n\n\n" not in result.output


def test_no_double_blank_line_in_a_full_interactive_run(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["setup", "--path", str(tmp_path)],
        input="\nbalanced\nn\nn\nn\nn\n",
    )
    assert result.exit_code == 0, result.output
    assert "\n\n\n" not in result.output
