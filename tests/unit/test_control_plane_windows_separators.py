"""A control-plane path spelled with Windows separators is still control plane.

The command rule scans each segment's argv tokens for control-plane paths, and
those tokens come from ``shlex.split(..., posix=True)``. In POSIX mode ``\\`` is
an **escape character**, so ``rm .doberman\\policies.yaml`` tokenizes to the
single token ``.dobermanpolicies.yaml``: the separators are consumed before any
path check runs, and the result matches no glob.

Every control-plane guarantee in the command rule was therefore reachable on
Windows just by spelling the path the way Windows spells it — deleting the policy
document, or rewriting the ``.claude`` host-hook config to unhook Doberman
entirely. `names_control_plane` itself was never the problem; it normalizes
separators correctly. The path simply never reached it.

The fix re-scans a separator-normalized copy of the raw command, scan-only, so it
can only ever add a control-plane BLOCK.
"""

from datetime import datetime, timezone

import pytest

from doberman.engine.rules.commands import DestructiveCommandRule
from doberman.models import ActionType, EvalContext, ReasonCode, SecurityObject, Verdict

RULE = DestructiveCommandRule()


def _cmd(command, *, root="."):
    action = SecurityObject(
        id="cp-winsep-1",
        ts=datetime(2026, 8, 6, tzinfo=timezone.utc),
        agent_role="unknown",
        action_type=ActionType.shell_exec,
        tool_name="Bash",
        target=command,
        metadata={},
    )
    ctx = EvalContext(metadata={"raw_arguments": {"command": command}, "repo_root": root})
    return RULE.evaluate(action, ctx)


@pytest.mark.parametrize(
    "command",
    [
        r"rm .doberman\policies.yaml",
        r"del .doberman\policies.yaml",
        r"rm -rf .doberman\baselines",
        r"rm .claude\settings.json",
        r"rm .claude\settings.local.json",
        # nested, and absolute
        r"rm sub\.doberman\policies.yaml",
        r"rm C:\repo\.doberman\policies.yaml",
        # mixed separators — the realistic copy-paste shape
        r"rm ./sub\.doberman\policies.yaml",
    ],
)
def test_windows_spelled_control_plane_delete_is_blocked(command):
    result = _cmd(command)
    assert result.verdict is Verdict.BLOCK
    assert ReasonCode.protected_path_blocked in result.reason_codes


@pytest.mark.parametrize(
    "command",
    [
        r"echo {} > .claude\settings.json",
        r"echo x >> .claude\settings.local.json",
        r"cp evil.json .claude\settings.json",
        r"sed -i s/a/b/ .doberman\policies.yaml",
    ],
)
def test_windows_spelled_control_plane_write_is_blocked(command):
    """Rewriting the hook config unhooks Doberman without deleting anything."""
    assert _cmd(command).verdict is Verdict.BLOCK


def test_the_forward_slash_form_still_blocks():
    """Regression: the fix must not disturb the path that already worked."""
    assert _cmd("rm -rf .doberman").verdict is Verdict.BLOCK
    assert _cmd("echo '{}' > .claude/settings.json").verdict is Verdict.BLOCK


# --- the normalization must not invent blocks ---


@pytest.mark.parametrize(
    "command",
    [
        # A genuine POSIX escape. Normalizing gives the harmless tokens
        # `my/` and `file.txt`; neither is control plane.
        r"rm my\ file.txt",
        r"echo hello\ world",
        # Backslashes that have nothing to do with a path.
        r"grep -r 'a\\b' src",
        r"printf 'a\tb\n'",
        # An ordinary Windows path that is not control plane.
        r"rm C:\repo\build\out.txt",
        r"type src\doberman\models.py",
    ],
)
def test_ordinary_backslash_commands_are_not_blocked(command):
    assert _cmd(command).verdict is not Verdict.BLOCK


def test_a_command_with_no_backslash_is_untouched():
    """The scan short-circuits on commands with no `\\`, so the common path pays
    nothing and cannot change behavior."""
    assert _cmd("ls -la").verdict is not Verdict.BLOCK
    assert _cmd("git status").verdict is not Verdict.BLOCK


def test_explanation_does_not_echo_the_command():
    """Prime Directive 3: name the category, never the path."""
    result = _cmd(r"rm C:\repo\.doberman\policies.yaml")
    blob = f"{result.explanation} {' '.join(str(c) for c in result.reason_codes)}"
    assert "C:" not in blob
    assert "policies.yaml" not in blob


def test_unbalanced_quoting_still_catches_the_control_plane():
    """A command whose normalized form will not tokenize must not become a free
    bypass — the crude fallback split still sees the path."""
    assert _cmd(r"rm '.doberman\policies.yaml").verdict is Verdict.BLOCK
