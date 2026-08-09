"""The Codex CLI control plane is self-protected (W1.3 — two-hosts-one-spine).

Doberman gates Claude Code's and OpenClaw's tool calls through hooks. Codex CLI
is the third front door, and its control plane — the hook config
(``~/.codex/hooks.json`` and ``<repo>/.codex/hooks.json``), ``config.toml`` (it
configures hooks, trust, AND the sandbox), the ``.codex`` dir itself, and the
plugin dirs that can carry plugin-bundled hooks — must be off-limits to a
proxied agent, exactly as ``.claude``/``.doberman`` already are. Otherwise the
agent could unhook, un-trust, or reconfigure its own leash.

The hook-and-trust surface is a hard BLOCK; the rest of ``.codex/**`` is
SENSITIVE (AUTH), mirroring the existing ``.claude`` split. Because the globs
live in ``CONTROL_PLANE_GLOBS``, the shared ``names_control_plane`` helper (used
by the command rule) catches a shell command that *names* one of these paths
too — including ``~``-prefixed and Windows-separator forms (the ADR 0066 class).
"""

from datetime import datetime, timezone

import pytest

from doberman.engine.rules.paths import (
    CONTROL_PLANE_GLOBS,
    ProtectedPathRule,
    names_control_plane,
)
from doberman.models import ActionType, EvalContext, ReasonCode, SecurityObject, Verdict

RULE = ProtectedPathRule()

#: The hook-and-trust surface — hard BLOCK.
BLOCKED_CODEX = [
    ".codex",  # the directory itself ("fire the cop")
    ".codex/hooks.json",  # hook surface
    ".codex/config.toml",  # configures hooks, trust, AND sandbox
    ".codex/plugins/evil",  # plugin-bundled hooks surface
    "sub/dir/.codex/hooks.json",  # nested repo
]

#: The rest of the Codex control directory — SENSITIVE (AUTH).
SENSITIVE_CODEX = [".codex/prompts.md", ".codex/anything-else.txt"]


def _action(target, *, action_type=ActionType.file_write):
    return SecurityObject(
        id="cp-codex",
        ts=datetime(2026, 8, 8, tzinfo=timezone.utc),
        agent_role="unknown",
        action_type=action_type,
        tool_name="t",
        target=target,
        metadata={},
    )


def _ctx(root):
    return EvalContext(metadata={"repo_root": str(root)})


@pytest.mark.parametrize("path", BLOCKED_CODEX)
@pytest.mark.guarantee("control-plane-self-protection", host="codex")
def test_codex_control_plane_write_is_blocked(path, tmp_path):
    result = RULE.evaluate(_action(path), _ctx(tmp_path))
    assert result.verdict is Verdict.BLOCK
    assert ReasonCode.protected_path_blocked in result.reason_codes


@pytest.mark.parametrize("path", BLOCKED_CODEX)
def test_codex_control_plane_delete_is_blocked(path, tmp_path):
    result = RULE.evaluate(_action(path, action_type=ActionType.file_delete), _ctx(tmp_path))
    assert result.verdict is Verdict.BLOCK
    assert ReasonCode.protected_path_blocked in result.reason_codes


@pytest.mark.parametrize("path", BLOCKED_CODEX)
def test_codex_control_plane_read_is_blocked(path, tmp_path):
    result = RULE.evaluate(_action(path, action_type=ActionType.file_read), _ctx(tmp_path))
    assert result.verdict is Verdict.BLOCK
    assert ReasonCode.protected_path_blocked in result.reason_codes


@pytest.mark.parametrize("path", BLOCKED_CODEX)
def test_command_naming_codex_control_plane_is_caught(path):
    # The shared helper the command rule uses must catch a control-plane path
    # hidden in a shell command string — including home-dir and Windows-separator
    # spellings (ADR 0066 class).
    assert names_control_plane(path)
    assert names_control_plane(f"~/{path}")
    assert names_control_plane(path.replace("/", "\\"))


@pytest.mark.parametrize("path", SENSITIVE_CODEX)
def test_rest_of_codex_dir_requires_auth(path, tmp_path):
    result = RULE.evaluate(_action(path), _ctx(tmp_path))
    assert result.verdict is Verdict.AUTH
    assert ReasonCode.sensitive_path_access in result.reason_codes


def test_raise_only_existing_control_plane_intact():
    # Raise-only: the Codex globs are append-only. The pre-existing .claude /
    # .doberman hard-block entries must remain present and unchanged.
    for existing in (".claude/settings.json", ".claude", ".doberman", ".doberman/**"):
        assert existing in CONTROL_PLANE_GLOBS
    # And the new Codex hook-and-trust surface is now covered.
    for added in (".codex/hooks.json", ".codex/config.toml", ".codex"):
        assert added in CONTROL_PLANE_GLOBS
