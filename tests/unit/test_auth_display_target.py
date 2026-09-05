"""The auth prompt shows the human what the agent asked for, never "<redacted>".

The log-side redactor (``proxy.normalize``) replaces any argument value over
256 chars, or holding a 40+ char unbroken run (a long path, a hash, a URL),
wholesale — so ``action.target`` for most real shell commands is the literal
``<redacted>``. Every prompter rendered that target, and the local dialog read
"Your agent wants to run a command: <redacted>" — nothing to judge.

Contracts under test:
* ``display_target`` renders the RAW arguments with only secret-shaped tokens
  masked, bounded in length; the logged target stays ``<redacted>``;
* the challenge carries it prompt-only: the message shows it, the caller's
  ``SecurityObject`` is untouched, and the dashboard's pending row never holds
  it (that channel withholds the command by design);
* the host spine and the host-hook auth wrapper hand it along.
"""

import asyncio
import json
from datetime import datetime, timezone

from doberman.auth import dashboard_prompter
from doberman.auth.challenge import AuthTier, run_auth_challenge
from doberman.auth.dashboard_prompter import DashboardPrompter
from doberman.auth.provider import challenge_parts
from doberman.hosthooks import hookio, spine
from doberman.models import (
    ActionType,
    Decision,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    Verdict,
)
from doberman.proxy.normalize import REDACTED, challenge_copy, display_target, normalize
from doberman.storage import approvals
from doberman.storage.heartbeat import touch_heartbeat

_NOW = datetime(2026, 9, 5, tzinfo=timezone.utc)
_LONG_PATH = (
    "C:/Users/someone/Documents/GitHub/Doberman/Doberman-Core/src/doberman/auth/provider.py"
)
_COMMAND = f"git diff --stat main -- {_LONG_PATH}"


class FakePrompter:
    def __init__(self) -> None:
        self.messages: list[str] = []

    def confirm(self, message: str) -> bool:
        self.messages.append(message)
        return True

    def read_code(self, message: str) -> str:
        self.messages.append(message)
        return ""


def _action(target: str | None = REDACTED) -> SecurityObject:
    return SecurityObject(
        id="act-dt",
        ts=_NOW,
        agent_role="tester",
        action_type=ActionType.shell_exec,
        tool_name="shell",
        target=target,
        risk=Risk.low,
    )


def _auth_decision() -> Decision:
    reasons = [ReasonCode.destructive_command]
    objective = GuardrailResult(
        verdict=Verdict.AUTH, risk=Risk.low, reason_codes=reasons, explanation="why"
    )
    return Decision(
        action_id="act-dt",
        final_verdict=Verdict.AUTH,
        final_risk=Risk.low,
        objective=objective,
        reason_codes=reasons,
        explanation="why",
        decided_at=_NOW,
    )


# --- display_target ---------------------------------------------------------------


def test_long_path_shown_in_full_while_logged_target_stays_redacted():
    args = {"command": _COMMAND}
    assert normalize("bash", args, {"repo_root": "."}).target == REDACTED  # log floor unchanged
    assert display_target(ActionType.shell_exec, args) == _COMMAND


def test_secret_shaped_token_is_masked_and_the_rest_kept():
    token = "ghp_" + "x" * 36
    args = {"command": f"curl -H 'Authorization: {token}' https://api.example.com/repos"}
    shown = display_target(ActionType.shell_exec, args)
    assert shown is not None
    assert token not in shown
    assert REDACTED in shown
    assert "https://api.example.com/repos" in shown


def test_sensitive_key_value_is_masked():
    shown = display_target(
        ActionType.shell_exec,
        {"command": "mysql --user=app --password=hunter2hunter2 -e 'select 1'"},
    )
    assert shown is not None
    assert "hunter2" not in shown
    assert "--user=app" in shown


def test_oversized_command_is_truncated_after_masking():
    token = "ghp_" + "y" * 36
    args = {"command": "echo " + "a " * 90 + token + " " + "b " * 150}
    shown = display_target(ActionType.shell_exec, args)
    assert shown is not None
    assert shown.startswith("echo a a a")
    assert token not in shown
    assert REDACTED in shown
    assert len(shown) < 400
    assert "more" in shown


def test_argv_shape_and_file_actions_render_too():
    assert (
        display_target(ActionType.shell_exec, {"command": "ls", "args": ["-la", _LONG_PATH]})
        == f"ls -la {_LONG_PATH}"
    )
    assert display_target(ActionType.file_write, {"path": _LONG_PATH, "content": "x"}) == _LONG_PATH
    assert display_target(ActionType.file_write, {}) is None


# --- prompt-only plumbing ---------------------------------------------------------


def test_challenge_parts_prefers_display_target_in_both_tones():
    action = _action().model_copy(update={"metadata": {"display_target": _COMMAND}})
    for tone in ("human", "technical"):
        parts = challenge_parts(_auth_decision(), action, AuthTier.soft_confirm, tone=tone)
        assert parts["target"] == _COMMAND
    assert challenge_parts(_auth_decision(), _action(), AuthTier.soft_confirm)["target"] == REDACTED


def test_challenge_copy_leaves_the_original_untouched_and_is_identity_when_empty():
    action = _action()
    shown = challenge_copy(action, {"command": _COMMAND})
    assert shown.metadata["display_target"] == _COMMAND
    assert shown.id == action.id and shown.target == action.target
    assert "display_target" not in action.metadata
    assert challenge_copy(action, {}) is action


def test_challenge_message_shows_the_command():
    prompter = FakePrompter()
    result = run_auth_challenge(
        _auth_decision(), challenge_copy(_action(), {"command": _COMMAND}), prompter=prompter
    )
    assert result.approved is True
    assert any(_COMMAND in m for m in prompter.messages)


def test_hookio_auth_wrapper_shows_the_command_and_binds_to_the_same_action_id():
    prompter = FakePrompter()
    hook_result, method = hookio.resolve_auth_result(
        _auth_decision(),
        challenge_copy(_action(), {"command": _COMMAND}),
        event="PreToolUse",
        prompter=prompter,
    )
    assert any(_COMMAND in m for m in prompter.messages)
    assert hook_result["hookSpecificOutput"]["permissionDecision"] == "allow", method


def test_dashboard_pending_row_never_carries_the_display_target(tmp_path, monkeypatch):
    root = str(tmp_path)
    touch_heartbeat(root)
    seen: list[str] = []

    def _resolver(seconds: float) -> None:  # noqa: ARG001 - resolves instead of waiting
        if seen:
            return
        rows = asyncio.run(approvals.list_pending(repo_root=root))
        seen.append(json.dumps(rows, default=str))
        asyncio.run(
            approvals.resolve(rows[0]["id"], decision="denied", totp_code=None, repo_root=root)
        )

    monkeypatch.setattr(dashboard_prompter, "_sleep", _resolver)
    result = run_auth_challenge(
        _auth_decision(),
        challenge_copy(_action(), {"command": _COMMAND}),
        prompter=DashboardPrompter(root),
    )
    assert result.approved is False
    assert seen
    assert _LONG_PATH not in seen[0]


def test_spine_result_carries_a_challenge_copy_and_a_clean_action(tmp_path):
    result = spine.evaluate_action(
        "bash", {"command": _COMMAND}, cwd=str(tmp_path), raw_session_id=None
    )
    assert result.challenge_action.metadata["display_target"] == _COMMAND
    assert result.challenge_action.id == result.action.id
    assert result.action.target == REDACTED
    assert "display_target" not in result.action.metadata
