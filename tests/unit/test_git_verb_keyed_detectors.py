"""Issue #550 — force-push / history-rewrite detectors must key on the git
VERB, not on flag-shaped substrings anywhere in argv.

Before the fix, ``_git_force_push_to_protected``/``_git_is_history_rewrite``
scanned the whole token list for "push"/"--force"/"reset"/"--hard"/
"filter-branch"/"clean" regardless of which git subcommand was actually
running, so a read-only verb (``log``, ``grep``, ...) whose *arguments*
happened to contain those words — once shell-quoting fails to keep them
inside one token — false-BLOCKed/AUTHed. The fix locates the real verb via
``_git_leading_globals`` (skipping ``-C <path>``/``-c <k=v>``/etc.) and only
inspects that verb's own argv.

Covers: false-positive read-only commands → PASS, no destructive_command
reason code; force-push/history-rewrite raise-only regression → unchanged
verdict + reason codes; a shell-quoted argument that keeps the flag text
inside one token; a chained command where the *first* segment merely mentions
a verb but the *second* segment is a real force-push.
"""

from datetime import datetime, timezone

import pytest

from doberman.engine.rules.commands import DestructiveCommandRule
from doberman.models import ActionType, EvalContext, ReasonCode, SecurityObject, Verdict

RULE = DestructiveCommandRule()


def _cmd(command, *, action_type=ActionType.shell_exec):
    action = SecurityObject(
        id="cmd-1",
        ts=datetime(2026, 6, 7, tzinfo=timezone.utc),
        agent_role="unknown",
        action_type=action_type,
        tool_name="shell_exec",
        target=command,
    )
    ctx = EvalContext(metadata={"raw_arguments": {"command": command}})
    return RULE.evaluate(action, ctx)


# --- (a) false positives: read-only verb, rewrite-flag-shaped ARGUMENTS ---


@pytest.mark.parametrize(
    "command",
    [
        # Literal examples from issue #550 (already correctly parsed as one
        # shlex token by the quoting; kept as an explicit regression guard).
        'git log --grep "push --force"',
        'git log -S "--force-with-lease"',
        'git grep "git push -f"',
        'git log --grep="push --force"',
        # The actual root-cause repro: once the flag-shaped words land as
        # SEPARATE argv tokens (no quoting), the old whole-argv scan
        # false-fired. These were BLOCK/AUTH before the fix, PASS after.
        "git log --grep push --force",
        "git log --grep push -f",
        "git grep git push -f",
        "git log -S --force-with-lease",
        "git log reset --hard",
        "git log filter-branch",
    ],
)
def test_read_only_verb_with_rewrite_flag_shaped_argument_is_not_flagged(command):
    result = _cmd(command)
    assert result.verdict is Verdict.PASS
    assert ReasonCode.destructive_command not in result.reason_codes


# --- (b) raise-only regression: real force-push / history-rewrite keep their
# verdict + reason codes exactly as observed on origin/main before the fix ---


@pytest.mark.parametrize(
    "command",
    [
        "git push --force origin main",
        "git push -f origin master",
        "git push origin +main",
        "git -C /repo push --force origin main",
        "git -c core.x=y push --force-with-lease origin release",
    ],
)
def test_real_force_push_still_blocks(command):
    result = _cmd(command, action_type=ActionType.git_op)
    assert result.verdict is Verdict.BLOCK
    assert result.reason_codes == [ReasonCode.destructive_command]


def test_real_hard_reset_still_requires_auth():
    result = _cmd("git reset --hard HEAD~3", action_type=ActionType.git_op)
    assert result.verdict is Verdict.AUTH
    assert result.reason_codes == [ReasonCode.destructive_command]


def test_interactive_rebase_is_unaffected():
    # `_git_is_history_rewrite` never covered bare `rebase` (only
    # reset --hard/filter-branch/clean -f) — this is not a detector this fix
    # touches; assert its verdict is unchanged (PASS), not invented.
    result = _cmd("git rebase -i HEAD~5", action_type=ActionType.git_op)
    assert result.verdict is Verdict.PASS


# --- (c) chained command: only the SECOND segment is a real force-push ---


def test_chained_command_second_segment_force_push_still_blocks():
    result = _cmd("git log --grep push && git push --force origin main")
    assert result.verdict is Verdict.BLOCK
    assert result.reason_codes == [ReasonCode.destructive_command]
