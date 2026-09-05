"""Issue #555 — bounded follow-up to the #603/#612 command-walk hardening.

``{ }``/subshell/keyword segmentation (``if``/``while``/``for``/``!``/
``coproc``/...) is already covered by
``test_rule_commands.py::test_shell_syntax_is_transparent_to_catastrophic_block``.
This file covers the two gaps issue #555 found once that was probed against
the FULL corpus of wrapper/keyword shapes:

* ``builtin <cmd>`` was never a recognized transparent wrapper (unlike its
  sibling ``command``), so ``builtin rm -rf /`` reached the rules with
  ``builtin`` still sitting in argv[0] and PASSed silently — fixed by adding
  it to ``_WRAPPER_VALUE_OPTIONS`` (same shape as ``command``/``exec``/
  ``nice``).
* ``eval "<payload>"`` was never recognized as an opaque string-payload
  shape (unlike its sibling ``sh -c``), so the destructive command hidden
  inside eval's single shlex token PASSed silently — fixed by teaching
  ``_opaque_shell_payload``/``_payload_command`` eval's own concatenation
  rule (bash joins ``eval``'s arguments with a single space and re-parses
  the result), reusing the existing opaque-payload AUTH floor (raised to
  BLOCK when the body scan finds a catastrophe) — no new reason code.

Covers: catches-evasion (destructive command reaches BLOCK/AUTH through the
wrapper/eval shape); no-new-false-positive (benign lookalikes stay PASS);
raise-only (today's verdict for every existing dangerous-command shape is
unchanged); ambiguity floors to AUTH with a human explanation, never a
silent PASS.
"""

from datetime import datetime, timezone

import pytest

from doberman.engine.rules.commands import DestructiveCommandRule, walk_command
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


# --- catches-evasion: builtin/eval must not hide a destructive segment -----


@pytest.mark.parametrize(
    "command",
    [
        "builtin rm -rf /",
        "BUILTIN rm -rf /",  # _wrapper_name lower-cases; raise-only, never fewer matches
        'eval "rm -rf /"',
        "eval 'rm -rf /'",
        "eval rm -rf /",  # unquoted: still concatenated + re-walked
        'Eval "rm -rf /"',
    ],
)
def test_wrapper_and_eval_evasions_still_block(command):
    result = _cmd(command)
    assert result.verdict is Verdict.BLOCK
    assert ReasonCode.destructive_command in result.reason_codes


def test_eval_benign_body_still_floors_to_auth():
    # Same policy as `sh -c "echo hi"`: an opaque payload is AUTH-floored
    # even when the body itself is vettable and benign — it is the SHAPE
    # (a string handed to eval/-c) that is categorically risky, not just
    # this instance's content.
    result = _cmd('eval "echo hi"')
    assert result.verdict is Verdict.AUTH
    assert ReasonCode.opaque_command in result.reason_codes
    assert result.explanation


def test_bare_eval_and_builtin_stay_pass():
    # No payload at all (`eval` with no args is a bash no-op); `builtin`
    # naming a genuinely benign builtin must not be flagged.
    assert _cmd("eval").verdict is Verdict.PASS
    assert _cmd("builtin echo hi").verdict is Verdict.PASS


# --- no-new-false-positive: lookalikes that must keep today's PASS ---------


@pytest.mark.parametrize(
    "command",
    [
        'echo "{ not a group }"',
        "printf '(x)'",
        "grep -e '{' file",
        "find . -name '*.py' -exec echo {} \\;",
        "awk '{print $1}' file",
        "echo eval",  # "eval" as an ARGUMENT, not argv[0] — never opaque
        "echo builtin",
    ],
)
def test_no_new_false_positives(command):
    result = _cmd(command)
    assert result.verdict is Verdict.PASS
    assert not result.reason_codes


# --- raise-only regression: every existing dangerous shape keeps its verdict
# ----------------------------------------------------------------------------
# Values captured against the UNTOUCHED worktree before this change (see the
# session report) — the fix must not change any of these.


@pytest.mark.parametrize(
    "command",
    [
        "rm -rf /",
        "time rm -rf /",
        "command rm -rf /",
        "exec rm -rf /",
        "nice rm -rf /",
        "{ rm -rf /; }",
        "( rm -rf /)",
        "if true; then rm -rf /; fi",
        "while :; do rm -rf /; done",
        "for f in *; do rm -rf /; done",
        "! rm -rf /",
        'sh -c "rm -rf /"',
    ],
)
def test_raise_only_existing_dangerous_shapes_unchanged(command):
    result = _cmd(command)
    assert result.verdict is Verdict.BLOCK
    assert ReasonCode.destructive_command in result.reason_codes


def test_raise_only_sh_c_opaque_auth_unchanged():
    result = _cmd('sh -c "echo hi"')
    assert result.verdict is Verdict.AUTH
    assert ReasonCode.opaque_command in result.reason_codes


# --- walk_command shape: eval's payload is walked as a nested command ------


def test_walk_command_still_sees_eval_payload_as_one_opaque_token():
    # walk_command itself (the shared tokenizer) is unchanged by this fix —
    # eval's payload still arrives as a single shlex token; it is the
    # DestructiveCommandRule's opaque-payload handling (_opaque_shell_payload/
    # _payload_command) that re-walks it, exactly like `bash -c`'s payload.
    segments, ambiguous, _dynamic = walk_command('eval "rm -rf /"')
    assert segments == [["eval", "rm -rf /"]]
    assert ambiguous is False
