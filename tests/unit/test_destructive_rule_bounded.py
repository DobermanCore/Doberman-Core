"""#549 — DestructiveCommandRule's per-segment scan is bounded by segment
*count* (``_MAX_COMMAND_SEGMENTS``) but was not bounded by segment *length*,
so a single oversized inline payload (a heredoc, a base64 blob) drove
``walk_command``'s ``shlex.split`` call into super-linear time and stalled
the hot decision path (~7.7 min measured on an 800 KB payload).

Covers: a 1 MB command still evaluates quickly (wall-clock, matching the
sibling bound tests in ``test_rule_commands.py``); the actual per-segment
text handed to ``shlex.split`` is capped regardless of input size (a
deterministic counter, not just a timing race); a destructive command is
still caught when it sits at the head of an oversized payload (rm -rf /,
git push --force to a protected branch); an oversized payload with nothing
dangerous visible in the truncated prefix (echo of a long blob) still fails
UPWARD to AUTH rather than ALLOW, because a cut can never prove there is
nothing destructive past it (raise-only — #549 follow-up review finding).

#549 follow-up: the original cut only failed upward when the truncation
landed inside an open quote (shlex's own ``ValueError``); a cut in plain
unquoted text silently dropped everything past byte 65536 with no signal at
all, so ``"rm " + "a" * 70000 + " -rf /"`` returned PASS instead of BLOCK.
Any truncation now marks the walk ambiguous, so it can only ever raise a
verdict, never lower one — updated the two tests below (from PASS to AUTH)
that encoded the old, now-closed gap.
"""

import time
from datetime import datetime, timezone

from doberman.engine.rules import commands as commands_module
from doberman.engine.rules.commands import DestructiveCommandRule
from doberman.models import ActionType, EvalContext, SecurityObject, Verdict

RULE = DestructiveCommandRule()


def _cmd(command: str):
    action = SecurityObject(
        id="cmd-bounded-1",
        ts=datetime(2026, 9, 5, tzinfo=timezone.utc),
        agent_role="unknown",
        action_type=ActionType.shell_exec,
        tool_name="shell_exec",
        target=command,
    )
    ctx = EvalContext(metadata={"raw_arguments": {"command": command}})
    return RULE.evaluate(action, ctx)


def test_evaluates_a_one_megabyte_command_quickly():
    huge_command = "rm " + ("A" * (1024 * 1024))
    start = time.perf_counter()
    result = _cmd(huge_command)
    elapsed = time.perf_counter() - start
    print(f"\n1 MB command evaluated in {elapsed:.3f}s")
    assert elapsed < 3.0, f"took {elapsed:.3f}s — the per-segment scan is not length-bounded"
    # #549 follow-up: truncation now always marks the walk ambiguous (raise-
    # only — a cut can never prove nothing destructive follows it), so an
    # oversized segment fails upward to AUTH rather than silently PASSing.
    assert result.verdict is Verdict.AUTH


def test_shlex_input_is_length_bounded_regardless_of_command_size(monkeypatch):
    # Deterministic counter (not a timing race): whatever walk_command hands
    # to shlex.split per segment must never exceed the per-segment scan
    # bound, no matter how large the raw command is -- this is the actual
    # root-cause fix for #549, not just a symptom of it running fast today.
    max_len_seen = 0
    real_split = commands_module.shlex.split

    def _counting_split(s, *args, **kwargs):
        nonlocal max_len_seen
        max_len_seen = max(max_len_seen, len(s))
        return real_split(s, *args, **kwargs)

    monkeypatch.setattr(commands_module.shlex, "split", _counting_split)

    huge_command = "rm " + ("A" * (1024 * 1024))
    _cmd(huge_command)

    assert max_len_seen > 0
    assert max_len_seen <= commands_module._MAX_SEGMENT_SCAN_BYTES


def test_destructive_rm_still_caught_at_head_of_oversized_payload():
    huge_command = "rm -rf / " + ("A" * (1024 * 1024))
    result = _cmd(huge_command)
    assert result.verdict is Verdict.BLOCK


def test_git_force_push_to_protected_branch_still_caught_at_head_of_oversized_payload():
    huge_command = "git push --force origin main " + ("A" * (1024 * 1024))
    result = _cmd(huge_command)
    assert result.verdict is Verdict.BLOCK


def test_benign_oversized_echo_payload_fails_upward_not_allow():
    # #549 follow-up: renamed from ..._stays_allow — a truncated segment
    # can never prove nothing destructive was cut away, so this must fail
    # upward to AUTH rather than silently ALLOW, same as any other cut.
    huge_command = "echo " + ("A" * (1024 * 1024))
    result = _cmd(huge_command)
    assert result.verdict is Verdict.AUTH


def test_destructive_suffix_hidden_past_the_truncation_cut_is_not_allow():
    """#549 follow-up review finding: the byte cut is applied to the RAW
    stripped segment, not just to whatever `shlex.split` happens to see. A
    single oversized unquoted token (no embedded quote, so shlex never
    raises) can carry its destructive flags/operand PAST byte 65536 -- the
    truncated prefix alone (`rm <65533 a's>`) looks like an ordinary `rm`
    with one operand, no `-rf`. Silently returning PASS here would be a
    raise-only violation: the unbounded scan would have BLOCKed this same
    command. Must fail upward (AUTH or BLOCK), never ALLOW.
    """
    huge_command = "rm " + ("a" * 70000) + " -rf /"
    result = _cmd(huge_command)
    assert result.verdict is not Verdict.PASS
    assert result.verdict in (Verdict.AUTH, Verdict.BLOCK)


def test_walk_command_marks_an_oversized_segment_ambiguous():
    oversized = "echo " + ("a" * (commands_module._MAX_SEGMENT_SCAN_BYTES + 10))
    _segments, ambiguous, _dynamic = commands_module.walk_command(oversized)
    assert ambiguous is True


def test_walk_command_leaves_a_short_plain_segment_unambiguous():
    small = "echo hello world"
    _segments, ambiguous, _dynamic = commands_module.walk_command(small)
    assert ambiguous is False
