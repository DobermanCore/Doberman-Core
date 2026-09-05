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
git push --force to a protected branch); a benign oversized payload (echo of
a long blob) stays PASS — the bound must not manufacture ambiguity out of
ordinary truncation.
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
    assert result.verdict is Verdict.PASS


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


def test_benign_oversized_echo_payload_stays_allow():
    huge_command = "echo " + ("A" * (1024 * 1024))
    result = _cmd(huge_command)
    assert result.verdict is Verdict.PASS
