"""C9 — authority tiers: every FLOOR_HARD_BLOCKS code is reachable as BLOCK.

FLOOR_HARD_BLOCKS (policy/modes.py) is the mode-independent hard-block floor —
five reason codes that always BLOCK regardless of security mode. This file
proves each of the five is actually reachable as a BLOCK today, two ways:

* Three codes (secret_exfiltration, protected_path_blocked, destructive_command)
  are reachable through the shipped detection corpus's default mapping (no role,
  no resolved policy) — proven dynamically via evaluate_corpus so this survives
  corpus edits and rule changes without a hand-maintained row-to-code table.
* Two codes (role_blocked_target, policy_source_blocked) are structurally
  opt-in: their rules abstain (PASS) unless EvalContext.role / metadata
  ["resolved_policy"] is set, which the corpus's mapping (tests/benchmarks/
  mapping.py) never does. Proven directly against the rule instead.

See docs/AUTHORITY_TIERS.md for the full T0-T3 tier writeup this test backs.
"""

from datetime import datetime, timezone

from doberman.engine.rules.policy_source import PolicySourceRule
from doberman.engine.rules.role_boundary import RoleBoundaryRule
from doberman.models import ActionType, EvalContext, ReasonCode, SecurityObject, Verdict
from doberman.policy.modes import FLOOR_HARD_BLOCKS
from doberman.policy.sources import ResolvedPolicy
from doberman.roles.roles import RoleDefinition
from tests.benchmarks.profiles import build_pipeline
from tests.benchmarks.suites.corpus import evaluate_corpus, load_corpus

#: Reachable through the corpus's default (no role, no resolved policy) mapping.
_CORPUS_REACHABLE_FLOOR_CODES = frozenset(
    {
        ReasonCode.secret_exfiltration,
        ReasonCode.protected_path_blocked,
        ReasonCode.destructive_command,
    }
)
#: Opt-in floor codes the corpus's mapping cannot construct (no role /
#: resolved_policy field) — proven directly against the rule instead.
_OPT_IN_FLOOR_CODES = frozenset(
    {
        ReasonCode.role_blocked_target,
        ReasonCode.policy_source_blocked,
    }
)


def test_the_two_coverage_paths_partition_every_floor_hard_block_code():
    """A future sixth FLOOR_HARD_BLOCKS code must be added to one of the two
    sets above (and proven by one of the tests below) or this fails loudly —
    the coverage claim can never silently go stale."""
    assert _CORPUS_REACHABLE_FLOOR_CODES | _OPT_IN_FLOOR_CODES == FLOOR_HARD_BLOCKS
    assert _CORPUS_REACHABLE_FLOOR_CODES & _OPT_IN_FLOOR_CODES == frozenset()


def test_every_corpus_reachable_floor_code_has_a_block_row():
    """Drive the real corpus through the real (builtin-only) engine and collect
    every reason code seen on a BLOCK verdict; every corpus-reachable floor code
    must appear at least once."""
    results = evaluate_corpus(load_corpus(), build_pipeline(load_plugins=False))
    seen_on_block = {
        ReasonCode(code)
        for row_result in results
        if row_result.verdict is Verdict.BLOCK
        for code in row_result.reason_codes
    }
    missing = _CORPUS_REACHABLE_FLOOR_CODES - seen_on_block
    assert missing == set(), (
        f"FLOOR_HARD_BLOCKS codes with no corpus BLOCK coverage: "
        f"{sorted(code.value for code in missing)}"
    )


def _role_action(target: str) -> SecurityObject:
    return SecurityObject(
        id="c9-role-1",
        ts=datetime(2026, 9, 2, tzinfo=timezone.utc),
        agent_role="c9",
        action_type=ActionType.file_write,
        tool_name="fs_write",
        target=target,
    )


def test_role_blocked_target_floor_is_reachable(tmp_path):
    """Opt-in: the corpus's mapping never sets EvalContext.role, so this floor
    code is proven directly against RoleBoundaryRule with an active role."""
    role = RoleDefinition(name="c9-role", blocked=["forbidden/**"])
    ctx = EvalContext(role=role, metadata={"repo_root": str(tmp_path)})
    result = RoleBoundaryRule().evaluate(_role_action("forbidden/secret.txt"), ctx)
    assert result.verdict is Verdict.BLOCK
    assert ReasonCode.role_blocked_target in result.reason_codes


def _policy_action(target: str) -> SecurityObject:
    return SecurityObject(
        id="c9-policy-1",
        ts=datetime(2026, 9, 2, tzinfo=timezone.utc),
        agent_role="c9",
        action_type=ActionType.file_write,
        tool_name="fs_write",
        target=target,
    )


def test_policy_source_blocked_floor_is_reachable(tmp_path):
    """Opt-in: the corpus's mapping never populates metadata['resolved_policy'],
    so this floor code is proven directly against PolicySourceRule."""
    resolved = ResolvedPolicy(blocked_globs=("app/secret.txt",))
    ctx = EvalContext(metadata={"repo_root": str(tmp_path), "resolved_policy": resolved})
    result = PolicySourceRule().evaluate(_policy_action("app/secret.txt"), ctx)
    assert result.verdict is Verdict.BLOCK
    assert ReasonCode.policy_source_blocked in result.reason_codes
