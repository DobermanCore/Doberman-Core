"""Hardening test for how the subjective score path handles garbage surprise metadata.

Two invariants were audited as "only indirectly tested." Verified against the
actual suite before adding anything (ponytail: no duplicate coverage):

1. **Hard-block-allowlist clamp** (a non-allowlisted subjective ``BLOCK`` is
   clamped to ``AUTH`` by ``decide()``; only ``lethal_trifecta`` may stay
   ``BLOCK``) — ALREADY covered directly, end-to-end, in
   ``tests/unit/test_execution_rule.py``
   (``test_subjective_block_clamped_with_reason_and_audit_truth`` and
   ``test_real_allowlist_honors_a_lethal_trifecta_subjective_block``). No test
   added here.

2. **Fail toward caution when surprise can't be computed** — ALSO already
   covered: the caution lives in the *executor*, not here. When
   ``surprise_blended`` raises, ``proxy.executor._surprise_or_caution`` returns
   ``1.0`` (maximally surprising → step-up), asserted in
   ``tests/integration/test_subjective_integration.py`` and
   ``tests/unit/test_conservative_default.py``. No test added here.

What's left, and is the one genuine gap: ``engine.subjective._read_surprise``
reads the *already-precomputed* value out of ``ctx.metadata``. In the proxy path
that value is always a real float (the executor guarantees it). But
``_read_surprise`` is also reachable with missing or non-numeric metadata (a
non-proxy caller, or corrupt state), and every existing test passes a real
``float`` or omits the key. This pins that path.

Note the semantics deliberately: a missing/garbage surprise resolves to ``0.0``,
which is **"no behavioral signal," not "safe."** ``0.0`` makes the geometric
score ``(surprise · sensitivity · care) ** 1/3`` collapse to ``0`` so the
abnormality *nudge* doesn't fire — that is intentional (you don't manufacture an
AUTH prompt from corrupt metadata), and it is safe only because the trifecta
floor, the detectors, and the objective guardrail all protect independently of
this term, and because any exception on this path is caught by
``_safe_evaluate`` and fails to ``AUTH``. Do NOT "fix" this default to ``1.0``:
that would step up on every corrupt-metadata action, and the real
compute-failure caution already lives in the executor (see invariant 2 above).
"""

from datetime import datetime, timezone

import pytest

from doberman.engine.subjective import SubjectiveGuardrail, _read_surprise
from doberman.models import (
    ActionType,
    Algebra,
    BlastRadius,
    Capability,
    DestinationClass,
    EvalContext,
    Provenance,
    Reversibility,
    SecurityObject,
    TargetClass,
    Verdict,
)

_NOW = datetime(2026, 6, 9, tzinfo=timezone.utc)


class _Unrepresentable:
    """A plain object with no numeric conversion — plausible 'garbage metadata'."""


# Mirrors test_subjective_engine.py's _jointly_high_action(): high sensitivity
# (secret target) WITHOUT the trifecta, so the SCORE path (not the floor) is
# what's exercised.
def _jointly_high_action() -> SecurityObject:
    return SecurityObject(
        id="sf-1",
        ts=_NOW,
        agent_role="frontend",
        action_type=ActionType.file_write,
        tool_name="fs_write",
        target="backend/api.ts",
        reversibility=Reversibility.low,
        algebra=Algebra(
            capability=Capability.mutate,
            target_class=TargetClass.secret,
            destination_class=DestinationClass.none,
            blast_radius=BlastRadius.many,
            provenance=Provenance.trusted_instruction,
            classification_confidence=0.9,
        ),
    )


def _engine() -> SubjectiveGuardrail:
    return SubjectiveGuardrail(load_plugins=False)


@pytest.mark.parametrize(
    "malformed", ["nan", None, _Unrepresentable()], ids=["nan-string", "none", "object"]
)
def test_malformed_surprise_metadata_is_ignored_not_fatal(malformed):
    """Non-numeric surprise must not raise; it resolves to the 0.0 no-signal
    default (nudge off), never a crash and never a *different* verdict than an
    explicit 0.0. It is NOT the "safe" extreme — see this module's docstring for
    why 0.0 is correct here and where the real fail-toward-caution lives."""
    ctx = EvalContext(metadata={"surprise": malformed})

    # _read_surprise must swallow the garbage (no TypeError, no NaN leak) and
    # return the no-signal default. Removing the isinstance guard makes None/an
    # object raise TypeError and "nan" leak through as 1.0 — this pins the guard.
    assert _read_surprise(ctx) == 0.0

    # End-to-end, garbage surprise must be indistinguishable from an explicit
    # no-signal 0.0 (same verdict), never crashing the guardrail and never
    # scoring the action differently because the metadata happened to be junk.
    action = _jointly_high_action()
    baseline = _engine().evaluate(action, EvalContext(metadata={"surprise": 0.0}))
    malformed_result = _engine().evaluate(action, ctx)
    assert baseline.verdict is Verdict.PASS
    assert malformed_result.verdict is baseline.verdict
