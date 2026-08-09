"""The lethal-trifecta floor at the OBJECTIVE layer (defense-in-depth).

Covers :class:`~doberman.engine.rules.trifecta_floor.TrifectaFloorRule` and, most
importantly, the end-to-end defect it closes: because the execution rule
(:func:`~doberman.engine.decision_engine.decide`) runs the objective guardrail
first and short-circuits on any non-PASS, an objective ``AUTH`` used to MASK the
mandated hard ``BLOCK`` in strict/paranoid — the subjective layer (which owns the
floor) never ran. The floor now also fires objective-side, so the AUTH can no
longer downgrade the block.

Minimal-behavior-change contract also pinned here: the rule emits ``BLOCK`` ONLY in
the hard-block modes; in Light/Balanced it abstains (``PASS``) so the existing
subjective soft-mode ``AUTH`` path stays byte-identical.
"""

from datetime import datetime, timezone

import pytest

from doberman.engine.decision_engine import decide
from doberman.engine.objective import ObjectiveGuardrail
from doberman.engine.rules.destinations import ExternalDestinationRule
from doberman.engine.rules.trifecta_floor import TrifectaFloorRule
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
    Risk,
    SecurityObject,
    TargetClass,
    Verdict,
)

_NOW = datetime(2026, 6, 9, tzinfo=timezone.utc)
_ALL_MODES = ("light", "balanced", "strict", "paranoid")
_HARD_BLOCK_MODES = ("strict", "paranoid")
_SOFT_MODES = ("light", "balanced")


def _trifecta_algebra(**overrides) -> Algebra:
    """A full lethal-trifecta algebra: secret target + untrusted + external."""
    base = dict(
        capability=Capability.send,
        target_class=TargetClass.secret,
        destination_class=DestinationClass.unknown_external,
        blast_radius=BlastRadius.single,
        provenance=Provenance.untrusted_data,
        classification_confidence=0.9,
    )
    base.update(overrides)
    return Algebra(**base)


def _action(algebra: Algebra) -> SecurityObject:
    """A benign-shaped action carrying ``algebra`` (the rule reads only algebra)."""
    return SecurityObject(
        id="tf-rule-1",
        ts=_NOW,
        agent_role="unknown",
        action_type=ActionType.file_write,
        tool_name="fs_write",
        target="backend/api.ts",
        algebra=algebra,
    )


def _trifecta_egress_action() -> SecurityObject:
    """A trifecta action to an UNKNOWN external host — so the external-destination
    rule alone returns AUTH (strict), the exact shape that used to mask the block.
    """
    return SecurityObject(
        id="tf-egress-1",
        ts=_NOW,
        agent_role="unknown",
        action_type=ActionType.network_request,
        tool_name="net_post",
        target="https://evil.example/collect",
        external_destination="https://evil.example/collect",
        algebra=_trifecta_algebra(),
    )


# --- 1. hard-block modes ----------------------------------------------------------


@pytest.mark.parametrize("mode", _HARD_BLOCK_MODES)
def test_trifecta_hard_blocks_in_strict_and_paranoid(mode):
    result = TrifectaFloorRule().evaluate(_action(_trifecta_algebra()), EvalContext(mode=mode))
    assert result.verdict is Verdict.BLOCK
    assert result.risk is Risk.critical
    assert ReasonCode.lethal_trifecta in result.reason_codes


# --- 2. soft modes abstain (byte-identical subjective AUTH path) -------------------


@pytest.mark.parametrize("mode", _SOFT_MODES)
def test_trifecta_abstains_in_soft_modes(mode):
    # The rule must NOT step up in Light/Balanced — the subjective layer still owns
    # the soft-mode AUTH, so the objective floor abstains and changes nothing.
    result = TrifectaFloorRule().evaluate(_action(_trifecta_algebra()), EvalContext(mode=mode))
    assert result.verdict is Verdict.PASS


# --- 3. benign: the floor never trips without the full co-occurrence --------------


@pytest.mark.parametrize("mode", _ALL_MODES)
@pytest.mark.parametrize(
    "override",
    [
        {"provenance": Provenance.trusted_instruction},  # trusted content
        {"provenance": Provenance.unknown},
        {"target_class": TargetClass.internal},  # benign target
        {"target_class": TargetClass.public},
        {"destination_class": DestinationClass.internal},  # not external
        {"destination_class": DestinationClass.none},
    ],
)
def test_floor_never_trips_without_full_cooccurrence(mode, override):
    result = TrifectaFloorRule().evaluate(
        _action(_trifecta_algebra(**override)), EvalContext(mode=mode)
    )
    assert result.verdict is Verdict.PASS


@pytest.mark.parametrize("mode", _ALL_MODES)
def test_default_all_unknown_algebra_passes_everywhere(mode):
    # An uninferred action defaults to the all-unknown algebra → the predicate is
    # False → PASS (safe): the floor never fabricates a block from missing data.
    result = TrifectaFloorRule().evaluate(_action(Algebra()), EvalContext(mode=mode))
    assert result.verdict is Verdict.PASS


# --- 4. the defect, end-to-end via decide() ---------------------------------------


def test_objective_auth_masked_the_block_without_the_rule():
    # Reproduces the DEFECT: with only the external-destination rule objective-side,
    # the rule returns AUTH, decide() short-circuits on the objective AUTH (the
    # subjective floor never runs), and the mandated hard BLOCK is masked to AUTH.
    action = _trifecta_egress_action()
    ctx = EvalContext(mode="strict")
    objective_without = ObjectiveGuardrail(rules=[ExternalDestinationRule()], load_plugins=False)

    assert objective_without.evaluate(action, ctx).verdict is Verdict.AUTH
    masked = decide(action, objective_without, SubjectiveGuardrail(load_plugins=False), ctx)
    assert masked.final_verdict is Verdict.AUTH  # the bug: BLOCK downgraded to AUTH


def test_trifecta_floor_rule_unmasks_the_block_end_to_end():
    # The FIX: with the floor rule also objective-side, it BLOCKs, the raise-only
    # combine lifts the objective verdict to BLOCK, and decide() returns the
    # mandated hard block — no longer maskable by the external-destination AUTH.
    action = _trifecta_egress_action()
    ctx = EvalContext(mode="strict")
    objective_with = ObjectiveGuardrail(
        rules=[ExternalDestinationRule(), TrifectaFloorRule()], load_plugins=False
    )

    fixed = decide(action, objective_with, SubjectiveGuardrail(load_plugins=False), ctx)
    assert fixed.final_verdict is Verdict.BLOCK
    assert ReasonCode.lethal_trifecta in fixed.reason_codes


def test_default_objective_guardrail_hard_blocks_the_trifecta_in_strict():
    # Pins registration in BUILTIN_RULE_TYPES: the full default objective guardrail
    # (no rules= override) hard-BLOCKs. MUTATION: remove TrifectaFloorRule from
    # BUILTIN_RULE_TYPES and this reverts to AUTH and fails.
    action = _trifecta_egress_action()
    result = ObjectiveGuardrail(load_plugins=False).evaluate(action, EvalContext(mode="strict"))
    assert result.verdict is Verdict.BLOCK
    assert ReasonCode.lethal_trifecta in result.reason_codes


def test_balanced_mode_still_auths_via_subjective_floor_unchanged():
    # Soft-mode byte-identity guard: the objective floor abstains in Balanced, so
    # the objective guardrail does NOT block, and the trifecta egress is handled
    # exactly as before — the subjective floor steps it up to AUTH (never BLOCK).
    # Adding the objective rule changed nothing in the soft modes.
    action = _trifecta_egress_action()
    ctx = EvalContext(mode="balanced")
    objective = ObjectiveGuardrail(load_plugins=False)

    assert objective.evaluate(action, ctx).verdict is not Verdict.BLOCK
    final = decide(action, objective, SubjectiveGuardrail(load_plugins=False), ctx)
    assert final.final_verdict is Verdict.AUTH
    assert ReasonCode.lethal_trifecta in final.reason_codes


# --- 5. back-compat: the re-export still resolves ---------------------------------


def test_trifecta_fires_re_export_from_subjective_still_resolves():
    from doberman.engine.subjective import (
        TRIFECTA_DESTINATIONS,
        TRIFECTA_PROVENANCE,
        TRIFECTA_TARGETS,
        trifecta_fires,
    )
    from doberman.engine.trifecta import trifecta_fires as leaf_trifecta_fires

    # Same object re-bound, not a copy — existing callers get the leaf predicate.
    assert trifecta_fires is leaf_trifecta_fires
    assert trifecta_fires(_trifecta_algebra())
    assert not trifecta_fires(Algebra())
    assert TargetClass.secret in TRIFECTA_TARGETS
    assert Provenance.untrusted_data in TRIFECTA_PROVENANCE
    assert DestinationClass.unknown_external in TRIFECTA_DESTINATIONS
