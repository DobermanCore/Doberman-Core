"""Structural proof for docs/AUTHORITY_TIERS.md's tier ladder (T0-T3).

``tests/unit/test_authority_tiers.py`` is a regression guard over TODAY'S rule
set (every ``FLOOR_HARD_BLOCKS`` code is reachable, and the five floor rules'
boundaries are discrete). It says nothing about a rule that does not exist
yet. This file asks a different question for each tier: if a brand-new rule
were registered tomorrow -- built-in or a ``doberman.rules``/``doberman.
detectors``/``doberman.adjudicators`` plugin -- does the ENGINE itself stop it
from exceeding its tier's ceiling, or does only the rule author's discipline?

Finding, with file:line citations (see the report for the full writeup):

* T2 (subjective/detector seam) and T3 (adjudicator seam) ARE structurally
  clamped by the engine, for ANY registered detector/adjudicator -- proven
  below by monkeypatching real built-in classes and by registering fresh
  fake ones through the same ``extra_detectors``/``adjudicators=`` seams a
  real plugin would use.
* T0/T1 (the objective/rule seam) is NOT. ``ObjectiveGuardrail.evaluate``
  (src/doberman/engine/objective.py:101-114) combines every rule's raw
  result raise-only with no reason-code/tier check, and ``decide()``
  (src/doberman/engine/decision_engine.py:233) treats ANY non-PASS objective
  result as immediately final. ``policy.modes.FLOOR_HARD_BLOCKS`` (the set
  this page calls "the floor") is never imported by either module -- grep
  confirms its only readers are docs, comments, and tests. Nothing in
  ``Guardrail``/the built-in ``Rule`` classes carries a tier or ceiling
  attribute for the engine to check in the first place. A new rule that
  returns ``Verdict.BLOCK`` for ANY reason code becomes the final decision,
  unclamped -- proven below as a deliberately FAILING test
  (``test_GAP_...``), left red on purpose. See the report for why this is a
  design call rather than a fix made here.
"""

import re
from datetime import datetime, timezone
from pathlib import Path

import pytest

from doberman.engine.decision_engine import decide
from doberman.engine.detectors import BUILTIN_DETECTOR_TYPES
from doberman.engine.objective import ObjectiveGuardrail
from doberman.engine.subjective import SubjectiveGuardrail
from doberman.models import (
    ActionType,
    EvalContext,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    Verdict,
)
from doberman.policy.modes import FLOOR_HARD_BLOCKS

_DOC_PATH = Path(__file__).resolve().parents[2] / "docs" / "AUTHORITY_TIERS.md"

#: Any reason code that is NOT on the subjective hard-block allowlist (which
#: today contains only ``lethal_trifecta``) -- used to prove a raw BLOCK gets
#: clamped regardless of which non-allowlisted code it carries.
_ARBITRARY_NON_ALLOWLISTED_CODE = ReasonCode.unusual_for_deployment


def _action_for(action_type: ActionType) -> SecurityObject:
    """A minimal, valid action of the given type -- no rule-specific shape."""
    return SecurityObject(
        id=f"structural-{action_type.value}",
        ts=datetime(2026, 9, 5, tzinfo=timezone.utc),
        agent_role="structural-proof",
        action_type=action_type,
        tool_name="synthetic",
    )


def _passthrough_objective() -> ObjectiveGuardrail:
    """An ObjectiveGuardrail with no rules -- always PASS, so subjective runs."""
    return ObjectiveGuardrail(rules=[], load_plugins=False)


# --- (d) doc <-> code agreement: the T0 table IS FLOOR_HARD_BLOCKS ----------


def _parse_t0_table_reason_codes() -> set[str]:
    """Extract every backtick-quoted reason code from the T0 table's first
    column. A doc edit that adds/removes a row without touching the code (or
    vice versa) changes this set and fails the test below."""
    text = _DOC_PATH.read_text(encoding="utf-8")
    start = text.index("## T0:")
    end = text.index("\n## ", start + 1)
    section = text[start:end]
    return set(re.findall(r"^\|\s*`([a-z_]+)`\s*\|", section, flags=re.MULTILINE))


def test_doc_t0_table_matches_floor_hard_blocks_exactly():
    doc_codes = _parse_t0_table_reason_codes()
    assert doc_codes, "failed to parse any reason code from the T0 table; doc format changed"
    code_values = {rc.value for rc in FLOOR_HARD_BLOCKS}
    assert doc_codes == code_values, (
        f"docs/AUTHORITY_TIERS.md's T0 table and policy.modes.FLOOR_HARD_BLOCKS "
        f"disagree: doc-only={doc_codes - code_values} code-only={code_values - doc_codes}"
    )
    # Every parsed string must also be a real ReasonCode member (typo guard).
    for code in doc_codes:
        assert ReasonCode(code) in FLOOR_HARD_BLOCKS


# --- T2 (subjective/detector seam): the engine DOES clamp, for ANY detector -


@pytest.mark.parametrize("detector_type", BUILTIN_DETECTOR_TYPES)
def test_subjective_seam_clamps_any_builtin_detectors_raw_block(monkeypatch, detector_type):
    """Whichever built-in detector class raw-emits the BLOCK, decide() clamps
    it to AUTH: the clamp (decision_engine.py:259-270) is keyed on the
    COMBINED subjective result's reason codes, not on which detector class
    produced it."""

    def _raw_block(self, action, ctx):  # noqa: ARG001 - signature must match Guardrail
        return GuardrailResult(
            verdict=Verdict.BLOCK,
            risk=Risk.critical,
            reason_codes=[_ARBITRARY_NON_ALLOWLISTED_CODE],
            explanation="synthetic raw BLOCK for the structural proof.",
        )

    monkeypatch.setattr(detector_type, "evaluate", _raw_block)
    subjective = SubjectiveGuardrail(load_plugins=False)
    decision = decide(
        _action_for(ActionType.file_write), _passthrough_objective(), subjective, EvalContext()
    )
    assert decision.final_verdict is Verdict.AUTH
    assert ReasonCode.subjective_block_clamped in decision.reason_codes


class _FakeLowestTierDetector:
    """A detector registered at test time via ``extra_detectors`` -- exactly
    the seam a real ``doberman.detectors`` plugin uses. Its intended ceiling
    is T2 (AUTH-capped); it deliberately misbehaves and returns a raw BLOCK."""

    def evaluate(self, action: SecurityObject, ctx: EvalContext) -> GuardrailResult:
        return GuardrailResult(
            verdict=Verdict.BLOCK,
            risk=Risk.critical,
            reason_codes=[ReasonCode.confidentiality_sensitive_destination],
            explanation="a plugin-shaped detector attempting to hard-block outside its tier.",
        )


def test_fake_registered_detector_ceiling_is_clamped_with_documented_reason_and_explanation():
    subjective = SubjectiveGuardrail(
        load_builtins=False, load_plugins=False, extra_detectors=[_FakeLowestTierDetector()]
    )
    decision = decide(
        _action_for(ActionType.network_request),
        _passthrough_objective(),
        subjective,
        EvalContext(),
    )
    assert decision.final_verdict is Verdict.AUTH
    assert ReasonCode.subjective_block_clamped in decision.reason_codes
    assert "clamped" in decision.explanation.lower()
    assert "authentication" in decision.explanation.lower()


@pytest.mark.parametrize("action_type", list(ActionType))
def test_subjective_clamp_holds_for_every_action_type_when_raw_evaluate_is_block(action_type):
    """Part (b): one synthetic action per ActionType, with a registered
    detector's raw evaluate always the highest verdict (BLOCK). The engine's
    clamp holds regardless of action shape -- never exceeds AUTH."""
    subjective = SubjectiveGuardrail(
        load_builtins=False, load_plugins=False, extra_detectors=[_FakeLowestTierDetector()]
    )
    decision = decide(_action_for(action_type), _passthrough_objective(), subjective, EvalContext())
    assert decision.final_verdict is not Verdict.BLOCK
    assert decision.final_verdict is Verdict.AUTH


def test_real_allowlisted_code_is_the_only_escape_from_the_clamp():
    """Negative control: the clamp is reason-code-keyed, not verdict-keyed --
    the ONE real exception (lethal_trifecta) still reaches BLOCK, proving the
    test above isn't passing because BLOCK is unreachable outright."""

    class _TrifectaShapedDetector:
        def evaluate(self, action, ctx):
            return GuardrailResult(
                verdict=Verdict.BLOCK,
                risk=Risk.critical,
                reason_codes=[ReasonCode.lethal_trifecta],
                explanation="lethal trifecta; blocked regardless of score.",
            )

    subjective = SubjectiveGuardrail(
        load_builtins=False, load_plugins=False, extra_detectors=[_TrifectaShapedDetector()]
    )
    decision = decide(
        _action_for(ActionType.network_request),
        _passthrough_objective(),
        subjective,
        EvalContext(),
    )
    assert decision.final_verdict is Verdict.BLOCK
    assert ReasonCode.subjective_block_clamped not in decision.reason_codes


# --- T3 (adjudicator seam): shadow-only, for ANY registered adjudicator ----


class _AdversarialAdjudicator:
    """A registered adjudicator (mirrors a ``doberman.adjudicators`` plugin)
    that always recommends the OPPOSITE extreme of the real decision."""

    def adjudicate(self, features, current):  # noqa: ARG002 - Adjudicator protocol
        opposite = Verdict.BLOCK if current.verdict is not Verdict.BLOCK else Verdict.PASS
        return GuardrailResult(
            verdict=opposite,
            risk=Risk.critical if opposite is Verdict.BLOCK else Risk.low,
            reason_codes=[_ARBITRARY_NON_ALLOWLISTED_CODE],
            explanation="adversarial shadow recommendation for the structural proof.",
        )


@pytest.mark.parametrize("action_type", list(ActionType))
def test_adjudicator_never_changes_final_verdict_or_risk(action_type):
    """Part (b) for T3: swept across every ActionType, an adversarial
    adjudicator recommendation never reaches final_verdict/final_risk."""
    action = _action_for(action_type)
    objective = _passthrough_objective()
    subjective = SubjectiveGuardrail(load_plugins=False)
    baseline = decide(action, objective, subjective, EvalContext())
    adjudicated = decide(
        action, objective, subjective, EvalContext(), adjudicators=[_AdversarialAdjudicator()]
    )
    assert adjudicated.final_verdict is baseline.final_verdict
    assert adjudicated.final_risk is baseline.final_risk


def test_adjudicator_recommendation_is_observed_but_never_authoritative():
    """Proves the adjudicator is actually CONSULTED (not just trivially
    never-called): forces the real decision into the AUTH band, attaches an
    adjudicator recommending BLOCK, and confirms the recommendation lands
    only on Decision.shadow, never on final_verdict."""

    class _AuthDetector:
        def evaluate(self, action, ctx):
            return GuardrailResult(
                verdict=Verdict.AUTH,
                risk=Risk.medium,
                reason_codes=[ReasonCode.unusual_for_deployment],
                explanation="synthetic AUTH to land in the adjudicator's consult band.",
            )

    class _BlockRecommendingAdjudicator:
        def adjudicate(self, features, current):
            return GuardrailResult(
                verdict=Verdict.BLOCK,
                risk=Risk.critical,
                reason_codes=[ReasonCode.unusual_for_deployment],
                explanation="adjudicator would have blocked.",
            )

    subjective = SubjectiveGuardrail(
        load_builtins=False, load_plugins=False, extra_detectors=[_AuthDetector()]
    )
    decision = decide(
        _action_for(ActionType.network_request),
        _passthrough_objective(),
        subjective,
        EvalContext(),
        adjudicators=[_BlockRecommendingAdjudicator()],
    )
    assert decision.final_verdict is Verdict.AUTH  # never raised by the shadow recommendation
    assert decision.shadow is not None  # it WAS consulted (AUTH band)
    assert decision.shadow.verdict is Verdict.BLOCK  # its raw recommendation, observed only


# --- T0/T1 (objective/rule seam): the GAP -----------------------------------


class _FakeAuthOnlyRule:
    """Stands in for a hypothetical NEW T1 (AUTH-only) rule registered
    tomorrow via ``doberman.rules`` -- same seam ``ObjectiveGuardrail`` uses
    for every built-in and plugin rule alike (objective.py:84-96). Its
    intended ceiling is AUTH; the real ``Guardrail`` protocol has no
    attribute to declare that (that absence IS part of the gap). It
    deliberately misbehaves and returns a raw BLOCK using a reason code
    models.py documents as "AUTH-only by construction ... neither belongs on
    policy.modes.FLOOR_HARD_BLOCKS" (models.py:359-365).
    """

    def evaluate(self, action: SecurityObject, ctx: EvalContext) -> GuardrailResult:
        return GuardrailResult(
            verdict=Verdict.BLOCK,
            risk=Risk.high,
            reason_codes=[ReasonCode.verification_bypass_flag],
            explanation="synthetic T1-shaped rule misbehaving for the structural proof.",
        )


@pytest.mark.xfail(
    strict=True, reason="#630: objective layer has no engine-enforced authority ceiling"
)
def test_GAP_objective_layer_has_no_engine_enforced_authority_ceiling():
    """DELIBERATELY FAILING -- pins the design gap, do not "fix" by loosening
    this assertion or by editing engine code as a side effect of this task.

    Desired invariant (docs/AUTHORITY_TIERS.md): only a FLOOR_HARD_BLOCKS-coded
    rule may reach BLOCK; everything else is AUTH-capped by construction.

    Actual: ObjectiveGuardrail.evaluate (objective.py:101-114) reduces every
    rule's raw result with combine() alone -- max verdict, max risk, union of
    reason codes, no reason-code/tier check anywhere in the reduction. decide()
    (decision_engine.py:222-245) then treats ANY non-PASS objective result as
    immediately final; policy.modes.FLOOR_HARD_BLOCKS is never imported by
    either module. A new rule that returns Verdict.BLOCK for ANY reason code
    -- including one models.py documents as AUTH-only -- becomes the actual
    final decision, unclamped. This is rule-author discipline only, exactly
    matching (and slightly understating) docs/AUTHORITY_TIERS.md's own
    admission in "What this page does NOT claim".
    """
    guardrail = ObjectiveGuardrail(rules=[_FakeAuthOnlyRule()], load_plugins=False)
    decision = decide(
        _action_for(ActionType.file_write),
        guardrail,
        SubjectiveGuardrail(load_plugins=False),
        EvalContext(),
    )
    assert decision.final_verdict is Verdict.AUTH, (
        "GAP CONFIRMED: the objective layer has no engine-enforced authority "
        f"ceiling -- got {decision.final_verdict}, reasons={decision.reason_codes}. "
        "Any registered rule (built-in or plugin) can BLOCK for any reason code "
        "and the engine honors it unclamped. See objective.py:101-114 and "
        "decision_engine.py:222-245. This is a design call for the maintainer, "
        "not fixed by this test file."
    )
