"""Slice SL3.2 — conservative default + bounded novelty for unclassified actions.

Load-bearing properties: low confidence degrades to a SAFE default (elevated
sensitivity), never to zero/benign; the novelty contribution is one bounded
constant per action (no storms on brand-new-but-benign workflows).
"""

from datetime import datetime, timezone

from doberman.models import (
    ActionType,
    Algebra,
    SecurityObject,
    TargetClass,
)
from doberman.subjective.infer import (
    CONFIDENCE_FLOOR,
    NOVELTY_BONUS,
    UNCLASSIFIED_SENSITIVITY_FLOOR,
    infer_algebra,
    is_unclassified,
    novelty_bonus,
    sensitivity,
)

_NOW = datetime(2026, 6, 9, tzinfo=timezone.utc)


def test_default_algebra_is_unclassified_and_elevated():
    algebra = Algebra()  # zero confidence, all-unknown
    assert is_unclassified(algebra)
    assert sensitivity(algebra) >= UNCLASSIFIED_SENSITIVITY_FLOOR
    assert novelty_bonus(algebra) == NOVELTY_BONUS


def test_low_confidence_floors_even_a_benign_looking_target():
    # An adapter-free, weakly-classified "public" action still scores elevated.
    algebra = Algebra(target_class=TargetClass.public, classification_confidence=0.1)
    assert sensitivity(algebra) >= UNCLASSIFIED_SENSITIVITY_FLOOR


def test_confident_classification_uses_its_tier_without_a_bonus():
    algebra = Algebra(target_class=TargetClass.public, classification_confidence=0.9)
    assert not is_unclassified(algebra)
    assert sensitivity(algebra) == 0.1
    assert novelty_bonus(algebra) == 0.0


def test_sensitivity_never_resolves_to_zero():
    for target in TargetClass:
        for confidence in (0.0, CONFIDENCE_FLOOR, 0.9):
            algebra = Algebra(target_class=target, classification_confidence=confidence)
            assert sensitivity(algebra) > 0.0


def test_novelty_is_bounded_and_non_compounding_over_a_stream():
    # 100 actions from a brand-new application type: each contributes exactly
    # one bounded constant — consistent caution, not a storm.
    bonuses = []
    for i in range(100):
        action = SecurityObject(
            id=f"new-{i}",
            ts=_NOW,
            agent_role="unknown",
            action_type=ActionType.other,
            tool_name="never_seen_tool",
        )
        algebra = infer_algebra(action, None)
        bonuses.append(novelty_bonus(algebra))
    assert all(b <= NOVELTY_BONUS for b in bonuses)
    assert sum(bonuses) <= 100 * NOVELTY_BONUS
    assert NOVELTY_BONUS <= 0.25  # the bonus alone can never approach a step-up score
