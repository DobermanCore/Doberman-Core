"""Slice 10.1 — strengthen/weaken/neutral change classifier (ambiguous → weaken)."""

import pytest

from doberman.policy.drift import Classification, classify_change

WEAKENING_TRANSITIONS = [
    ({"r": "block"}, {"r": "auth"}),  # hard block → step-up
    ({"r": "auth"}, {"r": "allow"}),  # step-up → allow
    ({"r": "protected"}, {"r": "normal"}),  # protected → normal
    ({"r": "unknown"}, {"r": "trusted"}),  # unknown dest → trusted
    ({"r": "block"}, {}),  # protective entry removed entirely
    ({"enabled": True}, {"enabled": False}),  # a protection toggled off
]


@pytest.mark.parametrize(("before", "after"), WEAKENING_TRANSITIONS)
def test_weakening_transitions_classify_as_weaken(before, after):
    assert classify_change(before, after) is Classification.weaken


@pytest.mark.parametrize(("before", "after"), WEAKENING_TRANSITIONS)
def test_reverse_transitions_classify_as_strengthen(before, after):
    # The exact reverse of every weakening is a strengthening.
    assert classify_change(after, before) is Classification.strengthen


def test_mixed_change_is_weaken_fail_safe():
    before = {"a": "block", "b": "allow"}
    after = {"a": "auth", "b": "block"}  # a weakened, b strengthened
    assert classify_change(before, after) is Classification.weaken


def test_ambiguous_token_against_a_block_is_weaken():
    # An unrecognized target state is treated conservatively (ranks below block).
    assert classify_change({"r": "block"}, {"r": "mystery"}) is Classification.weaken


def test_no_op_is_neutral():
    assert classify_change({"r": "block"}, {"r": "block"}) is Classification.neutral
    assert classify_change({}, {}) is Classification.neutral


def test_pure_strengthen_adds_protection():
    assert classify_change({}, {"r": "block"}) is Classification.strengthen
    assert classify_change({"r": "allow"}, {"r": "auth"}) is Classification.strengthen
