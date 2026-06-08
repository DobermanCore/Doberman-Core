"""Slice 6.1 — recommended policy checklist.

Covers: core hard-blocks always present + enabled + non-disableable; step-ups
enabled by default; role tailoring; capability tailoring (N/A when absent);
immutable toggles; and round-trip serialization.
"""

import pytest

from doberman.discovery.scan import Capability
from doberman.models import Verdict
from doberman.policy.checklist import CATEGORY_HARD_BLOCK, PolicyDoc, recommend_policy
from doberman.roles.roles import load_builtin_roles


def test_core_hard_blocks_present_enabled_and_blocking():
    doc = recommend_policy()
    core = [it for it in doc.items if it.core]
    assert len(core) >= 4
    for it in core:
        assert it.enabled
        assert it.verdict is Verdict.BLOCK
        assert it.category == CATEGORY_HARD_BLOCK


def test_step_ups_enabled_by_default():
    doc = recommend_policy()
    step_ups = [it for it in doc.items if not it.core]
    assert step_ups
    assert all(it.enabled for it in step_ups)


def test_role_tailoring_adds_out_of_scope_item():
    fe = load_builtin_roles()["frontend"]
    assert recommend_policy(role=fe).get("step_up.role_out_of_scope") is not None
    assert recommend_policy(role=None).get("step_up.role_out_of_scope") is None


def test_capability_tailoring_marks_network_item_na_when_absent():
    no_net = recommend_policy(capabilities=[])
    item = no_net.get("step_up.unknown_destination")
    assert item is not None
    assert not item.applicable

    with_net = recommend_policy(
        capabilities=[Capability(name="network", category="tool", present=True)]
    )
    assert with_net.get("step_up.unknown_destination").applicable


def test_core_item_cannot_be_disabled_here():
    doc = recommend_policy()
    core_id = next(it.id for it in doc.items if it.core)
    with pytest.raises(ValueError):
        doc.with_item_enabled(core_id, False)


def test_step_up_toggle_is_immutable():
    doc = recommend_policy()
    sid = "step_up.bulk_operation"
    toggled = doc.with_item_enabled(sid, False)
    assert toggled.get(sid).enabled is False
    assert doc.get(sid).enabled is True  # original unchanged


def test_roundtrip_serialization_preserves_items_and_core_flag():
    doc = recommend_policy(role=load_builtin_roles()["backend"])
    restored = PolicyDoc.from_mapping(doc.to_mapping())
    assert restored.mode == doc.mode
    assert [it.id for it in restored.items] == [it.id for it in doc.items]
    assert restored.get("hard_block.protected_path").core
