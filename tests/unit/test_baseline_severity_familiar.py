"""Audit H4 / EF-4 — severity-aware familiar-at threshold (raise-only tightening).

A flat ``FAMILIAR_AT`` let an attacker "slow-boil" a dangerous capability to
zero novelty with just ``FAMILIAR_AT`` allows. High-severity feature classes
(destructive capabilities, secret/sensitive targets, external destinations,
mass blast radii) must require MORE prior allowed observations before they
count as "familiar" (novelty 0.0); benign classes are unchanged.
"""

from datetime import datetime, timezone

from doberman.models import (
    ActionType,
    Algebra,
    BlastRadius,
    Capability,
    DestinationClass,
    SecurityObject,
    TargetClass,
)
from doberman.subjective.baseline import (
    FAMILIAR_AT,
    FAMILIAR_AT_HIGH,
    _familiar_at,
    _novelty,
    novelty_score,
    observe,
)

_NOW = datetime(2026, 7, 17, tzinfo=timezone.utc)


def _action(
    capability=Capability.read,
    target_class=TargetClass.internal,
    destination_class=DestinationClass.none,
    blast_radius=BlastRadius.single,
    tool="fixed_tool",
):
    """A minimal action with a fixed, stable set of scoring keys.

    ``blast_radius=single`` and ``destination_class=none`` by default so only
    the dimension under test can land in the high-severity set — keeps each
    test isolated to the key it's actually exercising.
    """
    return SecurityObject(
        id="sev-1",
        ts=_NOW,
        agent_role="frontend",
        action_type=ActionType.other,
        tool_name=tool,
        target=None,
        algebra=Algebra(
            capability=capability,
            target_class=target_class,
            destination_class=destination_class,
            blast_radius=blast_radius,
            classification_confidence=0.9,
        ),
    )


async def _seed(root, eid, action, times):
    for _ in range(times):
        await observe(action, entity_id=eid, repo_root=root, now=_NOW)


# --- _familiar_at classification ---------------------------------------------


def test_familiar_at_classifies_destructive_capability_high():
    assert _familiar_at("capability:delete") == FAMILIAR_AT_HIGH
    assert _familiar_at("capability:grant") == FAMILIAR_AT_HIGH
    assert _familiar_at("capability:execute") == FAMILIAR_AT_HIGH


def test_familiar_at_classifies_secret_and_sensitive_targets_high():
    assert _familiar_at("target:secret") == FAMILIAR_AT_HIGH
    assert _familiar_at("target:sensitive") == FAMILIAR_AT_HIGH


def test_familiar_at_classifies_external_destinations_high():
    assert _familiar_at("dest:known_external") == FAMILIAR_AT_HIGH
    assert _familiar_at("dest:unknown_external") == FAMILIAR_AT_HIGH
    assert _familiar_at("destination:evil.example.com") == FAMILIAR_AT_HIGH
    # a per-host destination key may itself contain a colon (host:port) —
    # partition(":", 1) semantics must not misclassify it.
    assert _familiar_at("destination:evil.example.com:443") == FAMILIAR_AT_HIGH


def test_familiar_at_classifies_mass_blast_radius_high():
    assert _familiar_at("blast:many") == FAMILIAR_AT_HIGH
    assert _familiar_at("blast:mass") == FAMILIAR_AT_HIGH


def test_familiar_at_keeps_benign_keys_at_default():
    assert _familiar_at("capability:read") == FAMILIAR_AT
    assert _familiar_at("capability:mutate") == FAMILIAR_AT
    assert _familiar_at("target:public") == FAMILIAR_AT
    assert _familiar_at("target:internal") == FAMILIAR_AT
    assert _familiar_at("dest:none") == FAMILIAR_AT
    assert _familiar_at("dest:internal") == FAMILIAR_AT
    assert _familiar_at("blast:single") == FAMILIAR_AT
    assert _familiar_at("blast:few") == FAMILIAR_AT
    assert _familiar_at("tool:fs_read") == FAMILIAR_AT
    assert _familiar_at("path_class:src/*.py") == FAMILIAR_AT
    assert _familiar_at("command:ls") == FAMILIAR_AT


def test_familiar_at_never_returns_below_default():
    # Raise-only: no key classification may lower the threshold below FAMILIAR_AT.
    for key in ("capability:delete", "target:secret", "dest:unknown_external", "blast:mass"):
        assert _familiar_at(key) >= FAMILIAR_AT


# --- _novelty stays a 2-arg (with default) pure function ---------------------


def test_novelty_default_familiar_at_matches_previous_behavior():
    assert _novelty(0) == 1.0
    assert _novelty(FAMILIAR_AT) == 0.0
    assert 0.0 < _novelty(1) < 1.0


def test_novelty_respects_explicit_familiar_at():
    assert _novelty(3, familiar_at=FAMILIAR_AT_HIGH) > 0.0  # still novel
    assert _novelty(FAMILIAR_AT_HIGH, familiar_at=FAMILIAR_AT_HIGH) == 0.0


# --- end-to-end: novelty_score over the observe/allow pipeline ---------------


async def test_high_severity_capability_stays_novel_past_default_familiar_at(tmp_path):
    root = str(tmp_path)
    eid = "hmac:aaa"
    action = _action(capability=Capability.delete, tool="delete_tool")

    await _seed(root, eid, action, FAMILIAR_AT)  # 3 allows — old threshold
    score_at_default = await novelty_score(action, entity_id=eid, repo_root=root)
    assert score_at_default > 0.0, "a destructive capability must not be 'familiar' at 3 allows"

    await _seed(root, eid, action, FAMILIAR_AT_HIGH - FAMILIAR_AT)  # up to 10 total allows
    score_at_high = await novelty_score(action, entity_id=eid, repo_root=root)
    assert score_at_high == 0.0, "familiarity is reached once the higher threshold is met"


async def test_benign_capability_reaches_familiar_at_default_unchanged(tmp_path):
    root = str(tmp_path)
    eid = "hmac:bbb"
    action = _action(capability=Capability.read, tool="read_tool")

    await _seed(root, eid, action, FAMILIAR_AT)  # 3 allows
    score = await novelty_score(action, entity_id=eid, repo_root=root)
    assert score == 0.0, "benign classes must still reach familiar at the default threshold"


async def test_secret_target_and_external_destination_also_tightened(tmp_path):
    root = str(tmp_path)
    eid = "hmac:ccc"
    action = _action(
        capability=Capability.read,
        target_class=TargetClass.secret,
        destination_class=DestinationClass.unknown_external,
        tool="secret_reader",
    )

    await _seed(root, eid, action, FAMILIAR_AT)
    assert await novelty_score(action, entity_id=eid, repo_root=root) > 0.0

    await _seed(root, eid, action, FAMILIAR_AT_HIGH - FAMILIAR_AT)
    assert await novelty_score(action, entity_id=eid, repo_root=root) == 0.0


async def test_never_seen_key_is_fully_novel(tmp_path):
    root = str(tmp_path)
    action = _action(capability=Capability.delete, tool="brand_new_tool")
    assert await novelty_score(action, entity_id="hmac:ddd", repo_root=root) == 1.0


async def test_max_across_keys_preserved_with_mixed_severity(tmp_path):
    """A high-severity key freshly seen still dominates a familiar benign key.

    Regression for the ensemble's "worst of all keys" behavior: making one
    dimension severity-aware must not let a familiar benign key mask a
    brand-new high-severity one on the SAME action.
    """
    root = str(tmp_path)
    eid = "hmac:eee"
    benign = _action(capability=Capability.read, tool="shared_tool")
    await _seed(root, eid, benign, FAMILIAR_AT)  # capability:read + tool:shared_tool familiar

    # Same tool, but now paired with a destructive capability never seen before.
    mixed = _action(capability=Capability.delete, tool="shared_tool")
    score = await novelty_score(mixed, entity_id=eid, repo_root=root)
    assert score == 1.0, "the never-before-seen capability:delete key must dominate"
