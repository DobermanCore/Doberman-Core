"""Policy catalogue: content-hash identity of the effective policy (ADR 0088)."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from doberman.egress.velocity import VelocityThresholds
from doberman.policy.checklist import recommend_policy
from doberman.policy.preferences import PreferenceVector
from doberman.roles.roles import RoleDefinition
from doberman.storage.policy_catalogue import (
    SNAPSHOT_SCHEMA,
    VERSION_PREFIX,
    PolicySnapshotV1,
    build_snapshot,
    canonical_json,
    effective_enforcement_at_save,
    policy_version,
    snapshot_doc,
)

_NOW = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)
_ROLE = RoleDefinition(
    name="reviewer",
    description="SECRET-IN-ROLE-DESCRIPTION-sk-ant-000000000000000000000000",
    allowed=("src/**",),
    suspicious=("docs/**",),
    blocked=("**/.env*",),
)


def _doc():
    return recommend_policy()


def test_version_is_prefixed_sha256_of_canonical_json():
    snap = build_snapshot(_doc(), _ROLE, "enforce", "9.9.9")
    canonical = canonical_json(snap)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    assert policy_version(snap) == VERSION_PREFIX + digest
    assert len(policy_version(snap)) == len(VERSION_PREFIX) + 64


def test_canonical_json_is_sorted_compact_and_carries_the_schema_key():
    snap = build_snapshot(_doc(), None, "enforce", "9.9.9")
    canonical = canonical_json(snap)
    data = json.loads(canonical)
    assert canonical == json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    assert data["schema"] == SNAPSHOT_SCHEMA == 1
    assert data["engine"] == "9.9.9"
    assert data["enforcement_effective"] == "enforce"
    assert data["role"] is None
    assert set(data) == {"schema", "engine", "enforcement_effective", "doc", "role"}


GOLDEN = "pv1:f5e31a9030170392236337ec4fe1e6f5de9b3ccaf6ce5c64df81cf7b58ba59d6"


def test_golden_vector_pins_the_serialisation():
    # Computed once from the first green implementation (Task 1 Step 4). Any change
    # to the canonical form, the hashed fields, or their order goes red here.
    snap = build_snapshot(_doc(), _ROLE, "enforce", "9.9.9")
    assert policy_version(snap) == GOLDEN


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.with_mode("strict"),
        lambda d: d.with_enforcement("monitor"),
        lambda d: d.with_preferences(PreferenceVector(confidentiality=0.9)),
        lambda d: d.with_egress_velocity_thresholds(
            VelocityThresholds(burst=1, volume_bytes=1, fanout=1)
        ),
        lambda d: d.with_default_role_enabled(True),
        lambda d: d.with_approval_memory_seconds(0),
    ],
)
def test_every_verdict_relevant_doc_field_changes_the_version(mutate):
    base = policy_version(build_snapshot(_doc(), _ROLE, "enforce", "9.9.9"))
    assert policy_version(build_snapshot(mutate(_doc()), _ROLE, "enforce", "9.9.9")) != base


def test_role_engine_and_effective_enforcement_change_the_version():
    base = policy_version(build_snapshot(_doc(), _ROLE, "enforce", "9.9.9"))
    other_role = RoleDefinition(name="reviewer", allowed=("src/**", "tests/**"))
    assert policy_version(build_snapshot(_doc(), other_role, "enforce", "9.9.9")) != base
    assert policy_version(build_snapshot(_doc(), None, "enforce", "9.9.9")) != base
    assert policy_version(build_snapshot(_doc(), _ROLE, "enforce", "9.9.10")) != base
    assert policy_version(build_snapshot(_doc(), _ROLE, "monitor", "9.9.9")) != base


def test_cosmetic_fields_do_not_change_the_version():
    base = policy_version(build_snapshot(_doc(), _ROLE, "enforce", "9.9.9"))
    toned = _doc().with_message_tone("technical")
    assert policy_version(build_snapshot(toned, _ROLE, "enforce", "9.9.9")) == base


def test_snapshot_never_carries_descriptions_or_reason_text():
    snap = build_snapshot(_doc(), _ROLE, "enforce", "9.9.9")
    canonical = canonical_json(snap)
    assert "SECRET-IN-ROLE-DESCRIPTION" not in canonical
    assert "sk-ant-" not in canonical
    for item in snapshot_doc(_doc())["items"]:
        assert "description" not in item
    assert "message_tone" not in snapshot_doc(_doc().with_message_tone("technical"))
    assert "description" not in json.loads(canonical)["role"]


def test_snapshot_is_frozen_and_defaults_are_stable():
    a = build_snapshot(_doc(), None, "enforce", "9.9.9")
    b = build_snapshot(recommend_policy(), None, "enforce", "9.9.9")
    assert policy_version(a) == policy_version(b)
    with pytest.raises(ValidationError):
        a.engine = "x"  # type: ignore[misc]
    assert isinstance(a, PolicySnapshotV1)


def test_unknown_effective_enforcement_is_recorded_as_enforce():
    snap = build_snapshot(_doc(), None, "garbage", "9.9.9")
    assert snap.enforcement_effective == "enforce"


def test_effective_enforcement_at_save_applies_the_timer():
    doc = _doc()
    assert effective_enforcement_at_save(doc, _NOW) == "enforce"
    live = doc.with_enforcement("monitor", expires_at=_NOW.timestamp() + 60, revert="enforce")
    assert effective_enforcement_at_save(live, _NOW) == "monitor"
    expired = doc.with_enforcement("off", expires_at=_NOW.timestamp() - 1, revert="monitor")
    assert effective_enforcement_at_save(expired, _NOW) == "monitor"
    bad_revert = doc.with_enforcement("off", expires_at=_NOW.timestamp() - 1, revert="off")
    assert effective_enforcement_at_save(bad_revert, _NOW) == "enforce"
    assert effective_enforcement_at_save(doc.with_enforcement("nonsense"), _NOW) == "enforce"
