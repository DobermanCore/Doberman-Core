"""Policy catalogue: content-hash identity of the effective policy (ADR 0088)."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from doberman.config import save_policy
from doberman.egress.velocity import VelocityThresholds
from doberman.policy.checklist import recommend_policy
from doberman.policy.preferences import PreferenceVector
from doberman.roles.roles import RoleDefinition
from doberman.storage.policy_catalogue import (
    CATALOGUE_SCHEMA_VERSION,
    ORIGIN_CHANGE,
    ORIGIN_OBSERVED,
    SNAPSHOT_SCHEMA,
    VERSION_PREFIX,
    PolicySnapshotV1,
    build_snapshot,
    canonical_json,
    catalogue_path,
    effective_enforcement_at_save,
    find_versions,
    observe_current,
    policy_version,
    read_observations,
    read_snapshot,
    read_versions,
    record_version,
    snapshot_doc,
    verify_catalogue,
    version_at,
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


_T1 = datetime(2026, 8, 30, 10, 0, tzinfo=timezone.utc)
_T2 = datetime(2026, 8, 30, 11, 0, tzinfo=timezone.utc)
_T3 = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)


def _snap(mode="balanced"):
    return build_snapshot(_doc().with_mode(mode), None, "enforce", "9.9.9")


def test_record_version_stores_content_once_and_observes_changes_only(tmp_path):
    root = str(tmp_path)
    v1 = record_version(root, _snap(), origin=ORIGIN_OBSERVED, now=_T1)
    assert v1 == record_version(root, _snap(), origin=ORIGIN_OBSERVED, now=_T2)
    assert [v["version"] for v in read_versions(root)] == [v1]
    assert len(read_observations(root)) == 1  # same version twice -> one observation
    v2 = record_version(root, _snap("strict"), origin=ORIGIN_CHANGE, ledger_ts="L1", now=_T2)
    record_version(root, _snap(), origin=ORIGIN_OBSERVED, now=_T3)  # recurrence is recorded
    assert {v["version"] for v in read_versions(root)} == {v1, v2}
    obs = read_observations(root)
    assert [(o["version"], o["origin"], o["ledger_ts"]) for o in obs] == [
        (v1, ORIGIN_OBSERVED, None),
        (v2, ORIGIN_CHANGE, "L1"),
        (v1, ORIGIN_OBSERVED, None),
    ]
    assert obs[0]["ts"] == _T3.isoformat()


def test_read_versions_exposes_engine_and_schema_but_never_canonical(tmp_path):
    root = str(tmp_path)
    v = record_version(root, _snap(), origin=ORIGIN_OBSERVED, now=_T1)
    (row,) = read_versions(root)
    assert row == {"version": v, "first_seen": _T1.isoformat(), "engine": "9.9.9", "schema": 1}
    snap = read_snapshot(root, v)
    assert snap is not None and snap["doc"]["mode"] == "balanced"
    assert read_snapshot(root, "pv1:" + "0" * 64) is None


def test_version_at_uses_the_latest_observation_at_or_before_ts(tmp_path):
    root = str(tmp_path)
    v1 = record_version(root, _snap(), origin=ORIGIN_OBSERVED, now=_T1)
    v2 = record_version(root, _snap("strict"), origin=ORIGIN_OBSERVED, now=_T3)
    assert version_at(root, "2026-08-30T09:59:59+00:00") is None
    assert version_at(root, _T1.isoformat()) == v1
    assert version_at(root, _T2.isoformat()) == v1
    assert version_at(root, _T3.isoformat()) == v2
    assert version_at(root, "2027-01-01T00:00:00+00:00") == v2


def test_reads_on_a_missing_catalogue_fail_closed_to_nothing(tmp_path):
    root = str(tmp_path)
    assert read_versions(root) == []
    assert read_observations(root) == []
    assert version_at(root, _T1.isoformat()) is None
    assert read_snapshot(root, "pv1:" + "0" * 64) is None
    assert not catalogue_path(root).exists()


def test_observe_current_uses_defaults_when_no_policy_is_saved(tmp_path):
    root = str(tmp_path)
    v = observe_current(root, origin=ORIGIN_OBSERVED, now=_T1)
    assert v is not None and v.startswith("pv1:")
    assert v == observe_current(root, origin=ORIGIN_OBSERVED, now=_T2)
    snap = read_snapshot(root, v)
    assert snap["doc"] == snapshot_doc(recommend_policy())
    assert snap["enforcement_effective"] == "enforce"


def test_find_versions_matches_hex_prefixes(tmp_path):
    root = str(tmp_path)
    v = record_version(root, _snap(), origin=ORIGIN_OBSERVED, now=_T1)
    hex_part = v[len(VERSION_PREFIX) :]
    assert find_versions(root, hex_part[:8]) == [v]
    assert find_versions(root, v) == [v]
    assert find_versions(root, "zz") == []


def test_verify_reports_ok_drift_and_mismatch(tmp_path):
    root = str(tmp_path)
    assert verify_catalogue(root)["status"] == "drift"  # nothing recorded yet
    observe_current(root, origin=ORIGIN_OBSERVED, now=_T1)
    report = verify_catalogue(root)
    assert report["status"] == "ok" and report["current"] == report["recorded"]
    assert report["versions"] == 1 and report["mismatched"] == []
    # A hand edit of policies.yaml (bypassing every gate) shows as drift ...
    save_policy(recommend_policy().with_mode("paranoid"), root)  # records a change
    (tmp_path / ".doberman" / "policies.yaml").write_text(
        (tmp_path / ".doberman" / "policies.yaml").read_text().replace("paranoid", "light")
    )
    report = verify_catalogue(root)
    assert report["status"] == "drift" and report["current"] != report["recorded"]
    # ... and re-observing clears it.
    observe_current(root, origin=ORIGIN_OBSERVED, now=_T2)
    assert verify_catalogue(root)["status"] == "ok"
    # Tampering with stored content is a mismatch naming the id.
    conn = sqlite3.connect(str(catalogue_path(root)))
    victim = conn.execute("SELECT version FROM policy_versions LIMIT 1").fetchone()[0]
    conn.execute("UPDATE policy_versions SET canonical = '{}' WHERE version = ?", (victim,))
    conn.commit()
    conn.close()
    report = verify_catalogue(root)
    assert report["status"] == "mismatch" and report["mismatched"] == [victim]


def test_catalogue_schema_and_permissions(tmp_path):
    root = str(tmp_path)
    record_version(root, _snap(), origin=ORIGIN_OBSERVED, now=_T1)
    conn = sqlite3.connect(str(catalogue_path(root)))
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"schema_version", "policy_versions", "policy_observations"} <= tables
    assert (
        conn.execute("SELECT version FROM schema_version").fetchone()[0] == CATALOGUE_SCHEMA_VERSION
    )
    conn.close()
    if os.name != "nt":
        mode = stat.S_IMODE(catalogue_path(root).stat().st_mode)
        assert mode == 0o600


def test_module_has_no_update_or_delete_statements():
    import inspect

    import doberman.storage.policy_catalogue as module

    source = inspect.getsource(module).upper()
    body = source.split("_SCHEMA = ", 1)[1]  # skip the docstring/header
    assert "UPDATE " not in body
    assert "DELETE " not in body
