"""Policy catalogue: every policy version that has been in force in this repo.

A **policy version** is a content identity, not a label: ``"pv1:"`` followed by
the SHA-256 of the canonical JSON of a :class:`PolicySnapshotV1` — the exact
inputs the engine reads that a human can change (the saved policy document
minus cosmetic text, the active role's globs, the ledger-verified enforcement
state, and the engine version, which pins the rule set). Two repos with the
same configuration and the same Doberman release get the same id, and anyone
holding the snapshot can recompute it (plain SHA-256, deliberately not the
keyed HMAC in :mod:`doberman.storage.fingerprint`). ADR 0088.

The store (``.doberman/policies.db``, stdlib ``sqlite3``) is **append-only**:
``policy_versions`` holds each canonical snapshot once, ``policy_observations``
records every time the version in force was seen to change. It is a separate
file from ``doberman.db`` so ``decision-log-prune`` never touches it and it can
be exported on its own.

SECURITY / resilience:

* Never on the decision path. Nothing here can alter a verdict; every write is
  best-effort (log + continue) and every read fails closed to nothing.
* Redaction by construction: a snapshot holds enums, numbers, booleans,
  checklist ids, and operator-authored globs — the same material already in
  ``policies.yaml`` / ``role.yaml`` in the same ``0600`` directory. Item and
  role *descriptions*, ``message_tone``, ledger reasons, target paths, secrets,
  and prompts have no field to land in.
* This module is policy core: it never imports ``doberman.proxy``.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from doberman.policy.checklist import PolicyDoc
from doberman.roles.roles import RoleDefinition

logger = logging.getLogger("doberman.storage.policy_catalogue")

#: Snapshot schema carried inside every canonical snapshot (JSON key ``schema``).
SNAPSHOT_SCHEMA = 1
#: Every version id starts with this; the rest is a 64-char lower-case SHA-256 hex.
VERSION_PREFIX = "pv1:"

_ENFORCEMENT_STATES = ("enforce", "monitor", "off")
#: Keys of ``PolicyDoc.to_mapping()`` that never change a verdict and so never
#: mint a version.
_COSMETIC_DOC_KEYS = ("message_tone",)


class RoleSnapshot(BaseModel):
    """The verdict-relevant part of the active role (globs only, no description)."""

    model_config = ConfigDict(frozen=True)

    name: str
    allowed: tuple[str, ...] = ()
    suspicious: tuple[str, ...] = ()
    blocked: tuple[str, ...] = ()


class PolicySnapshotV1(BaseModel):
    """The exact content a policy version identifies (immutable).

    ``schema_version`` serialises as the JSON key ``schema`` (the field name
    avoids shadowing ``BaseModel.schema``).
    """

    model_config = ConfigDict(frozen=True, populate_by_name=True)

    schema_version: int = Field(default=SNAPSHOT_SCHEMA, alias="schema")
    engine: str
    enforcement_effective: str
    doc: dict[str, Any]
    role: RoleSnapshot | None = None


def snapshot_doc(doc: PolicyDoc) -> dict[str, Any]:
    """``PolicyDoc.to_mapping()`` minus everything that cannot change a verdict."""
    mapping = doc.to_mapping()
    for key in _COSMETIC_DOC_KEYS:
        mapping.pop(key, None)
    mapping["items"] = [
        {key: value for key, value in item.items() if key != "description"}
        for item in mapping.get("items", [])
    ]
    return mapping


def build_snapshot(
    doc: PolicyDoc,
    role: RoleDefinition | None,
    enforcement_effective: str,
    engine: str,
) -> PolicySnapshotV1:
    """Assemble the snapshot; an unrecognised enforcement state records as ``enforce``."""
    state = str(enforcement_effective).strip().lower()
    if state not in _ENFORCEMENT_STATES:
        state = "enforce"
    role_snapshot = (
        None
        if role is None
        else RoleSnapshot(
            name=role.name,
            allowed=role.allowed,
            suspicious=role.suspicious,
            blocked=role.blocked,
        )
    )
    return PolicySnapshotV1(
        engine=str(engine),
        enforcement_effective=state,
        doc=snapshot_doc(doc),
        role=role_snapshot,
    )


def canonical_json(snapshot: PolicySnapshotV1) -> str:
    """The bytes that are hashed: sorted keys, no whitespace, UTF-8 kept as-is."""
    return json.dumps(
        snapshot.model_dump(mode="json", by_alias=True),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def policy_version(snapshot: PolicySnapshotV1) -> str:
    """``pv1:`` + SHA-256 hex of :func:`canonical_json`."""
    digest = hashlib.sha256(canonical_json(snapshot).encode("utf-8")).hexdigest()
    return VERSION_PREFIX + digest


def effective_enforcement_at_save(doc: PolicyDoc, now: datetime) -> str:
    """The enforcement state a just-saved policy is acting under (pure timer rule).

    Used on the save path only: the gate has just run, so the on-disk state is
    ledger-legitimate by construction and only the soften timer needs applying.
    Mirrors the clamp in :func:`doberman.policy.drift.effective_enforcement`
    without its ledger read (which fails closed inside a running event loop).
    """
    state = str(doc.enforcement).strip().lower()
    if state == "enforce" or state not in _ENFORCEMENT_STATES:
        return "enforce"
    expires_at = doc.enforcement_expires_at
    if expires_at is not None and now.timestamp() >= expires_at:
        revert = str(doc.enforcement_revert).strip().lower()
        return revert if revert in ("enforce", "monitor") else "enforce"
    return state
