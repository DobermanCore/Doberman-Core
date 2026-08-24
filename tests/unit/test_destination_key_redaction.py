"""H4 — destination feature keys are keyed fingerprints, never raw hosts.

Found by flipping on H3's redaction probe: ``scoring_keys()`` appended
``destination:<host>`` verbatim — the one feature key that was neither a
coarse class nor a fingerprint, so a secret encoded into a hostname
(token-in-subdomain exfil) would persist raw in ``baseline_counts`` after any
*allowed* egress. Now the host is HMAC-fingerprinted (same equality class, so
familiarity math is unchanged), a fingerprint failure drops the key instead of
falling back to the raw host, and the v12 migration purges legacy raw rows
(raise-safe: colder = more novel).
"""

from datetime import datetime, timezone

from doberman.models import ActionType, Algebra, Capability, SecurityObject, TargetClass
from doberman.storage.db import open_db
from doberman.storage.fingerprint import fingerprint
from doberman.subjective import baseline
from doberman.subjective.baseline import frequency, observe, scoring_keys

_NOW = datetime(2026, 6, 9, tzinfo=timezone.utc)
_HOST = "attacker.example"


def _egress(host: str = _HOST) -> SecurityObject:
    return SecurityObject(
        id="dk-1",
        ts=_NOW,
        agent_role="frontend",
        action_type=ActionType.network_request,
        tool_name="net_post",
        target="https://x.test",
        external_destination=host,
        algebra=Algebra(
            capability=Capability.send,
            target_class=TargetClass.internal,
            classification_confidence=0.8,
        ),
    )


def test_destination_key_is_a_keyed_fingerprint_not_the_raw_host():
    keys = scoring_keys(_egress())
    destination_keys = [k for k in keys if k.startswith("destination:")]
    assert destination_keys == [f"destination:{fingerprint(_HOST)}"]
    assert destination_keys[0].startswith("destination:hmac:")
    assert all(_HOST not in k for k in keys)


async def test_familiarity_still_accrues_per_host(tmp_path):
    # Same host → same fingerprint → the familiarity count works exactly as the
    # raw key did; a different host maps to a different key.
    root = str(tmp_path)
    await observe(_egress(), entity_id="hmac:aaa", repo_root=root, now=_NOW)
    await observe(_egress(), entity_id="hmac:aaa", repo_root=root, now=_NOW)
    key = f"destination:{fingerprint(_HOST)}"
    assert await frequency(key, entity_id="hmac:aaa", repo_root=root) == 2
    other = f"destination:{fingerprint('other.example')}"
    assert await frequency(other, entity_id="hmac:aaa", repo_root=root) == 0


def test_fingerprint_failure_drops_the_key_never_the_raw_host(monkeypatch):
    def _boom(_value: str) -> str:
        raise RuntimeError("no key")

    monkeypatch.setattr(baseline, "fingerprint", _boom)
    keys = scoring_keys(_egress())
    # Removing the try/except (or falling back to the raw host) flips this red.
    assert not any(k.startswith("destination:") for k in keys)
    assert all(_HOST not in k for k in keys)


async def test_v12_migration_purges_legacy_raw_destination_rows(tmp_path):
    root = str(tmp_path)
    stamp = _NOW.isoformat()
    rows = [
        ("hmac:aaa", f"destination:{_HOST}"),  # legacy raw — must be purged
        ("hmac:aaa", f"destination:{fingerprint(_HOST)}"),  # already fingerprinted
        ("hmac:aaa", "capability:send"),  # untouched bystander
    ]
    async with open_db(root) as conn:
        for eid, key in rows:
            await conn.execute(
                "INSERT INTO baseline_counts "
                "(entity_id, feature_key, role, count, first_seen, last_seen, last_touched) "
                "VALUES (?, ?, 'frontend', 3, ?, ?, ?)",
                (eid, key, stamp, stamp, stamp),
            )
        await conn.commit()

    # Reopening runs _ensure_schema → the idempotent v12 purge.
    async with open_db(root) as conn:
        async with conn.execute(
            "SELECT feature_key FROM baseline_counts ORDER BY feature_key"
        ) as cur:
            kept = [row[0] for row in await cur.fetchall()]

    assert f"destination:{_HOST}" not in kept
    assert f"destination:{fingerprint(_HOST)}" in kept
    assert "capability:send" in kept
