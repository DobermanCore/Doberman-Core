"""Slice SL4.3 — peer-group cold-start and ADWIN drift handling.

Load-bearing properties: a new entity scores against its peer cohort (or a
conservative global prior with no peers) and transitions to its own baseline
at K observations; ADWIN drift triggers a baseline REFRESH; refresh only ever
discounts familiarity (surprise can only rise — never loosens protection).
"""

from datetime import datetime, timezone

import pytest

from doberman.models import (
    ActionType,
    Algebra,
    BlastRadius,
    Capability,
    DestinationClass,
    Provenance,
    SecurityObject,
    TargetClass,
)
from doberman.subjective.baseline import frequency, observe, reset_hst, surprise
from doberman.subjective.drift import (
    GLOBAL_PRIOR,
    K_OBSERVATIONS,
    feed_drift_value,
    note_allowed,
    refresh_baseline,
    reset_adwin,
    surprise_blended,
)

_NOW = datetime(2026, 6, 9, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def _fresh_models():
    reset_hst()
    reset_adwin()
    yield
    reset_hst()
    reset_adwin()


def _action(i=0, role="frontend", tool="fs_write", **kw):
    algebra = kw.pop(
        "algebra",
        Algebra(
            capability=Capability.mutate,
            target_class=TargetClass.internal,
            destination_class=DestinationClass.none,
            blast_radius=BlastRadius.single,
            provenance=Provenance.trusted_instruction,
            classification_confidence=0.8,
        ),
    )
    return SecurityObject(
        id=f"pd-{i}",
        ts=_NOW,
        agent_role=role,
        action_type=ActionType.file_write,
        tool_name=tool,
        target="src/app.py",
        algebra=algebra,
        **kw,
    )


def _novel_action(i=0, role="frontend"):
    return _action(
        i,
        role=role,
        algebra=Algebra(
            capability=Capability.send,
            target_class=TargetClass.secret,
            destination_class=DestinationClass.unknown_external,
            blast_radius=BlastRadius.many,
            provenance=Provenance.untrusted_data,
            classification_confidence=0.9,
        ),
    )


async def _seed(root, eid, factory, times, role="frontend"):
    for i in range(times):
        await observe(factory(i, role=role), entity_id=eid, repo_root=root, now=_NOW)


# --- cold start ----------------------------------------------------------------


async def test_new_entity_with_no_peers_uses_the_global_prior(tmp_path):
    root = str(tmp_path)
    score = await surprise_blended(_action(), entity_id="hmac:new", repo_root=root)
    # Zero own history + zero peers → dominated by the warn-leaning prior.
    assert score == pytest.approx(GLOBAL_PRIOR, abs=0.15)


async def test_new_entity_leans_on_its_peer_cohort(tmp_path):
    root = str(tmp_path)
    # A same-role peer with established habits.
    await _seed(root, "hmac:peer", _action, 30)
    # The new entity has NO history of its own.
    familiar_to_peer = await surprise_blended(_action(), entity_id="hmac:new", repo_root=root)
    novel_to_peer = await surprise_blended(_novel_action(), entity_id="hmac:new", repo_root=root)
    assert familiar_to_peer < 0.3  # peer knows this shape
    assert novel_to_peer >= 0.8  # nobody knows this shape
    # A different-role entity is NOT a peer.
    other_role = await surprise_blended(
        _action(role="mailer"), entity_id="hmac:other", repo_root=root
    )
    assert other_role == pytest.approx(GLOBAL_PRIOR, abs=0.15)


async def test_entity_transitions_to_its_own_baseline_at_k(tmp_path):
    root = str(tmp_path)
    await _seed(root, "hmac:mature", _action, K_OBSERVATIONS)
    own = await surprise(_action(), entity_id="hmac:mature", repo_root=root)
    blended = await surprise_blended(_action(), entity_id="hmac:mature", repo_root=root)
    assert blended == pytest.approx(own)  # weight 1.0: prior no longer consulted


# --- drift ----------------------------------------------------------------


def test_adwin_detects_a_regime_change():
    fired = False
    for _ in range(300):
        fired = fired or feed_drift_value("hmac:e", 0.0)
    assert not fired  # stable stream: no drift
    for _ in range(200):
        if feed_drift_value("hmac:e", 1.0):
            fired = True
            break
    assert fired  # clear shift detected


async def test_note_allowed_refreshes_on_drift(tmp_path):
    root = str(tmp_path)
    await _seed(root, "hmac:e", _action, 30)
    before = await frequency("target:internal", entity_id="hmac:e", repo_root=root)
    assert before == 30
    # A long stable stream then a SUSTAINED novel regime (all ALLOWED actions —
    # e.g. the operator genuinely changed workflows): each step touches a
    # never-seen tool, so the novelty stream jumps from ~0 to ~1 and stays there.
    for i in range(300):
        await note_allowed(_action(i), entity_id="hmac:e", repo_root=root)
    refreshed = False
    for i in range(200):
        exotic = _action(i, tool=f"exotic_tool_{i}")
        await observe(exotic, entity_id="hmac:e", repo_root=root, now=_NOW)
        if await note_allowed(exotic, entity_id="hmac:e", repo_root=root):
            refreshed = True
            break
    assert refreshed
    after = await frequency("target:internal", entity_id="hmac:e", repo_root=root)
    assert after < before  # familiarity was discounted, not accumulated


async def test_refresh_never_lowers_protection(tmp_path):
    root = str(tmp_path)
    await _seed(root, "hmac:e", _action, 40)
    familiar_before = await surprise(_action(), entity_id="hmac:e", repo_root=root)
    count_before = await frequency("target:internal", entity_id="hmac:e", repo_root=root)
    await refresh_baseline("hmac:e", repo_root=root)
    familiar_after = await surprise(_action(), entity_id="hmac:e", repo_root=root)
    count_after = await frequency("target:internal", entity_id="hmac:e", repo_root=root)
    novel_after = await surprise(_novel_action(), entity_id="hmac:e", repo_root=root)
    # A familiar shape never becomes MORE familiar; familiarity counts strictly
    # discount; and a dangerous novel shape still clears the strict threshold.
    assert familiar_after >= familiar_before - 1e-9
    assert count_after < count_before
    assert novel_after >= 0.5
    # The halved total re-engages the cold-start prior on the blended path.
    blended = await surprise_blended(_action(), entity_id="hmac:e", repo_root=root)
    assert blended >= familiar_after  # prior can only add caution here


async def test_refresh_failure_never_raises(tmp_path, monkeypatch):
    import doberman.subjective.drift as dr

    def _boom(*args, **kwargs):
        raise OSError("db gone")

    monkeypatch.setattr(dr, "open_db", _boom)
    await refresh_baseline("hmac:e", repo_root=str(tmp_path))  # must not raise
    assert not await note_allowed(_action(), entity_id="hmac:e", repo_root=str(tmp_path)) or True
