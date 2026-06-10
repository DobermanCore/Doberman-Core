"""Slice SL4.2 — calibrated surprise ensemble (HST + surprisal + robust z) + budget.

Load-bearing properties: familiar scores low and novel scores high; the
encoding always lands in [0,1] (River HST requirement); calibration makes
scores comparable across application types; the sliding step-up budget caps
family-wise flag inflation; familiarity never transfers across class
boundaries (poisoning with benign-class actions cannot make a secret-exfil
shape familiar); scoring is deterministic (seeded HST, no real clock).
"""

import itertools
from datetime import datetime, timezone

import pytest

from doberman.models import (
    ActionType,
    Algebra,
    BlastRadius,
    Capability,
    DestinationClass,
    Provenance,
    Reversibility,
    SecurityObject,
    SourceContext,
    TargetClass,
)
from doberman.storage.db import open_db
from doberman.subjective.baseline import (
    BUDGET_K,
    BUDGET_N,
    budget_allows_step_up,
    encode_algebra,
    observe,
    reset_hst,
    surprise,
)

_NOW = datetime(2026, 6, 9, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def _fresh_models():
    """HST state is process-lifetime; isolate it per test."""
    reset_hst()
    yield
    reset_hst()


def _coding_action(i=0, **kw):
    """A typical coding-assistant action: write an internal source file."""
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
        id=f"c-{i}",
        ts=_NOW,
        agent_role="frontend",
        action_type=ActionType.file_write,
        tool_name="fs_write",
        target="src/app.py",
        algebra=algebra,
        **kw,
    )


def _mail_action(i=0, **kw):
    """A typical mail-automation action: send to a known external host."""
    algebra = kw.pop(
        "algebra",
        Algebra(
            capability=Capability.send,
            target_class=TargetClass.internal,
            destination_class=DestinationClass.known_external,
            blast_radius=BlastRadius.single,
            provenance=Provenance.trusted_instruction,
            classification_confidence=0.8,
        ),
    )
    return SecurityObject(
        id=f"m-{i}",
        ts=_NOW,
        agent_role="mailer",
        action_type=ActionType.network_request,
        tool_name="send_email",
        target="https://mail.corp.example/send",
        external_destination="https://mail.corp.example/send",
        source_context=SourceContext.user,
        algebra=algebra,
        **kw,
    )


def _exfil_shape(i=0):
    """The dangerous co-occurrence: secret target, untrusted, external."""
    return _coding_action(
        i,
        algebra=Algebra(
            capability=Capability.send,
            target_class=TargetClass.secret,
            destination_class=DestinationClass.unknown_external,
            blast_radius=BlastRadius.many,
            provenance=Provenance.untrusted_data,
            classification_confidence=0.9,
        ),
    )


async def _seed(root, eid, factory, times):
    for i in range(times):
        await observe(factory(i), entity_id=eid, repo_root=root, now=_NOW)


# --- encoding ----------------------------------------------------------------


def test_encoding_round_trip_every_algebra_point_lands_in_unit_interval():
    enums = itertools.product(Capability, TargetClass, DestinationClass, BlastRadius, Provenance)
    for cap, target, dest, blast, prov in enums:
        for reversibility in Reversibility:
            action = _coding_action(
                algebra=Algebra(
                    capability=cap,
                    target_class=target,
                    destination_class=dest,
                    blast_radius=blast,
                    provenance=prov,
                    classification_confidence=0.5,
                ),
                reversibility=reversibility,
            )
            features = encode_algebra(action)
            assert features, "encoding must never be empty"
            assert all(0.0 <= v <= 1.0 for v in features.values())
            # One-hot groups stay one-hot.
            assert sum(v for k, v in features.items() if k.startswith("cap=")) == 1.0
            assert sum(v for k, v in features.items() if k.startswith("prov=")) == 1.0
            assert sum(v for k, v in features.items() if k.startswith("dest=")) == 1.0


# --- familiar vs novel ------------------------------------------------------------


async def test_familiar_scores_low_and_novel_scores_high(tmp_path):
    root = str(tmp_path)
    await _seed(root, "hmac:coder", _coding_action, 40)
    familiar = await surprise(_coding_action(99), entity_id="hmac:coder", repo_root=root)
    novel = await surprise(_exfil_shape(99), entity_id="hmac:coder", repo_root=root)
    # Familiar sits near zero; a never-seen shape clears the strict threshold
    # (0.5) with a wide margin of separation. (The exfil co-occurrence itself is
    # additionally floored deterministically by the SL7 trifecta, score aside.)
    assert familiar < 0.3
    assert novel >= 0.5
    assert novel - familiar >= 0.4


async def test_calibration_is_comparable_across_application_types(tmp_path):
    # One engine, two synthetic application types: after equivalent history the
    # familiar/novel split lands in comparable score territory for both.
    root = str(tmp_path)
    await _seed(root, "hmac:coder", _coding_action, 40)
    await _seed(root, "hmac:mailer", _mail_action, 40)

    coder_familiar = await surprise(_coding_action(99), entity_id="hmac:coder", repo_root=root)
    mailer_familiar = await surprise(_mail_action(99), entity_id="hmac:mailer", repo_root=root)
    coder_novel = await surprise(_exfil_shape(99), entity_id="hmac:coder", repo_root=root)
    mailer_novel = await surprise(_exfil_shape(99), entity_id="hmac:mailer", repo_root=root)

    assert abs(coder_familiar - mailer_familiar) < 0.25
    assert abs(coder_novel - mailer_novel) < 0.25
    assert min(coder_novel, mailer_novel) > max(coder_familiar, mailer_familiar)


async def test_scoring_is_a_pure_read(tmp_path):
    root = str(tmp_path)
    await _seed(root, "hmac:coder", _coding_action, 10)
    novel = _exfil_shape(1)
    first = await surprise(novel, entity_id="hmac:coder", repo_root=root)
    # Scoring the same novel action repeatedly must not teach the baseline.
    for _ in range(10):
        await surprise(novel, entity_id="hmac:coder", repo_root=root)
    again = await surprise(novel, entity_id="hmac:coder", repo_root=root)
    assert again == pytest.approx(first)


async def test_familiarity_does_not_transfer_across_class_boundaries(tmp_path):
    # Gradual-drift guard (placeholder strengthened in SL4.3/SL8): poisoning the
    # baseline with 100 allowed benign-class actions leaves the exfil shape novel.
    root = str(tmp_path)
    await _seed(root, "hmac:coder", _coding_action, 100)
    score = await surprise(_exfil_shape(1), entity_id="hmac:coder", repo_root=root)
    assert score >= 0.5


async def test_determinism_same_history_same_score(tmp_path):
    root_a = str(tmp_path / "a")
    root_b = str(tmp_path / "b")
    await _seed(root_a, "hmac:x", _coding_action, 25)
    score_a = await surprise(_exfil_shape(7), entity_id="hmac:x", repo_root=root_a)
    reset_hst()
    await _seed(root_b, "hmac:x", _coding_action, 25)
    score_b = await surprise(_exfil_shape(7), entity_id="hmac:x", repo_root=root_b)
    assert score_a == pytest.approx(score_b)


async def test_all_subscorer_failure_fails_toward_caution(tmp_path, monkeypatch):
    import doberman.subjective.baseline as bl

    def _boom(*args, **kwargs):
        raise OSError("db gone")

    monkeypatch.setattr(bl, "open_db", _boom)
    assert await surprise(_coding_action(), entity_id="hmac:x", repo_root=str(tmp_path)) == 1.0


# --- budget ----------------------------------------------------------------


async def _insert_decisions(root, eid, rows):
    async with open_db(root) as conn:
        for verdict, layer in rows:
            await conn.execute(
                "INSERT INTO decisions (ts, action_id, final_verdict, decided_layer, entity_id) "
                "VALUES (?, ?, ?, ?, ?)",
                (_NOW.isoformat(), "a", verdict, layer, eid),
            )
        await conn.commit()


async def test_budget_allows_until_k_subjective_step_ups(tmp_path):
    root = str(tmp_path)
    await _insert_decisions(root, "hmac:e", [("PASS", "combined")] * 10)
    assert await budget_allows_step_up(entity_id="hmac:e", repo_root=root)

    await _insert_decisions(root, "hmac:e", [("AUTH", "combined")] * BUDGET_K)
    assert not await budget_allows_step_up(entity_id="hmac:e", repo_root=root)


async def test_budget_window_slides(tmp_path):
    root = str(tmp_path)
    await _insert_decisions(root, "hmac:e", [("AUTH", "combined")] * BUDGET_K)
    # Push the step-ups out of the sliding window with PASS rows.
    await _insert_decisions(root, "hmac:e", [("PASS", "combined")] * BUDGET_N)
    assert await budget_allows_step_up(entity_id="hmac:e", repo_root=root)


async def test_budget_ignores_objective_auths_and_other_entities(tmp_path):
    root = str(tmp_path)
    # Objective-layer AUTHs and other entities' step-ups never consume the budget.
    await _insert_decisions(root, "hmac:e", [("AUTH", "objective")] * 5)
    await _insert_decisions(root, "hmac:other", [("AUTH", "combined")] * 5)
    assert await budget_allows_step_up(entity_id="hmac:e", repo_root=root)


async def test_budget_failure_means_the_step_up_surfaces(tmp_path, monkeypatch):
    import doberman.subjective.baseline as bl

    def _boom(*args, **kwargs):
        raise OSError("db gone")

    monkeypatch.setattr(bl, "open_db", _boom)
    assert await budget_allows_step_up(entity_id="hmac:e", repo_root=str(tmp_path)) is True
