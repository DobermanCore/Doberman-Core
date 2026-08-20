"""Slice H3 — pin contracts of the subjective layer left unpinned by the
existing suite, found by the 2026-08-19 hardening audit.

Each test targets one specific behavior and names, in its own docstring, the
exact source change that would flip it red. Test-only slice: nothing under
``src/`` is touched.
"""

import logging
from datetime import datetime, timezone

import pytest

import doberman.proxy.executor as executor
from doberman.engine.subjective import SubjectiveGuardrail
from doberman.models import (
    ActionType,
    Algebra,
    BlastRadius,
    Capability,
    DestinationClass,
    EvalContext,
    Provenance,
    ReasonCode,
    Reversibility,
    SecurityObject,
    TargetClass,
    Verdict,
)
from doberman.policy.preferences import PreferenceVector
from doberman.storage.db import open_db
from doberman.subjective.baseline import (
    MIN_CALIBRATION_SAMPLES,
    _calibrated,
    observe,
    reset_hst,
)
from doberman.subjective.drift import GLOBAL_PRIOR, reset_adwin, surprise_blended
from doberman.subjective.revealed import MIN_SAMPLES, _proposed_changes

_NOW = datetime(2026, 6, 9, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def _fresh_models():
    reset_hst()
    reset_adwin()
    yield
    reset_hst()
    reset_adwin()


# --- 1. cold-start prior is conservative, value-independently --------------------


def _cold_start_action(i=0, role="frontend"):
    algebra = Algebra(
        capability=Capability.mutate,
        target_class=TargetClass.internal,
        destination_class=DestinationClass.none,
        blast_radius=BlastRadius.single,
        provenance=Provenance.trusted_instruction,
        classification_confidence=0.8,
    )
    return SecurityObject(
        id=f"hp-cold-{i}",
        ts=_NOW,
        agent_role=role,
        action_type=ActionType.file_write,
        tool_name="fs_write",
        target="src/app.py",
        algebra=algebra,
    )


async def test_cold_start_prior_is_conservative_value_independently(tmp_path):
    """test_peer_and_drift.py:97 only checks score == approx(GLOBAL_PRIOR), which
    a moved-but-still-arbitrary GLOBAL_PRIOR (e.g. 0.05) would also satisfy. Pin
    the literal floor directly: GLOBAL_PRIOR itself must be warn-leaning, and a
    brand-new entity with zero peers must score at least 0.4. Flips red if
    GLOBAL_PRIOR is lowered below 0.5, or if surprise_blended's cold-start
    weighting (weight * own + (1 - weight) * prior) stops routing an unweighted
    new entity through the prior.
    """
    assert GLOBAL_PRIOR >= 0.5
    root = str(tmp_path)
    score = await surprise_blended(_cold_start_action(), entity_id="hmac:hp-new", repo_root=root)
    assert score >= 0.4


# --- 2. subjective detector garbage-return is isolated ----------------------------


def _action(algebra=None, reversibility=Reversibility.low, **kw):
    return SecurityObject(
        id="hp-2",
        ts=_NOW,
        agent_role="frontend",
        action_type=ActionType.file_write,
        tool_name="fs_write",
        target="backend/api.ts",
        reversibility=reversibility,
        algebra=algebra or Algebra(),
        **kw,
    )


def _ctx(surprise, mode="balanced", **extra):
    return EvalContext(mode=mode, metadata={"surprise": surprise, **extra})


class _ReturnsNoneDetector:
    def evaluate(self, action, ctx):
        return None


class _ReturnsDictDetector:
    def evaluate(self, action, ctx):
        return {"verdict": "PASS"}


@pytest.mark.parametrize("detector_cls", [_ReturnsNoneDetector, _ReturnsDictDetector])
def test_garbage_returning_detector_is_isolated_as_auth(detector_cls):
    """_isolate (src/doberman/engine/subjective.py ~L79-93) already covers a
    RAISING detector (test_subjective_engine.py::test_failing_detector_is_
    isolated_as_auth); this pins the sibling branch — a detector that RETURNS
    something that isn't a GuardrailResult. Flips red if the
    `isinstance(result, GuardrailResult)` check is removed or narrowed to only
    catch the raise path.
    """
    engine = SubjectiveGuardrail(load_plugins=False, extra_detectors=[detector_cls()])
    result = engine.evaluate(_action(), _ctx(0.0))
    assert result.verdict is Verdict.AUTH
    assert ReasonCode.rule_error in result.reason_codes


# --- 3. revealed-preference clamp at boundary weights -----------------------------


def test_proposed_changes_clamps_at_the_weight_boundaries():
    """_proposed_changes (src/doberman/subjective/revealed.py ~L152-168) clamps
    with max(0.0, round(weight - STEP, 4)) / min(1.0, round(weight + STEP, 4)),
    but every existing test starts from the 0.5 preset where the clamp never
    engages. Constructed directly with a boundary PreferenceVector (the public
    maybe_nudge path would additionally need MIN_SAMPLES DB rows, the F10 gate,
    and a rational Martingale belief stream — out of scope for this unit pin).
    Flips red if either max(0.0, ...) or min(1.0, ...) clamp is removed.
    """
    near_zero = PreferenceVector(confidentiality=0.03)
    strong_approve = {"confidentiality": (MIN_SAMPLES, 0)}
    proposals = _proposed_changes(strong_approve, near_zero)
    assert "confidentiality" in proposals
    assert 0.0 <= proposals["confidentiality"] <= 1.0
    assert proposals["confidentiality"] == 0.0  # clamped, never negative

    near_one = PreferenceVector(blast_radius=0.97)
    strong_deny = {"blast_radius": (0, MIN_SAMPLES)}
    proposals2 = _proposed_changes(strong_deny, near_one)
    assert "blast_radius" in proposals2
    assert 0.0 <= proposals2["blast_radius"] <= 1.0
    assert proposals2["blast_radius"] == 1.0  # clamped, never above 1

    # Exactly at the rail: a no-op is fine, but it must never raise or drift
    # out of [0, 1] (weight - STEP would be negative if unclamped).
    at_zero = PreferenceVector(reversibility=0.0)
    proposals3 = _proposed_changes({"reversibility": (MIN_SAMPLES, 0)}, at_zero)
    assert all(0.0 <= w <= 1.0 for w in proposals3.values())


# --- 4. baseline store never holds a raw secret-shaped value ---------------------


async def test_baseline_never_stores_a_raw_secret_shaped_value(tmp_path):
    """Feeds a marker through the file_write path (filename), the shell_exec
    path (command line, after the verb), and the external_destination path (a
    plain host embedding the marker), then scans every baseline_counts and
    baseline_transitions row. Flips green (remove the skip) once
    scoring_keys()/observe() stop leaking a raw destination host; flips red
    again if the file-write or shell-exec paths regress to leaking the
    filename/command line instead of their coarse classes.
    """
    root = str(tmp_path)
    marker = "FAKESECRETMARKER123"

    file_action = SecurityObject(
        id="hp-4a",
        ts=_NOW,
        agent_role="frontend",
        action_type=ActionType.file_write,
        tool_name="fs_write",
        target=f"config/{marker}.env",
        algebra=Algebra(
            capability=Capability.mutate,
            target_class=TargetClass.internal,
            classification_confidence=0.8,
        ),
    )
    shell_action = SecurityObject(
        id="hp-4b",
        ts=_NOW,
        agent_role="frontend",
        action_type=ActionType.shell_exec,
        tool_name="shell_exec",
        target=f"curl -H {marker} https://x.test",
        algebra=Algebra(
            capability=Capability.execute,
            target_class=TargetClass.internal,
            classification_confidence=0.8,
        ),
    )
    destination_action = SecurityObject(
        id="hp-4c",
        ts=_NOW,
        agent_role="frontend",
        action_type=ActionType.network_request,
        tool_name="net_post",
        target="https://x.test",
        external_destination=f"{marker}.attacker.example",
        algebra=Algebra(
            capability=Capability.send,
            target_class=TargetClass.internal,
            destination_class=DestinationClass.unknown_external,
            classification_confidence=0.8,
        ),
    )

    for action in (file_action, shell_action, destination_action):
        await observe(action, entity_id="hmac:hp-secret", repo_root=root, now=_NOW)

    async with open_db(root) as conn:
        async with conn.execute(
            "SELECT feature_key FROM baseline_counts WHERE entity_id = ?",
            ("hmac:hp-secret",),
        ) as cur:
            count_rows = await cur.fetchall()
        async with conn.execute(
            "SELECT from_state, to_state FROM baseline_transitions WHERE entity_id = ?",
            ("hmac:hp-secret",),
        ) as cur:
            transition_rows = await cur.fetchall()

    leaked = [row[0] for row in count_rows if marker in row[0]]
    leaked += [value for row in transition_rows for value in row if marker in value]
    assert not leaked, f"marker leaked into baseline store keys: {leaked}"


# --- 5. _calibrated() contract ----------------------------------------------------


async def test_calibrated_bounded_monotone_and_passthrough_below_min_samples(tmp_path):
    """_calibrated (src/doberman/subjective/baseline.py ~L550-572) is `raw *
    midrank_cdf` once history >= MIN_CALIBRATION_SAMPLES, else a passthrough of
    `raw`. Pins: (i) the result stays in [0, 1] for raw in [0, 1]; (ii) for a
    FIXED history it is monotone non-decreasing in raw (both raw and
    midrank_cdf(raw) are non-decreasing in raw, so their product is too);
    (iii) below MIN_CALIBRATION_SAMPLES the raw score passes through exactly
    unchanged. Flips red if `return raw * midrank_cdf` is changed to something
    that can exceed 1 or isn't monotone (e.g. adding a constant instead of
    multiplying), or if the `len(values) < MIN_CALIBRATION_SAMPLES: return raw`
    early return is removed.
    """
    root = str(tmp_path)
    stamp = _NOW.isoformat()
    async with open_db(root) as conn:
        # (iii) below the calibration floor: passthrough, exact.
        for _ in range(MIN_CALIBRATION_SAMPLES - 1):
            await conn.execute(
                "INSERT INTO score_history (entity_id, ts, kind, value, last_touched) "
                "VALUES (?, ?, ?, ?, ?)",
                ("hmac:hp-cal", stamp, "novelty", 0.5, stamp),
            )
        await conn.commit()
        assert await _calibrated(conn, "hmac:hp-cal", "novelty", 0.73) == 0.73

        # Cross the floor with a spread history for (i)/(ii).
        for v in [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0] * 3:
            await conn.execute(
                "INSERT INTO score_history (entity_id, ts, kind, value, last_touched) "
                "VALUES (?, ?, ?, ?, ?)",
                ("hmac:hp-cal", stamp, "novelty", v, stamp),
            )
        await conn.commit()

        raws = [0.0, 0.15, 0.35, 0.55, 0.75, 0.95, 1.0]
        results = [await _calibrated(conn, "hmac:hp-cal", "novelty", raw) for raw in raws]

    assert all(0.0 <= r <= 1.0 for r in results)
    assert results == sorted(results)  # monotone non-decreasing in raw


# --- 6. budget-overflow is logged -------------------------------------------------


async def test_budget_overflow_is_logged_for_review(monkeypatch, caplog):
    """_budget_or_surface (src/doberman/proxy/executor.py ~L338-349) logs via
    the "doberman.proxy.engine" logger when budget_allows_step_up returns
    False, and returns that False through unchanged. Flips red if the
    `if not budget_ok: _engine_logger.info(...)` branch is removed, or if the
    message stops containing "budget exhausted".
    """

    async def _denied(*, entity_id, repo_root):
        return False

    monkeypatch.setattr(executor, "budget_allows_step_up", _denied)
    caplog.set_level(logging.INFO, logger="doberman.proxy.engine")
    result = await executor._budget_or_surface("hmac:hp-budget")
    assert result is False
    assert "budget exhausted" in caplog.text
