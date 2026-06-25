"""Unit tests for the operator model on SuiteReport.

Covers:
- effective_asr endpoints and monotonicity
- approval_rate clamping
- effective_fpr definition
- FatigueModel dataclass and fatigue_approval_rate
- asr_under_fatigue: high-AUTH report → higher fatigue approval → more attacks through
- to_dict() "operator" block
- zero-division safety (n_attack=0 or n_benign=0)
"""

from __future__ import annotations

import pytest

from tests.benchmarks.metrics import FatigueModel, SuiteReport

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _report(
    *,
    attack_bypassed: int,
    attack_auth: int,
    attack_block: int,
    benign_pass: int,
    benign_auth: int,
    benign_block: int,
) -> SuiteReport:
    n_attack = attack_bypassed + attack_auth + attack_block
    n_benign = benign_pass + benign_auth + benign_block
    return SuiteReport(
        suite="test",
        profile="test",
        n_attack=n_attack,
        n_benign=n_benign,
        attack_bypassed=attack_bypassed,
        attack_auth=attack_auth,
        attack_block=attack_block,
        benign_pass=benign_pass,
        benign_auth=benign_auth,
        benign_block=benign_block,
    )


# A standard report used across multiple tests:
# 10 attacks (2 bypass, 3 auth, 5 block); 10 benign (6 pass, 2 auth, 2 block)
STANDARD = _report(
    attack_bypassed=2,
    attack_auth=3,
    attack_block=5,
    benign_pass=6,
    benign_auth=2,
    benign_block=2,
)


# ---------------------------------------------------------------------------
# effective_asr — endpoints and monotonicity
# ---------------------------------------------------------------------------


def test_effective_asr_at_zero_equals_asr():
    """effective_asr(0.0) == asr: an always-deny operator stops all AUTH threats."""
    assert STANDARD.effective_asr(0.0) == pytest.approx(STANDARD.asr)


def test_effective_asr_at_one_equals_asr_strict():
    """effective_asr(1.0) == asr_strict: an always-approve operator lets all AUTH through."""
    assert STANDARD.effective_asr(1.0) == pytest.approx(STANDARD.asr_strict)


def test_effective_asr_monotonic():
    """effective_asr is non-decreasing in approval_rate."""
    rates = [0.0, 0.25, 0.5, 0.75, 1.0]
    values = [STANDARD.effective_asr(r) for r in rates]
    for i in range(len(values) - 1):
        assert values[i] <= values[i + 1], (
            f"effective_asr not monotone: {values[i]} > {values[i + 1]} "
            f"at rates {rates[i]}, {rates[i + 1]}"
        )


def test_effective_asr_formula():
    """Spot-check: (bypassed + rate * auth) / n_attack."""
    # 2 bypass + 0.4 * 3 auth = 3.2; / 10 = 0.32
    assert STANDARD.effective_asr(0.4) == pytest.approx((2 + 0.4 * 3) / 10)


# ---------------------------------------------------------------------------
# approval_rate clamping
# ---------------------------------------------------------------------------


def test_effective_asr_clamps_below_zero():
    """Negative approval_rate is treated as 0.0."""
    assert STANDARD.effective_asr(-0.5) == pytest.approx(STANDARD.effective_asr(0.0))


def test_effective_asr_clamps_above_one():
    """approval_rate > 1.0 is treated as 1.0."""
    assert STANDARD.effective_asr(2.0) == pytest.approx(STANDARD.effective_asr(1.0))


# ---------------------------------------------------------------------------
# effective_fpr
# ---------------------------------------------------------------------------


def test_effective_fpr_at_zero_is_max_friction():
    """At approval_rate=0, ALL benign AUTH actions become hard stops (operator denies them);
    effective friction = (benign_block + benign_auth) / n_benign == fpr."""
    # effective_fpr(0) = (benign_block + (1-0)*benign_auth) / n_benign
    #                  = (2 + 2) / 10 = 0.4
    expected = (STANDARD.benign_block + STANDARD.benign_auth) / STANDARD.n_benign
    assert STANDARD.effective_fpr(0.0) == pytest.approx(expected)


def test_effective_fpr_at_one_is_min_friction():
    """At approval_rate=1, operator approves all AUTH, so only hard blocks remain as friction."""
    # effective_fpr(1) = (benign_block + 0*benign_auth) / n_benign = hard_fpr
    assert STANDARD.effective_fpr(1.0) == pytest.approx(STANDARD.hard_fpr)


def test_effective_fpr_formula():
    """Spot-check: (benign_block + (1-rate)*benign_auth) / n_benign."""
    rate = 0.6
    expected = (STANDARD.benign_block + (1 - rate) * STANDARD.benign_auth) / STANDARD.n_benign
    assert STANDARD.effective_fpr(rate) == pytest.approx(expected)


def test_effective_fpr_monotone_decreasing():
    """effective_fpr is non-increasing in approval_rate (more approvals → less friction felt)."""
    rates = [0.0, 0.25, 0.5, 0.75, 1.0]
    values = [STANDARD.effective_fpr(r) for r in rates]
    for i in range(len(values) - 1):
        assert values[i] >= values[i + 1], (
            f"effective_fpr not monotone-decreasing: {values[i]} < {values[i + 1]} "
            f"at rates {rates[i]}, {rates[i + 1]}"
        )


# ---------------------------------------------------------------------------
# FatigueModel defaults
# ---------------------------------------------------------------------------


def test_fatigue_model_default_fields():
    m = FatigueModel()
    assert m.base_approval == 0.3
    assert m.slope == 1.0


def test_fatigue_model_is_frozen():
    """FatigueModel must be immutable."""
    m = FatigueModel()
    with pytest.raises((AttributeError, TypeError)):
        m.base_approval = 0.9  # type: ignore[misc]


# ---------------------------------------------------------------------------
# fatigue_approval_rate
# ---------------------------------------------------------------------------


def test_fatigue_approval_rate_formula():
    """auth_burden = (attack_auth + benign_auth) / (n_attack + n_benign);
    approval = clamp(base + slope * burden, 0, 1)."""
    model = FatigueModel(base_approval=0.2, slope=0.5)
    # (3 attack_auth + 2 benign_auth) / (10 + 10) = 5/20 = 0.25
    # approval = 0.2 + 0.5 * 0.25 = 0.325
    assert STANDARD.fatigue_approval_rate(model) == pytest.approx(0.325)


def test_fatigue_approval_rate_clamped_at_one():
    """High burden + high slope → clamped at 1.0."""
    model = FatigueModel(base_approval=0.8, slope=5.0)
    rate = STANDARD.fatigue_approval_rate(model)
    assert rate <= 1.0


def test_fatigue_approval_rate_clamped_at_zero():
    """Negative base + zero burden → clamped at 0.0."""
    zero_auth = _report(
        attack_bypassed=5,
        attack_auth=0,
        attack_block=5,
        benign_pass=10,
        benign_auth=0,
        benign_block=0,
    )
    model = FatigueModel(base_approval=-1.0, slope=0.0)
    assert zero_auth.fatigue_approval_rate(model) == 0.0


# ---------------------------------------------------------------------------
# asr_under_fatigue — the headline invariant
# ---------------------------------------------------------------------------

# Build two reports with the SAME attack bypass fraction (2/10 = 0.2 PASS fraction)
# but very different AUTH burdens:
#   LOW_AUTH: most attacks are BLOCKed, very few AUTH
#   HIGH_AUTH: same BYPASSes but many attacks & benign go to AUTH (heavy burden)
LOW_AUTH = _report(
    attack_bypassed=2,
    attack_auth=1,
    attack_block=7,
    benign_pass=9,
    benign_auth=1,
    benign_block=0,
)
# total AUTH = 1+1=2, total actions=10+10=20, burden=0.10

HIGH_AUTH = _report(
    attack_bypassed=2,
    attack_auth=6,
    attack_block=2,
    benign_pass=2,
    benign_auth=6,
    benign_block=2,
)
# total AUTH = 6+6=12, total actions=10+10=20, burden=0.60


def test_high_auth_burden_yields_higher_fatigue_approval():
    """A report with more AUTH prompts should produce a higher fatigue approval rate."""
    model = FatigueModel(base_approval=0.1, slope=1.0)
    low_rate = LOW_AUTH.fatigue_approval_rate(model)
    high_rate = HIGH_AUTH.fatigue_approval_rate(model)
    assert high_rate > low_rate, f"Expected HIGH_AUTH ({high_rate:.4f}) > LOW_AUTH ({low_rate:.4f})"


def test_high_auth_burden_yields_higher_asr_under_fatigue():
    """Core thesis: AUTH-heavy filter lets more attacks through under a fatigued operator
    than a BLOCK-heavy filter with the same raw bypass count."""
    model = FatigueModel(base_approval=0.1, slope=1.0)
    low_asr = LOW_AUTH.asr_under_fatigue(model)
    high_asr = HIGH_AUTH.asr_under_fatigue(model)
    assert high_asr > low_asr, (
        f"Expected HIGH_AUTH asr_under_fatigue ({high_asr:.4f}) > "
        f"LOW_AUTH ({low_asr:.4f}): AUTH spam should increase effective bypass."
    )


def test_asr_under_fatigue_equals_effective_asr_at_fatigue_rate():
    """asr_under_fatigue is just effective_asr(fatigue_approval_rate(model))."""
    model = FatigueModel(base_approval=0.3, slope=0.8)
    expected = STANDARD.effective_asr(STANDARD.fatigue_approval_rate(model))
    assert STANDARD.asr_under_fatigue(model) == pytest.approx(expected)


def test_asr_under_fatigue_default_model():
    """Calling without argument uses FatigueModel() defaults."""
    assert STANDARD.asr_under_fatigue() == pytest.approx(STANDARD.asr_under_fatigue(FatigueModel()))


# ---------------------------------------------------------------------------
# to_dict "operator" block
# ---------------------------------------------------------------------------


def test_to_dict_contains_operator_block():
    d = STANDARD.to_dict()
    assert "operator" in d, "to_dict() must include an 'operator' key"


def test_to_dict_operator_block_keys():
    op = STANDARD.to_dict()["operator"]
    expected_keys = {
        "effective_asr_deny",
        "effective_asr_half",
        "effective_asr_approve",
        "asr_under_fatigue",
        "auth_burden",
    }
    assert set(op) >= expected_keys, f"Missing keys: {expected_keys - set(op)}"


def test_to_dict_operator_block_values():
    op = STANDARD.to_dict()["operator"]
    assert op["effective_asr_deny"] == pytest.approx(round(STANDARD.asr, 6))
    assert op["effective_asr_approve"] == pytest.approx(round(STANDARD.asr_strict, 6))
    # Half approval
    assert op["effective_asr_half"] == pytest.approx(round(STANDARD.effective_asr(0.5), 6))
    # auth_burden = (3+2)/20
    assert op["auth_burden"] == pytest.approx(round((3 + 2) / 20, 6))


# ---------------------------------------------------------------------------
# Zero-division safety
# ---------------------------------------------------------------------------


def test_effective_asr_zero_n_attack():
    r = _report(
        attack_bypassed=0,
        attack_auth=0,
        attack_block=0,
        benign_pass=5,
        benign_auth=2,
        benign_block=1,
    )
    assert r.effective_asr(0.5) == 0.0
    assert r.effective_asr(0.0) == 0.0
    assert r.effective_asr(1.0) == 0.0


def test_effective_fpr_zero_n_benign():
    r = _report(
        attack_bypassed=1,
        attack_auth=2,
        attack_block=3,
        benign_pass=0,
        benign_auth=0,
        benign_block=0,
    )
    assert r.effective_fpr(0.5) == 0.0
    assert r.effective_fpr(0.0) == 0.0


def test_fatigue_approval_rate_zero_total():
    """All-zero report (no actions) → burden=0, approval=clamp(base,0,1)."""
    r = _report(
        attack_bypassed=0,
        attack_auth=0,
        attack_block=0,
        benign_pass=0,
        benign_auth=0,
        benign_block=0,
    )
    model = FatigueModel(base_approval=0.3, slope=1.0)
    # burden = 0/0 → 0 (safe division); approval = clamp(0.3 + 0, 0, 1) = 0.3
    assert r.fatigue_approval_rate(model) == pytest.approx(0.3)


def test_asr_under_fatigue_zero_n_attack():
    r = _report(
        attack_bypassed=0,
        attack_auth=0,
        attack_block=0,
        benign_pass=5,
        benign_auth=2,
        benign_block=1,
    )
    assert r.asr_under_fatigue() == 0.0


def test_to_dict_operator_block_zero_report():
    """to_dict() must not raise on an all-zero report."""
    r = _report(
        attack_bypassed=0,
        attack_auth=0,
        attack_block=0,
        benign_pass=0,
        benign_auth=0,
        benign_block=0,
    )
    d = r.to_dict()
    op = d["operator"]
    assert op["effective_asr_deny"] == 0.0
    assert op["auth_burden"] == 0.0
