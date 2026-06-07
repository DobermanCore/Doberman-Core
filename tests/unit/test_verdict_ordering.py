"""Slice 2.2 — the raise-only combination: the most important tests in the repo.

`combine` must NEVER return a verdict or risk lower than either input.
"""

import random

import pytest

from doberman.engine.decision_engine import combine, max_risk, max_verdict
from doberman.models import (
    RISK_ORDER,
    VERDICT_ORDER,
    GuardrailResult,
    ReasonCode,
    Risk,
    Verdict,
)

ALL_VERDICTS = list(Verdict)
ALL_RISKS = list(Risk)


def make_result(
    verdict: Verdict,
    risk: Risk,
    reasons: list[ReasonCode] | None = None,
) -> GuardrailResult:
    """Build a valid GuardrailResult (non-PASS needs reasons + explanation)."""
    if verdict is Verdict.PASS:
        return GuardrailResult(verdict=verdict, risk=risk, reason_codes=reasons or [])
    return GuardrailResult(
        verdict=verdict,
        risk=risk,
        reason_codes=reasons or [ReasonCode.unknown_tool],
        explanation=f"{verdict} for testing.",
    )


@pytest.mark.parametrize("a", ALL_VERDICTS)
@pytest.mark.parametrize("b", ALL_VERDICTS)
def test_full_verdict_matrix_takes_max(a, b):
    combined = combine(make_result(a, Risk.low), make_result(b, Risk.low))
    assert VERDICT_ORDER[combined.verdict] == max(VERDICT_ORDER[a], VERDICT_ORDER[b])
    assert combined.verdict == max_verdict(a, b)


@pytest.mark.parametrize("a", ALL_RISKS)
@pytest.mark.parametrize("b", ALL_RISKS)
def test_full_risk_matrix_takes_max(a, b):
    combined = combine(make_result(Verdict.PASS, a), make_result(Verdict.PASS, b))
    assert RISK_ORDER[combined.risk] == max(RISK_ORDER[a], RISK_ORDER[b])
    assert combined.risk == max_risk(a, b)
    # Risk advances independently of verdict: mixed-verdict pairs too.
    mixed = combine(make_result(Verdict.AUTH, a), make_result(Verdict.BLOCK, b))
    assert mixed.risk == max_risk(a, b)
    assert mixed.verdict is Verdict.BLOCK


def test_none_passthrough_returns_equal_but_unaliased_copy():
    a = make_result(Verdict.AUTH, Risk.high)
    out = combine(a, None)
    assert out == a
    assert out is not a
    # No aliasing: mutating one reason list must not affect the other.
    out.reason_codes.append(ReasonCode.downstream_error)
    assert a.reason_codes == [ReasonCode.unknown_tool]


def test_combine_never_lowers_property():
    """THE invariant: over many random pairs, combine never returns below
    max(a, b) on either axis, and never drops a reason code."""
    rng = random.Random(20260607)  # noqa: S311 — seeded PRNG for test determinism only
    codes = list(ReasonCode)

    def random_result() -> GuardrailResult:
        verdict = rng.choice(ALL_VERDICTS)
        # PASS may legally carry ZERO reasons — include that in the distribution.
        min_reasons = 0 if verdict is Verdict.PASS else 1
        return make_result(
            verdict,
            rng.choice(ALL_RISKS),
            reasons=rng.sample(codes, rng.randint(min_reasons, len(codes))),
        )

    for _ in range(1000):
        a = random_result()
        b = random_result()
        combined = combine(a, b)
        assert VERDICT_ORDER[combined.verdict] >= VERDICT_ORDER[a.verdict]
        assert VERDICT_ORDER[combined.verdict] >= VERDICT_ORDER[b.verdict]
        assert RISK_ORDER[combined.risk] >= RISK_ORDER[a.risk]
        assert RISK_ORDER[combined.risk] >= RISK_ORDER[b.risk]
        # No reason is ever lost...
        assert set(combined.reason_codes) == set(a.reason_codes) | set(b.reason_codes)
        # ...and the union is order-preserving: a's codes (deduped) first,
        # then b's new codes in b's order.
        expected = list(dict.fromkeys([*a.reason_codes, *b.reason_codes]))
        assert combined.reason_codes == expected


def test_reason_union_is_deduplicated_and_order_preserving():
    a = make_result(Verdict.AUTH, Risk.medium, [ReasonCode.unknown_tool])
    b = make_result(
        Verdict.BLOCK,
        Risk.high,
        [ReasonCode.unknown_tool, ReasonCode.downstream_error],
    )
    combined = combine(a, b)
    assert combined.reason_codes == [ReasonCode.unknown_tool, ReasonCode.downstream_error]


def test_explanations_compose():
    a = make_result(Verdict.AUTH, Risk.medium)
    b = make_result(Verdict.BLOCK, Risk.high)
    combined = combine(a, b)
    assert "AUTH for testing." in combined.explanation
    assert "BLOCK for testing." in combined.explanation


def test_combined_non_pass_always_carries_reasons():
    # Inputs are valid by construction, so any non-PASS combination keeps
    # at least one reason — the model validator would reject otherwise.
    a = make_result(Verdict.PASS, Risk.low)
    b = make_result(Verdict.BLOCK, Risk.critical)
    combined = combine(a, b)
    assert combined.verdict is Verdict.BLOCK
    assert combined.reason_codes  # never an unexplained non-PASS
    assert combined.explanation.strip()


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        ((Verdict.PASS, Risk.low), (Verdict.AUTH, Risk.high), (Verdict.AUTH, Risk.high)),
        ((Verdict.BLOCK, Risk.critical), (Verdict.PASS, Risk.low), (Verdict.BLOCK, Risk.critical)),
        ((Verdict.AUTH, Risk.medium), (Verdict.AUTH, Risk.low), (Verdict.AUTH, Risk.medium)),
    ],
)
def test_thesis_repl_examples(a, b, expected):
    combined = combine(make_result(*a), make_result(*b))
    assert (combined.verdict, combined.risk) == expected
