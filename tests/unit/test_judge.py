"""Unit tests for `doberman.judge` (C15 v1 — offline, measurement-only judge).

Mirrors `tests/unit/test_explain.py`'s pattern exactly: no test here requires the
real `anthropic` package or a network call. LLM-path tests inject a fake module
into `sys.modules` so the whole file runs in a standalone dev venv lacking the
optional `[judge]` extra.
"""

import importlib.machinery
import importlib.util
import itertools
import sys
import types

import pytest

from doberman.engine.adjudicator import Adjudicator
from doberman.judge import HaikuJudgeAdjudicator, _recommend, judge_enabled
from doberman.models import (
    RISK_ORDER,
    VERDICT_ORDER,
    GuardrailResult,
    ReasonCode,
    Risk,
    Verdict,
)

_PASS = GuardrailResult(verdict=Verdict.PASS, risk=Risk.low)

_ALL_VERDICTS = (Verdict.PASS, Verdict.AUTH, Verdict.BLOCK)
_ALL_RISKS = (Risk.low, Risk.medium, Risk.high, Risk.critical)
_ALL_BOOL_PAIRS = ((True, True), (True, False), (False, True), (False, False))


def _make_current(verdict: Verdict, risk: Risk) -> GuardrailResult:
    """A valid `GuardrailResult` for every (verdict, risk) combination —
    non-PASS verdicts need a reason code + explanation (model validator)."""
    if verdict is Verdict.PASS:
        return GuardrailResult(verdict=verdict, risk=risk)
    return GuardrailResult(
        verdict=verdict,
        risk=risk,
        reason_codes=[ReasonCode.unclassified_action],
        explanation="pre-existing deterministic verdict",
    )


@pytest.mark.parametrize(
    ("unambiguous", "high_impact", "expected_risk", "expected_verdict", "expect_raise"),
    [
        # C6 spec (defenseclaw-derived-security-candidates-c1-c8-spec.md:139):
        # TT->CRITICAL, TF->HIGH, FT->MEDIUM, FF->LOW — EXHAUSTIVE, never None.
        (True, True, Risk.critical, Verdict.AUTH, True),
        (True, False, Risk.high, Verdict.AUTH, True),
        (False, True, Risk.medium, Verdict.PASS, True),
        (False, False, Risk.low, Verdict.PASS, False),
    ],
)
def test_recommend_maps_all_four_boolean_combinations_exhaustively(
    unambiguous, high_impact, expected_risk, expected_verdict, expect_raise
):
    """The mapping never abstains on a valid boolean pair (unlike the old
    ambiguous->None shape) and is applied raise-only against a PASS/low
    `current`: a mapped risk of high/critical also raises the verdict to
    AUTH; medium/low never raise the verdict past whatever `current` had."""
    result = _recommend(unambiguous, high_impact, _PASS)
    assert result.risk == expected_risk
    assert result.verdict == expected_verdict
    if expect_raise:
        assert result.reason_codes == [ReasonCode.unclassified_action]
        assert result.explanation.strip()
    else:
        # nothing raised relative to `current` -> current's own reason
        # codes/explanation are carried through unchanged, not replaced.
        assert result.reason_codes == _PASS.reason_codes
        assert result.explanation == _PASS.explanation


@pytest.mark.parametrize(("unambiguous", "high_impact"), _ALL_BOOL_PAIRS)
@pytest.mark.parametrize(("verdict", "risk"), list(itertools.product(_ALL_VERDICTS, _ALL_RISKS)))
def test_recommend_never_lowers_current_on_either_axis(verdict, risk, unambiguous, high_impact):
    """Raise-only property (C6 spec): for every (unambiguous, high_impact)
    pair and every possible `current` verdict/risk, `_recommend` never
    returns a risk or verdict lower than `current`'s."""
    current = _make_current(verdict, risk)
    result = _recommend(unambiguous, high_impact, current)
    assert RISK_ORDER[result.risk] >= RISK_ORDER[risk]
    assert VERDICT_ORDER[result.verdict] >= VERDICT_ORDER[verdict]


def test_haiku_judge_adjudicator_is_structurally_an_adjudicator():
    assert isinstance(HaikuJudgeAdjudicator(), Adjudicator)


class _TextBlock:
    def __init__(self, text: str) -> None:
        self.type = "text"
        self.text = text


class _FakeMessage:
    def __init__(self, text: str) -> None:
        self.content = [_TextBlock(text)]


class _FakeMessagesAPI:
    def __init__(self, responder) -> None:
        self._responder = responder

    def create(self, *, model, max_tokens, timeout, system, messages):
        assert isinstance(model, str) and model
        assert isinstance(max_tokens, int) and max_tokens > 0
        assert isinstance(system, list) and len(system) == 1
        assert system[0]["type"] == "text"
        assert system[0]["cache_control"] == {"type": "ephemeral"}
        assert isinstance(messages, list) and len(messages) == 1
        assert messages[0]["role"] == "user"
        return self._responder(
            {
                "model": model,
                "max_tokens": max_tokens,
                "timeout": timeout,
                "system": system,
                "messages": messages,
            }
        )


class _FakeAnthropicClient:
    def __init__(self, responder) -> None:
        self.messages = _FakeMessagesAPI(responder)


def _install_fake_anthropic(monkeypatch, responder, *, constructed: list | None = None):
    """Inject an importable fake `anthropic` module (mirrors test_explain.py)."""
    fake_module = types.ModuleType("anthropic")
    fake_module.__spec__ = importlib.machinery.ModuleSpec("anthropic", loader=None)

    def _ctor():
        if constructed is not None:
            constructed.append(True)
        return _FakeAnthropicClient(responder)

    fake_module.Anthropic = _ctor
    monkeypatch.setitem(sys.modules, "anthropic", fake_module)


def _never_called(_kwargs):
    raise AssertionError("the judge must not be called when the opt-in gate is off")


def test_env_gate_off_makes_zero_network_calls(monkeypatch):
    constructed: list = []
    _install_fake_anthropic(monkeypatch, _never_called, constructed=constructed)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.delenv("DOBERMAN_JUDGE_ENABLED", raising=False)
    judge = HaikuJudgeAdjudicator()
    result = judge.adjudicate({"action_type": "file_read"}, _PASS)
    assert result is None
    assert constructed == []


def test_judge_enabled_mirrors_the_gate(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("DOBERMAN_JUDGE_ENABLED", raising=False)
    assert judge_enabled() is False
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setenv("DOBERMAN_JUDGE_ENABLED", "1")
    _install_fake_anthropic(monkeypatch, _never_called)
    assert judge_enabled() is True
