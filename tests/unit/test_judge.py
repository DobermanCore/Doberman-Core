"""Unit tests for `doberman.judge` (C15 v1 — offline, measurement-only judge).

Mirrors `tests/unit/test_explain.py`'s pattern exactly: no test here requires the
real `anthropic` package or a network call. LLM-path tests inject a fake module
into `sys.modules` so the whole file runs in a standalone dev venv lacking the
optional `[judge]` extra.
"""

import importlib.machinery
import itertools
import json
import sys
import threading
import time
import types
from datetime import datetime, timezone

import pytest

from doberman.engine.adjudicator import Adjudicator, redacted_features
from doberman.judge import HaikuJudgeAdjudicator, _recommend, judge_enabled
from doberman.models import (
    RISK_ORDER,
    VERDICT_ORDER,
    ActionType,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    SourceContext,
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


@pytest.mark.parametrize(
    "response_text",
    [
        "not json at all",
        json.dumps({"unambiguous": True}),  # missing high_impact
        json.dumps({"high_impact": False}),  # missing unambiguous
        json.dumps({"unambiguous": "yes", "high_impact": False}),  # wrong type
        json.dumps({"unambiguous": True, "high_impact": 1}),  # wrong type
        "",  # empty
        json.dumps([True, False]),  # not an object
    ],
)
def test_malformed_response_abstains_never_raises(monkeypatch, response_text):
    _install_fake_anthropic(monkeypatch, lambda kwargs: _FakeMessage(response_text))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setenv("DOBERMAN_JUDGE_ENABLED", "1")
    judge = HaikuJudgeAdjudicator()
    result = judge.adjudicate({"action_type": "file_read"}, _PASS)
    assert result is None


def test_client_raising_abstains(monkeypatch):
    def _boom(_kwargs):
        raise RuntimeError("network error")

    _install_fake_anthropic(monkeypatch, _boom)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setenv("DOBERMAN_JUDGE_ENABLED", "1")
    judge = HaikuJudgeAdjudicator()
    result = judge.adjudicate({"action_type": "file_read"}, _PASS)
    assert result is None


def test_valid_response_maps_to_a_recommendation(monkeypatch):
    _install_fake_anthropic(
        monkeypatch,
        lambda kwargs: _FakeMessage(json.dumps({"unambiguous": True, "high_impact": False})),
    )
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setenv("DOBERMAN_JUDGE_ENABLED", "1")
    judge = HaikuJudgeAdjudicator()
    result = judge.adjudicate({"action_type": "file_read"}, _PASS)
    assert result == _recommend(True, False, _PASS)


def test_hard_timeout_returns_none_within_bound(monkeypatch):
    import doberman.judge as judge_module

    monkeypatch.setattr(judge_module, "_JUDGE_TIMEOUT_S", 0.05)

    def _slow(_kwargs):
        time.sleep(0.3)
        return _FakeMessage(json.dumps({"unambiguous": True, "high_impact": False}))

    _install_fake_anthropic(monkeypatch, _slow)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setenv("DOBERMAN_JUDGE_ENABLED", "1")
    judge = HaikuJudgeAdjudicator()
    start = time.monotonic()
    result = judge.adjudicate({"action_type": "file_read"}, _PASS)
    elapsed = time.monotonic() - start
    assert result is None
    assert elapsed < 0.2  # well under the fake client's 0.3s block


def test_timed_out_worker_is_a_daemon_thread(monkeypatch):
    """Review finding: a non-daemon worker left running past the timeout would
    be joined by CPython's `_python_exit` atexit hook, blocking interpreter
    exit on a hung connection and leaking one non-daemon thread per timed-out
    call. The worker must be a daemon thread named "doberman-judge" so it
    never blocks exit - and `adjudicate` itself must still return within
    `_JUDGE_TIMEOUT_S` regardless of how long the underlying call keeps
    running.
    """
    import doberman.judge as judge_module

    monkeypatch.setattr(judge_module, "_JUDGE_TIMEOUT_S", 0.05)

    release = threading.Event()

    def _slow(_kwargs):
        release.wait(timeout=2)  # held open past the timeout on purpose
        return _FakeMessage(json.dumps({"unambiguous": True, "high_impact": False}))

    _install_fake_anthropic(monkeypatch, _slow)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setenv("DOBERMAN_JUDGE_ENABLED", "1")

    judge = HaikuJudgeAdjudicator()
    start = time.monotonic()
    result = judge.adjudicate({"action_type": "file_read"}, _PASS)
    elapsed = time.monotonic() - start

    try:
        assert result is None
        assert elapsed < 0.5  # bounded by _JUDGE_TIMEOUT_S, not the 2s release wait

        judge_threads = [t for t in threading.enumerate() if t.name == "doberman-judge"]
        assert judge_threads, "expected the timed-out judge worker to still be alive"
        assert all(t.daemon for t in judge_threads), "judge worker must be a daemon thread"
    finally:
        release.set()  # let the worker finish so it doesn't leak into other tests
        for t in threading.enumerate():
            if t.name == "doberman-judge":
                t.join(timeout=2)


def test_judge_request_never_leaks_beyond_redacted_features(monkeypatch):
    secret = "SYNTHETIC-SECRET-AKIA0000TEST"  # noqa: S105 - synthetic fixture, not a real key
    action = SecurityObject(
        id="t1",
        ts=datetime(2026, 1, 1, tzinfo=timezone.utc),
        agent_role="cli",
        action_type=ActionType.file_read,
        tool_name="cat",
        target="/etc/secrets/prod.key",
        external_destination="evil.example.com",
        source_context=SourceContext.user,
    )
    # The secret rides only in `current.explanation` here, on purpose: this proves
    # the judge sends `features` alone and never touches `current` for the payload,
    # even though `current` is a required Protocol argument.
    current = GuardrailResult(
        verdict=Verdict.AUTH,
        risk=Risk.high,
        reason_codes=[ReasonCode.sensitive_secret_access],
        explanation=f"leaked if forwarded: {secret}",
    )
    features = redacted_features(action, current)

    seen: dict = {}

    def _capture(kwargs):
        seen.update(kwargs)
        return _FakeMessage(json.dumps({"unambiguous": True, "high_impact": False}))

    _install_fake_anthropic(monkeypatch, _capture)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setenv("DOBERMAN_JUDGE_ENABLED", "1")

    judge = HaikuJudgeAdjudicator()
    result = judge.adjudicate(features, current)

    assert result is not None
    sent = json.dumps(seen, default=str)
    assert secret not in sent
    assert "/etc/secrets/prod.key" not in sent
    assert "evil.example.com" not in sent
    payload_keys = set(json.loads(seen["messages"][0]["content"]))
    assert payload_keys <= set(features.keys())
