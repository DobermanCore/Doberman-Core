"""The narrator and the shadow judge on the named OrcaRouter provider.

Both call sites used to hard-code an Anthropic model and client. They now pick
their model and transport from the active provider while keeping the Anthropic
path byte for byte. These tests pin the new branch and the unchanged one:

* ``orcarouter``: the request goes to the pinned gateway origin, carries the
  OrcaRouter key, and names the model the user saved - never the Anthropic one;
* a provider failure still falls back exactly as before (template text for the
  narrator, abstain for the judge), because neither may raise into a caller;
* ``anthropic``: the fixed Haiku model and the ``anthropic`` client are still
  what runs, so switching providers is the only thing that changes.

No test reaches the network: the OrcaRouter transport is scripted and the
Anthropic client is an injected fake.
"""

from __future__ import annotations

import importlib.machinery
import json
import sys
import types

import pytest

from doberman.explain import explain_decision_with_source, template_explanation
from doberman.judge import HaikuJudgeAdjudicator
from doberman.models import GuardrailResult, Risk, Verdict
from doberman.providers import orcarouter as mod
from doberman.providers import set_orcarouter_model, use_provider

_KEY = "sk-orca-synthetic-seam-key"  # noqa: S105 - fixture value, not a real secret
_PASS = GuardrailResult(verdict=Verdict.PASS, risk=Risk.low)


class _Transport:
    """Records outgoing requests and replays one queued response."""

    def __init__(self, response=None, *, error=None):
        self.requests = []
        self._response = response
        self._error = error

    def __call__(self, request, timeout):
        self.requests.append(request)
        if self._error is not None:
            raise self._error
        return self._response

    @property
    def only_body(self) -> dict:
        assert len(self.requests) == 1
        return json.loads(self.requests[0].data)


def _completion(text: str) -> tuple[int, bytes]:
    return (
        200,
        json.dumps({"choices": [{"message": {"role": "assistant", "content": text}}]}).encode(),
    )


@pytest.fixture(autouse=True)
def _isolated_provider_state(tmp_path, monkeypatch):
    monkeypatch.setenv(mod.KEY_FILE_ENV, str(tmp_path / "orcarouter.key"))
    monkeypatch.setenv(mod.CATALOG_CACHE_ENV, str(tmp_path / "orcarouter-models.json"))
    monkeypatch.setenv("DOBERMAN_PROVIDER_FILE", str(tmp_path / "providers.json"))
    monkeypatch.delenv(mod.ORCAROUTER_KEY_ENV, raising=False)
    monkeypatch.delenv("DOBERMAN_LLM_PROVIDER", raising=False)
    monkeypatch.delenv("DOBERMAN_EXPLAIN_LLM", raising=False)
    monkeypatch.delenv("DOBERMAN_JUDGE_ENABLED", raising=False)
    return tmp_path


@pytest.fixture
def transport(monkeypatch):
    def _install(response=None, *, error=None):
        installed = _Transport(response, error=error)
        monkeypatch.setattr(mod, "_urllib_open", installed)
        return installed

    return _install


def _row() -> dict:
    return {
        "ts": "2026-01-01T00:00:00Z",
        "action_id": "a" * 32,
        "agent_role": "coder",
        "action_type": "shell_exec",
        "target_path_class": "outside_repo",
        "final_verdict": "BLOCK",
        "decided_layer": "objective",
        "reason_codes_json": json.dumps(["destructive_command"]),
    }


# --- narrator ----------------------------------------------------------------


def test_narrator_uses_the_gateway_origin_and_the_saved_model(monkeypatch, transport):
    monkeypatch.setenv("DOBERMAN_EXPLAIN_LLM", "1")
    mod.save_api_key(_KEY)
    set_orcarouter_model("vendor/narrator-model")
    use_provider("orcarouter")
    sent = transport(_completion("a shorter explanation"))

    text, source = explain_decision_with_source(_row())

    assert (text, source) == ("a shorter explanation", "llm")
    assert sent.requests[0].full_url == "https://api.orcarouter.ai/v1/chat/completions"
    assert sent.requests[0].get_header("Authorization") == f"Bearer {_KEY}"
    body = sent.only_body
    assert body["model"] == "vendor/narrator-model"
    # The payload is still the redacted envelope, not the raw row: the path is
    # sent as its class only, never under a raw ``target_path`` key.
    encoded = json.dumps(body)
    assert '"target_path"' not in encoded
    assert "target_path_class" in encoded
    assert body["messages"][1]["role"] == "user"


def test_narrator_never_sends_the_anthropic_model_on_orcarouter(monkeypatch, transport):
    monkeypatch.setenv("DOBERMAN_EXPLAIN_LLM", "1")
    mod.save_api_key(_KEY)
    set_orcarouter_model("vendor/narrator-model")
    use_provider("orcarouter")
    sent = transport(_completion("ok"))

    explain_decision_with_source(_row())

    assert sent.only_body["model"] != "claude-haiku-4-5-20251001"


def test_narrator_falls_back_to_the_template_when_the_gateway_fails(monkeypatch, transport):
    monkeypatch.setenv("DOBERMAN_EXPLAIN_LLM", "1")
    mod.save_api_key(_KEY)
    use_provider("orcarouter")
    transport(error=OSError("offline"))
    row = _row()

    text, source = explain_decision_with_source(row)

    assert source == "template"
    assert text == template_explanation(row)


def test_narrator_gate_is_off_without_an_orcarouter_key(monkeypatch, transport):
    monkeypatch.setenv("DOBERMAN_EXPLAIN_LLM", "1")
    use_provider("orcarouter")
    sent = transport(_completion("should not be reached"))

    text, source = explain_decision_with_source(_row())

    assert source == "template"
    assert sent.requests == []


def test_narrator_gate_still_needs_the_explicit_opt_in(transport, monkeypatch):
    mod.save_api_key(_KEY)
    use_provider("orcarouter")
    sent = transport(_completion("should not be reached"))

    assert explain_decision_with_source(_row())[1] == "template"
    assert sent.requests == []

    monkeypatch.setenv("DOBERMAN_EXPLAIN_LLM", "1")
    assert explain_decision_with_source(_row())[1] == "llm"
    assert len(sent.requests) == 1


# --- shadow judge ------------------------------------------------------------


class _FakeMessage:
    def __init__(self, text: str) -> None:
        self.content = [types.SimpleNamespace(type="text", text=text)]
        self.usage = types.SimpleNamespace(
            input_tokens=10, output_tokens=5, cache_read_input_tokens=0
        )


class _FakeMessages:
    def __init__(self, responder) -> None:
        self._responder = responder

    def create(self, **kwargs):
        return self._responder(kwargs)


class _FakeAnthropicClient:
    def __init__(self, responder) -> None:
        self.messages = _FakeMessages(responder)


def _install_fake_anthropic(monkeypatch, responder, *, constructed: list | None = None):
    module = types.ModuleType("anthropic")
    module.__spec__ = importlib.machinery.ModuleSpec("anthropic", loader=None)

    def _ctor():
        if constructed is not None:
            constructed.append(True)
        return _FakeAnthropicClient(responder)

    module.Anthropic = _ctor
    monkeypatch.setitem(sys.modules, "anthropic", module)


def test_judge_uses_the_gateway_origin_and_the_saved_model(monkeypatch, transport):
    mod.save_api_key(_KEY)
    set_orcarouter_model("vendor/judge-model")
    use_provider("orcarouter")
    monkeypatch.setenv("DOBERMAN_JUDGE_ENABLED", "1")
    sent = transport(_completion(json.dumps({"unambiguous": True, "high_impact": True})))

    result = HaikuJudgeAdjudicator().adjudicate({"action_type": "file_read"}, _PASS)

    assert result is not None
    assert result.risk is Risk.critical
    assert sent.requests[0].full_url == "https://api.orcarouter.ai/v1/chat/completions"
    assert sent.only_body["model"] == "vendor/judge-model"


def test_judge_abstains_when_the_gateway_fails(monkeypatch, transport):
    mod.save_api_key(_KEY)
    use_provider("orcarouter")
    monkeypatch.setenv("DOBERMAN_JUDGE_ENABLED", "1")
    transport(error=OSError("offline"))

    assert HaikuJudgeAdjudicator().adjudicate({"action_type": "file_read"}, _PASS) is None


def test_judge_stays_off_without_an_orcarouter_key(monkeypatch, transport):
    use_provider("orcarouter")
    monkeypatch.setenv("DOBERMAN_JUDGE_ENABLED", "1")
    sent = transport(_completion(json.dumps({"unambiguous": True, "high_impact": True})))

    assert HaikuJudgeAdjudicator().adjudicate({"action_type": "file_read"}, _PASS) is None
    assert sent.requests == []


# --- the unchanged default ----------------------------------------------------


def test_anthropic_judge_still_calls_the_fixed_haiku_model(monkeypatch):
    seen: list[dict] = []
    _install_fake_anthropic(
        monkeypatch,
        lambda kwargs: seen.append(kwargs) or _FakeMessage(json.dumps({"unambiguous": False})),
    )
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setenv("DOBERMAN_JUDGE_ENABLED", "1")
    use_provider("anthropic")

    HaikuJudgeAdjudicator().adjudicate({"action_type": "file_read"}, _PASS)

    assert seen[0]["model"] == "claude-haiku-4-5-20251001"


def test_anthropic_narrator_still_calls_the_fixed_haiku_model(monkeypatch):
    seen: list[dict] = []
    _install_fake_anthropic(
        monkeypatch, lambda kwargs: seen.append(kwargs) or _FakeMessage("template-ish text")
    )
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setenv("DOBERMAN_EXPLAIN_LLM", "1")
    use_provider("anthropic")

    text, source = explain_decision_with_source(_row())

    assert (text, source) == ("template-ish text", "llm")
    assert seen[0]["model"] == "claude-haiku-4-5-20251001"


def test_switching_providers_does_not_touch_the_anthropic_default(monkeypatch):
    from doberman.providers import anthropic_model

    use_provider("orcarouter")

    assert anthropic_model() == "claude-haiku-4-5-20251001"
