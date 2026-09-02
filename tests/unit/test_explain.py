"""Unit tests for `doberman.explain` (decision transparency, ADR 0029).

Covers the deterministic offline template, the redaction allowlist that
defends the (optional) LLM narrator payload, and the three-way opt-in gate
(``anthropic`` installed + ``ANTHROPIC_API_KEY`` set + ``DOBERMAN_EXPLAIN_LLM``
flagged). None of this requires the real ``anthropic`` package: the LLM-path
tests inject a fake module into ``sys.modules`` so the whole file runs in the
standalone dev venv, which intentionally lacks the optional extras.

The `doberman tui` CLI guard (missing the ``textual`` extra) is tested here
too, not in ``test_tui.py``, because that file's `importorskip("textual")`
would otherwise skip the guard test in exactly the environment meant to
exercise it.
"""

import importlib.machinery
import importlib.util
import json
import sys
import types

import pytest
from typer.testing import CliRunner

from doberman.cli.main import app
from doberman.explain import (
    REDACTED_FIELDS,
    build_explanation_payload,
    explain_decision,
    explain_decision_with_source,
    llm_enrichment_enabled,
    template_explanation,
)

runner = CliRunner()


def _row(**overrides) -> dict:
    row = {
        "ts": "2026-07-07T00:00:00+00:00",
        "action_id": "act-1",
        "agent_role": "cli",
        "action_type": "shell_exec",
        "target_path_class": "*.sh",
        "risk": "critical",
        "source_context": "user",
        "final_verdict": "BLOCK",
        "decided_layer": "objective",
        "reason_codes_json": json.dumps(["destructive_command"]),
    }
    row.update(overrides)
    return row


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
        # Keyword-only mirror of the real `Anthropic().messages.create` surface:
        # if explain.py's call shape drifts, this raises TypeError (→ template
        # fallback) and the enabled-path assertions fail, instead of a permissive
        # `**kwargs` fake silently blessing a broken real call.
        assert isinstance(model, str) and model
        assert isinstance(max_tokens, int) and max_tokens > 0
        assert isinstance(system, str) and system
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


def _install_fake_anthropic(monkeypatch, responder) -> None:
    """Inject an importable fake `anthropic` module without installing anything.

    `importlib.util.find_spec` reads `__spec__` off an already-`sys.modules`-cached
    module rather than hitting the filesystem, so a bare `ModuleSpec` is enough to
    make the module "importable" for `_llm_enrichment_enabled`'s gate check.
    """
    fake_module = types.ModuleType("anthropic")
    fake_module.__spec__ = importlib.machinery.ModuleSpec("anthropic", loader=None)
    fake_module.Anthropic = lambda: _FakeAnthropicClient(responder)
    monkeypatch.setitem(sys.modules, "anthropic", fake_module)


def _never_called(_kwargs):
    raise AssertionError("the LLM must not be called when the opt-in gate is off")


# --- template_explanation ----------------------------------------------------


def test_template_explanation_for_block_row_mentions_policy_or_role_change():
    row = _row(final_verdict="BLOCK", reason_codes_json=json.dumps(["destructive_command"]))
    text = template_explanation(row)
    assert text
    assert "destructive" in text.lower()
    assert "policy" in text.lower() or "role" in text.lower()


def test_template_explanation_for_auth_row_mentions_reauth_path():
    row = _row(final_verdict="AUTH", reason_codes_json=json.dumps(["secret_exfiltration"]))
    text = template_explanation(row)
    assert text
    assert "secret" in text.lower()
    assert "authentic" in text.lower() or "elevation" in text.lower()


def test_template_explanation_names_five_minute_memory_approval():
    text = template_explanation(_row(final_verdict="AUTH", auth_result="soft_confirm+memory"))
    assert "approved via 5-minute memory" in text
    assert "soft_confirm" in text


def test_unknown_reason_code_is_humanized_not_a_keyerror():
    row = _row(reason_codes_json=json.dumps(["some_future_code"]))
    text = template_explanation(row)
    assert "some future code" in text


@pytest.mark.parametrize(
    "reason_codes_json",
    [None, "not valid json", json.dumps({"not": "a list"}), json.dumps(123)],
)
def test_malformed_reason_codes_never_raises(reason_codes_json):
    row = _row(reason_codes_json=reason_codes_json)
    text = template_explanation(row)
    assert isinstance(text, str)
    assert text


def test_explain_decision_on_empty_row_never_raises():
    text = explain_decision({})
    assert isinstance(text, str)
    assert text


def test_template_explanation_is_ascii_only():
    # cp1252-safe on Windows: no em dash or other non-ASCII punctuation, for
    # either verdict's closing sentence.
    for verdict in ("BLOCK", "AUTH", "PASS"):
        text = template_explanation(_row(final_verdict=verdict))
        assert text.isascii(), text


def test_template_explanation_decided_layer_is_plain_words_not_raw_schema():
    objective = template_explanation(_row(decided_layer="objective"))
    assert "objective guardrail layer" in objective
    combined = template_explanation(_row(decided_layer="combined"))
    assert "objective and subjective guardrail layers together" in combined
    assert "combined guardrail layer" not in combined


def test_pass_row_with_no_reason_codes_says_what_was_checked():
    row = _row(final_verdict="PASS", reason_codes_json=json.dumps([]))
    text = template_explanation(row)
    assert "no specific reason codes were recorded" not in text.lower()
    assert "checked" in text.lower()
    assert "clean" in text.lower()


def test_explain_decision_with_source_reports_template_when_disabled(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("DOBERMAN_EXPLAIN_LLM", raising=False)
    row = _row()
    text, source = explain_decision_with_source(row)
    assert source == "template"
    assert text == template_explanation(row)


def test_explain_decision_with_source_reports_llm_on_success(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setenv("DOBERMAN_EXPLAIN_LLM", "1")
    _install_fake_anthropic(monkeypatch, lambda kwargs: _FakeMessage("stubbed narrator text"))
    text, source = explain_decision_with_source(_row())
    assert (text, source) == ("stubbed narrator text", "llm")


def test_explain_decision_with_source_reports_template_on_llm_failure(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setenv("DOBERMAN_EXPLAIN_LLM", "1")

    def _boom(_kwargs):
        raise RuntimeError("network error")

    _install_fake_anthropic(monkeypatch, _boom)
    row = _row()
    text, source = explain_decision_with_source(row)
    assert source == "template"
    assert text == template_explanation(row)


def test_llm_enrichment_enabled_mirrors_the_gate(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("DOBERMAN_EXPLAIN_LLM", raising=False)
    assert llm_enrichment_enabled() is False

    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setenv("DOBERMAN_EXPLAIN_LLM", "1")
    _install_fake_anthropic(monkeypatch, _never_called)
    assert llm_enrichment_enabled() is True


# --- redaction allowlist (security) ------------------------------------------


def test_build_explanation_payload_never_leaks_a_stray_secret_key():
    secret = "SYNTHETIC-SECRET-AKIA0000TEST"  # noqa: S105 — synthetic test fixture, not a real key
    row = _row(raw_arg=secret)
    payload = build_explanation_payload(row)
    assert "raw_arg" not in payload
    assert secret not in json.dumps(payload)


def test_redacted_fields_allowlist_is_pinned():
    # Hard-coded on purpose: widening the production allowlist must fail THIS
    # test and force a human review — the constant can never bless itself.
    assert REDACTED_FIELDS == (
        "ts",
        "action_id",
        "agent_role",
        "action_type",
        "target_path_class",
        "risk",
        "source_context",
        "final_verdict",
        "decided_layer",
        "reason_codes_json",
        "auth_required",
        "auth_result",
        "elevation_id",
        "entity_id",
        "session_id",
    )


def test_build_explanation_payload_only_pulls_allowlisted_fields():
    row = _row(raw_arg="unexpected")
    payload = build_explanation_payload(row)
    assert set(payload) <= set(REDACTED_FIELDS)
    # And it genuinely projects the meaningful columns — an empty dict must fail.
    assert payload["final_verdict"] == "BLOCK"
    assert payload["decided_layer"] == "objective"
    assert payload["risk"] == "critical"
    assert payload["reason_codes_json"] == row["reason_codes_json"]


# --- LLM opt-in gate: off by default ------------------------------------------


def test_llm_gate_off_with_no_env_vars(monkeypatch):
    _install_fake_anthropic(monkeypatch, _never_called)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("DOBERMAN_EXPLAIN_LLM", raising=False)
    row = _row()
    assert explain_decision(row) == template_explanation(row)


def test_llm_gate_off_with_flag_but_no_key(monkeypatch):
    _install_fake_anthropic(monkeypatch, _never_called)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("DOBERMAN_EXPLAIN_LLM", "1")
    row = _row()
    assert explain_decision(row) == template_explanation(row)


def test_llm_gate_off_with_key_but_no_flag(monkeypatch):
    _install_fake_anthropic(monkeypatch, _never_called)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.delenv("DOBERMAN_EXPLAIN_LLM", raising=False)
    row = _row()
    assert explain_decision(row) == template_explanation(row)


def test_llm_gate_off_when_anthropic_not_importable(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setenv("DOBERMAN_EXPLAIN_LLM", "1")

    real_find_spec = importlib.util.find_spec

    def _fake_find_spec(name, *args, **kwargs):
        if name == "anthropic":
            return None
        return real_find_spec(name, *args, **kwargs)

    monkeypatch.setattr(importlib.util, "find_spec", _fake_find_spec)
    row = _row()
    assert explain_decision(row) == template_explanation(row)


# --- LLM opt-in gate: enabled path (fake anthropic, no real install) ---------


def test_llm_path_returns_stub_text_when_enabled(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setenv("DOBERMAN_EXPLAIN_LLM", "1")
    _install_fake_anthropic(monkeypatch, lambda kwargs: _FakeMessage("stubbed narrator text"))
    row = _row()
    assert explain_decision(row) == "stubbed narrator text"


def test_llm_path_falls_back_to_template_when_stub_raises(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setenv("DOBERMAN_EXPLAIN_LLM", "1")

    def _boom(_kwargs):
        raise RuntimeError("network error")

    _install_fake_anthropic(monkeypatch, _boom)
    row = _row()
    assert explain_decision(row) == template_explanation(row)


def test_llm_path_falls_back_to_template_when_stub_returns_blank_text(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setenv("DOBERMAN_EXPLAIN_LLM", "1")
    _install_fake_anthropic(monkeypatch, lambda kwargs: _FakeMessage("   "))
    row = _row()
    assert explain_decision(row) == template_explanation(row)


def test_llm_request_payload_never_contains_a_stray_secret(monkeypatch):
    # End-to-end egress check on the ENABLED path: even if a caller merged a raw
    # value onto the row, the request that reaches the SDK must not contain it,
    # and the user message must be exactly the allowlist projection.
    secret = "SYNTHETIC-SECRET-AKIA0000TEST"  # noqa: S105 — synthetic test fixture, not a real key
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setenv("DOBERMAN_EXPLAIN_LLM", "1")
    seen: dict = {}

    def _capture(kwargs):
        seen.update(kwargs)
        return _FakeMessage("ok")

    _install_fake_anthropic(monkeypatch, _capture)
    row = _row(raw_arg=secret)
    assert explain_decision(row) == "ok"
    assert secret not in json.dumps(seen, default=str)
    assert set(json.loads(seen["messages"][0]["content"])) <= set(REDACTED_FIELDS)


@pytest.mark.parametrize("flag", ["0", "false", "no", "off", "", " "])
def test_llm_gate_off_for_non_truthy_flag_values(monkeypatch, flag):
    _install_fake_anthropic(monkeypatch, _never_called)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setenv("DOBERMAN_EXPLAIN_LLM", flag)
    row = _row()
    assert explain_decision(row) == template_explanation(row)


def test_use_llm_false_forces_template_even_when_fully_enabled(monkeypatch):
    _install_fake_anthropic(monkeypatch, _never_called)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setenv("DOBERMAN_EXPLAIN_LLM", "1")
    row = _row()
    assert explain_decision(row, use_llm=False) == template_explanation(row)


def test_use_llm_true_cannot_bypass_the_env_opt_in_gate(monkeypatch):
    # `use_llm` may only restrict, never widen: True without the env flag stays
    # on the template and never touches the SDK.
    _install_fake_anthropic(monkeypatch, _never_called)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.delenv("DOBERMAN_EXPLAIN_LLM", raising=False)
    row = _row()
    assert explain_decision(row, use_llm=True) == template_explanation(row)


# --- `doberman tui` CLI guard (missing the `textual` extra) ------------------


def test_tui_command_without_textual_prints_install_hint_and_exits_1(monkeypatch):
    real_find_spec = importlib.util.find_spec

    def _fake_find_spec(name, *args, **kwargs):
        if name == "textual":
            return None
        return real_find_spec(name, *args, **kwargs)

    monkeypatch.setattr(importlib.util, "find_spec", _fake_find_spec)
    result = runner.invoke(app, ["tui"])
    assert result.exit_code == 1
    assert result.stderr.startswith("error: ")
    assert "doberman-core[tui]" in result.output


def test_tui_appears_in_help():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "tui" in result.output


def test_tui_command_with_missing_path_exits_2_before_the_textual_check(tmp_path):
    missing = tmp_path / "does-not-exist"
    result = runner.invoke(app, ["tui", "--path", str(missing)])
    assert result.exit_code == 2
    assert "does not exist" in result.output
