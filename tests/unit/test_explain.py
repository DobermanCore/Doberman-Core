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
    headline,
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


# --- round 7: an absent/"unknown" agent_role never renders literally ---------


def test_missing_agent_role_renders_as_an_agent():
    row = _row(agent_role=None)
    text = template_explanation(row)
    assert text.startswith("an agent attempted ")


def test_agent_role_literally_unknown_renders_as_an_agent_not_the_word_unknown():
    # "unknown" is a real (not merely absent) SourceContext/agent_role value on
    # some rows - rendering it literally used to read as "unknown attempted
    # shell_exec.", which looks like a bug rather than a deliberate "we don't
    # know" statement.
    row = _row(agent_role="unknown")
    text = template_explanation(row)
    assert text.startswith("an agent attempted ")
    assert "unknown attempted" not in text


# --- round 5: the layer sentence is plain words, not jargon -------------------


def test_layer_sentence_is_plain_words_for_objective_only():
    row = _row(final_verdict="BLOCK", decided_layer="objective")
    text = template_explanation(row)
    assert "Doberman decided BLOCK after checking the rules." in text
    assert "guardrail layer" not in text


def test_layer_sentence_names_the_behaviour_baseline_when_combined():
    row = _row(final_verdict="BLOCK", decided_layer="combined")
    text = template_explanation(row)
    assert "Doberman decided BLOCK after checking the rules and the behaviour baseline." in text


def test_layer_sentence_defaults_to_objective_when_missing():
    row = _row(final_verdict="AUTH", decided_layer=None)
    text = template_explanation(row)
    assert "Doberman decided AUTH after checking the rules." in text


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


def test_every_reason_code_has_a_gloss():
    """Gloss coverage 58/58 - every `ReasonCode` value must have a plain-English
    description in `REASON_DESCRIPTIONS`, not just fall back to a humanized
    form of the code itself (the fallback is a safety net, not a target)."""
    from doberman.explain import _MISSING_REASON_DESCRIPTIONS

    assert _MISSING_REASON_DESCRIPTIONS == set()


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


# --- round 6: with_reasons=False for the dash feed body ----------------------


def test_with_reasons_true_by_default_states_the_reason_codes():
    row = _row(reason_codes_json=json.dumps(["destructive_command"]))
    text = template_explanation(row)
    assert "Reasons:" in text
    assert "destructive" in text.lower()


def test_with_reasons_false_omits_the_reasons_clause():
    row = _row(reason_codes_json=json.dumps(["destructive_command"]))
    text = template_explanation(row, with_reasons=False)
    assert "Reasons:" not in text
    assert "destructive" not in text.lower()
    # The rest of the sentence (what/verdict) is unaffected.
    assert "Doberman decided BLOCK" in text


def test_with_reasons_false_omits_the_no_codes_fallback_too():
    row = _row(reason_codes_json=json.dumps([]))
    text = template_explanation(row, with_reasons=False)
    assert "No specific reason codes" not in text


# --- round 6: headline() - a short, reason-first fragment --------------------


@pytest.mark.parametrize(
    ("reason_codes_json", "expected_substrings"),
    [
        (json.dumps(["destructive_command"]), ["Recursive delete", "blocked", "shell_exec"]),
        (json.dumps(["sensitive_secret_access"]), ["Secret file read", "blocked"]),
        (json.dumps(["unknown_external_destination"]), ["External upload"]),
        (json.dumps(["secret_exfiltration"]), ["Secret exfiltration attempt"]),
        (json.dumps(["bulk_operation"]), ["Bulk operation"]),
        (json.dumps(["lethal_trifecta"]), ["Lethal-trifecta pattern"]),
    ],
)
def test_headline_is_reason_first_for_representative_codes(reason_codes_json, expected_substrings):
    row = _row(reason_codes_json=reason_codes_json)
    text = headline(row)
    for substring in expected_substrings:
        assert substring in text


def test_headline_uses_target_path_class_for_path_focused_codes():
    row = _row(
        reason_codes_json=json.dumps(["sensitive_secret_access"]),
        action_type="file_read",
        target_path_class=".env",
    )
    text = headline(row)
    assert ".env class" in text
    assert "blocked" in text


def test_headline_falls_back_to_action_type_when_no_path_focus():
    row = _row(
        reason_codes_json=json.dumps(["destructive_command"]),
        action_type="shell_exec",
        target_path_class=None,
    )
    text = headline(row)
    assert text.endswith("shell_exec")


def test_headline_uses_needs_approval_for_auth_verdict():
    row = _row(final_verdict="AUTH", reason_codes_json=json.dumps(["unknown_external_destination"]))
    text = headline(row)
    assert "needs approval" in text


def test_headline_falls_back_gracefully_with_no_reason_codes():
    row = _row(reason_codes_json=json.dumps([]))
    text = headline(row)
    assert text
    assert "blocked" in text


def test_headline_never_crashes_on_an_empty_row():
    text = headline({})
    assert isinstance(text, str)
    assert text


def test_headline_distinguishes_otherwise_identical_block_rows():
    """The whole point: eight BLOCKs with different reasons must not collapse
    to the same headline - two different reason codes must produce two
    different headlines even with the same verdict/action type."""
    base = {"final_verdict": "BLOCK", "action_type": "shell_exec"}
    a = headline(_row(**base, reason_codes_json=json.dumps(["destructive_command"])))
    b = headline(_row(**base, reason_codes_json=json.dumps(["bulk_operation"])))
    assert a != b


@pytest.mark.parametrize(
    "reason_codes_json",
    [
        json.dumps(["destructive_command"]),
        json.dumps(["sensitive_secret_access"]),
        json.dumps(["unknown_external_destination"]),
        json.dumps(["multi_step_exfil"]),
        json.dumps(["lethal_trifecta", "bulk_operation"]),
        json.dumps([]),
    ],
)
def test_headline_stays_at_or_under_nine_words(reason_codes_json):
    row = _row(reason_codes_json=reason_codes_json, target_path_class=".env")
    text = headline(row)
    assert len(text.split()) <= 9


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
