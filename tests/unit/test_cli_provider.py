"""CLI controls for the named provider (``doberman provider ...``).

These tests pin the shell contract around the provider chosen for the optional
LLM narrator and the shadow judge:

* the key is only ever written to its per-user file - ``status`` reports the
  source, never the value or a fragment of it;
* ``models`` lists exactly the IDs the live catalog returned, and labels the
  degraded sources instead of inventing a list;
* ``use`` persists the choice and refuses an unknown name;
* the Anthropic default is untouched when nothing is selected.

The transport is scripted, so no test reaches the network.
"""

from __future__ import annotations

import json
import os

import pytest
from typer.testing import CliRunner

from doberman.cli.main import app
from doberman.providers import active_provider_name, orcarouter_model, set_orcarouter_model
from doberman.providers import orcarouter as mod

runner = CliRunner()

_KEY = "sk-orca-synthetic-cli-key"  # noqa: S105 - fixture value, not a real secret


class _Opener:
    def __init__(self, *responses):
        self.requests = []
        self._responses = list(responses)

    def __call__(self, request, timeout):
        self.requests.append(request)
        if not self._responses:
            raise AssertionError("unexpected extra request")
        response = self._responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response

    @property
    def urls(self):
        return [request.full_url for request in self.requests]


def _entry(model_id, *, endpoints=("openai",), modalities=("text",), name=None):
    entry = {"id": model_id, "supported_endpoint_types": list(endpoints)}
    if modalities:
        entry["architecture"] = {"input_modalities": list(modalities)}
    if name:
        entry["name"] = name
    return entry


def _catalog(*entries):
    return (200, json.dumps({"data": list(entries)}).encode())


@pytest.fixture(autouse=True)
def _isolated_provider_state(tmp_path, monkeypatch):
    monkeypatch.setenv(mod.KEY_FILE_ENV, str(tmp_path / "orcarouter.key"))
    monkeypatch.setenv(mod.CATALOG_CACHE_ENV, str(tmp_path / "orcarouter-models.json"))
    monkeypatch.setenv("DOBERMAN_PROVIDER_FILE", str(tmp_path / "providers.json"))
    monkeypatch.delenv(mod.ORCAROUTER_KEY_ENV, raising=False)
    monkeypatch.delenv("DOBERMAN_LLM_PROVIDER", raising=False)
    return tmp_path


@pytest.fixture
def opener(monkeypatch):
    def _install(*responses):
        transport = _Opener(*responses)
        monkeypatch.setattr(mod, "_urllib_open", transport)
        return transport

    return _install


# --- status ------------------------------------------------------------------


def test_status_reports_the_unchanged_anthropic_default():
    result = runner.invoke(app, ["provider", "status"])

    assert result.exit_code == 0, result.output
    assert "Active provider: anthropic" in result.output
    assert "https://api.orcarouter.ai/v1" in result.output
    assert "key source: none" in result.output


def test_status_never_prints_the_key_or_a_fragment(tmp_path):
    mod.save_api_key(_KEY)
    result = runner.invoke(app, ["provider", "status"])

    assert result.exit_code == 0, result.output
    assert _KEY not in result.output
    assert _KEY[:12] not in result.output
    assert "key source: file" in result.output


def test_status_names_the_environment_override(monkeypatch):
    monkeypatch.setenv("DOBERMAN_LLM_PROVIDER", "orcarouter")
    result = runner.invoke(app, ["provider", "status"])

    assert result.exit_code == 0, result.output
    assert "Active provider: orcarouter" in result.output
    assert "DOBERMAN_LLM_PROVIDER is set" in result.output


# --- use ---------------------------------------------------------------------


def test_use_persists_the_selection():
    result = runner.invoke(app, ["provider", "use", "orcarouter"])

    assert result.exit_code == 0, result.output
    assert active_provider_name() == "orcarouter"


def test_use_rejects_an_unknown_name_and_keeps_the_default():
    result = runner.invoke(app, ["provider", "use", "some-other-gateway"])

    assert result.exit_code == 1
    assert active_provider_name() == "anthropic"


# --- set-key / clear-key -----------------------------------------------------


def test_set_key_from_stdin_writes_a_private_file_and_does_not_echo(tmp_path):
    result = runner.invoke(app, ["provider", "set-key", "--stdin"], input=f"{_KEY}\n")

    assert result.exit_code == 0, result.output
    assert _KEY not in result.output
    key_file = tmp_path / "orcarouter.key"
    assert key_file.read_text().strip() == _KEY
    assert oct(key_file.stat().st_mode & 0o777) == "0o600"


def test_set_key_rejects_a_misshaped_value_without_echoing_it(tmp_path):
    result = runner.invoke(app, ["provider", "set-key", "--stdin"], input="not-a-key\n")

    assert result.exit_code == 1
    assert "not-a-key" not in result.output
    assert not (tmp_path / "orcarouter.key").exists()


def test_clear_key_reports_both_states(tmp_path):
    first = runner.invoke(app, ["provider", "clear-key"])
    assert first.exit_code == 0, first.output
    assert "No stored OrcaRouter key" in first.output

    mod.save_api_key(_KEY)
    second = runner.invoke(app, ["provider", "clear-key"])
    assert second.exit_code == 0, second.output
    assert "removed" in second.output
    assert not (tmp_path / "orcarouter.key").exists()


def test_clear_key_leaves_an_environment_key_alone(monkeypatch):
    monkeypatch.setenv(mod.ORCAROUTER_KEY_ENV, _KEY)
    result = runner.invoke(app, ["provider", "clear-key"])

    assert result.exit_code == 0, result.output
    assert "still set in the environment" in result.output
    assert os.environ[mod.ORCAROUTER_KEY_ENV] == _KEY


# --- models ------------------------------------------------------------------


def test_models_prints_the_live_catalog_verbatim(opener):
    transport = opener(_catalog(_entry("zeta/model"), _entry("alpha/model")))

    result = runner.invoke(app, ["provider", "models"])

    assert result.exit_code == 0, result.output
    assert "catalog: live" in result.output
    assert result.output.index("alpha/model") < result.output.index("zeta/model")
    assert transport.urls == ["https://api.orcarouter.ai/v1/models?capability=chat"]


def test_models_marks_the_saved_model_and_only_catalog_ids(opener):
    mod.save_api_key(_KEY)
    set_orcarouter_model("vendor/chosen")
    opener(_catalog(_entry("vendor/chosen"), _entry("vendor/other")))

    result = runner.invoke(app, ["provider", "models"])

    assert result.exit_code == 0, result.output
    marked = [line for line in result.output.splitlines() if line.strip().startswith("*")]
    assert marked == [" * vendor/chosen"]


def test_models_does_not_mark_a_saved_model_the_catalog_dropped(opener):
    mod.save_api_key(_KEY)
    set_orcarouter_model("vendor/gone")
    opener(_catalog(_entry("vendor/current")))

    result = runner.invoke(app, ["provider", "models"])

    assert result.exit_code == 0, result.output
    assert "vendor/current" in result.output
    assert "vendor/gone" not in result.output
    assert not [line for line in result.output.splitlines() if line.strip().startswith("*")]


def test_models_labels_a_degraded_catalog(opener):
    import urllib.error

    opener(urllib.error.URLError("offline"))

    result = runner.invoke(app, ["provider", "models"])

    assert result.exit_code == 0, result.output
    assert "degraded" in result.output
    seed_ids = {model.id for model in mod.SEED_MODELS}
    listed = {
        line.strip().lstrip("* ").strip()
        for line in result.output.splitlines()
        if "/" in line and not line.startswith(("catalog:", "reason:"))
    }
    assert listed <= seed_ids


def test_models_json_is_the_catalog_payload(opener):
    opener(_catalog(_entry("vendor/a", modalities=("text", "image"), name="A")))

    result = runner.invoke(app, ["provider", "models", "--capability", "chat", "--json"])

    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["capability"] == "chat"
    assert data["source"] == "live"
    assert [model["id"] for model in data["models"]] == ["vendor/a"]
    assert data["models"][0]["input_modalities"] == ["text", "image"]


def test_models_image_modality_narrows_the_list(opener):
    transport = opener(
        _catalog(_entry("vendor/vision", modalities=("text", "image")), _entry("vendor/text"))
    )

    result = runner.invoke(app, ["provider", "models", "--modality", "image"])

    assert result.exit_code == 0, result.output
    assert transport.urls == ["https://api.orcarouter.ai/v1/models?capability=chat"]
    assert "vendor/vision" in result.output
    assert "vendor/text" not in result.output


def test_models_rejects_an_unknown_capability_before_any_request(opener):
    transport = opener()

    result = runner.invoke(app, ["provider", "models", "--capability", "telepathy"])

    assert result.exit_code == 1
    assert "telepathy" in result.output
    assert transport.requests == []


def test_models_after_an_auth_failure_is_labeled_and_scrubbed(opener):
    mod.save_api_key(_KEY)
    opener((401, json.dumps({"error": {"message": f"bad key {_KEY}"}}).encode()))

    result = runner.invoke(app, ["provider", "models"])

    assert result.exit_code == 0, result.output
    assert "degraded" in result.output
    assert "rejected the key" in result.output
    assert _KEY not in result.output


# --- regression: the default path is untouched --------------------------------


def test_selecting_orcarouter_does_not_move_the_fixed_anthropic_model():
    from doberman.providers import anthropic_model

    before = anthropic_model()
    runner.invoke(app, ["provider", "use", "orcarouter"])

    assert anthropic_model() == before == "claude-haiku-4-5-20251001"


def test_orcarouter_model_default_is_the_documented_fallback():
    assert orcarouter_model() == mod.FALLBACK_MODEL
