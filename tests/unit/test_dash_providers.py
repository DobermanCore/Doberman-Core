"""Unit tests for the dashboard's ``/api/providers`` surface (D7).

The route is the browser's only path to the named OrcaRouter provider: it
reports which provider is active, stores/clears that provider's own API key,
and returns the model catalog the gateway's ``GET /v1/models`` just produced.
The provider is injected with a scripted transport, so every test here is
hermetic and asserts against small synthetic catalog shapes.

Invariants pinned by this file:

* the key never comes back in a response - success, validation error, or
  upstream error (the upstream echoes it on purpose in one test);
* model options come from the catalog response, not from a hand-written list
  in the shell;
* a degraded catalog is labeled as such, and the image filter really narrows
  the list server-side;
* the Anthropic path stays untouched (same default, same fixed model).
"""

from __future__ import annotations

import json
import urllib.error

import pytest
from starlette.testclient import TestClient

from doberman.dash.app import create_app
from doberman.providers import active_provider_name, orcarouter_model
from doberman.providers import orcarouter as mod
from doberman.providers.orcarouter import OrcaRouterProvider

_TOKEN = "test-dash-token-0123456789"  # noqa: S105 - fixture value, not a real secret
_KEY = "sk-orca-synthetic-dashboard-key"  # noqa: S105 - fixture value, not a real secret


class _Opener:
    """A scripted transport: records requests, replays queued responses."""

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
    def urls(self) -> list[str]:
        return [request.full_url for request in self.requests]


def _entry(model_id, *, endpoints=("openai",), modalities=("text",), name=None):
    entry = {"id": model_id, "supported_endpoint_types": list(endpoints)}
    if modalities:
        entry["architecture"] = {"input_modalities": list(modalities)}
    if name:
        entry["name"] = name
    return entry


def _catalog(*entries) -> tuple[int, bytes]:
    return (200, json.dumps({"data": list(entries)}).encode())


def _make(tmp_path, *responses) -> tuple[TestClient, _Opener]:
    opener = _Opener(*responses)
    app = create_app(_TOKEN, str(tmp_path), provider=OrcaRouterProvider(opener=opener))
    return TestClient(app), opener


def _headers() -> dict:
    return {"Authorization": f"Bearer {_TOKEN}"}


@pytest.fixture(autouse=True)
def _isolated_provider_state(tmp_path, monkeypatch):
    """Per-test key file, catalog cache and provider settings file."""
    monkeypatch.setenv(mod.KEY_FILE_ENV, str(tmp_path / "orcarouter.key"))
    monkeypatch.setenv(mod.CATALOG_CACHE_ENV, str(tmp_path / "orcarouter-models.json"))
    monkeypatch.setenv("DOBERMAN_PROVIDER_FILE", str(tmp_path / "providers.json"))
    monkeypatch.delenv(mod.ORCAROUTER_KEY_ENV, raising=False)
    monkeypatch.delenv("DOBERMAN_LLM_PROVIDER", raising=False)
    return tmp_path


# --- auth --------------------------------------------------------------------


def test_get_without_token_is_401(tmp_path):
    client, _ = _make(tmp_path)
    assert client.get("/api/providers").status_code == 401


def test_post_without_token_is_401(tmp_path):
    client, _ = _make(tmp_path)
    assert client.post("/api/providers", json={"action": "clear_key"}).status_code == 401


def test_post_with_wrong_token_is_401(tmp_path):
    client, _ = _make(tmp_path)
    resp = client.post(
        "/api/providers",
        headers={"Authorization": "Bearer wrong"},
        json={"action": "clear_key"},
    )
    assert resp.status_code == 401


def test_an_unauthorized_get_does_not_touch_the_catalog(tmp_path):
    client, opener = _make(tmp_path, _catalog(_entry("vendor/a")))
    client.get("/api/providers")
    assert opener.requests == []


# --- GET: provider status + catalog -----------------------------------------


def test_get_reports_the_active_provider_and_both_named_providers(tmp_path):
    client, _ = _make(tmp_path, _catalog(_entry("vendor/a")))
    data = client.get("/api/providers", headers=_headers()).json()

    assert data["active"] == "anthropic"
    assert data["env_override"] is False
    assert [provider["name"] for provider in data["providers"]] == ["anthropic", "orcarouter"]
    orca = data["providers"][1]
    assert orca["base_url"] == "https://api.orcarouter.ai/v1"
    assert orca["auth"] == "api_key"
    # No credential is configured, and no field leaks one.
    assert orca["configured"] is False
    assert orca["key_source"] is None


def test_get_reads_the_chat_capability_from_the_pinned_origin(tmp_path):
    client, opener = _make(tmp_path, _catalog(_entry("vendor/a")))
    client.get("/api/providers", headers=_headers())

    assert opener.urls == ["https://api.orcarouter.ai/v1/models?capability=chat"]


def test_get_returns_the_catalog_models_verbatim(tmp_path):
    client, _ = _make(
        tmp_path,
        _catalog(
            _entry("zeta/model", name="Zeta"),
            _entry("alpha/model", modalities=("text", "image"), name="Alpha"),
        ),
    )
    data = client.get("/api/providers", headers=_headers()).json()

    catalog = data["catalog"]
    assert catalog["capability"] == "chat"
    assert catalog["source"] == "live"
    assert catalog["auth_failed"] is False
    assert [model["id"] for model in catalog["models"]] == ["alpha/model", "zeta/model"]
    alpha = catalog["models"][0]
    assert alpha["input_modalities"] == ["text", "image"]
    assert alpha["name"] == "Alpha"
    assert data["recommended_model"] == mod.FALLBACK_MODEL


def test_get_unknown_capability_is_400_and_makes_no_request(tmp_path):
    client, opener = _make(tmp_path)
    resp = client.get("/api/providers?capability=telepathy", headers=_headers())

    assert resp.status_code == 400
    assert "telepathy" in resp.json()["error"]
    assert opener.requests == []


def test_get_image_modality_narrows_the_catalog(tmp_path):
    client, _ = _make(
        tmp_path,
        _catalog(
            _entry("vendor/vision", modalities=("text", "image")),
            _entry("vendor/text-only", modalities=("text",)),
        ),
    )
    data = client.get("/api/providers?capability=chat&modality=image", headers=_headers()).json()

    assert data["catalog"]["modalities"] == ["image"]
    assert [model["id"] for model in data["catalog"]["models"]] == ["vendor/vision"]


def test_get_after_an_upstream_auth_failure_is_labeled_and_flagged(tmp_path):
    # A real key is on file (so the provider really sends one) and the upstream
    # deliberately echoes it back: the route must not pass that through.
    mod.save_api_key(_KEY)
    client, _ = _make(
        tmp_path,
        (401, json.dumps({"error": {"message": f"bad key {_KEY}"}}).encode()),
    )
    resp = client.get("/api/providers", headers=_headers())

    assert resp.status_code == 200
    catalog = resp.json()["catalog"]
    assert catalog["auth_failed"] is True
    assert catalog["source"] == "seed"
    assert _KEY not in resp.text
    assert "***" in catalog["error"]


def test_get_after_a_network_failure_shows_a_labeled_degraded_catalog(tmp_path):
    client, _ = _make(tmp_path, urllib.error.URLError("offline"))
    catalog = client.get("/api/providers", headers=_headers()).json()["catalog"]

    assert catalog["source"] == "seed"
    assert catalog["error"]
    assert catalog["models"]  # the verified seed, not an empty dropdown


def test_catalog_failure_never_fabricates_a_model_list(tmp_path):
    client, _ = _make(tmp_path, urllib.error.URLError("offline"))
    models = client.get("/api/providers", headers=_headers()).json()["catalog"]["models"]

    seed_ids = {model.id for model in mod.SEED_MODELS}
    assert {model["id"] for model in models} <= seed_ids


# --- POST: provider selection ------------------------------------------------


def test_use_provider_persists_the_choice(tmp_path):
    client, _ = _make(tmp_path)
    resp = client.post(
        "/api/providers",
        headers=_headers(),
        json={"action": "use_provider", "provider": "orcarouter"},
    )

    assert resp.status_code == 200
    assert resp.json()["active"] == "orcarouter"
    settings = json.loads((tmp_path / "providers.json").read_text())
    assert settings["provider"] == "orcarouter"


def test_use_provider_rejects_an_unknown_name(tmp_path):
    client, _ = _make(tmp_path)
    resp = client.post(
        "/api/providers",
        headers=_headers(),
        json={"action": "use_provider", "provider": "some-other-gateway"},
    )

    assert resp.status_code == 400
    assert active_provider_name() == "anthropic"


def test_use_provider_requires_a_name(tmp_path):
    client, _ = _make(tmp_path)
    resp = client.post("/api/providers", headers=_headers(), json={"action": "use_provider"})
    assert resp.status_code == 400


def test_env_override_is_reported_so_the_selector_can_explain_itself(tmp_path, monkeypatch):
    monkeypatch.setenv("DOBERMAN_LLM_PROVIDER", "anthropic")
    client, _ = _make(tmp_path, _catalog(_entry("vendor/a")))
    data = client.get("/api/providers", headers=_headers()).json()

    assert data["env_override"] is True


# --- POST: API key ------------------------------------------------------------


def test_save_key_stores_it_and_never_returns_it(tmp_path):
    client, _ = _make(tmp_path)
    resp = client.post(
        "/api/providers", headers=_headers(), json={"action": "save_key", "key": _KEY}
    )

    assert resp.status_code == 200
    assert _KEY not in resp.text
    orca = next(p for p in resp.json()["providers"] if p["name"] == "orcarouter")
    assert orca["configured"] is True
    assert orca["key_source"] == "file"
    assert (tmp_path / "orcarouter.key").read_text().strip() == _KEY


def test_save_key_rejects_a_misshaped_value_without_echoing_it(tmp_path):
    client, _ = _make(tmp_path)
    resp = client.post(
        "/api/providers", headers=_headers(), json={"action": "save_key", "key": "not-a-key"}
    )

    assert resp.status_code == 400
    assert "not-a-key" not in resp.text
    assert not (tmp_path / "orcarouter.key").exists()


def test_save_key_requires_a_string(tmp_path):
    client, _ = _make(tmp_path)
    resp = client.post("/api/providers", headers=_headers(), json={"action": "save_key", "key": 5})
    assert resp.status_code == 400


def test_clear_key_reports_whether_one_existed(tmp_path):
    client, _ = _make(tmp_path)
    first = client.post("/api/providers", headers=_headers(), json={"action": "clear_key"})
    assert first.status_code == 200
    assert first.json()["removed"] is False

    client.post("/api/providers", headers=_headers(), json={"action": "save_key", "key": _KEY})
    second = client.post("/api/providers", headers=_headers(), json={"action": "clear_key"})
    assert second.json()["removed"] is True
    assert not (tmp_path / "orcarouter.key").exists()


def test_saving_a_key_invalidates_the_cached_catalog(tmp_path):
    client, opener = _make(
        tmp_path,
        (401, b'{"error": "invalid key"}'),
        _catalog(_entry("vendor/a")),
    )
    degraded = client.get("/api/providers", headers=_headers()).json()
    assert degraded["catalog"]["auth_failed"] is True

    client.post("/api/providers", headers=_headers(), json={"action": "save_key", "key": _KEY})
    healthy = client.get("/api/providers", headers=_headers()).json()

    assert healthy["catalog"]["auth_failed"] is False
    assert healthy["catalog"]["source"] == "live"
    assert len(opener.requests) == 2


# --- POST: model selection ----------------------------------------------------


def test_set_model_accepts_an_id_the_catalog_returned(tmp_path):
    client, _ = _make(tmp_path, _catalog(_entry("vendor/a"), _entry("vendor/b")))
    resp = client.post(
        "/api/providers", headers=_headers(), json={"action": "set_model", "model": "vendor/b"}
    )

    assert resp.status_code == 200
    assert resp.json()["model"] == "vendor/b"
    settings = json.loads((tmp_path / "providers.json").read_text())
    assert settings["orcarouter_model"] == "vendor/b"


def test_set_model_rejects_an_id_no_catalog_offered(tmp_path):
    client, _ = _make(tmp_path, _catalog(_entry("vendor/a")))
    resp = client.post(
        "/api/providers",
        headers=_headers(),
        json={"action": "set_model", "model": "free-text/not-in-catalog"},
    )

    assert resp.status_code == 400
    assert "catalog" in resp.json()["error"]
    assert orcarouter_model() != "free-text/not-in-catalog"


def test_set_model_requires_a_value(tmp_path):
    client, _ = _make(tmp_path)
    resp = client.post("/api/providers", headers=_headers(), json={"action": "set_model"})
    assert resp.status_code == 400


def test_set_model_validation_always_refetches_the_catalog(tmp_path):
    client, opener = _make(tmp_path, _catalog(_entry("vendor/a")), _catalog(_entry("vendor/a")))
    client.get("/api/providers", headers=_headers())
    client.post(
        "/api/providers", headers=_headers(), json={"action": "set_model", "model": "vendor/a"}
    )
    # A second fetch: a stale in-memory catalog must not validate a model the
    # gateway may have dropped.
    assert len(opener.requests) == 2


def test_unknown_action_is_400(tmp_path):
    client, _ = _make(tmp_path)
    resp = client.post("/api/providers", headers=_headers(), json={"action": "delete_everything"})
    assert resp.status_code == 400


def test_a_non_object_body_is_400(tmp_path):
    client, _ = _make(tmp_path)
    resp = client.post("/api/providers", headers=_headers(), json=[1, 2, 3])
    assert resp.status_code == 400


# --- the shell ---------------------------------------------------------------


def test_shell_ships_a_masked_key_field(tmp_path):
    client, _ = _make(tmp_path)
    html = client.get("/").text

    assert 'id="provider-key"' in html
    assert 'type="password"' in html
    assert 'autocomplete="off"' in html
    assert "sk-orca-..." in html
    # The key is typed, never prefilled by the server.
    assert 'value="sk-orca' not in html


def test_shell_has_no_hand_written_model_options(tmp_path):
    client, _ = _make(tmp_path)
    html = client.get("/").text

    # The model control is a search box + a listbox built from the API, not a
    # <select> or a static set of <option>s.
    start = html.index('id="provider-form"')
    end = html.index('id="shortcuts-panel"')
    segment = html[start:end]
    assert 'role="combobox"' in segment
    assert 'role="listbox"' in segment
    assert "<option" not in segment


def test_shell_dropdown_is_filled_from_the_providers_endpoint(tmp_path):
    client, _ = _make(tmp_path)
    html = client.get("/").text

    assert 'fetch("/api/providers"' in html
    assert "&modality=" in html
    assert "&refresh=1" in html
    assert "li.dataset.modelId = m.id;" in html


def test_shell_never_hardcodes_a_model_id_as_a_dropdown_option(tmp_path):
    client, _ = _make(tmp_path)
    html = client.get("/").text

    # Seed ids may be named in prose/comments, but they must not be emitted as
    # selectable options or default values in the shell.
    for model_id in ("openai/gpt-5.5", "anthropic/claude-opus-4.8", "google/gemini-3.5-flash"):
        assert model_id not in html
