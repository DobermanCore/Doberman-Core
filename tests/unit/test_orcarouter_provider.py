"""Unit tests for the named OrcaRouter provider (``doberman.providers.orcarouter``).

The provider is the only place that talks to ``https://api.orcarouter.ai/v1``:
it resolves its own credential, discovers the model catalog from ``GET
/v1/models``, and performs one chat completion. These tests drive it through an
injected ``opener`` so the whole file is hermetic - no socket, no real key, and
no captured catalog dump (the payloads below are small synthetic shapes that
mirror the documented field names).

What is pinned here:

* the catalog is the only source of model ids, and the capability/modality
  filters fail closed (an undeclared modality never passes);
* a failure never fabricates a list: it degrades to last-known-good, then to
  the small verified seed, and says which;
* every error is typed (auth / rate-limit / unavailable) and no message - and
  no response - ever contains the key, even when the upstream echoes it.
"""

from __future__ import annotations

import json
import stat
import urllib.error
import urllib.request

import pytest

from doberman.providers import orcarouter as mod
from doberman.providers.base import (
    ChatRequest,
    ModelCatalog,
    ModelInfo,
    ProviderAuthError,
    ProviderConfigError,
    ProviderRateLimitError,
    ProviderUnavailableError,
)

_KEY = "sk-orca-synthetic-test-key-not-real"  # noqa: S105 - fixture value


def _entry(
    model_id: str,
    *,
    endpoints: tuple[str, ...] = ("openai",),
    modalities: tuple[str, ...] = ("text",),
    context_length: int | None = 128_000,
    parameters: tuple[str, ...] = (),
    name: str | None = None,
) -> dict:
    entry = {
        "id": model_id,
        "object": "model",
        "supported_endpoint_types": list(endpoints),
        "supported_parameters": list(parameters),
    }
    if context_length is not None:
        entry["context_length"] = context_length
    if modalities:
        entry["architecture"] = {"input_modalities": list(modalities)}
    if name is not None:
        entry["name"] = name
    return entry


def _catalog_body(*models: dict) -> bytes:
    return json.dumps({"object": "list", "data": list(models)}).encode("utf-8")


class _Opener:
    """A scripted transport: records every request, returns queued responses."""

    def __init__(self, *responses):
        self.requests: list[urllib.request.Request] = []
        self.timeouts: list[float] = []
        self._responses = list(responses)

    def __call__(self, request, timeout):
        self.requests.append(request)
        self.timeouts.append(timeout)
        if not self._responses:
            raise AssertionError("unexpected extra request")
        response = self._responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def _provider(opener, *, key: str | None = _KEY, clock=None) -> mod.OrcaRouterProvider:
    kwargs = {"opener": opener, "key": key}
    if clock is not None:
        kwargs["clock"] = clock
    return mod.OrcaRouterProvider(**kwargs)


@pytest.fixture(autouse=True)
def _isolated_paths(tmp_path, monkeypatch):
    """Never read or write the real per-user key/catalog files."""
    monkeypatch.setenv(mod.KEY_FILE_ENV, str(tmp_path / "orcarouter.key"))
    monkeypatch.setenv(mod.CATALOG_CACHE_ENV, str(tmp_path / "orcarouter-models.json"))
    monkeypatch.delenv(mod.ORCAROUTER_KEY_ENV, raising=False)
    return tmp_path


# --- catalog parsing ---------------------------------------------------------


def test_catalog_ids_are_verbatim_and_sorted(_isolated_paths):
    opener = _Opener(
        (
            200,
            _catalog_body(
                _entry("zeta/model-b", context_length=8_000),
                _entry("alpha/model-a", name="Alpha: Model A", parameters=("reasoning",)),
            ),
        )
    )
    catalog = _provider(opener).models("chat")

    assert catalog.source == "live"
    assert catalog.degraded is False
    # Vendor/model ids verbatim (never aliased), deterministic order.
    assert catalog.ids() == ["alpha/model-a", "zeta/model-b"]
    alpha = catalog.models[0]
    assert alpha.name == "Alpha: Model A"
    assert alpha.context_length == 128_000
    assert alpha.supports_reasoning is True
    assert alpha.input_modalities == ("text",)
    assert catalog.models[1].context_length == 8_000
    assert catalog.models[1].supports_reasoning is False


def test_catalog_request_is_pinned_to_the_one_origin_and_carries_the_key(_isolated_paths):
    opener = _Opener((200, _catalog_body(_entry("alpha/model-a"))))
    _provider(opener).models("chat")

    request = opener.requests[0]
    assert request.full_url == "https://api.orcarouter.ai/v1/models?capability=chat"
    assert request.get_header("Authorization") == f"Bearer {_KEY}"
    assert request.get_method() == "GET"


def test_catalog_entry_without_id_is_skipped(_isolated_paths):
    opener = _Opener(
        (
            200,
            _catalog_body(
                {"object": "model", "supported_endpoint_types": ["openai"]},
                "not-a-dict",
                _entry("alpha/model-a"),
            ),
        )
    )
    catalog = _provider(opener).models("chat")
    assert catalog.ids() == ["alpha/model-a"]


def test_entry_missing_metadata_keeps_the_id_and_leaves_fields_empty(_isolated_paths):
    opener = _Opener(
        (
            200,
            json.dumps(
                {
                    "data": [
                        {
                            "id": "orcarouter/fusion",
                            "supported_endpoint_types": ["openai", "anthropic"],
                        }
                    ]
                }
            ).encode(),
        )
    )
    catalog = _provider(opener).models("chat")

    assert catalog.ids() == ["orcarouter/fusion"]
    assert catalog.models[0].context_length is None
    assert catalog.models[0].input_modalities == ()
    # name falls back to the id rather than inventing a label
    assert catalog.models[0].name == "orcarouter/fusion"


# --- capability / modality filters ------------------------------------------


def test_chat_requires_a_chat_endpoint_type(_isolated_paths):
    opener = _Opener(
        (
            200,
            _catalog_body(
                _entry("vendor/chat", endpoints=("openai",)),
                _entry("vendor/chat-gemini", endpoints=("gemini",)),
                _entry("vendor/chat-anthropic", endpoints=("anthropic",)),
                _entry("vendor/chat-response", endpoints=("openai-response",)),
                _entry("vendor/image-only", endpoints=("image-generation",)),
                _entry("vendor/no-endpoints", endpoints=()),
                _entry("vendor/unrelated", endpoints=("vertex-ai", "bedrock")),
            ),
        )
    )
    catalog = _provider(opener).models("chat")

    assert catalog.ids() == [
        "vendor/chat",
        "vendor/chat-anthropic",
        "vendor/chat-gemini",
        "vendor/chat-response",
    ]


def test_chat_excludes_non_chat_endpoint_types_present_in_the_same_entry(_isolated_paths):
    opener = _Opener(
        (
            200,
            _catalog_body(
                _entry("vendor/mixed", endpoints=("openai", "image-generation")),
                _entry("vendor/video", endpoints=("openai-video",)),
                _entry("vendor/rerank", endpoints=("jina-rerank",)),
                _entry("vendor/embed", endpoints=("embeddings",)),
            ),
        )
    )
    catalog = _provider(opener).models("chat")
    assert catalog.ids() == ["vendor/mixed"]


def test_image_modality_filter_is_fail_closed(_isolated_paths):
    opener = _Opener(
        (
            200,
            _catalog_body(
                _entry("vendor/vision", modalities=("text", "image")),
                _entry("vendor/text-only", modalities=("text",)),
                # No architecture block at all: it cannot prove image support.
                _entry("vendor/undeclared", modalities=()),
                _entry("vendor/audio", modalities=("text", "audio")),
            ),
        )
    )
    catalog = _provider(opener).models("chat", modalities=["image"])

    assert catalog.ids() == ["vendor/vision"]


def test_modality_filter_requires_every_requested_modality(_isolated_paths):
    opener = _Opener(
        (
            200,
            _catalog_body(
                _entry("vendor/vision", modalities=("text", "image")),
                _entry("vendor/vision-audio", modalities=("text", "image", "audio")),
            ),
        )
    )
    catalog = _provider(opener).models("chat", modalities=["image", "audio"])
    assert catalog.ids() == ["vendor/vision-audio"]


def test_non_chat_capabilities_use_their_strict_endpoint_type(_isolated_paths):
    bodies = {
        "embedding": _entry("vendor/embed", endpoints=("embeddings",)),
        "image": _entry("vendor/image", endpoints=("image-generation",)),
        "video": _entry("vendor/video", endpoints=("openai-video",)),
        "rerank": _entry("vendor/rerank", endpoints=("jina-rerank",)),
    }
    for capability, expected in bodies.items():
        opener = _Opener(
            (
                200,
                _catalog_body(
                    _entry("vendor/wrong", endpoints=("openai",)),
                    expected,
                ),
            )
        )
        catalog = _provider(opener).models(capability)

        assert catalog.ids() == [expected["id"]], capability
        assert opener.requests[0].full_url.endswith(f"?capability={capability}")


def test_unknown_capability_is_a_config_error_before_any_request(_isolated_paths):
    opener = _Opener()
    with pytest.raises(ProviderConfigError):
        _provider(opener).models("telepathy")
    assert opener.requests == []


def test_empty_chat_catalog_is_a_failed_discovery_not_an_empty_dropdown(_isolated_paths):
    opener = _Opener((200, _catalog_body(_entry("vendor/image", endpoints=("image-generation",)))))
    catalog = _provider(opener).models("chat")

    assert catalog.source == "seed"
    assert catalog.ids()  # a labeled fallback, never nothing


def test_empty_non_chat_catalog_is_a_real_answer(_isolated_paths):
    opener = _Opener((200, _catalog_body()))
    catalog = _provider(opener).models("rerank")

    assert catalog.source == "live"
    assert catalog.ids() == []
    assert catalog.degraded is False


# --- error mapping -----------------------------------------------------------


def test_401_marks_the_catalog_auth_failed_and_raises_nothing(_isolated_paths):
    opener = _Opener((401, b'{"error": {"message": "invalid key"}}'))
    catalog = _provider(opener).models("chat")

    assert catalog.source == "seed"
    assert catalog.auth_failed is True
    assert "401" in catalog.error


def test_403_is_also_an_auth_failure(_isolated_paths):
    opener = _Opener((403, b'{"error": "forbidden"}'))
    catalog = _provider(opener).models("chat")
    assert catalog.auth_failed is True


def test_429_is_not_an_auth_failure(_isolated_paths):
    opener = _Opener((429, b'{"error": {"message": "slow down"}}'))
    catalog = _provider(opener).models("chat")

    assert catalog.source == "seed"
    assert catalog.auth_failed is False
    assert "rate" in catalog.error.lower()


def test_5xx_is_unavailable(_isolated_paths):
    opener = _Opener((503, b"upstream down"))
    catalog = _provider(opener).models("chat")

    assert catalog.auth_failed is False
    assert "503" in catalog.error


def test_network_failure_is_unavailable(_isolated_paths):
    opener = _Opener(urllib.error.URLError("connection refused"))
    catalog = _provider(opener).models("chat")

    assert catalog.source == "seed"
    assert catalog.auth_failed is False


def test_non_json_body_is_unavailable(_isolated_paths):
    opener = _Opener((200, b"<html>not json</html>"))
    catalog = _provider(opener).models("chat")
    assert catalog.source == "seed"


def test_json_without_data_list_is_unavailable(_isolated_paths):
    opener = _Opener((200, b'{"models": []}'))
    catalog = _provider(opener).models("chat")
    assert catalog.source == "seed"


def test_oversized_catalog_is_rejected(_isolated_paths, monkeypatch):
    monkeypatch.setattr(mod, "_MAX_CATALOG_BYTES", 16)
    opener = _Opener((200, _catalog_body(_entry("vendor/a", name="x" * 200))))
    catalog = _provider(opener).models("chat")
    assert catalog.source == "seed"


def test_oversized_completion_response_is_rejected(_isolated_paths):
    opener = _Opener((200, b"x" * (mod._MAX_RESPONSE_BYTES + 1)))
    with pytest.raises(ProviderUnavailableError):
        _provider(opener).chat(_request())


def test_error_body_never_repeats_the_key(_isolated_paths):
    body = json.dumps({"error": {"message": f"invalid api key {_KEY}"}}).encode()
    opener = _Opener((401, body))
    catalog = _provider(opener).models("chat")

    assert _KEY not in catalog.error
    assert "***" in catalog.error


def test_chat_401_raises_auth_error_without_the_key(_isolated_paths):
    body = json.dumps({"error": {"message": f"bad token {_KEY}"}}).encode()
    opener = _Opener((401, body))
    with pytest.raises(ProviderAuthError) as excinfo:
        _provider(opener).chat(_request())
    assert excinfo.value.needs_reauth is True
    assert _KEY not in str(excinfo.value)


def test_chat_429_raises_rate_limit(_isolated_paths):
    opener = _Opener((429, b"{}"))
    with pytest.raises(ProviderRateLimitError):
        _provider(opener).chat(_request())


def test_chat_network_error_raises_unavailable(_isolated_paths):
    opener = _Opener(urllib.error.URLError("no route"))
    with pytest.raises(ProviderUnavailableError):
        _provider(opener).chat(_request())


# --- credential handling -----------------------------------------------------


def test_missing_key_is_a_config_error(_isolated_paths):
    provider = _provider(_Opener(), key=None)
    assert provider.configured() is False
    with pytest.raises(ProviderConfigError):
        provider.chat(_request())


def test_env_key_wins_over_the_file(_isolated_paths, monkeypatch):
    mod.save_api_key(_KEY)
    monkeypatch.setenv(mod.ORCAROUTER_KEY_ENV, "sk-orca-from-env")
    assert mod.resolve_api_key() == "sk-orca-from-env"
    assert mod.credential_status()["source"] == "env"


def test_save_key_writes_a_private_file_and_reports_no_value(_isolated_paths):
    mod.save_api_key(_KEY)
    path = mod.key_path()

    assert path.read_text(encoding="utf-8").strip() == _KEY
    if path.stat().st_mode & stat.S_IRWXG or path.stat().st_mode & stat.S_IRWXO:
        pytest.fail("the key file must not be group/world readable")
    status = mod.credential_status()
    assert status == {"configured": True, "source": "file", "path": str(path)}
    assert _KEY not in json.dumps(status)


def test_save_key_rejects_an_empty_or_misshaped_value(_isolated_paths):
    with pytest.raises(ProviderConfigError):
        mod.save_api_key("   ")
    with pytest.raises(ProviderConfigError):
        mod.save_api_key("not-an-orcarouter-key")
    with pytest.raises(ProviderConfigError):
        mod.save_api_key("sk-orca-has space")
    assert not mod.key_path().exists()


def test_save_key_message_never_contains_the_rejected_value(_isolated_paths):
    try:
        mod.save_api_key("totally-wrong-value")
    except ProviderConfigError as exc:
        assert "totally-wrong-value" not in str(exc)


def test_clear_key_removes_the_file_and_reports_whether_it_existed(_isolated_paths):
    assert mod.clear_api_key() is False
    mod.save_api_key(_KEY)
    assert mod.clear_api_key() is True
    assert mod.credential_status()["configured"] is False


def test_credential_status_before_any_key(_isolated_paths):
    assert mod.credential_status() == {
        "configured": False,
        "source": None,
        "path": str(mod.key_path()),
    }


# --- caching and degraded sources -------------------------------------------


def test_second_call_within_the_ttl_is_served_from_memory(_isolated_paths):
    now = [0.0]
    opener = _Opener((200, _catalog_body(_entry("vendor/a"))))
    provider = _provider(opener, clock=lambda: now[0])

    provider.models("chat")
    now[0] = mod._CACHE_TTL_S - 1
    provider.models("chat")

    assert len(opener.requests) == 1


def test_cache_expires_and_refresh_bypasses_it(_isolated_paths):
    now = [0.0]
    opener = _Opener(
        (200, _catalog_body(_entry("vendor/a"))),
        (200, _catalog_body(_entry("vendor/b"))),
        (200, _catalog_body(_entry("vendor/c"))),
    )
    provider = _provider(opener, clock=lambda: now[0])

    assert provider.models("chat").ids() == ["vendor/a"]
    now[0] = mod._CACHE_TTL_S + 1
    assert provider.models("chat").ids() == ["vendor/b"]
    assert provider.models("chat", refresh=True).ids() == ["vendor/c"]


def test_invalidate_cache_forces_a_refetch(_isolated_paths):
    opener = _Opener(
        (200, _catalog_body(_entry("vendor/a"))),
        (200, _catalog_body(_entry("vendor/b"))),
    )
    provider = _provider(opener)

    provider.models("chat")
    provider.invalidate_cache()
    assert provider.models("chat").ids() == ["vendor/b"]


def test_a_live_fetch_is_written_as_last_known_good(_isolated_paths):
    opener = _Opener((200, _catalog_body(_entry("vendor/a"))))
    _provider(opener).models("chat")

    cached = json.loads(_isolated_paths.joinpath("orcarouter-models.json").read_text())
    assert [model["id"] for model in cached["models"]] == ["vendor/a"]


def test_failure_falls_back_to_last_known_good_before_the_seed(_isolated_paths):
    live = _Opener((200, _catalog_body(_entry("vendor/live-model"))))
    _provider(live).models("chat")

    failing = _Opener(urllib.error.URLError("offline"))
    catalog = _provider(failing).models("chat")

    assert catalog.source == "last_known_good"
    assert catalog.ids() == ["vendor/live-model"]
    assert catalog.degraded is True
    assert catalog.error


def test_failure_without_a_cache_returns_the_labeled_seed(_isolated_paths):
    opener = _Opener(urllib.error.URLError("offline"))
    catalog = _provider(opener).models("chat")

    assert catalog.source == "seed"
    assert catalog.ids() == sorted(model.id for model in mod.SEED_MODELS)
    assert "seed" in catalog.detail


def test_seed_is_only_offered_for_chat(_isolated_paths):
    opener = _Opener(urllib.error.URLError("offline"))
    catalog = _provider(opener).models("embedding")

    assert catalog.source == "seed"
    assert catalog.ids() == []


def test_last_known_good_is_ignored_when_it_lacks_the_requested_modality(_isolated_paths):
    live = _Opener((200, _catalog_body(_entry("vendor/vision", modalities=("text", "image")))))
    _provider(live).models("chat", modalities=["image"])

    failing = _Opener(urllib.error.URLError("offline"))
    # The cached copy was fetched for image; asking for both must not reuse it.
    catalog = _provider(failing).models("chat", modalities=["image", "audio"])

    assert catalog.source == "seed"


def test_corrupt_last_known_good_file_falls_back_to_the_seed(_isolated_paths):
    _isolated_paths.joinpath("orcarouter-models.json").write_text("{not json")
    opener = _Opener(urllib.error.URLError("offline"))
    catalog = _provider(opener).models("chat")
    assert catalog.source == "seed"


def test_unwritable_cache_does_not_fail_a_successful_fetch(_isolated_paths, monkeypatch):
    def _write_fails(*_args, **_kwargs):
        raise OSError("read-only")

    monkeypatch.setattr(mod, "_write_private", _write_fails)
    opener = _Opener((200, _catalog_body(_entry("vendor/a"))))
    catalog = _provider(opener).models("chat")

    assert catalog.source == "live"
    assert catalog.ids() == ["vendor/a"]


# --- model selection ---------------------------------------------------------


def test_default_model_prefers_the_recommended_one_only_when_offered():
    with_recommended = ModelCatalog(
        models=(
            ModelInfo(id=mod.RECOMMENDED_MODEL, name="cyber"),
            ModelInfo(id=mod.FALLBACK_MODEL, name="fusion"),
        )
    )
    public_only = ModelCatalog(models=(ModelInfo(id=mod.FALLBACK_MODEL, name="fusion"),))

    assert mod.default_model(with_recommended) == mod.RECOMMENDED_MODEL
    assert mod.default_model(public_only) == mod.FALLBACK_MODEL
    assert mod.default_model(None) == mod.FALLBACK_MODEL


def test_model_is_available_checks_the_catalog_it_was_given():
    catalog = ModelCatalog(models=(ModelInfo(id="vendor/a", name="a"),))
    assert mod.model_is_available("vendor/a", catalog) is True
    assert mod.model_is_available("vendor/not-there", catalog) is False


def test_seed_recommended_model_is_not_assumed_to_be_in_the_public_catalog(_isolated_paths):
    opener = _Opener(urllib.error.URLError("offline"))
    catalog = _provider(opener).models("chat")
    assert mod.RECOMMENDED_MODEL not in catalog.ids()
    assert mod.default_model(catalog) == mod.FALLBACK_MODEL


# --- completions -------------------------------------------------------------


def _request(**overrides) -> ChatRequest:
    fields = {
        "system": "system prompt",
        "user": "user prompt",
        "model": "vendor/a",
        "max_tokens": 32,
        "timeout_s": 1.5,
    }
    fields.update(overrides)
    return ChatRequest(**fields)


def test_chat_posts_to_the_pinned_endpoint_and_returns_the_text(_isolated_paths):
    opener = _Opener((200, b'{"choices": [{"message": {"content": "  hello  "}}]}'))
    result = _provider(opener).chat(_request())

    request = opener.requests[0]
    assert request.full_url == "https://api.orcarouter.ai/v1/chat/completions"
    assert request.get_method() == "POST"
    assert request.get_header("Authorization") == f"Bearer {_KEY}"
    body = json.loads(request.data)
    assert body["model"] == "vendor/a"
    assert body["messages"] == [
        {"role": "system", "content": "system prompt"},
        {"role": "user", "content": "user prompt"},
    ]
    assert body["max_tokens"] == 32
    assert body["stream"] is False
    assert result.text == "hello"
    assert result.model == "vendor/a"
    assert result.provider == "orcarouter"


def test_chat_accepts_list_of_content_parts(_isolated_paths):
    payload = {
        "choices": [
            {
                "message": {
                    "content": [
                        {"type": "text", "text": "part one "},
                        {"type": "text", "text": "two"},
                    ]
                }
            }
        ]
    }
    opener = _Opener((200, json.dumps(payload).encode()))
    assert _provider(opener).chat(_request()).text == "part one two"


def test_chat_rejects_an_empty_completion(_isolated_paths):
    opener = _Opener((200, b'{"choices": [{"message": {"content": "   "}}]}'))
    with pytest.raises(ProviderUnavailableError):
        _provider(opener).chat(_request())


def test_chat_rejects_a_malformed_completion(_isolated_paths):
    for body in (b"{}", b'{"choices": []}', b'{"choices": ["x"]}', b'{"choices": [{}]}'):
        opener = _Opener((200, body))
        with pytest.raises(ProviderUnavailableError):
            _provider(opener).chat(_request())


def test_chat_uses_the_request_timeout(_isolated_paths):
    opener = _Opener((200, b'{"choices": [{"message": {"content": "ok"}}]}'))
    _provider(opener).chat(_request(timeout_s=0.25))
    assert opener.timeouts == [0.25]


# --- shape of the module -----------------------------------------------------


def test_the_origin_is_a_constant_with_no_override_parameter():
    assert mod.ORCAROUTER_BASE_URL == "https://api.orcarouter.ai/v1"
    with pytest.raises(TypeError):
        mod.OrcaRouterProvider(base_url="https://example.test/v1")  # type: ignore[call-arg]
