"""Named model providers and the persisted choice between them.

Doberman has one optional LLM narrator (``doberman.explain``) and one offline
shadow judge (``doberman.judge``). Both used to construct an Anthropic client
inline; both now resolve a provider by name through :func:`get_provider`.

The choice is explicit and persisted per user (never per repo, so it cannot be
committed):

* ``DOBERMAN_LLM_PROVIDER`` env var, else
* ``provider`` in the per-user ``providers.json``, else
* :data:`~doberman.providers.base.DEFAULT_PROVIDER` (``anthropic``).

Each provider keeps its own credentials. Selecting ``orcarouter`` never makes
Doberman talk to an arbitrary endpoint: :class:`~doberman.providers.orcarouter.
OrcaRouterProvider` is pinned to ``https://api.orcarouter.ai/v1``.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from doberman.providers.anthropic import AnthropicProvider, anthropic_available
from doberman.providers.base import (
    DEFAULT_PROVIDER,
    PROVIDER_LABELS,
    ChatRequest,
    ChatResult,
    ModelCatalog,
    ModelInfo,
    ProviderAuthError,
    ProviderConfigError,
    ProviderError,
    ProviderRateLimitError,
    ProviderUnavailableError,
)
from doberman.providers.orcarouter import (
    CAPABILITIES,
    FALLBACK_MODEL,
    ORCAROUTER_BASE_URL,
    RECOMMENDED_MODEL,
    OrcaRouterProvider,
    clear_api_key,
    credential_status,
    default_model,
    key_path,
    model_is_available,
    resolve_api_key,
    save_api_key,
)

__all__ = [
    "CAPABILITIES",
    "DEFAULT_PROVIDER",
    "FALLBACK_MODEL",
    "MODEL_ENV",
    "ORCAROUTER_BASE_URL",
    "PROVIDER_ENV",
    "PROVIDER_LABELS",
    "RECOMMENDED_MODEL",
    "SETTINGS_FILE_ENV",
    "AnthropicProvider",
    "ChatRequest",
    "ChatResult",
    "ModelCatalog",
    "ModelInfo",
    "OrcaRouterProvider",
    "ProviderAuthError",
    "ProviderConfigError",
    "ProviderError",
    "ProviderRateLimitError",
    "ProviderUnavailableError",
    "active_provider_name",
    "anthropic_available",
    "anthropic_model",
    "clear_api_key",
    "credential_status",
    "default_model",
    "get_provider",
    "key_path",
    "load_settings",
    "model_is_available",
    "orcarouter_model",
    "provider_status",
    "resolve_api_key",
    "save_api_key",
    "save_settings",
    "set_orcarouter_model",
    "use_provider",
]

#: Env override selecting the provider (an explicit opt-in always wins).
PROVIDER_ENV = "DOBERMAN_LLM_PROVIDER"
#: Env override for the OrcaRouter model ID (verbatim catalog ID).
MODEL_ENV = "DOBERMAN_ORCAROUTER_MODEL"
#: Per-user settings-file override (tests inject a temp path).
SETTINGS_FILE_ENV = "DOBERMAN_PROVIDER_FILE"

_SETTINGS_NAME = "providers.json"


def _settings_path() -> Path:
    override = os.environ.get(SETTINGS_FILE_ENV)
    if override:
        return Path(override)
    # Same per-user directory as the OrcaRouter key file; never inside a repo.
    return key_path().parent / _SETTINGS_NAME


def load_settings() -> dict[str, Any]:
    """The persisted provider settings; ``{}`` when absent or unreadable.

    Never raises: a corrupt file must not break the decision path. Contains no
    secret (provider name, model id, reasoning effort only).
    """
    path = _settings_path()
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError:
        return {}
    try:
        data = json.loads(raw)
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def save_settings(settings: dict[str, Any]) -> None:
    """Persist settings (0600 next to the key file). Rejects unknown providers."""
    provider = settings.get("provider")
    if provider is not None and provider not in PROVIDER_LABELS:
        raise ProviderConfigError(f"unknown provider {provider!r}")
    payload = {
        "provider": settings.get("provider") or DEFAULT_PROVIDER,
        "model": settings.get("model") or "",
        "orcarouter_model": settings.get("orcarouter_model") or "",
    }
    path = _settings_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        tmp.replace(path)
    except OSError as exc:
        raise ProviderConfigError("could not save the provider settings") from exc


def active_provider_name() -> str:
    """Resolve the active provider name, failing closed to the default."""
    env = os.environ.get(PROVIDER_ENV, "").strip().lower()
    if env:
        return env if env in PROVIDER_LABELS else DEFAULT_PROVIDER
    stored = load_settings().get("provider")
    if isinstance(stored, str) and stored in PROVIDER_LABELS:
        return stored
    return DEFAULT_PROVIDER


def use_provider(name: str) -> str:
    """Switch the active provider and persist the choice; returns the name."""
    normalized = name.strip().lower()
    if normalized not in PROVIDER_LABELS:
        raise ProviderConfigError(f"unknown provider {name!r}")
    settings = load_settings()
    settings["provider"] = normalized
    save_settings(settings)
    return normalized


def orcarouter_model() -> str:
    """The configured OrcaRouter model, verbatim; the public fallback otherwise."""
    env = os.environ.get(MODEL_ENV, "").strip()
    if env:
        return env
    for key in ("orcarouter_model", "model"):
        value = load_settings().get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return FALLBACK_MODEL


def set_orcarouter_model(model_id: str) -> str:
    """Persist the chosen OrcaRouter model ID (validated against the catalog).

    Validation against the live catalog happens in the dashboard route, which
    has a provider instance; this layer only guarantees a non-empty string.
    """
    model = str(model_id).strip()
    if not model:
        raise ProviderConfigError("a model ID is required")
    settings = load_settings()
    settings["orcarouter_model"] = model
    save_settings(settings)
    return model


def anthropic_model() -> str:
    """The historical Claude model — deliberately unchanged."""
    return "claude-haiku-4-5-20251001"


def get_provider(name: str | None = None) -> AnthropicProvider | OrcaRouterProvider:
    """Return a provider instance by name (the active one when omitted)."""
    resolved = (name or active_provider_name()).strip().lower()
    if resolved == "orcarouter":
        return OrcaRouterProvider()
    if resolved == "anthropic":
        return AnthropicProvider()
    raise ProviderConfigError(f"unknown provider {name!r}")


def provider_status() -> dict[str, Any]:
    """Browser-safe status for every provider: no key, no partial key."""
    status = credential_status()
    env_override = os.environ.get(PROVIDER_ENV, "").strip()
    return {
        "active": active_provider_name(),
        # An env var outranks the per-user file, so a dashboard selection
        # cannot take effect while it is set. Saying so is cheaper than
        # letting the selector look broken.
        "env_override": bool(env_override),
        "providers": [
            {
                "name": "anthropic",
                "label": PROVIDER_LABELS["anthropic"],
                "configured": anthropic_available(),
                "auth": "api_key",
                "note": "environment credential; unchanged legacy narrator",
            },
            {
                "name": "orcarouter",
                "label": PROVIDER_LABELS["orcarouter"],
                "configured": bool(status["configured"]),
                "auth": "api_key",
                "key_source": status["source"],
                "note": "named gateway; model list is read from its live catalog",
                "base_url": ORCAROUTER_BASE_URL,
                "model": orcarouter_model(),
                "capabilities": list(CAPABILITIES),
            },
        ],
    }
