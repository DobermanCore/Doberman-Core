"""Shared types for named model providers (OrcaRouter, Anthropic).

A *provider* here is the thing Doberman's optional LLM enrichment talks to: it
names an endpoint, resolves a credential, discovers the models it offers, and
performs one chat completion. Two providers ship in core:

* ``anthropic`` — the historical Claude narrator, configured exactly as before
  (``anthropic`` installed, its key in the environment, an explicit opt-in
  flag). Its behavior is unchanged by this module.
* ``orcarouter`` — an OpenAI-compatible gateway (``https://api.orcarouter.ai/v1``)
  addressed by name, with its own independent config, credential store, and
  live model catalog. See :mod:`doberman.providers.orcarouter`.

Every failure a provider can produce is one of the exceptions below. They are
deliberately small and typed so callers (``doberman.explain``,
``doberman.judge``, the dashboard) can classify an error without parsing a
message — and so no message ever has to carry key material.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

#: Provider name -> human label, in the order the dashboard lists them. A
#: named entry, never a generic "any endpoint": each provider validates its own
#: origin and keeps its own credential.
PROVIDER_LABELS: dict[str, str] = {
    "anthropic": "Anthropic",
    "orcarouter": "OrcaRouter",
}

DEFAULT_PROVIDER = "anthropic"


class ProviderError(Exception):
    """Base class for every provider failure (never carries a secret)."""


class ProviderConfigError(ProviderError):
    """The provider is not configured (no key, bad origin, unknown name)."""


class ProviderAuthError(ProviderError):
    """The upstream rejected the credential (HTTP 401/403).

    Terminal for the credential that made the request: the caller should mark
    that account ``needs_reauth`` rather than retry. ``needs_reauth`` is always
    true here so no caller has to infer it from a status code.
    """

    needs_reauth = True


class ProviderRateLimitError(ProviderError):
    """The upstream asked us to back off (HTTP 429)."""


class ProviderUnavailableError(ProviderError):
    """Network failure, timeout, 5xx, or a malformed response."""


@dataclass(frozen=True)
class ModelInfo:
    """Minimal, browser-safe metadata for one catalog model.

    ``id`` is the vendor/model identifier verbatim — never rewritten into a
    friendlier alias, because it is what goes back on the wire.
    """

    id: str
    name: str
    context_length: int | None = None
    input_modalities: tuple[str, ...] = ()
    supported_endpoint_types: tuple[str, ...] = ()
    supports_reasoning: bool = False
    reasoning_efforts: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        """The subset the dashboard may receive: ids and capability facts only."""
        return {
            "id": self.id,
            "name": self.name,
            "context_length": self.context_length,
            "input_modalities": list(self.input_modalities),
            "supports_reasoning": self.supports_reasoning,
            "reasoning_efforts": list(self.reasoning_efforts),
        }


@dataclass(frozen=True)
class ModelCatalog:
    """The result of model discovery, plus where the list actually came from.

    ``source`` is part of the contract, not a debugging aid: the UI must label
    a ``seed``/``last_known_good`` list as degraded rather than present it as
    the live catalog. ``error`` is a short, non-secret reason ("HTTP 401",
    "timed out") so a caller can say *why* it degraded without parsing an
    exception; it never carries a key or a response body.
    """

    models: tuple[ModelInfo, ...] = ()
    source: str = "live"  # "live" | "seed" | "last_known_good"
    detail: str = ""
    error: str = ""
    auth_failed: bool = False

    @property
    def degraded(self) -> bool:
        return self.source != "live"

    def ids(self) -> list[str]:
        return [model.id for model in self.models]


@dataclass(frozen=True)
class ChatRequest:
    """One completion request: system text, user text, and a hard ceiling.

    ``cache_system`` asks an adapter that supports it to mark the system block
    as cacheable; adapters that do not support the concept ignore it.
    """

    system: str
    user: str
    model: str
    max_tokens: int
    timeout_s: float
    cache_system: bool = False


@dataclass(frozen=True)
class ChatResult:
    text: str
    model: str
    provider: str
    extra: dict[str, object] = field(default_factory=dict)


def coerce_modalities(values: Sequence[str] | None) -> tuple[str, ...]:
    """Normalize a modality list: lower-case, trimmed, de-duplicated, ordered."""
    if not values:
        return ()
    seen: list[str] = []
    for value in values:
        text = str(value).strip().lower()
        if text and text not in seen:
            seen.append(text)
    return tuple(seen)
