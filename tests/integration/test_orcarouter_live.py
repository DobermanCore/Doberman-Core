"""Live OrcaRouter check: run only where a real account key is present.

Everything else in the suite injects an opener, so this is the one place that
proves the named provider's wire contract against the real gateway: discovery
from ``GET /v1/models`` and one completion through ``POST /v1/chat/completions``.
It is skipped unless ``ORCAROUTER_API_KEY`` is set, so CI without a key never
reaches the network (and never fails for the absence of one).

The key is read by the provider itself and never printed; a failure is reported
as the provider's scrubbed message plus the HTTP status.
"""

from __future__ import annotations

import os

import pytest

from doberman.providers.base import ProviderAuthError, ProviderError
from doberman.providers.orcarouter import (
    ORCAROUTER_BASE_URL,
    ChatRequest,
    OrcaRouterProvider,
)

pytestmark = pytest.mark.skipif(
    not os.environ.get("ORCAROUTER_API_KEY", "").strip(),
    reason="needs a real OrcaRouter account key",
)

#: Small ceiling so a stuck upstream cannot hold the job open.
_TIMEOUT_S = 45.0
#: How many catalog models to try before deciding the key cannot complete one.
_MAX_ATTEMPTS = 6


def test_the_live_catalog_answers_on_the_pinned_origin():
    provider = OrcaRouterProvider()
    assert provider.base_url == "https://api.orcarouter.ai/v1"
    assert ORCAROUTER_BASE_URL == "https://api.orcarouter.ai/v1"

    catalog = provider.models("chat", refresh=True)

    assert catalog.source == "live", catalog.detail
    assert catalog.models, "the live chat catalog returned no models"
    # IDs are the gateway's own, verbatim: a vendor/model pair, never rewritten.
    for model in catalog.models:
        assert "/" in model.id, model.id
    # Chat entries must advertise a chat-capable endpoint type.
    for model in catalog.models:
        assert set(model.supported_endpoint_types) & {
            "openai",
            "anthropic",
            "gemini",
            "openai-response",
        }, model.id


def test_one_live_completion_travels_through_the_provider():
    provider = OrcaRouterProvider(key=os.environ["ORCAROUTER_API_KEY"])
    catalog = provider.models("chat", refresh=True)
    assert catalog.source == "live", catalog.detail

    attempts: list[str] = []
    for model in catalog.models[:_MAX_ATTEMPTS]:
        try:
            result = provider.chat(
                ChatRequest(
                    model=model.id,
                    system="You are a terse assistant.",
                    user="Reply with exactly: gateway path verified",
                    max_tokens=32,
                    timeout_s=_TIMEOUT_S,
                )
            )
        except ProviderAuthError:
            # A key may be entitled to only a subset of the public catalog:
            # the gateway answers 403 for a model this account cannot use.
            attempts.append(f"{model.id}: not entitled")
            continue
        except ProviderError as exc:
            attempts.append(f"{model.id}: {exc}")
            continue
        assert result.text.strip(), model.id
        assert result.provider == "orcarouter"
        assert result.model == model.id
        return

    pytest.fail("no catalog model completed for this key: " + "; ".join(attempts))
