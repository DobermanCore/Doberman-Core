"""The historical Anthropic narrator provider, moved behind the provider seam.

This is a byte-for-byte behavioral port of the client construction that used to
live inline in ``doberman.explain``/``doberman.judge``: the same lazy
``import anthropic``, the same ``Anthropic()`` constructor (which reads its own
key from the environment), the same ``messages.create`` shape, and the same
hardcoded Claude Haiku model. Nothing about the Anthropic path changes; it is
simply reachable through the same seam as OrcaRouter so callers stop branching.

Its opt-in gate stays where it was — in ``explain``/``judge`` — because the two
call sites deliberately use *different* env flags (``DOBERMAN_EXPLAIN_LLM`` vs
``DOBERMAN_JUDGE_ENABLED``). Moving the gate here would collapse them.
"""

from __future__ import annotations

from doberman.providers.base import ChatRequest, ChatResult, ProviderConfigError


def anthropic_available() -> bool:
    """Whether the optional ``anthropic`` extra can be imported right now."""
    import importlib.util

    return importlib.util.find_spec("anthropic") is not None


class AnthropicProvider:
    """Chat completions through the Anthropic SDK, unchanged from before."""

    name = "anthropic"
    label = "Anthropic"

    def chat(self, request: ChatRequest) -> ChatResult:
        if not anthropic_available():
            raise ProviderConfigError('the optional "anthropic" package is not installed')
        try:
            import anthropic  # lazy: only imported once the caller's gate passed
        except ImportError as exc:  # pragma: no cover - find_spec already checked
            raise ProviderConfigError('the optional "anthropic" package is not installed') from exc

        client = anthropic.Anthropic()
        system: object = request.system
        if request.cache_system:
            # Only the judge asked for this historically: one text block with an
            # ephemeral cache hint, exactly as before.
            system = [
                {
                    "type": "text",
                    "text": request.system,
                    "cache_control": {"type": "ephemeral"},
                }
            ]
        message = client.messages.create(
            model=request.model,
            max_tokens=request.max_tokens,
            timeout=request.timeout_s,
            system=system,
            messages=[{"role": "user", "content": request.user}],
        )
        text = "".join(
            block.text for block in message.content if getattr(block, "type", None) == "text"
        )
        if not text.strip():
            raise ValueError("empty LLM response")
        return ChatResult(text=text, model=request.model, provider=self.name)
