"""The named OrcaRouter provider: fixed origin, own credential, live model catalog.

OrcaRouter (https://www.orcarouter.ai) is an OpenAI-compatible gateway that
routes many vendors' models behind one endpoint. This module is a *named*
provider, not a generic "point me at any base URL" option: the origin is a
constant, the credential is OrcaRouter's own (``sk-orca-`` keys), and the model
list is discovered from that origin's ``GET /v1/models``. Nothing here accepts a
user-supplied endpoint.

Design constraints inherited from the repo:

* **stdlib only** — ``doberman.explain``/``doberman.judge`` may be imported from
  the CLI, the dashboard and the TUI; this module must not pull in the optional
  ``anthropic`` extra or any HTTP SDK. Requests go through ``urllib.request``,
  mirroring ``doberman.update_check``.
* **never expose the key** — it is read from ``ORCAROUTER_API_KEY`` or a
  per-user ``0600`` file, passed to the transport as a header, and never put in
  an exception, a log record, a return value, or the model catalog.
* **bounded everything** — every response is read with a byte cap, every call
  has a timeout, the model list is capped, and every field is shape-checked.
  A malformed or oversized reply is a typed failure, not a partial catalog.

Model discovery follows the gateway's capability contract:

====================  =====================  ====================================
``capability``        query                  additional local filter
====================  =====================  ====================================
``chat``              ``?capability=chat``   ``supported_endpoint_types`` must
                                             intersect the chat endpoint set;
                                             ``architecture.input_modalities``
                                             must contain every requested
                                             modality (fail closed)
``embedding``         ``?capability=embedding``  ``embeddings`` endpoint type
``image``             ``?capability=image``  ``image-generation`` endpoint type
``video``             ``?capability=video``  strict ``openai-video``
``rerank``            ``?capability=rerank`` strict ``jina-rerank``
====================  =====================  ====================================

The chat list additionally excludes image-generation / openai-video /
jina-rerank endpoints when they appear alongside a chat endpoint, because those
are not chat models even if the gateway groups them loosely.

When discovery fails the provider never fabricates a list: it falls back to the
last known good catalog written by an earlier successful fetch, then to a small
seed of IDs verified against the live catalog, and labels which of the three it
returned (:attr:`~doberman.providers.base.ModelCatalog.source`). Callers are
expected to show that label.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from doberman.providers.base import (
    ChatRequest,
    ChatResult,
    ModelCatalog,
    ModelInfo,
    ProviderAuthError,
    ProviderConfigError,
    ProviderRateLimitError,
    ProviderUnavailableError,
    coerce_modalities,
)

#: The one origin this provider ever talks to (no base-URL override exists).
ORCAROUTER_BASE_URL = "https://api.orcarouter.ai/v1"

#: Account key env var. Keys issued by OrcaRouter carry this prefix.
ORCAROUTER_KEY_ENV = "ORCAROUTER_API_KEY"
ORCAROUTER_KEY_PREFIX = "sk-orca-"

#: Per-user credential/cache file overrides (tests inject temp paths).
KEY_FILE_ENV = "DOBERMAN_ORCAROUTER_KEY_FILE"
CATALOG_CACHE_ENV = "DOBERMAN_ORCAROUTER_CACHE_FILE"

#: Endpoint types that mean "this model can answer a chat completion".
CHAT_ENDPOINT_TYPES = frozenset({"openai", "anthropic", "gemini", "openai-response"})
#: Endpoint types that are explicitly NOT chat, even if the gateway groups them
#: under ``capability=chat`` on some accounts.
NON_CHAT_ENDPOINT_TYPES = frozenset(
    {"image-generation", "openai-video", "jina-rerank", "embeddings"}
)

CAPABILITIES: tuple[str, ...] = ("chat", "embedding", "image", "video", "rerank")
#: Endpoint type each non-chat capability MUST advertise (strict, per the
#: gateway's own capability vocabulary).
REQUIRED_ENDPOINT_TYPE: dict[str, str] = {
    "embedding": "embeddings",
    "image": "image-generation",
    "video": "openai-video",
    "rerank": "jina-rerank",
}

_HTTP_TIMEOUT_S = 8.0
#: One transport read cap for every response, catalog or completion. A catalog
#: of 1000 models is ~1.2 MB, so the completion-sized cap was too small to hold
#: the very list discovery exists to read.
_MAX_RESPONSE_BYTES = 4 * 1024 * 1024
#: Post-hoc check applied to a catalog body, which keeps the guarantee even when
#: a caller injects its own ``opener`` that does not honour ``_MAX_RESPONSE_BYTES``.
_MAX_CATALOG_BYTES = _MAX_RESPONSE_BYTES
_MAX_MODELS = 1000
_CACHE_TTL_S = 300.0

#: The model used when the caller has saved none and the live catalog does not
#: offer the recommended one. Present in the public catalog.
FALLBACK_MODEL = "orcarouter/fusion"

#: Recommended by OrcaRouter for security work. It is not in the public catalog
#: (it requires business verification), so it is preferred only when the live
#: catalog actually offers it — never assumed.
RECOMMENDED_MODEL = "orcacyber-zero"

#: Cold-start seed: IDs verified present in the live catalog on 2026-10-21, with
#: the capability metadata each one advertised then. Used ONLY when discovery
#: fails and no last-known-good cache exists; the caller labels it as degraded.
#: ``reasoning_efforts`` on GPT-5.5 is the four-step ladder OrcaRouter documents
#: for that model (the catalog itself does not enumerate the values).
SEED_MODELS: tuple[ModelInfo, ...] = (
    ModelInfo(
        id="openai/gpt-5.5",
        name="OpenAI: GPT-5.5",
        context_length=272_000,
        input_modalities=("file", "image", "text"),
        supported_endpoint_types=("openai", "openai-response"),
        supports_reasoning=True,
        reasoning_efforts=("low", "medium", "high", "xhigh"),
    ),
    ModelInfo(
        id="anthropic/claude-opus-4.8",
        name="Anthropic: Claude Opus 4.8",
        context_length=1_000_000,
        input_modalities=("file", "image", "text"),
        supported_endpoint_types=("openai", "anthropic", "openai-response"),
        supports_reasoning=True,
    ),
    ModelInfo(
        id="google/gemini-3.5-flash",
        name="Gemini 3.5 Flash",
        context_length=1_048_576,
        input_modalities=("text", "image", "video", "file", "audio"),
        supported_endpoint_types=("openai", "gemini"),
        supports_reasoning=True,
    ),
    ModelInfo(
        id="deepseek/deepseek-v4-pro",
        name="DeepSeek: DeepSeek V4 Pro",
        context_length=1_048_576,
        input_modalities=("text",),
        supported_endpoint_types=("openai", "openai-response"),
        supports_reasoning=True,
    ),
    ModelInfo(
        id=FALLBACK_MODEL,
        name="OrcaRouter Fusion",
        context_length=1_000_000,
        input_modalities=(),
        supported_endpoint_types=("openai", "openai-response", "anthropic", "gemini"),
    ),
)


# ---------------------------------------------------------------------------
# On-disk locations (per-user, never inside the repo)
# ---------------------------------------------------------------------------


def _config_dir() -> Path:
    """Per-user Doberman config dir — same resolution as the TOTP secret."""
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.path.join(
            os.path.expanduser("~"), "AppData", "Local"
        )
    else:
        base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return Path(base) / "doberman"


def key_path() -> Path:
    override = os.environ.get(KEY_FILE_ENV)
    return Path(override) if override else _config_dir() / "orcarouter.key"


def catalog_cache_path() -> Path:
    override = os.environ.get(CATALOG_CACHE_ENV)
    return Path(override) if override else _config_dir() / "orcarouter-models.json"


def _private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        path.chmod(0o700)
    except OSError:
        pass


def _write_private(path: Path, payload: str) -> None:
    """Atomically write a 0600 file: temp file in the same dir, then replace."""
    _private_dir(path.parent)
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}-", suffix=".tmp")
    try:
        # ``mkstemp`` already yields 0600 on POSIX; the explicit chmod on the
        # *path* (not ``os.fchmod``, which does not exist on Windows) makes the
        # intent portable without breaking the Windows CI jobs.
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
        try:
            os.chmod(tmp_name, 0o600)
        except OSError:
            pass
        os.replace(tmp_name, path)
    except OSError:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


# ---------------------------------------------------------------------------
# Credential handling
# ---------------------------------------------------------------------------


def _read_key_file() -> str | None:
    path = key_path()
    try:
        if not path.exists():
            return None
        value = path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return value or None


def resolve_api_key() -> str | None:
    """The active key, env first (env wins so a shell can override the file)."""
    env_value = os.environ.get(ORCAROUTER_KEY_ENV, "").strip()
    if env_value:
        return env_value
    return _read_key_file()


def credential_status() -> dict[str, object]:
    """Browser-safe credential state — never the key itself, nor any fragment."""
    if os.environ.get(ORCAROUTER_KEY_ENV, "").strip():
        return {"configured": True, "source": "env", "path": str(key_path())}
    if _read_key_file():
        return {"configured": True, "source": "file", "path": str(key_path())}
    return {"configured": False, "source": None, "path": str(key_path())}


def validate_key_format(value: str) -> str:
    """Reject an obviously wrong paste before it is written to disk.

    Only enforced on the *save* path: an environment variable is treated as
    authoritative (an operator may inject a differently-shaped key), while the
    value we are about to persist should at least look like an OrcaRouter key.
    """
    key = value.strip()
    if not key:
        raise ProviderConfigError("the API key is empty")
    if not key.startswith(ORCAROUTER_KEY_PREFIX):
        raise ProviderConfigError(f"an OrcaRouter API key starts with {ORCAROUTER_KEY_PREFIX!r}")
    if any(ch.isspace() for ch in key):
        raise ProviderConfigError("the API key contains whitespace")
    return key


def save_api_key(value: str) -> None:
    """Persist a key to the per-user 0600 file (never to the repo, never logged)."""
    key = validate_key_format(value)
    _write_private(key_path(), key)


def clear_api_key() -> bool:
    """Delete the stored key file; returns whether one existed."""
    path = key_path()
    try:
        path.unlink()
        return True
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise ProviderConfigError("could not remove the stored OrcaRouter key") from exc


# ---------------------------------------------------------------------------
# Transport
# ---------------------------------------------------------------------------

#: ``(request, timeout) -> (status, body)``. Injected in tests; the default is
#: urllib, so no extra dependency is required.
Opener = Callable[[urllib.request.Request, float], tuple[int, bytes]]

#: Anything shaped like an OrcaRouter key, for scrubbing upstream error text
#: that may quote one back at us (see :func:`_error_message`).
_KEY_LIKE = re.compile(r"sk-orca-[A-Za-z0-9._\-]+")


def _urllib_open(request: urllib.request.Request, timeout: float) -> tuple[int, bytes]:
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            return response.status, _bounded_read(response)
    except urllib.error.HTTPError as exc:
        # HTTPError is also a response: read a bounded slice so an error body
        # can never balloon memory, then re-raise as data so the caller can map
        # the status to a typed provider error.
        try:
            body = _bounded_read(exc)
        except OSError:
            body = b""
        return exc.code, body
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ProviderUnavailableError("could not reach the OrcaRouter API") from exc


def _bounded_read(response: Any, limit: int = _MAX_RESPONSE_BYTES) -> bytes:
    data = response.read(limit + 1)
    if len(data) > limit:
        raise ProviderUnavailableError("the OrcaRouter response was larger than expected")
    return data


def _error_message(body: bytes, key: str) -> str:
    """A short upstream reason with any echoed key scrubbed out."""
    fallback = "the OrcaRouter API returned an error"
    try:
        payload = json.loads(body.decode("utf-8", "replace"))
    except (ValueError, UnicodeDecodeError):
        return fallback
    if not isinstance(payload, dict):
        return fallback
    error = payload.get("error")
    message = ""
    if isinstance(error, dict):
        message = str(error.get("message") or "")
    elif isinstance(error, str):
        message = error
    if not message:
        message = str(payload.get("message") or "")
    message = " ".join(message.split())[:200]
    if key:
        message = message.replace(key, "***")
    # The exact key is not the only thing worth scrubbing: an upstream that
    # echoes *a* key (a proxy in front of it, a stale credential, a body that
    # quotes one in an example) must not get it relayed to the dashboard. This
    # message reaches a browser, so any value shaped like an OrcaRouter key is
    # masked whether or not it is the one we sent.
    message = _KEY_LIKE.sub("***", message)
    return message or fallback


def _raise_for_status(status: int, body: bytes, key: str) -> None:
    if 200 <= status < 300:
        return
    detail = _error_message(body, key)
    if status in (401, 403):
        raise ProviderAuthError(f"OrcaRouter rejected the API key (HTTP {status}): {detail}")
    if status == 429:
        raise ProviderRateLimitError(f"OrcaRouter rate-limited the request: {detail}")
    raise ProviderUnavailableError(f"OrcaRouter returned HTTP {status}: {detail}")


def _decode_json(body: bytes) -> dict[str, Any]:
    try:
        payload = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ProviderUnavailableError("OrcaRouter returned a non-JSON response") from exc
    if not isinstance(payload, dict):
        raise ProviderUnavailableError("OrcaRouter returned an unexpected JSON shape")
    return payload


# ---------------------------------------------------------------------------
# Catalog parsing
# ---------------------------------------------------------------------------


def _str_tuple(value: Any) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    return coerce_modalities([item for item in value if isinstance(item, str)])


def _model_from_payload(item: Any) -> ModelInfo | None:
    """Turn one catalog entry into :class:`ModelInfo`, or ``None`` if unusable.

    Only ``id`` is required: the gateway's smaller entries (e.g.
    ``orcarouter/fusion``) legitimately omit ``architecture``. Missing metadata
    is left empty rather than guessed.
    """
    if not isinstance(item, dict):
        return None
    model_id = item.get("id")
    if not isinstance(model_id, str) or not model_id.strip():
        return None
    architecture = item.get("architecture")
    modalities: tuple[str, ...] = ()
    if isinstance(architecture, dict):
        modalities = _str_tuple(architecture.get("input_modalities"))
    parameters = _str_tuple(item.get("supported_parameters"))
    context_length = item.get("context_length")
    if not isinstance(context_length, int) or context_length <= 0:
        context_length = None
    name = item.get("name")
    return ModelInfo(
        id=model_id.strip(),
        name=str(name).strip() if isinstance(name, str) and name.strip() else model_id,
        context_length=context_length,
        input_modalities=modalities,
        supported_endpoint_types=_str_tuple(item.get("supported_endpoint_types")),
        supports_reasoning="reasoning" in parameters or "include_reasoning" in parameters,
    )


def _matches_capability(model: ModelInfo, capability: str, modalities: Sequence[str]) -> bool:
    endpoints = set(model.supported_endpoint_types)
    if capability == "chat":
        if not endpoints & CHAT_ENDPOINT_TYPES:
            return False
        if endpoints and not (endpoints - NON_CHAT_ENDPOINT_TYPES):
            return False
        if modalities:
            # Fail closed: a model that does not declare its input modalities
            # cannot prove it accepts the attached one.
            if not model.input_modalities:
                return False
            if not set(modalities) <= set(model.input_modalities):
                return False
        return True
    required = REQUIRED_ENDPOINT_TYPE.get(capability)
    if required is None:
        return False
    return required in endpoints


def _sort_models(models: list[ModelInfo]) -> tuple[ModelInfo, ...]:
    return tuple(sorted(models, key=lambda model: model.id))


# ---------------------------------------------------------------------------
# Provider
# ---------------------------------------------------------------------------


class OrcaRouterProvider:
    """Named provider bound to :data:`ORCAROUTER_BASE_URL`.

    Instances are cheap; the catalog cache lives on the instance (the dashboard
    holds one) and the last-known-good copy lives on disk (shared across
    processes). ``opener`` exists so tests can drive the exact request/response
    contract without a socket.
    """

    name = "orcarouter"
    label = "OrcaRouter"
    base_url = ORCAROUTER_BASE_URL

    def __init__(
        self,
        *,
        key: str | None = None,
        opener: Opener | None = None,
        timeout_s: float = _HTTP_TIMEOUT_S,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._explicit_key = key
        self._opener = opener or _urllib_open
        self._timeout_s = timeout_s
        self._clock = clock
        self._cache: dict[tuple[str, tuple[str, ...]], tuple[float, ModelCatalog]] = {}

    # -- credential ---------------------------------------------------------

    def api_key(self) -> str:
        key = self._explicit_key or resolve_api_key()
        if not key:
            raise ProviderConfigError(
                "no OrcaRouter API key configured; set it in the dashboard "
                "or export it in the environment"
            )
        return key

    def configured(self) -> bool:
        return bool(self._explicit_key or resolve_api_key())

    def invalidate_cache(self) -> None:
        """Drop the in-memory catalog cache after a credential/config change."""
        self._cache.clear()

    # -- catalog ------------------------------------------------------------

    def models(
        self,
        capability: str = "chat",
        *,
        modalities: Sequence[str] = (),
        refresh: bool = False,
    ) -> ModelCatalog:
        """Discover models for ``capability`` (see the module table).

        Never raises for a network/auth failure: returns the best available list
        and says where it came from. ``refresh=True`` bypasses the in-memory
        cache but still records the result.
        """
        if capability not in CAPABILITIES:
            raise ProviderConfigError(f"unknown capability {capability!r}")
        wanted = coerce_modalities(modalities)
        cache_key = (capability, wanted)
        now = self._clock()
        if not refresh:
            cached = self._cache.get(cache_key)
            if cached is not None and now - cached[0] < _CACHE_TTL_S:
                return cached[1]

        try:
            catalog = self._fetch_catalog(capability, wanted)
        except ProviderAuthError as exc:
            catalog = self._degraded(capability, wanted, str(exc), auth_failed=True)
        except (ProviderConfigError, ProviderRateLimitError, ProviderUnavailableError) as exc:
            catalog = self._degraded(capability, wanted, str(exc), auth_failed=False)
        self._cache[cache_key] = (now, catalog)
        return catalog

    def _fetch_catalog(self, capability: str, modalities: tuple[str, ...]) -> ModelCatalog:
        url = f"{ORCAROUTER_BASE_URL}/models?capability={capability}"
        request = urllib.request.Request(  # noqa: S310 — constant https base, not user input
            url,
            headers={
                "Accept": "application/json",
                "User-Agent": _user_agent(),
            },
            method="GET",
        )
        key = self._explicit_key or resolve_api_key() or ""
        if key:
            request.add_header("Authorization", f"Bearer {key}")
        try:
            status, body = self._opener(request, self._timeout_s)
        except ProviderUnavailableError:
            raise
        except OSError as exc:
            raise ProviderUnavailableError("could not reach the OrcaRouter API") from exc
        _raise_for_status(status, body, key)
        if len(body) > _MAX_CATALOG_BYTES:
            raise ProviderUnavailableError("the OrcaRouter catalog was larger than expected")
        payload = _decode_json(body)
        data = payload.get("data")
        if not isinstance(data, list):
            raise ProviderUnavailableError("OrcaRouter returned no model list")

        models: list[ModelInfo] = []
        for item in data[:_MAX_MODELS]:
            model = _model_from_payload(item)
            if model is not None and _matches_capability(model, capability, modalities):
                models.append(model)
        if not models:
            # An empty list is a real answer for capability=video/rerank today,
            # but for chat it means the shape/filters changed - treat that as a
            # failed discovery so the caller still gets a labeled fallback.
            if capability == "chat":
                raise ProviderUnavailableError("OrcaRouter's catalog listed no usable chat models")
            return ModelCatalog(models=(), source="live", detail=f"{capability}: 0 models")
        catalog = ModelCatalog(models=_sort_models(models), source="live")
        self._save_last_known_good(modalities, catalog)
        return catalog

    def _degraded(
        self, capability: str, modalities: tuple[str, ...], error: str, *, auth_failed: bool
    ) -> ModelCatalog:
        if capability == "chat":
            cached = self._load_last_known_good(modalities)
            if cached:
                return ModelCatalog(
                    models=cached,
                    source="last_known_good",
                    detail="showing the last catalog fetched successfully",
                    error=error,
                    auth_failed=auth_failed,
                )
            seeds = tuple(
                model for model in SEED_MODELS if _matches_capability(model, "chat", modalities)
            )
            return ModelCatalog(
                models=_sort_models(list(seeds)),
                source="seed",
                detail="showing a small verified seed list; not the live catalog",
                error=error,
                auth_failed=auth_failed,
            )
        return ModelCatalog(
            models=(),
            source="seed",
            detail=f"no verified seed exists for {capability}",
            error=error,
            auth_failed=auth_failed,
        )

    # -- last-known-good cache ---------------------------------------------

    def _save_last_known_good(self, modalities: tuple[str, ...], catalog: ModelCatalog) -> None:
        payload = {
            "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "modalities": list(modalities),
            "models": [
                {
                    "id": model.id,
                    "name": model.name,
                    "context_length": model.context_length,
                    "input_modalities": list(model.input_modalities),
                    "supported_endpoint_types": list(model.supported_endpoint_types),
                    "supports_reasoning": model.supports_reasoning,
                }
                for model in catalog.models
            ],
        }
        try:
            _write_private(catalog_cache_path(), json.dumps(payload))
        except OSError:
            # A cache write failure must not turn a successful fetch into an
            # error; the next fetch simply has no fallback.
            pass

    def _load_last_known_good(self, modalities: tuple[str, ...]) -> tuple[ModelInfo, ...]:
        path = catalog_cache_path()
        try:
            if not path.exists():
                return ()
            raw = path.read_text(encoding="utf-8")
        except OSError:
            return ()
        if len(raw) > _MAX_CATALOG_BYTES:
            return ()
        try:
            payload = json.loads(raw)
        except ValueError:
            return ()
        if not isinstance(payload, dict):
            return ()
        cached_modalities = _str_tuple(payload.get("modalities"))
        if not set(modalities) <= set(cached_modalities):
            return ()
        entries = payload.get("models")
        if not isinstance(entries, list):
            return ()
        models: list[ModelInfo] = []
        for entry in entries[:_MAX_MODELS]:
            model = _model_from_payload(entry)
            if model is not None and _matches_capability(model, "chat", modalities):
                models.append(model)
        return _sort_models(models)

    # -- completions --------------------------------------------------------

    def chat(self, request: ChatRequest) -> ChatResult:
        """One chat completion. Raises a typed :class:`ProviderError` on failure."""
        key = self.api_key()
        body = {
            "model": request.model,
            "messages": [
                {"role": "system", "content": request.system},
                {"role": "user", "content": request.user},
            ],
            "max_tokens": max(1, int(request.max_tokens)),
            "stream": False,
        }
        http_request = urllib.request.Request(  # noqa: S310 — constant https base, not user input
            f"{ORCAROUTER_BASE_URL}/chat/completions",
            data=json.dumps(body).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": _user_agent(),
            },
            method="POST",
        )
        try:
            status, raw = self._opener(http_request, request.timeout_s)
        except ProviderUnavailableError:
            raise
        except OSError as exc:
            raise ProviderUnavailableError("could not reach the OrcaRouter API") from exc
        _raise_for_status(status, raw, key)
        payload = _decode_json(raw)
        text = _completion_text(payload)
        if not text:
            raise ProviderUnavailableError("OrcaRouter returned an empty completion")
        return ChatResult(text=text, model=request.model, provider=self.name)


def _completion_text(payload: dict[str, Any]) -> str:
    """Extract assistant text from an OpenAI-shaped completion.

    Accepts both a plain string ``content`` and the newer list-of-parts form;
    anything else is a malformed response.
    """
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        raise ProviderUnavailableError("OrcaRouter returned no choices")
    first = choices[0]
    if not isinstance(first, dict):
        raise ProviderUnavailableError("OrcaRouter returned a malformed choice")
    message = first.get("message")
    if not isinstance(message, dict):
        raise ProviderUnavailableError("OrcaRouter returned no message")
    content = message.get("content")
    if isinstance(content, str):
        return content.strip()
    if isinstance(content, list):
        parts = [
            part.get("text", "")
            for part in content
            if isinstance(part, dict) and part.get("type") in (None, "text")
        ]
        return "".join(str(part) for part in parts).strip()
    return ""


def _user_agent() -> str:
    try:
        from doberman import __version__

        return f"doberman/{__version__}"
    except Exception:  # noqa: BLE001 — the header is cosmetic; never fail a request for it
        return "doberman"


# ---------------------------------------------------------------------------
# Model selection
# ---------------------------------------------------------------------------


def default_model(catalog: ModelCatalog | None = None) -> str:
    """The model to preselect: the recommended one when the account offers it.

    ``orcacyber-zero`` is OrcaRouter's recommended model for security work but is
    not in the public catalog (business verification), so it is chosen only when
    the discovered catalog really contains it; otherwise the public fallback is
    used. A caller with no catalog at all gets the fallback too.
    """
    if catalog is not None:
        ids = set(catalog.ids())
        if RECOMMENDED_MODEL in ids:
            return RECOMMENDED_MODEL
    return FALLBACK_MODEL


def model_is_available(model_id: str, catalog: ModelCatalog) -> bool:
    return model_id in set(catalog.ids())
