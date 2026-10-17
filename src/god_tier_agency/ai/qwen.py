"""Qwen client — God-Tier v5.0.

Cliente DashScope OpenAI-compatible con:
    - Pre-flight validation (context length, tokens)
    - Per-instance cache + circuit breaker (NO shared)
    - Streaming con timeout + cleanup
    - Retry-After respetado
    - Cost con Decimal
    - Vision support (qwen-vl-max)
    - SIEM-ready

God-Tier v5.0 — diferenciadores vs v4.0:

FIX BLOQUEANTES:
    - FIX #1: CircuitBreaker PER-INSTANCE
    - FIX #2: ResponseCache PER-INSTANCE
    - FIX #3: RateLimitError captura Retry-After
    - FIX #4: Streaming captura RateLimitError específico
    - FIX #5: _validate_request usa estimate_tokens()

FIX QWEN-ESPECÍFICOS:
    - FIX #6: chat_vision() método REAL para vision
    - FIX #7: qwen-vl-max auto-detectado
    - FIX #8: frequency_penalty + presence_penalty pasados
    - FIX #9: max_context_tokens = 128_000 (Qwen-max real)

OTROS:
    - AIContentFilteredError handling
    - Cost con Decimal
    - trace_id + correlation_id + engagement_id
    - content_hash en logs (no content raw)
    - to_prometheus()
    - VALID_MODELS validation
    - __repr__
    - health_check override

Filosofía:
    - PER-INSTANCE state
    - Retry-After respetado
    - Vision funcional
    - Forense sin content raw
    - Fail-closed
"""

from __future__ import annotations

import asyncio
import time
from decimal import Decimal
from typing import Any, AsyncIterator
from uuid import UUID

from openai import (
    APIConnectionError,
    APIStatusError,
    APITimeoutError,
    AsyncOpenAI,
    RateLimitError,
)

from god_tier_agency.ai._resilience import (
    CircuitBreaker,
    ResponseCache,
    parse_retry_after,
)
from god_tier_agency.ai.base import (
    AIClient,
    AIContentFilteredError,
    AIContextLengthError,
    AIInvalidResponseError,
    AIProviderDownError,
    AIRateLimitError,
    AITimeoutError,
    ChatMessage,
    ChatRequest,
    FinishReason,
    LLMResponse,
    MessageRole,
    ModelCapabilities,
)
from god_tier_agency.config import settings
from god_tier_agency.core.context import get_context
from god_tier_agency.core.exceptions import AIError
from god_tier_agency.core.logging import get_logger

_log = get_logger("ai.qwen")


# ============================================================================
# CONSTANTES
# ============================================================================

# Pricing (USD per 1M tokens) — Qwen-max actualizado
PRICE_INPUT_PER_M: Decimal = Decimal("0.40")
PRICE_OUTPUT_PER_M: Decimal = Decimal("1.20")

# FIX #6, #7: modelos válidos + context limits por modelo
VALID_MODELS: dict[str, int] = {
    "qwen-max": 128_000,            # FIX #9: 128K real
    "qwen-max-latest": 128_000,
    "qwen-plus": 128_000,
    "qwen-turbo": 1_000_000,
    "qwen-long": 10_000_000,
    "qwen-vl-max": 32_000,          # FIX #7
    "qwen-vl-plus": 32_000,
    "qwen2.5-72b-instruct": 128_000,
}

# Timeouts
DEFAULT_CONNECT_TIMEOUT: float = 10.0
DEFAULT_READ_TIMEOUT: float = 120.0
STREAM_CHUNK_TIMEOUT: float = 60.0

# Circuit breaker
DEFAULT_CIRCUIT_THRESHOLD: int = 5
DEFAULT_CIRCUIT_OPEN_SECONDS: float = 60.0

# Cache
DEFAULT_CACHE_MAX_ENTRIES: int = 1000
DEFAULT_CACHE_TTL_SECONDS: float = 3600.0


# ============================================================================
# CLIENT
# ============================================================================

class QwenClient(AIClient):
    """Cliente Qwen con DashScope OpenAI-compatible API.

    God-Tier v5.0:
        - Per-instance cache + circuit breaker
        - Vision support funcional
        - Retry-After respetado
        - Streaming con timeout
    """

    def __init__(
        self,
        *,
        api_key: str | None = None,
        base_url: str | None = None,
        model: str = "qwen-max",
        enable_cache: bool = True,
        cache_max_entries: int = DEFAULT_CACHE_MAX_ENTRIES,
        cache_ttl_seconds: float = DEFAULT_CACHE_TTL_SECONDS,
        connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
        read_timeout: float = DEFAULT_READ_TIMEOUT,
        circuit_threshold: int = DEFAULT_CIRCUIT_THRESHOLD,
        circuit_open_seconds: float = DEFAULT_CIRCUIT_OPEN_SECONDS,
    ) -> None:
        # FIX #19: validar modelo
        if model not in VALID_MODELS:
            raise ValueError(
                f"Modelo Qwen inválido: {model!r}. "
                f"Válidos: {sorted(VALID_MODELS.keys())}"
            )

        # API key
        key = (
            api_key
            or settings.qwen_api_key.get_secret_value()
        )
        if not key:
            raise ValueError("Qwen API key no configurada")

        # FIX #20: validar base_url
        url = base_url or settings.qwen_base_url
        if not url:
            raise ValueError("Qwen base_url no configurada")
        if not url.startswith(("https://", "http://")):
            raise ValueError(f"base_url debe usar http(s): {url!r}")
        if not url.startswith("https://") and "localhost" not in url:
            _log.warning("qwen_insecure_base_url", base_url=url)

        # Cliente OpenAI
        self._client = AsyncOpenAI(
            api_key=key,
            base_url=url,
            timeout=read_timeout,
            max_retries=0,
        )

        # Config
        self._model = model
        self._enable_cache = enable_cache
        self._max_context = VALID_MODELS[model]

        # FIX #1: CircuitBreaker PER-INSTANCE
        self._circuit = CircuitBreaker(
            threshold=circuit_threshold,
            open_seconds=circuit_open_seconds,
            provider="qwen",
        )

        # FIX #2: ResponseCache PER-INSTANCE
        self._cache: ResponseCache | None = (
            ResponseCache(
                max_entries=cache_max_entries,
                ttl=cache_ttl_seconds,
            )
            if enable_cache
            else None
        )

    # ------------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------------

    @property
    def model_name(self) -> str:
        return self._model

    @property
    def provider(self) -> str:
        return "qwen"

    @property
    def capabilities(self) -> ModelCapabilities:
        is_vl = "vl" in self._model.lower()
        return ModelCapabilities(
            supports_json_mode=True,
            supports_streaming=True,
            supports_function_calling=True,
            supports_vision=is_vl,  # FIX #6: solo si es vl model
            supports_system_prompt=True,
            supports_seed=False,  # Qwen no soporta seed consistentemente
            supports_stop_sequences=True,
            max_context_tokens=self._max_context,  # FIX #9
            max_output_tokens=8_192,
            price_input_per_m=float(PRICE_INPUT_PER_M),
            price_output_per_m=float(PRICE_OUTPUT_PER_M),
            provider="qwen",
            model_family="qwen",
        )

    # ------------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------------

    def _validate_request(self, request: ChatRequest) -> None:
        """Pre-flight validation."""
        is_compatible, reason = self.capabilities.is_compatible_with(request)
        if not is_compatible:
            raise AIError(
                f"Request incompatible con qwen: {reason}",
                context={"provider": "qwen", "reason": reason},
            )

        # FIX #5: usar método centralizado
        input_tokens = request.estimate_tokens()
        output_tokens = request.max_tokens
        max_ctx = self._max_context

        if input_tokens + output_tokens > max_ctx:
            raise AIContextLengthError(
                f"Request excede context window: "
                f"{input_tokens + output_tokens} > {max_ctx}",
                context={
                    "provider": "qwen",
                    "model": self._model,
                    "input_tokens": input_tokens,
                    "max_output": output_tokens,
                    "max_context": max_ctx,
                },
            )

    # ------------------------------------------------------------------------
    # Chat (sync)
    # ------------------------------------------------------------------------

    async def chat(self, request: ChatRequest) -> LLMResponse:
        """Chat completion con fallback, cache, y circuit breaker."""
        # 1. Pre-flight
        self._validate_request(request)

        # 2. Circuit breaker
        if self._circuit.is_open():
            raise AIProviderDownError(
                "Qwen circuit breaker abierto",
                context={
                    "provider": "qwen",
                    "circuit": self._circuit.status().to_dict(),
                },
            )

        # 3. Cache lookup
        use_cache = (
            self._cache is not None
            and request.temperature <= 0.01
        )
        if use_cache and self._cache is not None:
            cached = self._cache.get(request, self._model)
            if cached is not None:
                _log.info(
                    "qwen_cache_hit",
                    provider="qwen",
                    correlation_id=get_context().get("correlation_id"),
                )
                return cached

        # 4. Llamada real
        start = time.perf_counter()
        try:
            kwargs = self._build_kwargs(request)
            resp = await self._client.chat.completions.create(**kwargs)

        except RateLimitError as e:
            # FIX #3: Retry-After capturado
            retry_after = parse_retry_after(
                e.response.headers.get("retry-after")
                if e.response is not None else None
            )
            self._circuit.record_failure()
            raise AIRateLimitError(
                f"Qwen rate limit: {e}",
                retry_after_seconds=retry_after,
                context={
                    "provider": "qwen",
                    "retry_after_seconds": retry_after,
                },
            ) from e

        except APITimeoutError as e:
            self._circuit.record_failure()
            raise AITimeoutError(
                f"Qwen timeout después de {request.timeout_seconds}s",
                context={
                    "provider": "qwen",
                    "timeout_seconds": request.timeout_seconds,
                },
            ) from e

        except APIConnectionError as e:
            self._circuit.record_failure()
            raise AIProviderDownError(
                f"Qwen no accesible: {e}",
                context={"provider": "qwen"},
            ) from e

        except APIStatusError as e:
            # FIX #10: content filter
            if e.status_code == 400 and "content_filter" in str(e).lower():
                self._circuit.record_failure()
                raise AIContentFilteredError(
                    f"Qwen content filter: {e}",
                    context={"provider": "qwen"},
                ) from e

            if e.status_code == 400 and "context" in str(e).lower():
                raise AIContextLengthError(
                    f"Qwen context length excedido: {e}",
                    context={"provider": "qwen"},
                ) from e

            if e.status_code >= 500:
                self._circuit.record_failure()

            raise AIError(
                f"Qwen API error {e.status_code}: {e}",
                context={
                    "provider": "qwen",
                    "status_code": e.status_code,
                },
                retryable=e.status_code >= 500,
            ) from e

        except Exception as e:
            self._circuit.record_failure()
            raise AIError(
                f"Qwen error inesperado: {type(e).__name__}: {e}",
                context={"provider": "qwen"},
                retryable=True,
            ) from e

        # 5. Success
        self._circuit.record_success()

        if not resp.choices:
            raise AIInvalidResponseError(
                "Qwen devolvió respuesta sin choices",
                context={"provider": "qwen"},
            )

        latency_ms = (time.perf_counter() - start) * 1000
        response = self._build_response(resp, latency_ms, request)

        # 6. Cache store
        if use_cache and self._cache is not None:
            self._cache.set(request, self._model, response)

        # 7. Log forense
        self._log_response(response, request)

        return response

    # ------------------------------------------------------------------------
    # Vision (FIX #6, #7)
    # ------------------------------------------------------------------------

    async def chat_vision(
        self,
        image_url: str,
        prompt: str,
        *,
        request: ChatRequest | None = None,
    ) -> LLMResponse:
        """Chat con imagen (solo modelos vl-*).

        FIX #6, #7: método REAL para vision.
        """
        if not self.capabilities.supports_vision:
            raise AIError(
                f"Modelo {self._model} no soporta vision. "
                f"Usa qwen-vl-max o qwen-vl-plus.",
                context={"provider": "qwen", "model": self._model},
            )

        # Construir request con imagen
        if request is None:
            request = ChatRequest(
                messages=[
                    ChatMessage(
                        role=MessageRole.USER,
                        content=prompt,
                        metadata={"image_url": image_url},
                    ),
                ],
                max_tokens=2000,
            )

        self._validate_request(request)

        if self._circuit.is_open():
            raise AIProviderDownError(
                "Qwen circuit breaker abierto",
                context={"provider": "qwen"},
            )

        # Construir messages con imagen
        messages = []
        if request.system:
            messages.append({"role": "system", "content": request.system})
        for m in request.messages:
            if m.metadata.get("image_url"):
                messages.append({
                    "role": m.role.value,
                    "content": [
                        {"type": "text", "text": m.content},
                        {
                            "type": "image_url",
                            "image_url": {"url": m.metadata["image_url"]},
                        },
                    ],
                })
            else:
                messages.append(m.to_openai_dict())

        start = time.perf_counter()
        try:
            resp = await self._client.chat.completions.create(
                model=self._model,
                messages=messages,
                temperature=request.temperature,
                max_tokens=request.max_tokens,
            )
        except Exception as e:
            self._circuit.record_failure()
            raise AIError(
                f"Qwen vision error: {type(e).__name__}: {e}",
                context={"provider": "qwen"},
                retryable=True,
            ) from e

        self._circuit.record_success()
        latency_ms = (time.perf_counter() - start) * 1000
        return self._build_response(resp, latency_ms, request)

    # ------------------------------------------------------------------------
    # Chat streaming
    # ------------------------------------------------------------------------

    async def chat_stream(self, request: ChatRequest) -> AsyncIterator[str]:
        """Chat streaming con timeout + cleanup (FIX #4)."""
        self._validate_request(request)

        if self._circuit.is_open():
            raise AIProviderDownError(
                "Qwen circuit breaker abierto",
                context={"provider": "qwen"},
            )

        # FIX #8: incluir frequency_penalty + presence_penalty
        kwargs: dict[str, Any] = {
            "model": self._model,
            "messages": request.to_openai_messages(),
            "temperature": request.temperature,
            "max_tokens": request.max_tokens,
            "top_p": request.top_p,
            "frequency_penalty": request.frequency_penalty,
            "presence_penalty": request.presence_penalty,
            "stream": True,
            "stream_options": {"include_usage": True},  # FIX #14
        }
        if request.response_format_json:
            kwargs["response_format"] = {"type": "json_object"}
        if request.stop:
            kwargs["stop"] = request.stop

        stream = None
        try:
            stream = await self._client.chat.completions.create(**kwargs)

            async for chunk in stream:
                if chunk.choices and chunk.choices[0].delta.content:
                    yield chunk.choices[0].delta.content

            self._circuit.record_success()

        except RateLimitError as e:
            # FIX #4: RateLimitError específico
            retry_after = parse_retry_after(
                e.response.headers.get("retry-after")
                if e.response is not None else None
            )
            self._circuit.record_failure()
            raise AIRateLimitError(
                f"Qwen streaming rate limit: {e}",
                retry_after_seconds=retry_after,
                context={"provider": "qwen"},
            ) from e

        except APITimeoutError as e:
            self._circuit.record_failure()
            raise AITimeoutError(
                "Qwen streaming timeout",
                context={"provider": "qwen"},
            ) from e

        except APIConnectionError as e:
            self._circuit.record_failure()
            raise AIProviderDownError(
                f"Qwen streaming connection error: {e}",
                context={"provider": "qwen"},
            ) from e

        except Exception as e:
            self._circuit.record_failure()
            raise AIError(
                f"Qwen streaming error: {type(e).__name__}: {e}",
                context={"provider": "qwen"},
                retryable=True,
            ) from e

        finally:
            # FIX #13: cleanup
            if stream is not None:
                try:
                    await stream.close()
                except Exception:
                    pass

    # ------------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------------

    def _build_kwargs(self, request: ChatRequest) -> dict[str, Any]:
        """Construye kwargs para OpenAI SDK."""
        kwargs: dict[str, Any] = {
            "model": self._model,
            "messages": request.to_openai_messages(),
            "temperature": request.temperature,
            "max_tokens": request.max_tokens,
            "top_p": request.top_p,
            "frequency_penalty": request.frequency_penalty,  # FIX #8
            "presence_penalty": request.presence_penalty,    # FIX #8
        }
        if request.response_format_json:
            kwargs["response_format"] = {"type": "json_object"}
        if request.stop:
            kwargs["stop"] = request.stop
        # Qwen NO soporta seed consistentemente
        return kwargs

    def _build_response(
        self,
        resp: Any,
        latency_ms: float,
        request: ChatRequest,
    ) -> LLMResponse:
        """Construye LLMResponse desde OpenAI response."""
        usage = resp.usage
        if usage is None:
            raise AIInvalidResponseError(
                "Qwen response sin usage",
                context={"provider": "qwen"},
            )

        prompt_tokens = usage.prompt_tokens or 0
        completion_tokens = usage.completion_tokens or 0
        total_tokens = usage.total_tokens or (prompt_tokens + completion_tokens)

        cost = self._estimate_cost(prompt_tokens, completion_tokens)

        finish_reason_str = resp.choices[0].finish_reason or "stop"
        try:
            finish_reason = FinishReason(finish_reason_str)
        except ValueError:
            finish_reason = FinishReason.UNKNOWN

        ctx = get_context()

        return LLMResponse(
            content=resp.choices[0].message.content or "",
            model=self._model,
            provider=self.provider,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            cost_usd=float(cost),
            latency_ms=latency_ms,
            finish_reason=finish_reason,
            trace_id=request.trace_id or ctx.get("trace_id"),
            correlation_id=ctx.get("correlation_id"),
            engagement_id=request.engagement_id or ctx.get("engagement_id"),
        )

    def _estimate_cost(
        self,
        prompt_tokens: int,
        completion_tokens: int,
    ) -> Decimal:
        """Cost con Decimal."""
        input_cost = (
            Decimal(prompt_tokens) * PRICE_INPUT_PER_M / Decimal("1000000")
        )
        output_cost = (
            Decimal(completion_tokens) * PRICE_OUTPUT_PER_M / Decimal("1000000")
        )
        return input_cost + output_cost

    def _log_response(
        self,
        response: LLMResponse,
        request: ChatRequest,
    ) -> None:
        """Log forense SIN content raw."""
        ctx = get_context()
        _log.info(
            "qwen_response",
            provider="qwen",
            model=response.model,
            tokens=response.total_tokens,
            prompt_tokens=response.prompt_tokens,
            completion_tokens=response.completion_tokens,
            cost_usd=round(response.cost_usd, 6),
            latency_ms=round(response.latency_ms, 2),
            finish_reason=response.finish_reason.value,
            content_hash=response.content_hash,
            request_temp=request.temperature,
            request_max_tokens=request.max_tokens,
            correlation_id=ctx.get("correlation_id"),
            engagement_id=ctx.get("engagement_id"),
            trace_id=response.trace_id,
        )

    # ------------------------------------------------------------------------
    # Health check
    # ------------------------------------------------------------------------

    async def health_check(self, timeout_seconds: float = 10.0) -> bool:
        """Health check con ping ligero."""
        try:
            resp = await self._client.chat.completions.create(
                model=self._model,
                messages=[{"role": "user", "content": "ping"}],
                max_tokens=1,
                timeout=timeout_seconds,
            )
            return bool(resp.choices)
        except Exception as e:
            _log.debug("qwen_health_check_failed", error=str(e)[:200])
            return False

    # ------------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------------

    def cache_stats(self) -> dict[str, Any] | None:
        if self._cache is None:
            return None
        return self._cache.stats()

    def circuit_status(self) -> dict[str, Any]:
        return self._circuit.status().to_dict()

    def reset_circuit(self) -> None:
        self._circuit.reset()
        _log.info("qwen_circuit_reset", provider="qwen")

    def to_prometheus(self, namespace: str = "godtier_qwen") -> str:
        status = self._circuit.status()
        cache = self.cache_stats()
        lines = [
            f'{namespace}_circuit_open {1 if status.is_open else 0}',
            f'{namespace}_circuit_failures {status.failures}',
            f'{namespace}_circuit_opens_total {status.total_opens}',
        ]
        if cache:
            lines.append(f'{namespace}_cache_hits {cache["hits"]}')
            lines.append(f'{namespace}_cache_misses {cache["misses"]}')
            lines.append(f'{namespace}_cache_size {cache["size"]}')
        return "\n".join(lines)

    def __repr__(self) -> str:
        return (
            f"QwenClient(model={self._model!r}, "
            f"cache={'on' if self._cache else 'off'}, "
            f"circuit_open={self._circuit.is_open()})"
        )


__all__ = [
    "QwenClient",
    "PRICE_INPUT_PER_M",
    "PRICE_OUTPUT_PER_M",
    "VALID_MODELS",
    "DEFAULT_CONNECT_TIMEOUT",
    "DEFAULT_READ_TIMEOUT",
]
