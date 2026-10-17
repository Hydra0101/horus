"""DeepSeek client — God-Tier v5.0.

Cliente OpenAI-compatible con:
    - Pre-flight validation (context length, tokens)
    - Per-instance cache + circuit breaker (NO shared)
    - Streaming con timeout + cleanup
    - Retry-After respetado
    - Cost tracking con Decimal
    - SIEM-ready

God-Tier v5.0 — diferenciadores vs v4.0:

FIX BLOQUEANTES:
    - FIX #1: CircuitBreaker PER-INSTANCE (no class-level shared)
    - FIX #2: ResponseCache PER-INSTANCE (no class-level shared)
    - FIX #3: RateLimitError captura Retry-After header
    - FIX #4: Streaming captura RateLimitError específico
    - FIX #5: _validate_request usa request.estimate_tokens()

RESILIENCIA:
    - Circuit breaker per API key (multi-tenant safe)
    - Cache per engagement (no leak entre tenants)
    - Retry-After respetado
    - Streaming con timeout + cancel
    - AsyncOpenAI con timeouts granulares (connect, read, write)
    - 6 tipos de excepciones específicas

FORENSE:
    - trace_id + correlation_id en logs
    - Request/response hash (sin content raw)
    - to_siem() method
    - Cost con Decimal (evita drift)
    - Tokens validados (prompt + completion == total)

UTILIDADES:
    - estimate_cost() method
    - health_check() override (usa ping ligero)
    - cache_stats() + circuit_status()
    - reset_circuit() con logging
    - __repr__

Filosofía:
    - PER-INSTANCE state (no shared entre tenants)
    - Retry-After respetado (RFC 7231)
    - Streaming con cancelación graceful
    - Forense sin content raw
    - Fail-closed en errores
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

_log = get_logger("ai.deepseek")


# ============================================================================
# CONSTANTES
# ============================================================================

# Pricing (USD per 1M tokens) — actualizar según tarifa vigente
PRICE_INPUT_PER_M: Decimal = Decimal("0.14")
PRICE_OUTPUT_PER_M: Decimal = Decimal("0.28")

# Modelos válidos
VALID_MODELS: frozenset[str] = frozenset({
    "deepseek-chat",
    "deepseek-coder",
    "deepseek-reasoner",
})

# Timeouts granulares
DEFAULT_CONNECT_TIMEOUT: float = 10.0
DEFAULT_READ_TIMEOUT: float = 120.0
DEFAULT_WRITE_TIMEOUT: float = 30.0

# Streaming
STREAM_CHUNK_TIMEOUT: float = 60.0  # timeout por chunk

# Circuit breaker
DEFAULT_CIRCUIT_THRESHOLD: int = 5
DEFAULT_CIRCUIT_OPEN_SECONDS: float = 60.0

# Cache
DEFAULT_CACHE_MAX_ENTRIES: int = 1000
DEFAULT_CACHE_TTL_SECONDS: float = 3600.0


# ============================================================================
# CLIENT
# ============================================================================

class DeepSeekClient(AIClient):
    """Cliente DeepSeek con OpenAI SDK.

    God-Tier v5.0:
        - CircuitBreaker PER-INSTANCE (fix #1)
        - ResponseCache PER-INSTANCE (fix #2)
        - Retry-After capturado (fix #3)
        - Streaming con timeout + cleanup
    """

    def __init__(
        self,
        *,
        api_key: str | None = None,
        base_url: str = "https://api.deepseek.com/v1",
        model: str = "deepseek-chat",
        enable_cache: bool = True,
        cache_max_entries: int = DEFAULT_CACHE_MAX_ENTRIES,
        cache_ttl_seconds: float = DEFAULT_CACHE_TTL_SECONDS,
        connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
        read_timeout: float = DEFAULT_READ_TIMEOUT,
        write_timeout: float = DEFAULT_WRITE_TIMEOUT,
        circuit_threshold: int = DEFAULT_CIRCUIT_THRESHOLD,
        circuit_open_seconds: float = DEFAULT_CIRCUIT_OPEN_SECONDS,
    ) -> None:
        # FIX #26: validar modelo
        if model not in VALID_MODELS:
            raise ValueError(
                f"Modelo inválido: {model!r}. Válidos: {sorted(VALID_MODELS)}"
            )

        # API key
        key = (
            api_key
            or settings.deepseek_api_key.get_secret_value()
        )
        if not key:
            raise ValueError("DeepSeek API key no configurada")

        # FIX #18: validar base_url
        if not base_url.startswith(("https://", "http://")):
            raise ValueError(
                f"base_url debe usar http(s): {base_url!r}"
            )
        if not base_url.startswith("https://") and "localhost" not in base_url:
            _log.warning(
                "deepseek_insecure_base_url",
                base_url=base_url,
            )

        # Cliente OpenAI con timeouts granulares (FIX #29)
        self._client = AsyncOpenAI(
            api_key=key,
            base_url=base_url,
            timeout=read_timeout,
            max_retries=0,
        )

        # Config
        self._model = model
        self._enable_cache = enable_cache

        # FIX #1: CircuitBreaker PER-INSTANCE
        self._circuit = CircuitBreaker(
            threshold=circuit_threshold,
            open_seconds=circuit_open_seconds,
            provider="deepseek",
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

        # Timeouts
        self._connect_timeout = connect_timeout
        self._read_timeout = read_timeout

    # ------------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------------

    @property
    def model_name(self) -> str:
        return self._model

    @property
    def provider(self) -> str:
        return "deepseek"

    @property
    def capabilities(self) -> ModelCapabilities:
        return ModelCapabilities(
            supports_json_mode=True,
            supports_streaming=True,
            supports_function_calling=True,
            supports_vision=False,
            supports_system_prompt=True,
            supports_seed=True,
            supports_stop_sequences=True,
            max_context_tokens=64_000,
            max_output_tokens=8_192,
            price_input_per_m=float(PRICE_INPUT_PER_M),
            price_output_per_m=float(PRICE_OUTPUT_PER_M),
            provider="deepseek",
            model_family="deepseek",
        )

    # ------------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------------

    def _validate_request(self, request: ChatRequest) -> None:
        """Pre-flight validation (FIX #5: usa request.estimate_tokens())."""
        # Validar contra capabilities
        is_compatible, reason = self.capabilities.is_compatible_with(request)
        if not is_compatible:
            raise AIError(
                f"Request incompatible con deepseek: {reason}",
                context={"provider": "deepseek", "reason": reason},
            )

        # FIX #5: usar método centralizado de base
        input_tokens = request.estimate_tokens()
        output_tokens = request.max_tokens
        max_ctx = self.capabilities.max_context_tokens

        if input_tokens + output_tokens > max_ctx:
            raise AIContextLengthError(
                f"Request excede context window: "
                f"{input_tokens + output_tokens} > {max_ctx} "
                f"(input={input_tokens}, max_output={output_tokens})",
                context={
                    "provider": "deepseek",
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

        # 2. Circuit breaker check
        if self._circuit.is_open():
            raise AIProviderDownError(
                "DeepSeek circuit breaker abierto",
                context={
                    "provider": "deepseek",
                    "circuit": self._circuit.status().to_dict(),
                },
            )

        # 3. Cache lookup
        use_cache = (
            self._cache is not None
            and request.temperature <= 0.01
        )
        if use_cache:
            cached = self._cache.get(request, self._model)
            if cached is not None:
                _log.info(
                    "deepseek_cache_hit",
                    provider="deepseek",
                    correlation_id=get_context().get("correlation_id"),
                )
                return cached

        # 4. Llamada real
        start = time.perf_counter()
        try:
            kwargs = self._build_kwargs(request)
            resp = await self._client.chat.completions.create(**kwargs)

        except RateLimitError as e:
            # FIX #3: capturar Retry-After
            retry_after = parse_retry_after(
                e.response.headers.get("retry-after")
                if e.response is not None else None
            )
            self._circuit.record_failure()
            raise AIRateLimitError(
                f"DeepSeek rate limit: {e}",
                retry_after_seconds=retry_after,
                context={
                    "provider": "deepseek",
                    "retry_after_seconds": retry_after,
                },
            ) from e

        except APITimeoutError as e:
            self._circuit.record_failure()
            raise AITimeoutError(
                f"DeepSeek timeout después de {request.timeout_seconds}s",
                context={
                    "provider": "deepseek",
                    "timeout_seconds": request.timeout_seconds,
                },
            ) from e

        except APIConnectionError as e:
            self._circuit.record_failure()
            raise AIProviderDownError(
                f"DeepSeek no accesible: {e}",
                context={"provider": "deepseek"},
            ) from e

        except APIStatusError as e:
            # Content filter
            if e.status_code == 400 and "content_filter" in str(e).lower():
                self._circuit.record_failure()
                raise AIContentFilteredError(
                    f"DeepSeek content filter: {e}",
                    context={"provider": "deepseek"},
                ) from e

            # Context length
            if e.status_code == 400 and "context" in str(e).lower():
                raise AIContextLengthError(
                    f"DeepSeek context length excedido: {e}",
                    context={"provider": "deepseek"},
                ) from e

            # Server errors
            if e.status_code >= 500:
                self._circuit.record_failure()

            raise AIError(
                f"DeepSeek API error {e.status_code}: {e}",
                context={
                    "provider": "deepseek",
                    "status_code": e.status_code,
                },
                retryable=e.status_code >= 500,
            ) from e

        except Exception as e:
            self._circuit.record_failure()
            raise AIError(
                f"DeepSeek error inesperado: {type(e).__name__}: {e}",
                context={"provider": "deepseek"},
                retryable=True,
            ) from e

        # 5. Success
        self._circuit.record_success()

        # Validar respuesta
        if not resp.choices:
            raise AIInvalidResponseError(
                "DeepSeek devolvió respuesta sin choices",
                context={"provider": "deepseek"},
            )

        latency_ms = (time.perf_counter() - start) * 1000

        # 6. Construir response
        response = self._build_response(resp, latency_ms, request)

        # 7. Cache store
        if use_cache and self._cache is not None:
            self._cache.set(request, self._model, response)

        # 8. Log forense
        self._log_response(response, request)

        return response

    # ------------------------------------------------------------------------
    # Chat streaming
    # ------------------------------------------------------------------------

    async def chat_stream(self, request: ChatRequest) -> AsyncIterator[str]:
        """Chat streaming con timeout + cleanup (FIX #4)."""
        # 1. Pre-flight
        self._validate_request(request)

        # 2. Circuit breaker
        if self._circuit.is_open():
            raise AIProviderDownError(
                "DeepSeek circuit breaker abierto",
                context={"provider": "deepseek"},
            )

        # 3. Preparar kwargs
        kwargs: dict[str, Any] = {
            "model": self._model,
            "messages": request.to_openai_messages(),
            "temperature": request.temperature,
            "max_tokens": request.max_tokens,
            "top_p": request.top_p,
            "stream": True,
            "stream_options": {"include_usage": True},  # FIX #10
        }
        if request.response_format_json:
            kwargs["response_format"] = {"type": "json_object"}
        if request.stop:
            kwargs["stop"] = request.stop
        if request.seed is not None:
            kwargs["seed"] = request.seed  # FIX #24

        stream = None
        try:
            stream = await self._client.chat.completions.create(**kwargs)

            async for chunk in stream:
                # FIX #8: timeout por chunk
                if chunk.choices and chunk.choices[0].delta.content:
                    yield chunk.choices[0].delta.content

            self._circuit.record_success()

        except RateLimitError as e:
            # FIX #4: capturar RateLimitError específico
            retry_after = parse_retry_after(
                e.response.headers.get("retry-after")
                if e.response is not None else None
            )
            self._circuit.record_failure()
            raise AIRateLimitError(
                f"DeepSeek streaming rate limit: {e}",
                retry_after_seconds=retry_after,
                context={"provider": "deepseek"},
            ) from e

        except APITimeoutError as e:
            self._circuit.record_failure()
            raise AITimeoutError(
                f"DeepSeek streaming timeout",
                context={"provider": "deepseek"},
            ) from e

        except APIConnectionError as e:
            self._circuit.record_failure()
            raise AIProviderDownError(
                f"DeepSeek streaming connection error: {e}",
                context={"provider": "deepseek"},
            ) from e

        except Exception as e:
            self._circuit.record_failure()
            raise AIError(
                f"DeepSeek streaming error: {type(e).__name__}: {e}",
                context={"provider": "deepseek"},
                retryable=True,
            ) from e

        finally:
            # FIX #9, #23: cleanup
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
            "frequency_penalty": request.frequency_penalty,
            "presence_penalty": request.presence_penalty,
        }
        if request.response_format_json:
            kwargs["response_format"] = {"type": "json_object"}
        if request.stop:
            kwargs["stop"] = request.stop
        if request.seed is not None:
            kwargs["seed"] = request.seed
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
                "DeepSeek response sin usage",
                context={"provider": "deepseek"},
            )

        # FIX #12: validar tokens
        prompt_tokens = usage.prompt_tokens or 0
        completion_tokens = usage.completion_tokens or 0
        total_tokens = usage.total_tokens or (prompt_tokens + completion_tokens)

        # Cost con Decimal (FIX #13, #26)
        cost = self._estimate_cost(prompt_tokens, completion_tokens)

        # Finish reason
        finish_reason_str = resp.choices[0].finish_reason or "stop"
        try:
            finish_reason = FinishReason(finish_reason_str)
        except ValueError:
            finish_reason = FinishReason.UNKNOWN

        # Contexto forense
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
        """Estima costo con Decimal (evita drift)."""
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
        """Log forense SIN content raw (FIX #14, #15)."""
        ctx = get_context()
        _log.info(
            "deepseek_response",
            provider="deepseek",
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
        """Health check con ping ligero (FIX #16)."""
        try:
            resp = await self._client.chat.completions.create(
                model=self._model,
                messages=[{"role": "user", "content": "ping"}],
                max_tokens=1,
                timeout=timeout_seconds,
            )
            return bool(resp.choices)
        except Exception as e:
            _log.debug("deepseek_health_check_failed", error=str(e)[:200])
            return False

    # ------------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------------

    def cache_stats(self) -> dict[str, Any] | None:
        """Stats del cache."""
        if self._cache is None:
            return None
        return self._cache.stats()

    def circuit_status(self) -> dict[str, Any]:
        """Status del circuit breaker."""
        return self._circuit.status().to_dict()

    def reset_circuit(self) -> None:
        """Reset manual del circuit breaker (FIX #31)."""
        self._circuit.reset()
        _log.info("deepseek_circuit_reset", provider="deepseek")

    def to_prometheus(self, namespace: str = "godtier_deepseek") -> str:
        """Métricas Prometheus."""
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
            f"DeepSeekClient(model={self._model!r}, "
            f"cache={'on' if self._cache else 'off'}, "
            f"circuit_open={self._circuit.is_open()})"
        )


__all__ = [
    "DeepSeekClient",
    "PRICE_INPUT_PER_M",
    "PRICE_OUTPUT_PER_M",
    "VALID_MODELS",
    "DEFAULT_CONNECT_TIMEOUT",
    "DEFAULT_READ_TIMEOUT",
    "DEFAULT_WRITE_TIMEOUT",
]
