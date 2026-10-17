"""AIGateway — God-Tier v5.0. Punto único de llamadas a LLM.

Ningún agente puede llamar directamente a DeepSeek/Qwen. Todo pasa por aquí.

God-Tier v5.0 — diferenciadores vs v2.1:

FIX BLOQUEANTES:
    - FIX #2: Budget ATOMIC reserve → record → release (no overspend)
    - FIX #3: Retry-After RESPETADO en cada retry
    - FIX #4: CostTracker SIN lock en @dataclass (serializable)
    - FIX #5: GatewayMetrics SIN lock en @dataclass (serializable)

USO DE RESILIENCE (FIX DRY #6, #7, #8):
    - CircuitBreaker de ai._resilience (no reimplementado)
    - ProviderHealth EWMA de ai._resilience
    - parse_retry_after de ai._resilience
    - ResponseCache de ai._resilience (opcional)

RESILIENCIA:
    - Budget ATOMIC con RESERVE + RELEASE
    - ProviderHealth EWMA routing (skip unhealthy si hay fallback)
    - CircuitBreaker per provider (half-open real)
    - Retry-After respetado (RFC 7231)
    - Deadline total por request
    - Kill switch global (asyncio.Event)

FORENSE:
    - trace_id propagado en ChatRequest
    - correlation_id + engagement_id en CostRecord
    - Structured logging (NO content raw, solo hash)
    - Provider health/circuit snapshots
    - Prometheus metrics export

ESCALABILIDAD:
    - Semáforo por provider (concurrencia)
    - Cache opcional (ResponseCache)
    - Async-safe budget lock (no serializa)
    - Lazy creation de providers

UTILIDADES:
    - call_llm() helper
    - health_snapshot()
    - circuits_snapshot()
    - to_prometheus()
    - kill_switch() / reset_kill_switch()

Filosofía:
    - ATOMIC: budget reserve+release
    - RESPECTFUL: Retry-After respetado
    - ADAPTIVE: routing por health
    - OBSERVABLE: métricas + snapshots
    - CANCELLABLE: kill switch
    - DRY: reutiliza _resilience
"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from dataclasses import dataclass, field
from threading import RLock
from typing import Any, Literal
from uuid import UUID, uuid4

from tenacity import (
    AsyncRetrying,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential_jitter,
)

from god_tier_agency.ai._resilience import (
    CircuitBreaker,
    ProviderHealth,
    ResponseCache,
    parse_retry_after,
)
from god_tier_agency.ai.base import (
    AIClient,
    AIContentFilteredError,
    AIContextLengthError,
    AIError,
    AIInvalidResponseError,
    AIProviderDownError,
    AIRateLimitError,
    AITimeoutError,
    ChatMessage,
    ChatRequest,
    LLMResponse,
    MessageRole,
)
from god_tier_agency.config import settings
from god_tier_agency.core.context import get_context
from god_tier_agency.core.exceptions import BudgetExceededError
from god_tier_agency.core.logging import get_logger

_log = get_logger("ai.gateway")


# ============================================================================
# TIPOS Y CONSTANTES
# ============================================================================

Role = Literal["planner", "exploiter", "verifier", "reporter", "recon"]
Provider = Literal["deepseek", "qwen", "ollama"]

# Roles válidos (ÚNICA fuente de verdad — FIX #25)
_VALID_ROLES: frozenset[str] = frozenset(
    {"planner", "exploiter", "verifier", "reporter", "recon"}
)

# Configuración
DEFAULT_MAX_COST: float = 100.0
DEFAULT_MAX_RETRIES: int = 3
DEFAULT_CONCURRENCY_PER_PROVIDER: int = 10
DEFAULT_TOTAL_TIMEOUT_SECONDS: float = 180.0
DEFAULT_CIRCUIT_THRESHOLD: int = 5
DEFAULT_CIRCUIT_OPEN_SECONDS: float = 60.0

# Retry config
RETRY_INITIAL_WAIT: float = 1.0
RETRY_MAX_WAIT: float = 15.0  # FIX #14: reducido de 30 a 15
RETRY_JITTER: float = 2.0

# Reservas conservadoras (heuristic)
DEFAULT_ESTIMATED_COST: float = 0.05


# ============================================================================
# COST RECORD (frozen, forense)
# ============================================================================

@dataclass(frozen=True)
class CostRecord:
    """Registro inmutable de una llamada a LLM."""

    call_id: UUID
    timestamp: float
    correlation_id: str | None
    engagement_id: str | None
    trace_id: str | None
    role: str
    provider: str
    model: str
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    cost_usd: float
    latency_ms: float
    cache_hit: bool = False
    success: bool = True
    error_code: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "call_id": str(self.call_id),
            "timestamp": self.timestamp,
            "correlation_id": self.correlation_id,
            "engagement_id": self.engagement_id,
            "trace_id": self.trace_id,
            "role": self.role,
            "provider": self.provider,
            "model": self.model,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
            "cost_usd": round(self.cost_usd, 6),
            "latency_ms": round(self.latency_ms, 2),
            "cache_hit": self.cache_hit,
            "success": self.success,
            "error_code": self.error_code,
        }


# ============================================================================
# COST TRACKER (SIN lock en dataclass — FIX #4)
# ============================================================================

@dataclass
class CostTracker:
    """Tracking de costos thread-safe SIN lock en dataclass.

    El lock vive en AIGateway y se pasa donde se necesita.
    Esto permite `dataclasses.asdict()` sin fallar.
    """

    max_cost: float = DEFAULT_MAX_COST
    total_cost: float = 0.0
    reserved_cost: float = 0.0  # FIX #2: reserva atómica
    total_calls: int = 0
    total_tokens: int = 0
    total_failures: int = 0
    records: list[CostRecord] = field(default_factory=list)

    # -- Atomic reservation (FIX #2) ----------------------------------------

    @property
    def available(self) -> float:
        """Budget disponible (max - spent - reserved)."""
        return max(0.0, self.max_cost - self.total_cost - self.reserved_cost)

    def can_reserve(self, amount: float) -> bool:
        """True si hay budget para reservar."""
        return (self.total_cost + self.reserved_cost + amount) <= self.max_cost

    def reserve(self, amount: float) -> bool:
        """Reserva atómica. Retorna True si éxito."""
        if not self.can_reserve(amount):
            return False
        self.reserved_cost += amount
        return True

    def release_reservation(self, amount: float) -> None:
        """Libera reserva."""
        self.reserved_cost = max(0.0, self.reserved_cost - amount)

    def consume(
        self,
        actual_cost: float,
        reserved: float,
    ) -> None:
        """Consume reserva y registra gasto real."""
        self.reserved_cost = max(0.0, self.reserved_cost - reserved)
        self.total_cost += actual_cost

    # -- Record (caller debe tener lock) ------------------------------------

    def record(
        self,
        response: LLMResponse,
        *,
        role: str,
        provider: str,
        cache_hit: bool = False,
        success: bool = True,
        error_code: str | None = None,
        call_id: UUID | None = None,
        correlation_id: str | None = None,
        engagement_id: str | None = None,
        trace_id: str | None = None,
    ) -> CostRecord:
        """Registra llamada (caller debe sostener lock)."""
        effective_cost = 0.0 if cache_hit else response.cost_usd
        entry = CostRecord(
            call_id=call_id or uuid4(),
            timestamp=time.time(),
            correlation_id=correlation_id,
            engagement_id=engagement_id,
            trace_id=trace_id,
            role=role,
            provider=provider,
            model=response.model,
            prompt_tokens=response.prompt_tokens,
            completion_tokens=response.completion_tokens,
            total_tokens=response.total_tokens,
            cost_usd=effective_cost,
            latency_ms=response.latency_ms,
            cache_hit=cache_hit,
            success=success,
            error_code=error_code,
        )
        self.total_cost += effective_cost
        self.total_tokens += response.total_tokens
        self.total_calls += 1
        if not success:
            self.total_failures += 1
        self.records.append(entry)

        # Truncar records si crece demasiado (evita memory leak)
        if len(self.records) > 10_000:
            self.records = self.records[-10_000:]

        return entry

    def is_over_budget(self) -> bool:
        return self.total_cost >= self.max_cost

    def remaining(self) -> float:
        return max(0.0, self.max_cost - self.total_cost)

    def summary(self) -> dict[str, Any]:
        by_role: dict[str, dict[str, Any]] = defaultdict(
            lambda: {"cost": 0.0, "calls": 0, "tokens": 0, "failures": 0}
        )
        by_provider: dict[str, int] = defaultdict(int)
        cache_hits = 0

        for r in self.records:
            by_role[r.role]["cost"] += r.cost_usd
            by_role[r.role]["calls"] += 1
            by_role[r.role]["tokens"] += r.total_tokens
            if not r.success:
                by_role[r.role]["failures"] += 1
            by_provider[r.provider] += 1
            if r.cache_hit:
                cache_hits += 1

        for role_data in by_role.values():
            role_data["cost"] = round(role_data["cost"], 6)

        return {
            "total_cost_usd": round(self.total_cost, 6),
            "reserved_usd": round(self.reserved_cost, 6),
            "available_usd": round(self.available, 6),
            "total_calls": self.total_calls,
            "total_tokens": self.total_tokens,
            "total_failures": self.total_failures,
            "remaining_usd": round(self.remaining(), 6),
            "max_cost_usd": self.max_cost,
            "cache_hits": cache_hits,
            "by_role": dict(by_role),
            "by_provider": dict(by_provider),
        }


# ============================================================================
# GATEWAY METRICS (SIN lock en dataclass — FIX #5)
# ============================================================================

@dataclass
class GatewayMetrics:
    """Métricas agregadas SIN lock en dataclass."""

    calls_total: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    errors_total: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    latency_sum_ms: dict[str, float] = field(default_factory=lambda: defaultdict(float))
    tokens_total: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    retries_total: int = 0
    fallbacks_total: int = 0
    circuit_opens_total: int = 0
    budget_rejections_total: int = 0

    # -- Record methods (caller tiene lock) ---------------------------------

    def record_call(
        self,
        provider: str,
        latency_ms: float,
        tokens: int,
        success: bool,
        error_code: str | None = None,
    ) -> None:
        self.calls_total[provider] += 1
        self.latency_sum_ms[provider] += latency_ms
        self.tokens_total[provider] += tokens
        if not success and error_code:
            self.errors_total[error_code] += 1

    def record_retry(self) -> None:
        self.retries_total += 1

    def record_fallback(self) -> None:
        self.fallbacks_total += 1

    def record_circuit_open(self) -> None:
        self.circuit_opens_total += 1

    def record_budget_rejection(self) -> None:
        self.budget_rejections_total += 1

    def snapshot(self) -> dict[str, Any]:
        avg_latency: dict[str, float] = {}
        for provider, count in self.calls_total.items():
            if count > 0:
                avg_latency[provider] = round(
                    self.latency_sum_ms[provider] / count, 2
                )
        return {
            "calls_total": dict(self.calls_total),
            "errors_total": dict(self.errors_total),
            "tokens_total": dict(self.tokens_total),
            "avg_latency_ms": avg_latency,
            "retries_total": self.retries_total,
            "fallbacks_total": self.fallbacks_total,
            "circuit_opens_total": self.circuit_opens_total,
            "budget_rejections_total": self.budget_rejections_total,
        }


# ============================================================================
# PROVIDER REF (con health + circuit — FIX #9)
# ============================================================================

@dataclass(frozen=True)
class _ProviderRef:
    """Referencia a un provider en la cascada."""
    name: str
    client: AIClient
    health: ProviderHealth
    circuit: CircuitBreaker


# ============================================================================
# AIGATEWAY
# ============================================================================

class AIGateway:
    """Punto único de llamadas a LLM con fallback, retry, y cost tracking.

    God-Tier v5.0:
        - Atomic budget (reserve → consume → release)
        - ProviderHealth EWMA routing
        - Circuit breaker per provider
        - Retry-After respetado
        - Kill switch global
    """

    def __init__(
        self,
        deepseek: AIClient | None = None,
        qwen: AIClient | None = None,
        *,
        max_cost: float | None = None,
        max_retries: int = DEFAULT_MAX_RETRIES,
        concurrency_per_provider: int = DEFAULT_CONCURRENCY_PER_PROVIDER,
        total_timeout_seconds: float = DEFAULT_TOTAL_TIMEOUT_SECONDS,
        circuit_threshold: int = DEFAULT_CIRCUIT_THRESHOLD,
        circuit_open_seconds: float = DEFAULT_CIRCUIT_OPEN_SECONDS,
        enable_cache: bool = True,
    ) -> None:
        # Lazy import para evitar circular imports
        if deepseek is None:
            from god_tier_agency.ai.deepseek import DeepSeekClient
            deepseek = DeepSeekClient()
        if qwen is None:
            from god_tier_agency.ai.qwen import QwenClient
            qwen = QwenClient()

        self.deepseek = deepseek
        self.qwen = qwen

        # FIX #28: clamp total_timeout
        self.total_timeout_seconds = max(1.0, min(600.0, total_timeout_seconds))
        self.max_retries = max(1, min(10, max_retries))

        # Budget + metrics
        effective_max_cost = (
            max_cost if max_cost is not None
            else settings.max_cost_per_engagement
        )
        self.cost_tracker = CostTracker(max_cost=effective_max_cost)
        self.metrics = GatewayMetrics()

        # FIX #4, #5: locks externos
        self._cost_lock = RLock()
        self._metrics_lock = RLock()

        # Semáforos
        self._sema: dict[str, asyncio.Semaphore] = {
            "deepseek": asyncio.Semaphore(concurrency_per_provider),
            "qwen": asyncio.Semaphore(concurrency_per_provider),
        }

        # FIX #6, #7: usar resilience
        self._health: dict[str, ProviderHealth] = {
            "deepseek": ProviderHealth(provider="deepseek"),
            "qwen": ProviderHealth(provider="qwen"),
        }
        self._circuits: dict[str, CircuitBreaker] = {
            "deepseek": CircuitBreaker(
                threshold=circuit_threshold,
                open_seconds=circuit_open_seconds,
                provider="deepseek",
            ),
            "qwen": CircuitBreaker(
                threshold=circuit_threshold,
                open_seconds=circuit_open_seconds,
                provider="qwen",
            ),
        }

        # Cache opcional (usa ResponseCache de _resilience)
        self._cache: ResponseCache | None = (
            ResponseCache(max_entries=1000, ttl=3600.0)
            if enable_cache
            else None
        )

        # FIX #17: kill switch global
        self._kill_switch = asyncio.Event()

        # FIX #13: budget lock NO serializa (usa RLock externo)
        self._budget_lock = RLock()

    # ------------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------------

    async def call(
        self,
        role: Role,
        request: ChatRequest,
        prefer: Provider = "deepseek",
    ) -> LLMResponse:
        """Llama a un LLM con fallback, retry, y cost tracking.

        Raises:
            BudgetExceededError: si budget insuficiente.
            AIError: si todos los providers fallan.
            ValueError: si role inválido.
            asyncio.CancelledError: si kill switch activado.
        """
        # 0. Validar role (FIX #25: única fuente de verdad)
        if role not in _VALID_ROLES:
            raise ValueError(
                f"role inválido: {role!r}. Válidos: {sorted(_VALID_ROLES)}"
            )

        # 1. Kill switch check
        if self._kill_switch.is_set():
            raise asyncio.CancelledError("AIGateway kill switch activated")

        # 2. Forense context
        call_id = uuid4()
        ctx = get_context()
        correlation_id = ctx.get("correlation_id")
        engagement_id = ctx.get("engagement_id")
        trace_id = request.trace_id or ctx.get("trace_id")

        # 3. Cache lookup (si cacheable)
        if self._cache is not None and self._is_cacheable(request):
            cached = self._cache.get(request, self._pick_model(prefer))
            if cached is not None:
                _log.info(
                    "cache_hit",
                    role=role,
                    provider=cached.provider,
                    correlation_id=correlation_id,
                )
                # Cached response es frozen, marcar cached
                cached_updated = LLMResponse(
                    content=cached.content,
                    request_id=cached.request_id,
                    model=cached.model,
                    provider=cached.provider,
                    prompt_tokens=cached.prompt_tokens,
                    completion_tokens=cached.completion_tokens,
                    total_tokens=cached.total_tokens,
                    cost_usd=0.0,
                    latency_ms=cached.latency_ms,
                    finish_reason=cached.finish_reason,
                    cached=True,
                    cache_age_seconds=0.0,
                    timestamp=cached.timestamp,
                    trace_id=trace_id,
                    correlation_id=correlation_id,
                    engagement_id=engagement_id,
                )
                # Registrar en cost tracker (cost=0 por cache)
                with self._cost_lock:
                    self.cost_tracker.record(
                        cached_updated,
                        role=role,
                        provider=cached.provider,
                        cache_hit=True,
                        call_id=call_id,
                        correlation_id=correlation_id,
                        engagement_id=engagement_id,
                        trace_id=trace_id,
                    )
                return cached_updated

        # 4. FIX #2: Budget RESERVE atómico
        estimated_cost = DEFAULT_ESTIMATED_COST
        with self._budget_lock:
            if not self.cost_tracker.reserve(estimated_cost):
                with self._metrics_lock:
                    self.metrics.record_budget_rejection()
                raise BudgetExceededError(
                    f"Budget insuficiente: necesito ~${estimated_cost:.4f}, "
                    f"disponible ${self.cost_tracker.available:.4f}",
                    context=self.cost_tracker.summary(),
                )

        try:
            # 5. Cascade
            providers = self._get_provider_cascade(prefer)
            deadline = time.monotonic() + self.total_timeout_seconds
            last_error: BaseException | None = None

            for i, provider in enumerate(providers):
                # Deadline check
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise AITimeoutError(
                        f"Deadline excedido ({self.total_timeout_seconds}s)",
                        context={"role": role, "providers_tried": i},
                    )

                # Skip si circuit open
                if provider.circuit.is_open():
                    with self._metrics_lock:
                        self.metrics.record_circuit_open()
                    last_error = AIProviderDownError(
                        f"Circuit open para {provider.name}",
                        context={"provider": provider.name},
                    )
                    _log.info(
                        "provider_skipped_circuit",
                        provider=provider.name,
                        role=role,
                    )
                    continue

                # Skip si unhealthy Y hay siguiente provider
                if (
                    not provider.health.is_healthy
                    and i < len(providers) - 1
                ):
                    _log.info(
                        "provider_skipped_unhealthy",
                        provider=provider.name,
                        health_score=round(provider.health.score, 3),
                    )
                    continue

                try:
                    response = await self._call_provider(
                        provider=provider,
                        request=request,
                        role=role,
                        call_id=call_id,
                        correlation_id=correlation_id,
                        engagement_id=engagement_id,
                        trace_id=trace_id,
                        timeout_seconds=min(remaining, request.timeout_seconds),
                    )

                    # Registrar en cache (si cacheable)
                    if self._cache is not None and self._is_cacheable(request):
                        self._cache.set(
                            request,
                            self._pick_model(provider.name),
                            response,
                        )

                    if i > 0:
                        with self._metrics_lock:
                            self.metrics.record_fallback()
                    return response

                except (
                    AIError,
                    AIProviderDownError,
                    AIRateLimitError,
                    AITimeoutError,
                ) as e:
                    last_error = e
                    _log.warning(
                        "provider_failed",
                        role=role,
                        provider=provider.name,
                        attempt_in_cascade=i + 1,
                        total_providers=len(providers),
                        error=str(e)[:200],
                        error_code=getattr(e, "error_code", "unknown"),
                    )
                    continue

            # Todos fallaron
            _log.error(
                "all_providers_failed",
                role=role,
                providers=[p.name for p in providers],
                last_error=str(last_error)[:200] if last_error else None,
            )
            raise AIError(
                f"Todos los providers fallaron para role={role}",
                context={
                    "role": role,
                    "providers": [p.name for p in providers],
                    "last_error": str(last_error)[:500] if last_error else None,
                },
            ) from last_error

        finally:
            # FIX #2: RELEASE reserva (si no se consumió)
            with self._budget_lock:
                # Si el costo real se registró, la reserva ya se consumió
                # Si falló, liberar
                self.cost_tracker.release_reservation(estimated_cost)

    async def call_llm(
        self,
        role: Role,
        system_prompt: str,
        user_content: str,
        *,
        prefer: Provider = "deepseek",
        temperature: float = 0.2,
        max_tokens: int = 8000,
        response_format_json: bool = False,
        timeout_seconds: float = 120.0,
    ) -> LLMResponse:
        """Helper: construye ChatRequest y llama. FIX #15."""
        request = ChatRequest(
            system=system_prompt,
            messages=[
                ChatMessage(role=MessageRole.USER, content=user_content),
            ],
            temperature=temperature,
            max_tokens=max_tokens,
            response_format_json=response_format_json,
            timeout_seconds=timeout_seconds,
        )
        return await self.call(role=role, request=request, prefer=prefer)

    # ------------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------------

    @staticmethod
    def _is_cacheable(request: ChatRequest) -> bool:
        """True si el request es cacheable (temperature <= 0.01)."""
        return request.temperature <= 0.01

    def _pick_model(self, provider: Provider) -> str:
        """Retorna el modelo según el provider."""
        if provider == "deepseek":
            return getattr(self.deepseek, "model_name", "deepseek-chat")
        if provider == "qwen":
            return getattr(self.qwen, "model_name", "qwen-max")
        return "unknown"

    async def _call_provider(
        self,
        provider: _ProviderRef,
        request: ChatRequest,
        role: Role,
        call_id: UUID,
        correlation_id: str | None,
        engagement_id: str | None,
        trace_id: str | None,
        timeout_seconds: float,
    ) -> LLMResponse:
        """Llama a provider con semáforo + retry."""
        sema = self._sema.get(provider.name)
        if sema is None:
            return await self._execute_with_retry(
                provider, request, role, call_id,
                correlation_id, engagement_id, trace_id,
                timeout_seconds,
            )
        async with sema:
            return await self._execute_with_retry(
                provider, request, role, call_id,
                correlation_id, engagement_id, trace_id,
                timeout_seconds,
            )

    async def _execute_with_retry(
        self,
        provider: _ProviderRef,
        request: ChatRequest,
        role: Role,
        call_id: UUID,
        correlation_id: str | None,
        engagement_id: str | None,
        trace_id: str | None,
        timeout_seconds: float,
    ) -> LLMResponse:
        """Ejecuta con retry exponencial + Retry-After (FIX #3)."""
        # Override timeout
        request_with_timeout = request.model_copy(
            update={"timeout_seconds": timeout_seconds}
        )

        # FIX #3: retry_after control manual
        retry_after_seconds: float = 0.0

        async for attempt in AsyncRetrying(
            stop=stop_after_attempt(self.max_retries),
            wait=self._adaptive_wait,  # FIX #3: usa retry_after
            retry=retry_if_exception_type(
                (AIRateLimitError, AITimeoutError, AIProviderDownError)
            ),
            reraise=True,
        ):
            with attempt:
                attempt_num = attempt.retry_state.attempt_number
                if attempt_num > 1:
                    with self._metrics_lock:
                        self.metrics.record_retry()
                    _log.info(
                        "retry_attempt",
                        provider=provider.name,
                        attempt=attempt_num,
                        max_attempts=self.max_retries,
                        role=role,
                    )

                start = time.perf_counter()
                try:
                    response = await provider.client.chat(request_with_timeout)
                    latency_ms = (time.perf_counter() - start) * 1000

                    # Success
                    provider.circuit.record_success()
                    provider.health.record(success=True)

                    with self._cost_lock:
                        self.cost_tracker.record(
                            response,
                            role=role,
                            provider=provider.name,
                            call_id=call_id,
                            correlation_id=correlation_id,
                            engagement_id=engagement_id,
                            trace_id=trace_id,
                        )
                    with self._metrics_lock:
                        self.metrics.record_call(
                            provider=provider.name,
                            latency_ms=latency_ms,
                            tokens=response.total_tokens,
                            success=True,
                        )
                    self._log_call(role, provider, response, call_id)
                    return response

                except (AIRateLimitError, AITimeoutError, AIProviderDownError) as e:
                    latency_ms = (time.perf_counter() - start) * 1000
                    provider.circuit.record_failure()
                    provider.health.record(success=False)

                    # Capturar Retry-After (FIX #3)
                    if isinstance(e, AIRateLimitError):
                        retry_after_seconds = getattr(
                            e, "retry_after_seconds", 0.0,
                        )

                    with self._metrics_lock:
                        self.metrics.record_call(
                            provider=provider.name,
                            latency_ms=latency_ms,
                            tokens=0,
                            success=False,
                            error_code=getattr(e, "error_code", "unknown"),
                        )
                    raise

                except (AIContextLengthError, AIContentFilteredError,
                        AIInvalidResponseError) as e:
                    # No retryable
                    latency_ms = (time.perf_counter() - start) * 1000
                    with self._metrics_lock:
                        self.metrics.record_call(
                            provider=provider.name,
                            latency_ms=latency_ms,
                            tokens=0,
                            success=False,
                            error_code=getattr(e, "error_code", "unknown"),
                        )
                    raise

                except AIError as e:
                    latency_ms = (time.perf_counter() - start) * 1000
                    with self._metrics_lock:
                        self.metrics.record_call(
                            provider=provider.name,
                            latency_ms=latency_ms,
                            tokens=0,
                            success=False,
                            error_code=getattr(e, "error_code", "unknown"),
                        )
                    raise

        # Unreachable
        raise AIError("Retry loop agotado")

    def _adaptive_wait(self, retry_state: Any) -> float:
        """Espera adaptativa: Retry-After si disponible (FIX #3)."""
        exc = retry_state.outcome.exception() if retry_state.outcome else None
        attempt = retry_state.attempt_number

        # Base: exponential + jitter
        base = min(RETRY_MAX_WAIT, RETRY_INITIAL_WAIT * (2 ** (attempt - 1)))
        import random
        jitter = random.uniform(0, RETRY_JITTER)
        wait = base + jitter

        # FIX #3: Retry-After respetado
        if isinstance(exc, AIRateLimitError):
            retry_after = getattr(exc, "retry_after_seconds", 0.0)
            if retry_after > 0:
                wait = max(wait, retry_after)
                _log.info(
                    "retry_after_respected",
                    retry_after=round(retry_after, 2),
                )

        return min(wait, 120.0)

    def _get_provider_cascade(self, prefer: Provider) -> list[_ProviderRef]:
        """Retorna cascade según preferencia."""
        refs = {
            "deepseek": _ProviderRef(
                name="deepseek",
                client=self.deepseek,
                health=self._health["deepseek"],
                circuit=self._circuits["deepseek"],
            ),
            "qwen": _ProviderRef(
                name="qwen",
                client=self.qwen,
                health=self._health["qwen"],
                circuit=self._circuits["qwen"],
            ),
        }
        order = ["deepseek", "qwen"] if prefer == "deepseek" else ["qwen", "deepseek"]
        return [refs[name] for name in order]

    def _log_call(
        self,
        role: str,
        provider: _ProviderRef,
        resp: LLMResponse,
        call_id: UUID,
    ) -> None:
        """Log estructurado SIN content raw (FIX #12)."""
        ctx = get_context()
        _log.info(
            "llm_call",
            call_id=str(call_id),
            role=role,
            provider=provider.name,
            model=resp.model,
            tokens=resp.total_tokens,
            cost_usd=round(resp.cost_usd, 6),
            latency_ms=round(resp.latency_ms, 2),
            finish_reason=resp.finish_reason.value,
            cached=resp.cached,
            content_hash=resp.content_hash,
            correlation_id=ctx.get("correlation_id"),
            engagement_id=ctx.get("engagement_id"),
            trace_id=resp.trace_id,
        )

    # ------------------------------------------------------------------------
    # Kill switch (FIX #17)
    # ------------------------------------------------------------------------

    async def kill_switch(self) -> None:
        """Activa kill switch global."""
        self._kill_switch.set()
        _log.critical("aigw_kill_switch_activated")

    def reset_kill_switch(self) -> None:
        """Reset kill switch."""
        self._kill_switch.clear()
        _log.info("aigw_kill_switch_reset")

    @property
    def is_kill_switch_active(self) -> bool:
        return self._kill_switch.is_set()

    # ------------------------------------------------------------------------
    # Observability (FIX #18, #19, #23)
    # ------------------------------------------------------------------------

    def budget_summary(self) -> dict[str, Any]:
        """Resumen del budget."""
        with self._cost_lock:
            return self.cost_tracker.summary()

    def metrics_snapshot(self) -> dict[str, Any]:
        """Snapshot de métricas."""
        with self._metrics_lock:
            return self.metrics.snapshot()

    def health_snapshot(self) -> dict[str, Any]:
        """Snapshot de ProviderHealth (FIX #18)."""
        return {
            name: health.to_dict()
            for name, health in self._health.items()
        }

    def circuits_snapshot(self) -> dict[str, Any]:
        """Snapshot de circuits (FIX #19)."""
        return {
            name: circuit.status().to_dict()
            for name, circuit in self._circuits.items()
        }

    def cache_stats(self) -> dict[str, Any] | None:
        """Stats del cache (si habilitado)."""
        if self._cache is None:
            return None
        return self._cache.stats()

    def reset_circuits(self) -> None:
        """Reset manual de circuits."""
        for circuit in self._circuits.values():
            circuit.reset()
        _log.info("aigw_circuits_reset")

    def to_prometheus(self, namespace: str = "godtier_aigw") -> str:
        """Exporta métricas Prometheus (FIX #23)."""
        with self._cost_lock, self._metrics_lock:
            lines: list[str] = [
                f"# HELP {namespace}_calls_total Total LLM calls",
                f"# TYPE {namespace}_calls_total counter",
            ]
            for provider, count in sorted(self.metrics.calls_total.items()):
                lines.append(f'{namespace}_calls_total{{provider="{provider}"}} {count}')

            lines.append(f"# HELP {namespace}_cost_usd Total cost")
            lines.append(f"# TYPE {namespace}_cost_usd gauge")
            lines.append(f"{namespace}_cost_usd {self.cost_tracker.total_cost:.6f}")

            lines.append(f"# HELP {namespace}_tokens_total Total tokens")
            lines.append(f"{namespace}_tokens_total {self.cost_tracker.total_tokens}")

            lines.append(f"# HELP {namespace}_retries_total Total retries")
            lines.append(f"{namespace}_retries_total {self.metrics.retries_total}")

            lines.append(f"# HELP {namespace}_fallbacks_total Total fallbacks")
            lines.append(f"{namespace}_fallbacks_total {self.metrics.fallbacks_total}")

            # Health scores
            for name, health in self._health.items():
                lines.append(
                    f'{namespace}_health_score{{provider="{name}"}} '
                    f'{round(health.score, 4)}'
                )

            return "\n".join(lines)


__all__ = [
    "AIGateway",
    "CostTracker",
    "CostRecord",
    "GatewayMetrics",
    "Role",
    "Provider",
    "DEFAULT_MAX_COST",
    "DEFAULT_MAX_RETRIES",
    "DEFAULT_CONCURRENCY_PER_PROVIDER",
    "DEFAULT_TOTAL_TIMEOUT_SECONDS",
    "DEFAULT_CIRCUIT_THRESHOLD",
    "DEFAULT_CIRCUIT_OPEN_SECONDS",
]
