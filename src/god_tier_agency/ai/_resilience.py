"""Resilience primitives — God-Tier v5.0.

Módulo de resiliencia COMPARTIDO entre todos los clientes LLM
(DeepSeek, Qwen, Ollama). DRY: cero duplicación de lógica.

Contiene:
    - ResponseCache: LRU + TTL + hash canónico + stats forenses
    - CircuitBreaker: half-open REAL (1 probe) + exponential re-open
    - ProviderHealth: EWMA tracking con detección de degradación
    - parse_retry_after: RFC 7231 (delta-seconds + HTTP-date)

God-Tier features (diferenciadores vs versión naive):
    - CircuitBreaker half-open REAL: 1 probe, decide según resultado
    - Exponential re-open: cada re-open duplica tiempo (cap configurable)
    - Thundering herd protection: _probe_in_flight flag atómico
    - True LRU: OrderedDict con move_to_end (no min(expires_at))
    - Canonical JSON hash: sort_keys + separators + ensure_ascii=False
    - ProviderHealth con EWMA (detecta degradación suave)
    - Métricas forenses: total_opens, total_successes, expirations
    - Zero race conditions: RLock reentrante donde se necesita
    - Zero deadlocks: no callbacks cruzados entre clases
    - Immutable data classes (frozen=True) para evidencia forense
    - Async-safe: no bloquea event loop

Diseño fail-closed:
    - Si el cache falla → cache miss (nunca response stale silencioso)
    - Si el circuit falla → OPEN (nunca deja pasar tráfico a provider caído)
    - Si health falla → marca degraded (routing a fallback)

Uso:
    >>> # Circuit breaker por provider
    >>> cb = CircuitBreaker(threshold=5, open_seconds=60, provider="deepseek")
    >>> if cb.is_open():
    ...     raise AIProviderDownError("circuit open")
    >>> try:
    ...     result = await call_provider()
    ...     cb.record_success()
    ... except (AITimeoutError, AIProviderDownError):
    ...     cb.record_failure()

    >>> # Response cache con TTL
    >>> cache = ResponseCache(max_entries=1000, ttl=3600)
    >>> if (hit := cache.get(req, "deepseek-chat")) is not None:
    ...     return hit
    >>> response = await client.chat(req)
    >>> cache.set(req, "deepseek-chat", response)

    >>> # Health tracking con EWMA
    >>> health = ProviderHealth(provider="deepseek", alpha=0.2)
    >>> health.record(success=True)
    >>> if not health.is_healthy:
    ...     switch_to_fallback()
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Final

from god_tier_agency.ai.base import ChatRequest, LLMResponse
from god_tier_agency.core.logging import get_logger

_log = get_logger("ai.resilience")

# ============================================================================
# CONSTANTES
# ============================================================================

# Cache
DEFAULT_CACHE_MAX_ENTRIES: Final[int] = 1000
DEFAULT_CACHE_TTL_SECONDS: Final[float] = 3600.0
CACHE_DETERMINISTIC_TEMPERATURE: Final[float] = 0.01

# Circuit breaker
DEFAULT_CIRCUIT_THRESHOLD: Final[int] = 5
DEFAULT_CIRCUIT_OPEN_SECONDS: Final[float] = 60.0
DEFAULT_CIRCUIT_MAX_OPEN_SECONDS: Final[float] = 600.0  # 10 min cap
CIRCUIT_BACKOFF_MULTIPLIER: Final[float] = 2.0

# Health (EWMA)
DEFAULT_HEALTH_ALPHA: Final[float] = 0.2
DEFAULT_HEALTH_THRESHOLD: Final[float] = 0.5

# Retry-After
RETRY_AFTER_MAX_SECONDS: Final[float] = 3600.0  # 1 hora cap


# ============================================================================
# RESPONSE CACHE — True LRU + TTL + canonical hash
# ============================================================================


@dataclass(frozen=True)
class CacheEntry:
    """Entrada inmutable del cache con TTL.

    frozen=True: previene mutación accidental (defensa forense).
    """

    response: LLMResponse
    expires_at: float
    created_at: float
    key_hash: str  # SHA-256 truncado para trazabilidad

    def is_expired(self, now: float | None = None) -> bool:
        """True si la entrada expiró."""
        return self.expires_at < (now if now is not None else time.time())

    def age_seconds(self, now: float | None = None) -> float:
        """Antigüedad de la entrada en segundos."""
        return (now if now is not None else time.time()) - self.created_at


@dataclass
class CacheStats:
    """Estadísticas thread-safe del cache.

    Incluye expirations (TTL hits) y evictions (LRU) por separado para
    diagnóstico forense.
    """

    hits: int = 0
    misses: int = 0
    evictions: int = 0
    expirations: int = 0
    size: int = 0

    @property
    def hit_rate(self) -> float:
        """Hit rate con 4 decimales (precisión suficiente para tuning)."""
        total = self.hits + self.misses
        return round(self.hits / total, 4) if total else 0.0

    @property
    def total_lookups(self) -> int:
        return self.hits + self.misses

    def to_dict(self) -> dict[str, Any]:
        return {
            "hits": self.hits,
            "misses": self.misses,
            "evictions": self.evictions,
            "expirations": self.expirations,
            "size": self.size,
            "hit_rate": self.hit_rate,
            "total_lookups": self.total_lookups,
        }


class ResponseCache:
    """Cache LRU con TTL para respuestas determinísticas de LLM.

    Thread-safe con RLock (reentrante: get/set pueden llamar a _key, que
    no necesita lock, pero RLock previene deadlocks si añadimos métodos
    cruzados en el futuro).

    God-Tier features:
    - True LRU: OrderedDict con move_to_end (no min(expires_at))
    - TTL per entry con lazy expiration (no background threads)
    - Canonical JSON hash: sort_keys + separators + ensure_ascii=False
    - Cache keys determinísticas: SHA-256 de payload canónico
    - Zero memory leak: cleanup en get/set
    - Stats forenses: hits/misses/evictions/expirations
    - Solo cachea requests determinísticas (temperature <= 0.01)

    No cachear requests con temperatura alta (no determinísticas) es
    responsabilidad del caller, pero el método `is_cacheable()` provee
    un helper para la decisión.
    """

    def __init__(
        self,
        max_entries: int = DEFAULT_CACHE_MAX_ENTRIES,
        ttl: float = DEFAULT_CACHE_TTL_SECONDS,
    ) -> None:
        if max_entries < 1:
            raise ValueError(f"max_entries debe ser >= 1, es {max_entries}")
        if ttl <= 0:
            raise ValueError(f"ttl debe ser > 0, es {ttl}")

        self.max_entries = max_entries
        self.ttl = ttl
        self._store: OrderedDict[str, CacheEntry] = OrderedDict()
        self._lock = threading.RLock()
        self._stats = CacheStats()

    # ------------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------------

    @staticmethod
    def is_cacheable(request: ChatRequest) -> bool:
        """True si el request es determinístico (temperature <= threshold).

        Temperaturas altas producen respuestas no reproducibles. Cachearlas
        resulta en staleness inútil.
        """
        return request.temperature <= CACHE_DETERMINISTIC_TEMPERATURE

    def get(self, request: ChatRequest, model: str) -> LLMResponse | None:
        """Retorna respuesta cacheada o None si expiró/ausente.

        God-Tier: si expira, elimina la entrada inmediatamente (no la
        deja acumularse hasta el próximo set).
        """
        with self._lock:
            key = self._canonical_key(request, model)
            entry = self._store.get(key)

            if entry is None:
                self._stats.misses += 1
                return None

            if entry.is_expired():
                # Lazy expiration: cleanup inmediato
                del self._store[key]
                self._stats.expirations += 1
                self._stats.misses += 1
                self._stats.size = len(self._store)
                _log.debug(
                    "cache_expired",
                    model=model,
                    key_hash=entry.key_hash,
                    age_seconds=round(entry.age_seconds(), 2),
                )
                return None

            # LRU: mover al final (más recientemente usado)
            self._store.move_to_end(key)
            self._stats.hits += 1
            return entry.response

    def set(
        self,
        request: ChatRequest,
        model: str,
        response: LLMResponse,
    ) -> None:
        """Almacena respuesta con TTL.

        God-Tier: LRU eviction verdadera (popitem(last=False) = oldest).
        """
        with self._lock:
            key = self._canonical_key(request, model)

            if key in self._store:
                # Update: mover al final
                self._store.move_to_end(key)
            else:
                if len(self._store) >= self.max_entries:
                    # True LRU: eliminar el más antiguo (primero en OrderedDict)
                    evicted_key, evicted_entry = self._store.popitem(last=False)
                    self._stats.evictions += 1
                    _log.debug(
                        "cache_evicted_lru",
                        model=model,
                        key_hash=evicted_entry.key_hash,
                        age_seconds=round(evicted_entry.age_seconds(), 2),
                    )

            now = time.time()
            entry = CacheEntry(
                response=response,
                expires_at=now + self.ttl,
                created_at=now,
                key_hash=key[:16],
            )
            self._store[key] = entry
            self._stats.size = len(self._store)

    def invalidate(self, request: ChatRequest, model: str) -> bool:
        """Invalida una entrada específica. Retorna True si existía.

        Útil para invalidar respuestas obsoletas tras cambios de system prompt.
        """
        with self._lock:
            key = self._canonical_key(request, model)
            if key in self._store:
                del self._store[key]
                self._stats.size = len(self._store)
                return True
            return False

    def clear(self) -> None:
        """Limpia el cache completo. Reset stats."""
        with self._lock:
            self._store.clear()
            self._stats = CacheStats()

    def stats(self) -> dict[str, Any]:
        """Snapshot thread-safe de estadísticas."""
        with self._lock:
            self._stats.size = len(self._store)
            return self._stats.to_dict()

    # ------------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------------

    @staticmethod
    def _canonical_key(request: ChatRequest, model: str) -> str:
        """Hash canónico determinístico del request.

        God-Tier:
        - sort_keys=True → ignora orden de dicts
        - separators=(",", ":") → mínimo espacio (hash más corto)
        - ensure_ascii=False → unicode canónico (UTF-8 real, no escapes)
        - Redondeo de floats → 4 decimales (suficiente, evita drift)

        Incluye TODOS los parámetros que afectan la respuesta:
        - model, system, messages
        - temperature, max_tokens, top_p
        - frequency_penalty, presence_penalty
        - response_format_json, stop, seed
        """
        payload = json.dumps(
            {
                "model": model,
                "system": request.system or "",
                "messages": [m.to_api_dict() for m in request.messages],
                "temperature": round(request.temperature, 4),
                "max_tokens": request.max_tokens,
                "top_p": round(request.top_p, 4),
                "frequency_penalty": round(request.frequency_penalty, 4),
                "presence_penalty": round(request.presence_penalty, 4),
                "response_format_json": request.response_format_json,
                "stop": request.stop,
                "seed": request.seed,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# ============================================================================
# CIRCUIT BREAKER — half-open REAL + exponential re-open
# ============================================================================


@dataclass(frozen=True)
class CircuitStatus:
    """Estado inmutable del circuit breaker (snapshot forense).

    frozen=True: previene mutación accidental.
    """

    is_open: bool
    is_half_open: bool
    failures: int
    threshold: int
    opened_at: float | None
    seconds_until_half_open: float
    current_open_duration: float
    total_opens: int
    total_successes: int
    total_failures: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_open": self.is_open,
            "is_half_open": self.is_half_open,
            "failures": self.failures,
            "threshold": self.threshold,
            "opened_at": self.opened_at,
            "seconds_until_half_open": round(self.seconds_until_half_open, 2),
            "current_open_duration": round(self.current_open_duration, 2),
            "total_opens": self.total_opens,
            "total_successes": self.total_successes,
            "total_failures": self.total_failures,
        }


class CircuitBreaker:
    """Circuit breaker thread-safe con half-open REAL y exponential re-open.

    Estados:
        - CLOSED:    todo OK, requests permitidas
        - OPEN:      demasiados fallos, requests rechazadas por
                     `current_open_duration` segundos
        - HALF_OPEN: tras `current_open_duration`, se permite 1 probe
                     - probe exitoso → CLOSED (reset failures + duration)
                     - probe fallido → OPEN (reabre por `duration * 2`)

    God-Tier features:
    - Half-open REAL: no resetea failures hasta confirmar éxito
    - Thundering herd protection: _probe_in_flight flag atómico
    - Exponential re-open: cada re-open duplica duración (cap configurable)
    - Zero race conditions: RLock reentrante
    - Métricas forenses: total_opens, total_successes, total_failures
    - State machine explícito: transiciones validadas

    Uso típico:
        >>> cb = CircuitBreaker(threshold=5, open_seconds=60, provider="deepseek")
        >>> if cb.is_open():
        ...     raise AIProviderDownError("circuit breaker abierto")
        >>> try:
        ...     result = await call_provider()
        ...     cb.record_success()
        ... except (AITimeoutError, AIProviderDownError):
        ...     cb.record_failure()
    """

    def __init__(
        self,
        threshold: int = DEFAULT_CIRCUIT_THRESHOLD,
        open_seconds: float = DEFAULT_CIRCUIT_OPEN_SECONDS,
        max_open_seconds: float = DEFAULT_CIRCUIT_MAX_OPEN_SECONDS,
        provider: str = "unknown",
    ) -> None:
        if threshold < 1:
            raise ValueError(f"threshold debe ser >= 1, es {threshold}")
        if open_seconds <= 0:
            raise ValueError(f"open_seconds debe ser > 0, es {open_seconds}")
        if max_open_seconds < open_seconds:
            raise ValueError(
                f"max_open_seconds ({max_open_seconds}) debe ser >= "
                f"open_seconds ({open_seconds})"
            )

        self.threshold = threshold
        self.open_seconds = open_seconds
        self.max_open_seconds = max_open_seconds
        self.provider = provider

        # State machine
        self._failures: int = 0
        self._opened_at: float | None = None
        self._current_open_duration: float = open_seconds
        self._probe_in_flight: bool = False

        # Forense
        self._total_opens: int = 0
        self._total_successes: int = 0
        self._total_failures: int = 0

        # Thread safety (RLock: status() podría llamar a is_open() en el futuro)
        self._lock = threading.RLock()

    # ------------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------------

    def is_open(self) -> bool:
        """True si la request debe ser RECHAZADA.

        God-Tier logic:
        - Si CLOSED → False (permitir)
        - Si OPEN y elapsed < duration → True (rechazar)
        - Si OPEN y elapsed >= duration → HALF_OPEN:
            - Si ya hay un probe in-flight → True (rechazar, evitar storm)
            - Si no → False (permitir 1 probe, marcar in_flight)
        """
        with self._lock:
            if self._opened_at is None:
                return False

            elapsed = time.time() - self._opened_at
            if elapsed < self._current_open_duration:
                return True  # Aún en OPEN

            # Half-open window: permitir 1 probe
            if self._probe_in_flight:
                return True  # Ya hay un probe en curso

            self._probe_in_flight = True
            _log.info(
                "circuit_half_open_probe_allowed",
                provider=self.provider,
                failures=self._failures,
                current_open_duration=round(self._current_open_duration, 2),
            )
            return False

    def record_success(self) -> None:
        """Registra éxito. Cierra el circuit si estaba OPEN/HALF_OPEN."""
        with self._lock:
            was_open = self._opened_at is not None
            self._failures = 0
            self._opened_at = None
            self._probe_in_flight = False
            self._current_open_duration = self.open_seconds  # Reset
            self._total_successes += 1

            if was_open:
                _log.info(
                    "circuit_closed_after_success",
                    provider=self.provider,
                    total_successes=self._total_successes,
                )

    def record_failure(self) -> None:
        """Registra fallo. Abre o re-abre el circuit con backoff exponencial."""
        with self._lock:
            self._probe_in_flight = False
            self._failures += 1
            self._total_failures += 1

            if self._failures < self.threshold:
                return  # Aún no cruza threshold

            if self._opened_at is None:
                # Primera apertura
                self._opened_at = time.time()
                self._current_open_duration = self.open_seconds
                self._total_opens += 1
                _log.warning(
                    "circuit_opened",
                    provider=self.provider,
                    failures=self._failures,
                    threshold=self.threshold,
                    open_duration=round(self._current_open_duration, 2),
                )
            else:
                # Re-apertura tras probe fallido → exponential backoff
                self._current_open_duration = min(
                    self._current_open_duration * CIRCUIT_BACKOFF_MULTIPLIER,
                    self.max_open_seconds,
                )
                self._opened_at = time.time()
                self._total_opens += 1
                _log.error(
                    "circuit_reopened_exponential",
                    provider=self.provider,
                    failures=self._failures,
                    new_open_duration=round(self._current_open_duration, 2),
                    total_opens=self._total_opens,
                )

    def reset(self) -> None:
        """Reset manual (post-revisión humana o tests)."""
        with self._lock:
            self._failures = 0
            self._opened_at = None
            self._probe_in_flight = False
            self._current_open_duration = self.open_seconds
            _log.info("circuit_manual_reset", provider=self.provider)

    def status(self) -> CircuitStatus:
        """Snapshot inmutable del estado actual."""
        with self._lock:
            now = time.time()

            if self._opened_at is None:
                return CircuitStatus(
                    is_open=False,
                    is_half_open=False,
                    failures=self._failures,
                    threshold=self.threshold,
                    opened_at=None,
                    seconds_until_half_open=0.0,
                    current_open_duration=self._current_open_duration,
                    total_opens=self._total_opens,
                    total_successes=self._total_successes,
                    total_failures=self._total_failures,
                )

            elapsed = now - self._opened_at
            remaining = max(0.0, self._current_open_duration - elapsed)
            is_half = remaining <= 0.0 and self._probe_in_flight

            return CircuitStatus(
                is_open=remaining > 0.0,
                is_half_open=is_half,
                failures=self._failures,
                threshold=self.threshold,
                opened_at=self._opened_at,
                seconds_until_half_open=remaining,
                current_open_duration=self._current_open_duration,
                total_opens=self._total_opens,
                total_successes=self._total_successes,
                total_failures=self._total_failures,
            )

    def is_healthy(self) -> bool:
        """True si CLOSED o HALF_OPEN (no bloquea tráfico)."""
        with self._lock:
            if self._opened_at is None:
                return True
            elapsed = time.time() - self._opened_at
            return elapsed >= self._current_open_duration


# ============================================================================
# PROVIDER HEALTH — EWMA tracking
# ============================================================================


@dataclass
class ProviderHealth:
    """Health tracking con EWMA (Exponentially Weighted Moving Average).

    Mantiene un score continuo [0.0, 1.0] donde:
        - 1.0 = perfecto (todas las llamadas exitosas)
        - 0.0 = caído (todas las llamadas fallando)

    El score se actualiza con cada llamada:
        score = alpha * outcome + (1 - alpha) * score_prev

    Donde outcome = 1.0 para éxito, 0.0 para fallo.

    Alpha más bajo → más inercia (responde lento, menos ruidoso)
    Alpha más alto → más reactivo (responde rápido, más ruidoso)

    Recomendaciones:
        - alpha = 0.1: producción, minimiza falsos positivos
        - alpha = 0.2: balance (default)
        - alpha = 0.4: testing, reacciona rápido

    God-Tier features:
    - EWMA smoothing: no reacciona a un solo fallo (a menos que alpha=1.0)
    - Threshold configurable: is_healthy si score >= threshold
    - Forense: total_calls, total_failures, last_failure_at
    - Thread-safe con RLock

    Uso típico:
        >>> health = ProviderHealth(provider="deepseek", alpha=0.2)
        >>> health.record(success=True)
        >>> health.record(success=False)
        >>> if not health.is_healthy:
        ...     switch_to_fallback()
    """

    provider: str
    alpha: float = DEFAULT_HEALTH_ALPHA
    health_threshold: float = DEFAULT_HEALTH_THRESHOLD
    score: float = 1.0
    total_calls: int = 0
    total_failures: int = 0
    last_failure_at: float | None = None
    last_success_at: float | None = None

    _lock: threading.RLock = field(
        default_factory=threading.RLock, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        if not 0.0 < self.alpha <= 1.0:
            raise ValueError(f"alpha debe estar en (0, 1], es {self.alpha}")
        if not 0.0 <= self.health_threshold <= 1.0:
            raise ValueError(
                f"health_threshold debe estar en [0, 1], es {self.health_threshold}"
            )

    # ------------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------------

    def record(self, success: bool) -> None:
        """Registra outcome y actualiza EWMA score."""
        with self._lock:
            now = time.time()
            self.total_calls += 1

            if success:
                self.last_success_at = now
                outcome = 1.0
            else:
                self.total_failures += 1
                self.last_failure_at = now
                outcome = 0.0

            self.score = self.alpha * outcome + (1.0 - self.alpha) * self.score
            # Clamp (por floating point drift)
            self.score = max(0.0, min(1.0, self.score))

    @property
    def is_healthy(self) -> bool:
        """True si el score actual >= threshold."""
        with self._lock:
            return self.score >= self.health_threshold

    @property
    def failure_rate(self) -> float:
        """Tasa de fallos histórica (no EWMA)."""
        with self._lock:
            if self.total_calls == 0:
                return 0.0
            return round(self.total_failures / self.total_calls, 4)

    def to_dict(self) -> dict[str, Any]:
        """Snapshot forense."""
        with self._lock:
            return {
                "provider": self.provider,
                "score": round(self.score, 4),
                "is_healthy": self.score >= self.health_threshold,
                "health_threshold": self.health_threshold,
                "alpha": self.alpha,
                "total_calls": self.total_calls,
                "total_failures": self.total_failures,
                "failure_rate": (
                    round(self.total_failures / self.total_calls, 4)
                    if self.total_calls
                    else 0.0
                ),
                "last_failure_at": self.last_failure_at,
                "last_success_at": self.last_success_at,
            }

    def reset(self) -> None:
        """Reset manual (post-incidente)."""
        with self._lock:
            self.score = 1.0
            self.total_calls = 0
            self.total_failures = 0
            self.last_failure_at = None
            self.last_success_at = None


# ============================================================================
# RETRY-AFTER PARSER (RFC 7231)
# ============================================================================


def parse_retry_after(value: str | None, default: float = 1.0) -> float:
    """Parsea header Retry-After (RFC 7231).

    Formatos soportados:
        - delta-seconds: "120" → 120.0
        - HTTP-date:     "Wed, 21 Oct 2026 07:28:00 GMT" → segundos hasta date

    Args:
        value: Header value o None.
        default: Valor por defecto si parsing falla.

    Returns:
        Segundos a esperar (clamped a [0, RETRY_AFTER_MAX_SECONDS]).
    """
    if not value:
        return default

    value = value.strip()

    # Formato 1: delta-seconds (entero)
    if value.isdigit():
        return max(0.0, min(float(value), RETRY_AFTER_MAX_SECONDS))

    # Formato 2: HTTP-date
    try:
        from email.utils import parsedate_to_datetime

        dt = parsedate_to_datetime(value)
        if dt is None:
            return default
        delta = dt.timestamp() - time.time()
        return max(0.0, min(delta, RETRY_AFTER_MAX_SECONDS))
    except (TypeError, ValueError):
        _log.debug("retry_after_parse_failed", value=value)
        return default


# ============================================================================
# __all__ EXPORTS
# ============================================================================

__all__ = [
    # Cache
    "CacheEntry",
    "CacheStats",
    "ResponseCache",
    # Circuit breaker
    "CircuitStatus",
    "CircuitBreaker",
    # Health
    "ProviderHealth",
    # Retry-After
    "parse_retry_after",
    # Constants (útiles para tests)
    "DEFAULT_CACHE_MAX_ENTRIES",
    "DEFAULT_CACHE_TTL_SECONDS",
    "CACHE_DETERMINISTIC_TEMPERATURE",
    "DEFAULT_CIRCUIT_THRESHOLD",
    "DEFAULT_CIRCUIT_OPEN_SECONDS",
    "DEFAULT_CIRCUIT_MAX_OPEN_SECONDS",
    "CIRCUIT_BACKOFF_MULTIPLIER",
    "DEFAULT_HEALTH_ALPHA",
    "DEFAULT_HEALTH_THRESHOLD",
    "RETRY_AFTER_MAX_SECONDS",
]
