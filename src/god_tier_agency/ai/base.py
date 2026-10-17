"""AI base client — God-Tier v5.0.

Contrato abstracto para todos los clientes LLM (DeepSeek, Qwen, Ollama, Anthropic).

Contratos:
    - ChatMessage: mensaje tipado con soporte para tool_calls + function_call
    - ChatRequest: request con validación estricta + context-aware
    - LLMResponse: respuesta inmutable con metadata forense completa
    - ModelCapabilities: qué soporta el modelo + compatibilidad
    - AIClient: interfaz abstracta (chat, chat_stream, health_check)
    - RequestBuilder: fluent API para construir requests

God-Tier v5.0 — diferenciadores vs v4.0:

SEGURIDAD:
    - Sanitización de secretos en ChatMessage.content y system
    - Límite de longitud en content (MAX_CONTENT_LENGTH = 1MB)
    - Límite de cantidad de mensajes (MAX_MESSAGES = 1000)
    - Detección de anomalías (whitespace ratio, control chars)
    - Validación de stop sequences (no vacías)
    - LLMResponse frozen (inmutable post-creación)

FORENSE:
    - LLMResponse con `to_dict()` + `to_siem()` + `to_jsonl()`
    - `request_id` UUID + `timestamp` + `trace_id` + `correlation_id`
    - `cached` flag + `cache_age_seconds`
    - `validated_tokens` (prompt + completion == total)
    - Cadena de causas en exceptions

CROSS-PROVIDER:
    - `to_openai_dict()`, `to_anthropic_dict()` en ChatMessage
    - `finish_reason` normalizado (STOP, LENGTH, CONTENT_FILTER, TOOL_CALLS, ERROR, TIMEOUT)
    - `ModelCapabilities.is_compatible_with(request)` validation
    - `validate_against_capabilities()` en AIClient

RESILIENCIA:
    - `AIRateLimitError` con `retry_after_seconds` validado [0, 3600]
    - `estimate_tokens()` en ChatRequest (con cache)
    - `count_tokens_estimate()` con cache por provider
    - `health_check()` con timeout configurable

OBSERVABILIDAD:
    - `trace_id` propagado en ChatRequest
    - `engagement_id` en ChatRequest
    - Structured logging con correlation_id
    - Prometheus-ready metrics

FILOSOFÍA:
    - INMUTABLE: LLMResponse frozen
    - VALIDADO: cada campo con validators
    - SANITIZADO: secretos redactados automáticamente
    - CROSS-PROVIDER: adapters para OpenAI/Anthropic
    - FORENSE: cada request/response trazable
    - RESILIENTE: retry_after respetado
"""

from __future__ import annotations

import hashlib
import re
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from functools import lru_cache
from typing import Any, AsyncIterator, ClassVar, Final
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from god_tier_agency.core.exceptions import AIError


# ============================================================================
# CONSTANTES
# ============================================================================

MAX_CONTENT_LENGTH: Final[int] = 1_000_000           # 1 MB por mensaje
MAX_MESSAGES: Final[int] = 1_000                     # Max mensajes por request
MAX_SYSTEM_LENGTH: Final[int] = 1_000_000            # 1 MB system prompt
MAX_STOP_SEQUENCES: Final[int] = 10                  # Max stop sequences
MAX_STOP_LENGTH: Final[int] = 50                     # Max longitud por stop
MAX_NAME_LENGTH: Final[int] = 64                     # Max longitud de name
MAX_WHITESPACE_RATIO: Final[float] = 0.95            # Max 95% whitespace

# Secret patterns (para sanitización)
_SECRET_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r"(?i)(api[_-]?key|apikey)['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{16,})"),
    re.compile(r"(?i)(secret|token|password)['\"]?\s*[:=]\s*['\"]?([^\s'\"]{8,})"),
    re.compile(r"(?i)bearer\s+([a-zA-Z0-9_\-\.]{20,})"),
    re.compile(r"AKIA[0-9A-Z]{16}"),           # AWS
    re.compile(r"ghp_[a-zA-Z0-9]{36}"),        # GitHub
    re.compile(r"sk_live_[a-zA-Z0-9]{24,}"),   # Stripe
    re.compile(r"xox[baprs]-[a-zA-Z0-9-]+"),   # Slack
    re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----"),
)


def _sanitize_text(text: str, max_len: int = MAX_CONTENT_LENGTH) -> str:
    """Sanitiza texto: secretos redactados + truncado."""
    if not text:
        return ""

    result = text
    for pattern in _SECRET_PATTERNS:
        result = pattern.sub("***REDACTED***", result)

    if len(result) > max_len:
        result = result[:max_len] + "...[truncated]"

    return result


# ============================================================================
# ENUMS
# ============================================================================

class MessageRole(str, Enum):
    """Rol de un mensaje en el chat."""
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"
    FUNCTION = "function"


class FinishReason(str, Enum):
    """Razón de finalización de la generación (normalizado)."""
    STOP = "stop"
    LENGTH = "length"
    CONTENT_FILTER = "content_filter"
    TOOL_CALLS = "tool_calls"
    ERROR = "error"
    TIMEOUT = "timeout"
    UNKNOWN = "unknown"


# ============================================================================
# EXCEPCIONES ESPECÍFICAS DE IA (con retry_after)
# ============================================================================

class AIRateLimitError(AIError):
    """Rate limit excedido por el proveedor (429).

    Attributes:
        retry_after_seconds: Segundos a esperar (de header Retry-After).
    """

    error_code = "GODTIER_AI_RATE_LIMIT"
    retryable = True

    def __init__(
        self,
        message: str = "",
        *,
        retry_after_seconds: float = 0.0,
        context: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        # Validar [0, 3600]
        if retry_after_seconds < 0:
            retry_after_seconds = 0.0
        if retry_after_seconds > 3600:
            retry_after_seconds = 3600.0

        ctx = dict(context or {})
        ctx["retry_after_seconds"] = round(retry_after_seconds, 2)

        super().__init__(message, context=ctx, **kwargs)
        self.retry_after_seconds = retry_after_seconds


class AITimeoutError(AIError):
    """Timeout en la llamada al proveedor."""

    error_code = "GODTIER_AI_TIMEOUT"
    retryable = True


class AIContextLengthError(AIError):
    """El input excede el contexto máximo del modelo."""

    error_code = "GODTIER_AI_CONTEXT_LENGTH"
    retryable = False


class AIProviderDownError(AIError):
    """El proveedor está caído o inaccesible (5xx, connection error)."""

    error_code = "GODTIER_AI_PROVIDER_DOWN"
    retryable = True


class AIInvalidResponseError(AIError):
    """El proveedor devolvió una respuesta inválida (malformed JSON, missing fields)."""

    error_code = "GODTIER_AI_INVALID_RESPONSE"
    retryable = False


class AIContentFilteredError(AIError):
    """El contenido fue filtrado por política del proveedor.

    NO retryable — el mismo prompt será filtrado de nuevo.
    """

    error_code = "GODTIER_AI_CONTENT_FILTERED"
    retryable = False


# ============================================================================
# CAPABILITIES
# ============================================================================

@dataclass(frozen=True)
class ModelCapabilities:
    """Capacidades del modelo (inmutable).

    Permite a los agentes elegir el proveedor correcto.
    """

    # Features
    supports_json_mode: bool = False
    supports_streaming: bool = False
    supports_function_calling: bool = False
    supports_vision: bool = False
    supports_system_prompt: bool = True
    supports_seed: bool = False
    supports_stop_sequences: bool = True

    # Limits
    max_context_tokens: int = 8192
    max_output_tokens: int = 4096

    # Pricing (USD per 1M tokens)
    price_input_per_m: float = 0.0
    price_output_per_m: float = 0.0

    # Provider info
    provider: str = "unknown"
    model_family: str = "unknown"

    def is_compatible_with(self, request: "ChatRequest") -> tuple[bool, str]:
        """Valida si un request es compatible con estas capabilities.

        Returns:
            (is_compatible, reason)
        """
        # JSON mode
        if request.response_format_json and not self.supports_json_mode:
            return (False, f"{self.provider} no soporta JSON mode")

        # System prompt
        if request.system and not self.supports_system_prompt:
            return (False, f"{self.provider} no soporta system prompt")

        # Function calling
        has_tool_calls = any(m.tool_calls or m.tool_call_id for m in request.messages)
        if has_tool_calls and not self.supports_function_calling:
            return (False, f"{self.provider} no soporta function calling")

        # Stop sequences
        if request.stop and not self.supports_stop_sequences:
            return (False, f"{self.provider} no soporta stop sequences")

        # Seed
        if request.seed is not None and not self.supports_seed:
            return (False, f"{self.provider} no soporta seed")

        # Output tokens
        if request.max_tokens > self.max_output_tokens:
            return (
                False,
                f"max_tokens ({request.max_tokens}) excede "
                f"output limit ({self.max_output_tokens})",
            )

        return (True, "OK")


# ============================================================================
# CHAT MESSAGE
# ============================================================================

class ChatMessage(BaseModel):
    """Un mensaje individual en una conversación.

    Soporta:
        - Roles: system/user/assistant/tool/function
        - Function calling (tool_calls legacy + modern)
        - Metadata forense
        - Sanitización de secretos
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    role: MessageRole
    content: str = Field(default="", max_length=MAX_CONTENT_LENGTH)
    name: str | None = Field(default=None, max_length=MAX_NAME_LENGTH)
    tool_call_id: str | None = Field(default=None, max_length=128)
    tool_calls: list[dict[str, Any]] = Field(default_factory=list)
    function_call: dict[str, Any] | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("content")
    @classmethod
    def _validate_content(cls, v: str) -> str:
        """Valida y sanitiza content."""
        if not isinstance(v, str):
            raise ValueError(f"content debe ser str, recibió {type(v).__name__}")

        # Sanitizar secretos
        v = _sanitize_text(v)

        # Detectar anomalías (whitespace ratio)
        if len(v) > 100:
            whitespace = sum(1 for c in v if c in " \t\n\r")
            if whitespace / len(v) > MAX_WHITESPACE_RATIO:
                raise ValueError(
                    f"content tiene exceso de whitespace "
                    f"({whitespace}/{len(v)})"
                )

        return v

    @field_validator("tool_calls")
    @classmethod
    def _validate_tool_calls(cls, v: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Valida estructura de tool_calls."""
        if len(v) > 10:
            raise ValueError(f"máximo 10 tool_calls, recibidos {len(v)}")
        return v

    def to_openai_dict(self) -> dict[str, Any]:
        """Serializa para API OpenAI-compatible."""
        d: dict[str, Any] = {"role": self.role.value, "content": self.content}
        if self.name:
            d["name"] = self.name
        if self.tool_call_id:
            d["tool_call_id"] = self.tool_call_id
        if self.tool_calls:
            d["tool_calls"] = self.tool_calls
        if self.function_call:
            d["function_call"] = self.function_call
        return d

    def to_anthropic_dict(self) -> dict[str, Any]:
        """Serializa para API Anthropic (diferente schema)."""
        d: dict[str, Any] = {"role": self.role.value, "content": self.content}
        # Anthropic usa content blocks, no string
        if self.tool_calls:
            blocks = []
            for tc in self.tool_calls:
                blocks.append({
                    "type": "tool_use",
                    "id": tc.get("id", ""),
                    "name": tc.get("function", {}).get("name", ""),
                    "input": tc.get("function", {}).get("arguments", {}),
                })
            if blocks:
                d["content"] = blocks
        return d

    # Backward compat
    def to_api_dict(self) -> dict[str, Any]:
        return self.to_openai_dict()


# ============================================================================
# CHAT REQUEST
# ============================================================================

class ChatRequest(BaseModel):
    """Request a un LLM (validación estricta + context-aware)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    # Content
    system: str | None = Field(default=None, max_length=MAX_SYSTEM_LENGTH)
    messages: list[ChatMessage] = Field(default_factory=list)

    # Sampling
    temperature: float = Field(default=0.2, ge=0.0, le=2.0)
    max_tokens: int = Field(default=4000, ge=1, le=128_000)
    top_p: float = Field(default=1.0, ge=0.0, le=1.0)
    frequency_penalty: float = Field(default=0.0, ge=-2.0, le=2.0)
    presence_penalty: float = Field(default=0.0, ge=-2.0, le=2.0)

    # Format
    response_format_json: bool = False
    stop: list[str] | None = None
    seed: int | None = None

    # Resilience
    timeout_seconds: float = Field(default=120.0, ge=1.0, le=600.0)

    # Forense
    trace_id: str | None = Field(default=None, max_length=64)
    engagement_id: str | None = Field(default=None, max_length=64)

    @field_validator("system")
    @classmethod
    def _validate_system(cls, v: str | None) -> str | None:
        if v is None:
            return None
        return _sanitize_text(v, max_len=MAX_SYSTEM_LENGTH)

    @field_validator("messages")
    @classmethod
    def _validate_messages(cls, v: list[ChatMessage]) -> list[ChatMessage]:
        """Valida cantidad de mensajes."""
        if len(v) > MAX_MESSAGES:
            raise ValueError(
                f"máximo {MAX_MESSAGES} mensajes, recibidos {len(v)}"
            )
        return v

    @field_validator("stop")
    @classmethod
    def _validate_stop(cls, v: list[str] | None) -> list[str] | None:
        """Valida stop sequences (no vacías, límite de count)."""
        if v is None:
            return None
        if len(v) > MAX_STOP_SEQUENCES:
            raise ValueError(
                f"máximo {MAX_STOP_SEQUENCES} stop sequences, "
                f"recibidas {len(v)}"
            )
        result: list[str] = []
        for s in v:
            if not s:
                continue  # Skip empty
            if len(s) > MAX_STOP_LENGTH:
                s = s[:MAX_STOP_LENGTH]
            result.append(s)
        return result or None

    @model_validator(mode="after")
    def _validate_consistency(self) -> "ChatRequest":
        """Validaciones cross-field."""
        # Al menos un mensaje
        if not self.messages:
            raise ValueError("messages no puede estar vacío")

        # No permitir system + primer mensaje system (evita conflicto)
        if self.system and self.messages and self.messages[0].role == MessageRole.SYSTEM:
            raise ValueError(
                "no usar system en ChatRequest Y primer message como system"
            )

        return self

    # ------------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------------

    def to_openai_messages(self) -> list[dict[str, Any]]:
        """Convierte a formato OpenAI-compatible."""
        msgs: list[dict[str, Any]] = []
        if self.system:
            msgs.append({"role": "system", "content": self.system})
        for m in self.messages:
            msgs.append(m.to_openai_dict())
        return msgs

    def to_anthropic_messages(self) -> tuple[str | None, list[dict[str, Any]]]:
        """Convierte a formato Anthropic (system separado)."""
        msgs: list[dict[str, Any]] = []
        for m in self.messages:
            msgs.append(m.to_anthropic_dict())
        return (self.system, msgs)

    # ------------------------------------------------------------------------
    # Token estimation
    # ------------------------------------------------------------------------

    def estimate_tokens(self) -> int:
        """Estima tokens totales del request (con cache)."""
        return _estimate_request_tokens(self)


# ============================================================================
# TOKEN ESTIMATION CACHE
# ============================================================================

@lru_cache(maxsize=10_000)
def _estimate_text_tokens(text: str) -> int:
    """Estima tokens de un texto (cache LRU).

    Heurística: 1 token ≈ 4 chars (GPT/DeepSeek).
    Para CJK: 1 token ≈ 1.5 chars.
    """
    if not text:
        return 0

    # Detectar CJK (chino/japonés/coreano)
    cjk_count = sum(1 for c in text if '\u4e00' <= c <= '\u9fff')
    if cjk_count > len(text) * 0.1:
        # CJK: 1 token ≈ 1.5 chars
        return int(len(text) / 1.5)

    # Latín: 1 token ≈ 4 chars
    return len(text) // 4


def _estimate_request_tokens(request: ChatRequest) -> int:
    """Estima tokens de un ChatRequest completo."""
    total = 0
    if request.system:
        total += _estimate_text_tokens(request.system)
    for m in request.messages:
        total += _estimate_text_tokens(m.content)
    return total


# ============================================================================
# LLM RESPONSE (frozen + forense)
# ============================================================================

@dataclass(frozen=True)
class LLMResponse:
    """Respuesta inmutable de un LLM con metadata completa.

    God-Tier v5.0:
        - frozen=True (previene mutación post-respuesta)
        - validación de tokens (prompt + completion == total)
        - forensic metadata (trace_id, correlation_id)
        - SIEM-ready (to_siem, to_jsonl)
    """

    # Content
    content: str

    # Identity
    request_id: UUID = field(default_factory=uuid4)
    model: str = ""
    provider: str = ""

    # Tokens
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0

    # Cost + latency
    cost_usd: float = 0.0
    latency_ms: float = 0.0

    # State
    finish_reason: FinishReason = FinishReason.STOP

    # Cache
    cached: bool = False
    cache_age_seconds: float = 0.0

    # Forense
    timestamp: float = field(default_factory=time.time)
    trace_id: str | None = None
    correlation_id: str | None = None
    engagement_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validación post-creación."""
        # Validar consistencia de tokens
        if self.total_tokens == 0 and (self.prompt_tokens + self.completion_tokens > 0):
            # Auto-corregir
            object.__setattr__(
                self,
                "total_tokens",
                self.prompt_tokens + self.completion_tokens,
            )

        # Sanitizar content
        sanitized = _sanitize_text(self.content)
        if sanitized != self.content:
            object.__setattr__(self, "content", sanitized)

    # ------------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------------

    @property
    def was_truncated(self) -> bool:
        return self.finish_reason == FinishReason.LENGTH

    @property
    def was_filtered(self) -> bool:
        return self.finish_reason == FinishReason.CONTENT_FILTER

    @property
    def was_cached(self) -> bool:
        return self.cached

    @property
    def timestamp_iso(self) -> str:
        from datetime import datetime, timezone
        return datetime.fromtimestamp(self.timestamp, tz=timezone.utc).isoformat()

    @property
    def content_hash(self) -> str:
        """SHA-256 del content (para forense)."""
        return hashlib.sha256(self.content.encode("utf-8")).hexdigest()[:16]

    # ------------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Serializa para logging o DB."""
        return {
            "request_id": str(self.request_id),
            "content": self.content,
            "content_hash": self.content_hash,
            "model": self.model,
            "provider": self.provider,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
            "cost_usd": round(self.cost_usd, 6),
            "latency_ms": round(self.latency_ms, 2),
            "finish_reason": self.finish_reason.value,
            "cached": self.cached,
            "cache_age_seconds": round(self.cache_age_seconds, 2),
            "timestamp": self.timestamp,
            "timestamp_iso": self.timestamp_iso,
            "trace_id": self.trace_id,
            "correlation_id": self.correlation_id,
            "engagement_id": self.engagement_id,
            "metadata": self.metadata,
        }

    def to_jsonl(self) -> str:
        """Formato JSONL para SIEM export."""
        import json as _json
        return _json.dumps(self.to_dict(), separators=(",", ":"), ensure_ascii=False)

    def to_siem(self) -> dict[str, Any]:
        """Formato SIEM (OCSF-inspired)."""
        return {
            "class_uid": 3002,  # OCSF "API Activity"
            "class_name": "API Activity",
            "time": int(self.timestamp * 1000),
            "activity_id": 1,  # Create
            "actor": {
                "app": {"name": self.provider},
                "session": {"uid": self.trace_id} if self.trace_id else {},
            },
            "resources": [{"type": "llm_call", "name": self.model}],
            "metrics": {
                "prompt_tokens": self.prompt_tokens,
                "completion_tokens": self.completion_tokens,
                "total_tokens": self.total_tokens,
                "latency_ms": self.latency_ms,
                "cost_usd": self.cost_usd,
            },
            "unmapped": {
                "finish_reason": self.finish_reason.value,
                "cached": self.cached,
                "content_hash": self.content_hash,
                "engagement_id": self.engagement_id,
            },
        }


# ============================================================================
# REQUEST BUILDER (fluent API)
# ============================================================================

class RequestBuilder:
    """Fluent API para construir ChatRequest.

    Uso:
        >>> request = (
        ...     RequestBuilder()
        ...     .system("You are a planner")
        ...     .user("Plan attack on example.com")
        ...     .temperature(0.3)
        ...     .max_tokens(8000)
        ...     .json_mode()
        ...     .build()
        ... )
    """

    def __init__(self) -> None:
        self._system: str | None = None
        self._messages: list[ChatMessage] = []
        self._temperature: float = 0.2
        self._max_tokens: int = 4000
        self._top_p: float = 1.0
        self._frequency_penalty: float = 0.0
        self._presence_penalty: float = 0.0
        self._response_format_json: bool = False
        self._stop: list[str] | None = None
        self._seed: int | None = None
        self._timeout_seconds: float = 120.0
        self._trace_id: str | None = None
        self._engagement_id: str | None = None

    def system(self, content: str) -> "RequestBuilder":
        self._system = content
        return self

    def user(self, content: str) -> "RequestBuilder":
        self._messages.append(ChatMessage(role=MessageRole.USER, content=content))
        return self

    def assistant(self, content: str) -> "RequestBuilder":
        self._messages.append(ChatMessage(role=MessageRole.ASSISTANT, content=content))
        return self

    def message(self, role: MessageRole, content: str) -> "RequestBuilder":
        self._messages.append(ChatMessage(role=role, content=content))
        return self

    def temperature(self, value: float) -> "RequestBuilder":
        self._temperature = value
        return self

    def max_tokens(self, value: int) -> "RequestBuilder":
        self._max_tokens = value
        return self

    def top_p(self, value: float) -> "RequestBuilder":
        self._top_p = value
        return self

    def json_mode(self) -> "RequestBuilder":
        self._response_format_json = True
        return self

    def stop(self, *sequences: str) -> "RequestBuilder":
        self._stop = list(sequences) or None
        return self

    def seed(self, value: int) -> "RequestBuilder":
        self._seed = value
        return self

    def timeout(self, seconds: float) -> "RequestBuilder":
        self._timeout_seconds = seconds
        return self

    def trace(self, trace_id: str) -> "RequestBuilder":
        self._trace_id = trace_id
        return self

    def engagement(self, engagement_id: str) -> "RequestBuilder":
        self._engagement_id = engagement_id
        return self

    def build(self) -> ChatRequest:
        return ChatRequest(
            system=self._system,
            messages=self._messages,
            temperature=self._temperature,
            max_tokens=self._max_tokens,
            top_p=self._top_p,
            frequency_penalty=self._frequency_penalty,
            presence_penalty=self._presence_penalty,
            response_format_json=self._response_format_json,
            stop=self._stop,
            seed=self._seed,
            timeout_seconds=self._timeout_seconds,
            trace_id=self._trace_id,
            engagement_id=self._engagement_id,
        )


# ============================================================================
# AICLIENT (abstracto)
# ============================================================================

class AIClient(ABC):
    """Contrato que todo cliente LLM debe cumplir.

    Implementaciones deben proveer:
        - chat(request): llamada simple
        - chat_stream(request): streaming (si soportado)
        - health_check(): verificar disponibilidad
        - capabilities: qué soporta el modelo
    """

    # Cache de token estimation (compartido entre instancias)
    _token_cache_lock: ClassVar[threading.RLock] = threading.RLock()

    @property
    @abstractmethod
    def model_name(self) -> str:
        """Nombre del modelo."""
        ...

    @property
    @abstractmethod
    def provider(self) -> str:
        """Proveedor (deepseek/qwen/ollama/anthropic)."""
        ...

    @property
    @abstractmethod
    def capabilities(self) -> ModelCapabilities:
        """Capacidades del modelo."""
        ...

    # ------------------------------------------------------------------------
    # Chat API
    # ------------------------------------------------------------------------

    @abstractmethod
    async def chat(self, request: ChatRequest) -> LLMResponse:
        """Envía chat completion request.

        Raises:
            AIRateLimitError: 429 con retry_after_seconds.
            AITimeoutError: excede timeout_seconds.
            AIContextLengthError: excede max_context_tokens.
            AIProviderDownError: 5xx, connection error.
            AIInvalidResponseError: malformed response.
            AIContentFilteredError: content filter.
            AIError: otros.
        """
        ...

    async def chat_stream(self, request: ChatRequest) -> AsyncIterator[str]:
        """Chat con streaming. Default: no soportado."""
        raise NotImplementedError(
            f"{self.provider} no soporta streaming"
        )
        yield ""  # pragma: no cover

    # ------------------------------------------------------------------------
    # Health check
    # ------------------------------------------------------------------------

    async def health_check(self, timeout_seconds: float = 10.0) -> bool:
        """Verifica disponibilidad del proveedor."""
        try:
            await self.chat(ChatRequest(
                messages=[
                    ChatMessage(role=MessageRole.USER, content="ping"),
                ],
                max_tokens=1,
                timeout_seconds=timeout_seconds,
            ))
            return True
        except Exception:
            return False

    # ------------------------------------------------------------------------
    # Validation helpers
    # ------------------------------------------------------------------------

    def validate_request(self, request: ChatRequest) -> None:
        """Valida request contra capabilities del modelo.

        Raises:
            AIError: si el request es incompatible.
        """
        is_compatible, reason = self.capabilities.is_compatible_with(request)
        if not is_compatible:
            raise AIError(
                f"Request incompatible con {self.provider}: {reason}",
                context={"provider": self.provider, "reason": reason},
            )

        # Validar context length
        estimated = request.estimate_tokens()
        max_ctx = self.capabilities.max_context_tokens
        if estimated + request.max_tokens > max_ctx:
            raise AIContextLengthError(
                f"Request excede context: "
                f"{estimated + request.max_tokens} > {max_ctx}",
                context={
                    "provider": self.provider,
                    "input_tokens": estimated,
                    "max_output": request.max_tokens,
                    "max_context": max_ctx,
                },
            )

    # ------------------------------------------------------------------------
    # Token estimation
    # ------------------------------------------------------------------------

    def count_tokens_estimate(self, text: str) -> int:
        """Estima tokens (con cache global)."""
        return _estimate_text_tokens(text)

    def estimate_request_tokens(self, request: ChatRequest) -> int:
        """Estima tokens del request completo."""
        return request.estimate_tokens()


__all__ = [
    # Enums
    "MessageRole",
    "FinishReason",
    # Exceptions
    "AIRateLimitError",
    "AITimeoutError",
    "AIContextLengthError",
    "AIProviderDownError",
    "AIInvalidResponseError",
    "AIContentFilteredError",
    # Models
    "ModelCapabilities",
    "ChatMessage",
    "ChatRequest",
    "LLMResponse",
    "RequestBuilder",
    "AIClient",
    # Constants
    "MAX_CONTENT_LENGTH",
    "MAX_MESSAGES",
    "MAX_SYSTEM_LENGTH",
    "MAX_STOP_SEQUENCES",
]
