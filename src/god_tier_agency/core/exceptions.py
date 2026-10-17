"""Core exceptions — God-Tier v5.0.

Jerarquía COMPLETA con taxonomía, clasificación y forense:

    GodTierError                                  (base)
    ├── SecurityError                             (crítico, no retry)
    │   ├── PromptInjectionDetected
    │   ├── CanaryLeakDetected
    │   ├── ScopeViolation
    │   ├── SandboxEscapeDetected
    │   ├── IntegrityError
    │   └── TamperDetected
    ├── OperationalError                          (base)
    │   ├── FatalError                            (no retry)
    │   │   ├── BudgetExceededError
    │   │   ├── ConfigurationError
    │   │   ├── StateError
    │   │   ├── CheckpointError
    │   │   ├── KillSwitchError
    │   │   └── TaskAbortedError
    │   ├── RecoverableError                      (retry, base)
    │   │   ├── SandboxError
    │   │   ├── SerializationError
    │   │   ├── ConcurrencyError
    │   │   ├── TimeoutError
    │   │   ├── ResourceError
    │   │   ├── NetworkError
    │   │   └── AuditError
    │   └── PipelineError                         (fase del pipeline)
    ├── AIError                                   (retry)
    │   ├── AIRateLimitError                      (con retry_after)
    │   ├── AITimeoutError
    │   ├── AIContextLengthError
    │   ├── AIProviderDownError
    │   └── AIInvalidResponseError
    ├── ConsensusError
    └── EvidenceError
        └── EvidenceIntegrityError

God-Tier v5.0 — diferenciadores vs v4.0:

IDENTIDAD Y FORENSE:
    - `error_id`: hash SHA-256 único por instancia (trazable)
    - `timestamp`: Unix timestamp (timeline)
    - `correlation_id`: propagado desde context
    - `parent_exception`: chain de causas
    - `root_cause`: property que resuelve toda la cadena

CLASIFICACIÓN:
    - `ErrorCategory` enum (SIEM-friendly)
    - `classify_error()`: clasifica cualquier excepción
    - `is_fatal()` / `is_retryable()` / `is_security_error()`
    - `to_prometheus()`: métricas exportables
    - `to_siem_event()`: SIEM-ready

SEGURIDAD:
    - Sanitización automática de `message` y `context`
    - Detección de API keys, tokens, AWS, GitHub, Slack, Stripe
    - `secret_patterns` configurables

BUILDER PATTERN:
    - `.with_context(**kwargs)`: agrega contexto (chainable)
    - `.with_correlation_id(id)`: propaga correlación
    - `.with_parent(exc)`: agrega causa
    - Inmutable después de construido (frozen-like)

EXPORTS:
    - `to_dict()`: dict estructurado
    - `to_jsonl()`: SIEM-ready JSONL
    - `to_prometheus()`: Prometheus format
    - `to_siem_event()`: OCSF/CEF friendly

Filosofía:
    - FAIL-CLOSED: en duda, fatal
    - ZERO-TRUST: sanitiza todo output
    - FORENSIC: cada error con id/timestamp/correlation
    - OBSERVABLE: Prometheus + SIEM
    - TAXONOMY: errores clasificables automáticamente
"""

from __future__ import annotations

import hashlib
import re
import time
from datetime import datetime, timezone
from enum import Enum
from typing import Any, ClassVar, Final, Literal, Sequence


# ============================================================================
# TIPOS
# ============================================================================

Severity = Literal["low", "medium", "high", "critical"]

_VALID_SEVERITIES: Final[frozenset[str]] = frozenset(
    {"low", "medium", "high", "critical"}
)


# ============================================================================
# TAXONOMY ENUM (SIEM-friendly)
# ============================================================================

class ErrorCategory(str, Enum):
    """Categoría de error para clasificación automática (SIEM)."""
    # Security
    SECURITY = "security"
    PROMPT_INJECTION = "prompt_injection"
    CANARY_LEAK = "canary_leak"
    SCOPE_VIOLATION = "scope_violation"
    SANDBOX_ESCAPE = "sandbox_escape"
    INTEGRITY = "integrity"
    TAMPER = "tamper"
    # Operational
    CONFIGURATION = "configuration"
    BUDGET = "budget"
    STATE = "state"
    CHECKPOINT = "checkpoint"
    KILL_SWITCH = "kill_switch"
    TASK_ABORTED = "task_aborted"
    SANDBOX = "sandbox"
    SERIALIZATION = "serialization"
    CONCURRENCY = "concurrency"
    TIMEOUT = "timeout"
    RESOURCE = "resource"
    NETWORK = "network"
    AUDIT = "audit"
    PIPELINE = "pipeline"
    # AI
    AI = "ai"
    AI_RATE_LIMIT = "ai_rate_limit"
    AI_TIMEOUT = "ai_timeout"
    AI_CONTEXT_LENGTH = "ai_context_length"
    AI_PROVIDER_DOWN = "ai_provider_down"
    AI_INVALID_RESPONSE = "ai_invalid_response"
    CONSENSUS = "consensus"
    # Evidence
    EVIDENCE = "evidence"
    EVIDENCE_INTEGRITY = "evidence_integrity"
    # Fallback
    UNKNOWN = "unknown"


# ============================================================================
# SECRET SANITIZATION
# ============================================================================

_SECRET_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    # API keys (label: value)
    re.compile(
        r"(?i)(api[_-]?key|apikey|access[_-]?key|secret[_-]?key)['\"]?\s*[:=]\s*['\"]?"
        r"([a-zA-Z0-9_\-]{16,})"
    ),
    re.compile(
        r"(?i)(secret|token|password|passwd|pwd|bearer)\s*[:=]\s*['\"]?([^\s'\"]{8,})"
    ),
    re.compile(r"(?i)bearer\s+([a-zA-Z0-9_\-\.]{20,})"),
    # AWS
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ASIA[0-9A-Z]{16}"),
    # GitHub
    re.compile(r"ghp_[a-zA-Z0-9]{36}"),
    re.compile(r"github_pat_[a-zA-Z0-9_]{82}"),
    # Slack
    re.compile(r"xox[baprs]-[a-zA-Z0-9-]+"),
    # Stripe
    re.compile(r"sk_live_[a-zA-Z0-9]{24,}"),
    re.compile(r"pk_live_[a-zA-Z0-9]{24,}"),
    # Private keys
    re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----"),
    # Generic high-entropy base64 tokens (>= 40 chars)
    re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b"),
)

_REDACTED: Final[str] = "[REDACTED]"


def _sanitize_string(text: str, max_len: int = 2000) -> str:
    """Sanitiza string: remueve secretos + trunca."""
    if not text:
        return ""
    result = text
    for pattern in _SECRET_PATTERNS:
        result = pattern.sub(_REDACTED, result)
    if len(result) > max_len:
        result = result[:max_len] + "...[truncated]"
    return result


def _sanitize_value(value: Any, depth: int = 0, max_depth: int = 3) -> Any:
    """Sanitiza valor recursivamente (dict, list, str)."""
    if depth > max_depth:
        return "[MAX_DEPTH]"

    if isinstance(value, str):
        return _sanitize_string(value, max_len=1000)

    if isinstance(value, dict):
        return {
            str(k)[:100]: _sanitize_value(v, depth + 1, max_depth)
            for k, v in list(value.items())[:50]
        }

    if isinstance(value, (list, tuple)):
        return [
            _sanitize_value(v, depth + 1, max_depth)
            for v in list(value)[:50]
        ]

    if isinstance(value, (int, float, bool)) or value is None:
        return value

    # Fallback: str truncado
    return _sanitize_string(str(value), max_len=500)


# ============================================================================
# HELPERS
# ============================================================================

def _hash_error_id(error_code: str, message: str, timestamp: float) -> str:
    """Genera error_id único (SHA-256 truncated)."""
    payload = f"{error_code}:{message}:{timestamp}"
    return hashlib.sha256(payload.encode("utf-8", errors="ignore")).hexdigest()[:16]


def _validate_severity(sev: str) -> Severity:
    """Valida severidad (fail-safe a 'high')."""
    if sev not in _VALID_SEVERITIES:
        return "high"
    return sev  # type: ignore[return-value]


# ============================================================================
# BASE
# ============================================================================

class GodTierError(Exception):
    """Base de todas las excepciones del sistema.

    Attributes:
        error_code: Código único del error (ClassVar).
        category: Categoría para SIEM (ClassVar).
        default_severity: Severidad por defecto (ClassVar).
        retryable: Si es retryable por defecto (ClassVar).
        message: Mensaje sanitizado.
        context: Dict con detalles (sanitizado).
        severity: Severidad efectiva.
        error_id: ID único por instancia.
        timestamp: Unix timestamp.
        correlation_id: ID de correlación (opcional).
        parent_exception: Causa raíz (opcional).
    """

    error_code: ClassVar[str] = "GODTIER_ERROR"
    category: ClassVar[ErrorCategory] = ErrorCategory.UNKNOWN
    default_severity: ClassVar[Severity] = "medium"
    retryable: ClassVar[bool] = False

    def __init__(
        self,
        message: str = "",
        *,
        context: dict[str, Any] | None = None,
        severity: Severity | None = None,
        retryable: bool | None = None,
        correlation_id: str | None = None,
        parent_exception: BaseException | None = None,
    ) -> None:
        # Mensaje con fallback
        if not message:
            message = (self.__class__.__doc__ or self.error_code).split("\n")[0].strip()

        super().__init__(message)

        # Timestamp + error_id (primero, para que esté disponible)
        self.timestamp: float = time.time()
        self.error_id: str = _hash_error_id(self.error_code, message, self.timestamp)

        # Mensaje sanitizado
        self.message: str = _sanitize_string(message, max_len=2000)

        # Context sanitizado
        self.context: dict[str, Any] = (
            _sanitize_value(context) if context else {}
        )

        # Severity (con validación)
        self.severity: Severity = _validate_severity(
            severity or self.default_severity
        )

        # Retryable (instance override)
        if retryable is not None:
            self.retryable = retryable  # type: ignore[misc]

        # Trazabilidad
        self.correlation_id: str | None = correlation_id
        self.parent_exception: BaseException | None = parent_exception

    # ------------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------------

    @property
    def timestamp_iso(self) -> str:
        return datetime.fromtimestamp(self.timestamp, tz=timezone.utc).isoformat()

    @property
    def is_fatal(self) -> bool:
        """True si NO es retryable."""
        return not self.retryable

    @property
    def is_security(self) -> bool:
        """True si es un error de seguridad."""
        return isinstance(self, SecurityError)

    @property
    def root_cause(self) -> BaseException:
        """Root cause siguiendo la cadena de parent_exception."""
        current: BaseException = self
        seen: set[int] = {id(current)}
        while isinstance(current, GodTierError) and current.parent_exception:
            if id(current.parent_exception) in seen:
                break  # cycle protection
            seen.add(id(current.parent_exception))
            current = current.parent_exception
        return current

    @property
    def chain_depth(self) -> int:
        """Profundidad de la cadena de causas."""
        depth = 0
        current: BaseException | None = self
        seen: set[int] = set()
        while isinstance(current, GodTierError) and current.parent_exception:
            if id(current.parent_exception) in seen:
                break
            seen.add(id(current.parent_exception))
            depth += 1
            current = current.parent_exception
        return depth

    # ------------------------------------------------------------------------
    # Builder pattern (chainable)
    # ------------------------------------------------------------------------

    def with_context(self, **kwargs: Any) -> "GodTierError":
        """Agrega contexto (chainable)."""
        for k, v in kwargs.items():
            self.context[k] = _sanitize_value(v)
        return self

    def with_correlation_id(self, correlation_id: str) -> "GodTierError":
        """Propaga correlation_id (chainable)."""
        self.correlation_id = correlation_id
        return self

    def with_parent(self, exc: BaseException) -> "GodTierError":
        """Agrega causa raíz (chainable)."""
        self.parent_exception = exc
        return self

    # ------------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Serializa para logging estructurado / SIEM."""
        d: dict[str, Any] = {
            "error_id": self.error_id,
            "error_code": self.error_code,
            "category": self.category.value,
            "class": self.__class__.__name__,
            "message": self.message,
            "severity": self.severity,
            "retryable": self.retryable,
            "is_fatal": self.is_fatal,
            "is_security": self.is_security,
            "context": self.context,
            "correlation_id": self.correlation_id,
            "timestamp": self.timestamp,
            "timestamp_iso": self.timestamp_iso,
        }

        # Chain de causas
        if self.parent_exception is not None:
            d["parent_exception"] = {
                "class": type(self.parent_exception).__name__,
                "message": _sanitize_string(str(self.parent_exception)),
            }
            d["chain_depth"] = self.chain_depth

        return d

    def to_jsonl(self) -> str:
        """Formato JSONL para SIEM export."""
        import json as _json
        return _json.dumps(self.to_dict(), separators=(",", ":"), ensure_ascii=False)

    def to_siem_event(self) -> dict[str, Any]:
        """Formato SIEM-ready (OCSF-inspired)."""
        severity_map = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        return {
            "class_uid": 2001,  # OCSF "Security Finding"
            "class_name": "Security Finding",
            "time": int(self.timestamp * 1000),
            "severity_id": severity_map.get(self.severity, 2),
            "activity_id": 1,  # Create
            "finding_info": {
                "uid": self.error_id,
                "title": self.error_code,
                "desc": self.message,
                "types": [self.category.value],
            },
            "metadata": self.context,
            "actor": {
                "session": {"uid": self.correlation_id} if self.correlation_id else {},
            },
            "raw_data": self.message,
        }

    def to_prometheus(self, namespace: str = "godtier_errors") -> str:
        """Métricas Prometheus."""
        return "\n".join([
            f'{namespace}_total{{category="{self.category.value}",'
            f'code="{self.error_code}",severity="{self.severity}"}} 1',
        ])

    def __str__(self) -> str:
        return (
            f"[{self.error_code}] {self.message} "
            f"(severity={self.severity}, retryable={self.retryable})"
        )

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"error_id={self.error_id!r}, "
            f"code={self.error_code!r}, "
            f"severity={self.severity!r})"
        )


# ============================================================================
# SECURITY ERRORS
# ============================================================================

class SecurityError(GodTierError):
    """Violación de seguridad detectada (categoría base).

    NO retryable. Activación de kill switch global recomendada.
    """

    error_code = "GODTIER_SECURITY"
    category = ErrorCategory.SECURITY
    default_severity: ClassVar[Severity] = "critical"
    retryable = False


class PromptInjectionDetected(SecurityError):
    """Prompt injection detectada en input/output."""

    error_code = "GODTIER_PROMPT_INJECTION"
    category = ErrorCategory.PROMPT_INJECTION
    default_severity: ClassVar[Severity] = "critical"


class CanaryLeakDetected(SecurityError):
    """Canary token detectado en output — posible exfiltración."""

    error_code = "GODTIER_CANARY_LEAK"
    category = ErrorCategory.CANARY_LEAK
    default_severity: ClassVar[Severity] = "critical"


class ScopeViolation(SecurityError):
    """Target o acción fuera de scope autorizado."""

    error_code = "GODTIER_SCOPE_VIOLATION"
    category = ErrorCategory.SCOPE_VIOLATION
    default_severity: ClassVar[Severity] = "critical"


class SandboxEscapeDetected(SecurityError):
    """Intento de escape del sandbox detectado."""

    error_code = "GODTIER_SANDBOX_ESCAPE"
    category = ErrorCategory.SANDBOX_ESCAPE
    default_severity: ClassVar[Severity] = "critical"


class IntegrityError(SecurityError):
    """Fallo de integridad (hash chain, firma, checkpoint)."""

    error_code = "GODTIER_INTEGRITY"
    category = ErrorCategory.INTEGRITY
    default_severity: ClassVar[Severity] = "critical"


class TamperDetected(SecurityError):
    """Tampering detectado (audit log, state machine, evidence)."""

    error_code = "GODTIER_TAMPER"
    category = ErrorCategory.TAMPER
    default_severity: ClassVar[Severity] = "critical"


# ============================================================================
# OPERATIONAL — FATAL (no retry)
# ============================================================================

class OperationalError(GodTierError):
    """Error operativo general (base)."""

    error_code = "GODTIER_OPERATIONAL"
    category = ErrorCategory.UNKNOWN
    default_severity: ClassVar[Severity] = "medium"
    retryable = False


class FatalError(OperationalError):
    """Base para errores que NO se pueden reintentar."""

    error_code = "GODTIER_FATAL"
    category = ErrorCategory.UNKNOWN
    default_severity: ClassVar[Severity] = "high"
    retryable = False


class BudgetExceededError(FatalError):
    """Presupuesto de engagement agotado."""

    error_code = "GODTIER_BUDGET_EXCEEDED"
    category = ErrorCategory.BUDGET
    default_severity: ClassVar[Severity] = "high"


class ConfigurationError(FatalError):
    """Error de configuración."""

    error_code = "GODTIER_CONFIG"
    category = ErrorCategory.CONFIGURATION
    default_severity: ClassVar[Severity] = "critical"


class StateError(FatalError):
    """Estado inconsistente (state machine, transiciones inválidas)."""

    error_code = "GODTIER_STATE"
    category = ErrorCategory.STATE
    default_severity: ClassVar[Severity] = "high"


class CheckpointError(FatalError):
    """Error al persistir/restaurar checkpoint."""

    error_code = "GODTIER_CHECKPOINT"
    category = ErrorCategory.CHECKPOINT
    default_severity: ClassVar[Severity] = "high"


class KillSwitchError(FatalError):
    """Kill switch global activado.

    Distinto de TaskAbortedError (que es abort local).
    """

    error_code = "GODTIER_KILL_SWITCH"
    category = ErrorCategory.KILL_SWITCH
    default_severity: ClassVar[Severity] = "high"


class TaskAbortedError(FatalError):
    """Task abortado manualmente (no es fallo)."""

    error_code = "GODTIER_TASK_ABORTED"
    category = ErrorCategory.TASK_ABORTED
    default_severity: ClassVar[Severity] = "low"


# ============================================================================
# OPERATIONAL — RECOVERABLE (retry)
# ============================================================================

class RecoverableError(OperationalError):
    """Base para errores que SÍ se pueden reintentar."""

    error_code = "GODTIER_RECOVERABLE"
    category = ErrorCategory.UNKNOWN
    default_severity: ClassVar[Severity] = "medium"
    retryable = True


class SandboxError(RecoverableError):
    """Error en el sandbox."""

    error_code = "GODTIER_SANDBOX"
    category = ErrorCategory.SANDBOX


class SerializationError(RecoverableError):
    """Error de serialización/deserialización (JSON, Pydantic)."""

    error_code = "GODTIER_SERIALIZATION"
    category = ErrorCategory.SERIALIZATION


class ConcurrencyError(RecoverableError):
    """Error de concurrencia (race condition detectada)."""

    error_code = "GODTIER_CONCURRENCY"
    category = ErrorCategory.CONCURRENCY


class TimeoutError(RecoverableError):
    """Timeout genérico."""

    error_code = "GODTIER_TIMEOUT"
    category = ErrorCategory.TIMEOUT


class ResourceError(RecoverableError):
    """Recursos excedidos (OOM, CPU, PIDs, disk).

    NOTA: retryable=True por default, pero el caller debe decidir
    si el reintento tiene sentido (ej: OOM → reducir carga).
    """

    error_code = "GODTIER_RESOURCE"
    category = ErrorCategory.RESOURCE


class NetworkError(RecoverableError):
    """Error de red (timeout, connection refused, DNS)."""

    error_code = "GODTIER_NETWORK"
    category = ErrorCategory.NETWORK


class AuditError(RecoverableError):
    """Error de audit log (escritura, verificación)."""

    error_code = "GODTIER_AUDIT"
    category = ErrorCategory.AUDIT


# ============================================================================
# OPERATIONAL — PIPELINE (fase)
# ============================================================================

class PipelineError(OperationalError):
    """Error en el pipeline (fase específica).

    Attributes:
        phase: Fase del pipeline donde ocurrió el error.
    """

    error_code = "GODTIER_PIPELINE"
    category = ErrorCategory.PIPELINE
    default_severity: ClassVar[Severity] = "high"
    retryable = False

    def __init__(
        self,
        message: str = "",
        *,
        phase: str = "unknown",
        context: dict[str, Any] | None = None,
        severity: Severity | None = None,
        retryable: bool | None = None,
        correlation_id: str | None = None,
        parent_exception: BaseException | None = None,
    ) -> None:
        ctx = dict(context or {})
        ctx["pipeline_phase"] = phase
        super().__init__(
            message,
            context=ctx,
            severity=severity,
            retryable=retryable,
            correlation_id=correlation_id,
            parent_exception=parent_exception,
        )
        self.phase = phase


# ============================================================================
# AI ERRORS
# ============================================================================

class AIError(RecoverableError):
    """Error en llamadas a IA (base)."""

    error_code = "GODTIER_AI"
    category = ErrorCategory.AI
    default_severity: ClassVar[Severity] = "medium"
    retryable = True


class AIRateLimitError(AIError):
    """Rate limit del proveedor.

    Attributes:
        retry_after_seconds: Segundos a esperar (si el provider los provee).
    """

    error_code = "GODTIER_AI_RATE_LIMIT"
    category = ErrorCategory.AI_RATE_LIMIT
    retryable = True

    def __init__(
        self,
        message: str = "",
        *,
        retry_after_seconds: float = 0.0,
        context: dict[str, Any] | None = None,
        severity: Severity | None = None,
        retryable: bool | None = None,
        correlation_id: str | None = None,
        parent_exception: BaseException | None = None,
    ) -> None:
        # Validar retry_after [0, 3600]
        if retry_after_seconds < 0:
            retry_after_seconds = 0.0
        if retry_after_seconds > 3600:
            retry_after_seconds = 3600.0

        ctx = dict(context or {})
        ctx["retry_after_seconds"] = round(retry_after_seconds, 2)
        super().__init__(
            message,
            context=ctx,
            severity=severity,
            retryable=retryable,
            correlation_id=correlation_id,
            parent_exception=parent_exception,
        )
        self.retry_after_seconds = retry_after_seconds


class AITimeoutError(AIError):
    """Timeout en la llamada al proveedor."""

    error_code = "GODTIER_AI_TIMEOUT"
    category = ErrorCategory.AI_TIMEOUT
    retryable = True


class AIContextLengthError(AIError):
    """El input excede el contexto máximo del modelo."""

    error_code = "GODTIER_AI_CONTEXT_LENGTH"
    category = ErrorCategory.AI_CONTEXT_LENGTH
    retryable = False  # No tiene sentido retry con mismo input


class AIProviderDownError(AIError):
    """El proveedor está caído o inaccesible."""

    error_code = "GODTIER_AI_PROVIDER_DOWN"
    category = ErrorCategory.AI_PROVIDER_DOWN
    retryable = True


class AIInvalidResponseError(AIError):
    """El proveedor devolvió una respuesta inválida."""

    error_code = "GODTIER_AI_INVALID_RESPONSE"
    category = ErrorCategory.AI_INVALID_RESPONSE
    retryable = False


# ============================================================================
# CONSENSUS ERRORS
# ============================================================================

class ConsensusError(GodTierError):
    """Error en el consensus engine."""

    error_code = "GODTIER_CONSENSUS"
    category = ErrorCategory.CONSENSUS
    default_severity: ClassVar[Severity] = "high"
    retryable = False


# ============================================================================
# EVIDENCE ERRORS
# ============================================================================

class EvidenceError(GodTierError):
    """Error en manejo de evidencia."""

    error_code = "GODTIER_EVIDENCE"
    category = ErrorCategory.EVIDENCE
    default_severity: ClassVar[Severity] = "high"
    retryable = False


class EvidenceIntegrityError(EvidenceError):
    """Fallo de integridad de evidencia (hash, firma, timestamp)."""

    error_code = "GODTIER_EVIDENCE_INTEGRITY"
    category = ErrorCategory.EVIDENCE_INTEGRITY
    default_severity: ClassVar[Severity] = "critical"
    retryable = False


# ============================================================================
# HELPERS PÚBLICOS
# ============================================================================

def is_retryable(error: BaseException) -> bool:
    """True si la excepción es retryable.

    Fail-closed: si no podemos determinar, retorna False.
    """
    if not isinstance(error, BaseException):
        return False
    if isinstance(error, GodTierError):
        return bool(error.retryable)
    return bool(getattr(error, "retryable", False))


def is_fatal(error: BaseException) -> bool:
    """True si la excepción NO es retryable."""
    if not isinstance(error, BaseException):
        return True
    if isinstance(error, GodTierError):
        return not error.retryable
    return not bool(getattr(error, "retryable", False))


def is_security_error(error: BaseException) -> bool:
    """True si la excepción es de seguridad."""
    if isinstance(error, GodTierError):
        return isinstance(error, SecurityError)
    return False


def classify_error(error: BaseException) -> str:
    """Clasifica un error para SIEM (retorna categoría).

    Args:
        error: Cualquier excepción.

    Returns:
        Categoría como string (SIEM-friendly).
    """
    if isinstance(error, GodTierError):
        return error.category.value

    # Clasificación por nombre de clase para errores no-GodTier
    class_name = type(error).__name__.lower()
    if "timeout" in class_name:
        return ErrorCategory.TIMEOUT.value
    if "connection" in class_name or "network" in class_name:
        return ErrorCategory.NETWORK.value
    if "permission" in class_name or "forbidden" in class_name:
        return ErrorCategory.SECURITY.value
    if "value" in class_name or "type" in class_name:
        return ErrorCategory.CONFIGURATION.value
    if "key" in class_name or "index" in class_name:
        return ErrorCategory.STATE.value
    if "runtime" in class_name:
        return ErrorCategory.UNKNOWN.value
    return ErrorCategory.UNKNOWN.value


def to_siem_event(error: BaseException) -> dict[str, Any]:
    """Convierte una excepción a evento SIEM estructurado.

    Si es GodTierError → usa to_siem_event() completo.
    Si no → genera evento genérico.
    """
    if isinstance(error, GodTierError):
        return error.to_siem_event()

    # Fallback genérico
    now = time.time()
    return {
        "class_uid": 2001,
        "class_name": "Security Finding",
        "time": int(now * 1000),
        "severity_id": 3,  # High (fail-closed)
        "activity_id": 1,
        "finding_info": {
            "uid": _hash_error_id(type(error).__name__, str(error), now),
            "title": f"GENERIC_{type(error).__name__.upper()}",
            "desc": _sanitize_string(str(error)),
            "types": [classify_error(error)],
        },
        "metadata": {},
        "raw_data": _sanitize_string(str(error)),
    }


def errors_to_prometheus(
    errors: Sequence[BaseException],
    namespace: str = "godtier_errors",
) -> str:
    """Genera métricas Prometheus agregadas para múltiples errores.

    Args:
        errors: Lista de excepciones.
        namespace: Prefijo de las métricas.

    Returns:
        String en formato Prometheus.
    """
    by_category: dict[str, int] = {}
    by_code: dict[str, int] = {}
    by_severity: dict[str, int] = {}

    for e in errors:
        cat = classify_error(e)
        by_category[cat] = by_category.get(cat, 0) + 1

        code = getattr(e, "error_code", f"GENERIC_{type(e).__name__.upper()}")
        by_code[code] = by_code.get(code, 0) + 1

        sev = getattr(e, "severity", "high")
        by_severity[sev] = by_severity.get(sev, 0) + 1

    lines = [
        f"# HELP {namespace}_total Total errors",
        f"# TYPE {namespace}_total counter",
        f"{namespace}_total {len(errors)}",
    ]
    for cat, count in sorted(by_category.items()):
        lines.append(f'{namespace}_by_category{{category="{cat}"}} {count}')
    for code, count in sorted(by_code.items()):
        lines.append(f'{namespace}_by_code{{code="{code}"}} {count}')
    for sev, count in sorted(by_severity.items()):
        lines.append(f'{namespace}_by_severity{{severity="{sev}"}} {count}')

    return "\n".join(lines)


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    # Types
    "Severity",
    "ErrorCategory",
    # Base
    "GodTierError",
    # Security
    "SecurityError",
    "PromptInjectionDetected",
    "CanaryLeakDetected",
    "ScopeViolation",
    "SandboxEscapeDetected",
    "IntegrityError",
    "TamperDetected",
    # Operational (fatal)
    "OperationalError",
    "FatalError",
    "BudgetExceededError",
    "ConfigurationError",
    "StateError",
    "CheckpointError",
    "KillSwitchError",
    "TaskAbortedError",
    # Operational (recoverable)
    "RecoverableError",
    "SandboxError",
    "SerializationError",
    "ConcurrencyError",
    "TimeoutError",
    "ResourceError",
    "NetworkError",
    "AuditError",
    # Pipeline
    "PipelineError",
    # AI
    "AIError",
    "AIRateLimitError",
    "AITimeoutError",
    "AIContextLengthError",
    "AIProviderDownError",
    "AIInvalidResponseError",
    # Consensus
    "ConsensusError",
    # Evidence
    "EvidenceError",
    "EvidenceIntegrityError",
    # Helpers
    "is_retryable",
    "is_fatal",
    "is_security_error",
    "classify_error",
    "to_siem_event",
    "errors_to_prometheus",
]
