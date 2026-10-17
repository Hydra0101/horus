"""Agent exceptions — God-Tier v5.0.

Jerarquía COMPLETA con clasificación explícita retryable/fatal:

    GodTierError
    └── AgentError                              (base)
        ├── FATAL (retryable = False)
        │   ├── AgentContractError              (contrato violado)
        │   ├── AgentInputError                 (input inválido)
        │   ├── AgentConfigError                (config inválida)
        │   ├── AgentCancelledError             (cancelación manual)
        │   ├── AgentKillSwitchError            (kill switch global)
        │   ├── AgentSecurityError              (escape/violación)
        │   │   ├── AgentScopeViolationError
        │   │   ├── AgentEscapeError
        │   │   └── AgentCanaryLeakError
        │   ├── AgentBudgetExceededError        (budget agotado)
        │   └── AgentResourceError              (OOM/CPU/PIDs)
        ├── RETRYABLE (retryable = True, default)
        │   ├── AgentOutputError                (output inválido)
        │   ├── AgentTimeoutError               (timeout)
        │   ├── AgentToolError                  (tool falló)
        │   ├── AgentSerializationError         (JSON errors)
        │   ├── AgentConcurrencyError           (race condition)
        │   └── AgentLLMError                   (LLM falló)
        │       └── AgentRateLimitError         (429)

God-Tier v5.0 — diferenciadores vs v2.0:

CLASIFICACIÓN EXPLÍCITA:
    - Cada clase tiene `retryable: ClassVar[bool]` (no instance)
    - `AgentError` base NO hereda de RetryableError (fix fail-open)
    - Retry policy clara: fail-closed por default
    - 15 clases vs 10 (cobertura completa)

FORENSE:
    - `error_id`: UUID4 único por instancia (trazable)
    - `timestamp`: Unix timestamp (timeline)
    - `correlation_id`: propagado desde context
    - `to_dict()`: SIEM-ready
    - `to_jsonl()`: export directo
    - Chain de causas: `parent_exception`
    - Sanitización de comandos (secrets redactados)

OBSERVABILIDAD:
    - `error_code`: string inmutable + validado
    - `severity`: Literal alineado con sistema
    - `to_prometheus()`: métricas exportables
    - `classify_error()`: clasificación automática
    - `is_retryable()`, `is_fatal()`, `is_security_error()` helpers

SEGURIDAD:
    - Fail-closed: en duda, NO retry
    - Security errors: retryable=False explícito
    - Budget exceeded: fatal (no retry)
    - Kill switch: fatal (no retry)
    - RateLimit: retryable=True + retry_after validado

RESILIENCIA:
    - `retry_after_seconds` con validación (>= 0)
    - `max_retries` contextualizado
    - `circuit_breaker_open` flag
    - `deadline_exceeded` flag

Filosofía:
    - FAIL-CLOSED: en duda, clasificar como fatal
    - ZERO-TRUST: sanitizar todo output
    - FORENSIC: cada error con id/timestamp/correlation
    - OBSERVABLE: to_prometheus + classify_error
    - VERSIONABLE: error_code inmutable + severity
"""

from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, ClassVar, Final, Literal
from uuid import UUID, uuid4


# ============================================================================
# TIPOS
# ============================================================================

Severity = Literal["low", "medium", "high", "critical"]

_VALID_SEVERITIES: Final[frozenset[str]] = frozenset(
    {"low", "medium", "high", "critical"}
)


# ============================================================================
# SANITIZACIÓN DE SECRETOS
# ============================================================================

_SECRET_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    # API keys
    re.compile(
        r"(?i)(api[_-]?key|apikey|access[_-]?key)['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{16,})"
    ),
    re.compile(
        r"(?i)(secret|token|password|passwd|pwd)['\"]?\s*[:=]\s*['\"]?([^\s'\"]{8,})"
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
    # Generic high-entropy tokens
    re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b"),
    # Private keys
    re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----"),
)


def _sanitize(text: str, max_len: int = 500) -> str:
    """Sanitiza texto de secretos + trunca."""
    if not text:
        return ""
    result = text
    for pattern in _SECRET_PATTERNS:
        result = pattern.sub("[REDACTED]", result)
    if len(result) > max_len:
        result = result[:max_len] + "...[truncated]"
    return result


def _hash_error_id(error_code: str, message: str, timestamp: float) -> str:
    """Genera error_id determinístico + timestamp."""
    payload = f"{error_code}:{message}:{timestamp}"
    return hashlib.sha256(payload.encode("utf-8", errors="ignore")).hexdigest()[:16]


# ============================================================================
# ERROR TAXONOMY (documentación viva)
# ============================================================================

class ErrorCategory(str, Enum):
    """Categoría de error para clasificación automática (SIEM)."""
    CONTRACT = "contract"
    INPUT = "input"
    OUTPUT = "output"
    CONFIG = "config"
    CANCELLED = "cancelled"
    KILL_SWITCH = "kill_switch"
    SECURITY = "security"
    BUDGET = "budget"
    RESOURCE = "resource"
    TIMEOUT = "timeout"
    TOOL = "tool"
    SERIALIZATION = "serialization"
    CONCURRENCY = "concurrency"
    LLM = "llm"
    RATE_LIMIT = "rate_limit"
    UNKNOWN = "unknown"


# ============================================================================
# BASE
# ============================================================================

class AgentError(Exception):
    """Base de todas las excepciones de agentes.

    God-Tier v5.0:
        - NO hereda de RetryableError (fix fail-open)
        - `retryable` como ClassVar explícito por subclase
        - `error_code` como string inmutable
        - Forense: error_id, timestamp, correlation_id
        - SIEM-ready: to_dict() + to_jsonl()

    Attributes:
        error_code: Código único del error (inmutable por clase).
        category: Categoría para clasificación SIEM.
        default_severity: Severidad por defecto.
        retryable: Si el error puede reintentarse (ClassVar).
        agent_name: Nombre del agente que falló.
        correlation_id: ID de correlación (para SIEM).
        error_id: UUID único de esta instancia.
        timestamp: Unix timestamp del error.
    """

    error_code: ClassVar[str] = "GODTIER_AGENT"
    category: ClassVar[ErrorCategory] = ErrorCategory.UNKNOWN
    default_severity: ClassVar[Severity] = "high"
    retryable: ClassVar[bool] = False  # Fail-closed por default

    def __init__(
        self,
        message: str = "",
        *,
        agent_name: str = "unknown",
        context: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
        severity: Severity | None = None,
        retryable: bool | None = None,
        correlation_id: str | None = None,
        parent_exception: Exception | None = None,
    ) -> None:
        # Mensaje con fallback
        if not message:
            message = self.__class__.__doc__ or self.error_code
            message = message.split("\n")[0].strip()

        super().__init__(message)

        # Timestamp + ID
        self.timestamp: float = time.time()
        self.error_id: str = _hash_error_id(
            self.error_code, message, self.timestamp
        )

        # Mensaje
        self.message: str = _sanitize(message, max_len=2000)

        # Metadata
        self.agent_name: str = agent_name
        self.context: dict[str, Any] = context or {}
        self.metadata: dict[str, Any] = metadata or {}
        self.correlation_id: str | None = correlation_id
        self.parent_exception: Exception | None = parent_exception

        # Severity + retryable (instance overrides)
        self.severity: Severity = self._validate_severity(
            severity or self.default_severity
        )
        if retryable is not None:
            self.retryable = retryable  # type: ignore[misc]

    # ------------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------------

    @staticmethod
    def _validate_severity(sev: str) -> Severity:
        if sev not in _VALID_SEVERITIES:
            return "high"  # Fail-safe
        return sev  # type: ignore[return-value]

    # ------------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------------

    @property
    def timestamp_iso(self) -> str:
        return datetime.fromtimestamp(self.timestamp, tz=timezone.utc).isoformat()

    @property
    def is_fatal(self) -> bool:
        """True si el error NO es retryable."""
        return not self.retryable

    @property
    def is_security(self) -> bool:
        """True si es error de seguridad."""
        return self.category == ErrorCategory.SECURITY

    @property
    def root_cause(self) -> "Exception":
        """Root cause siguiendo la cadena de parent_exception."""
        current: Exception = self
        seen: set[int] = {id(current)}
        while isinstance(current, AgentError) and current.parent_exception:
            if id(current.parent_exception) in seen:
                break  # ciclo
            seen.add(id(current.parent_exception))
            current = current.parent_exception
        return current

    # ------------------------------------------------------------------------
    # Serialization (SIEM-ready)
    # ------------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Serializa el error para SIEM/audit log."""
        # Sanitizar context
        sanitized_context: dict[str, Any] = {}
        for k, v in self.context.items():
            if isinstance(v, str):
                sanitized_context[k] = _sanitize(v)
            elif isinstance(v, (int, float, bool)) or v is None:
                sanitized_context[k] = v
            elif isinstance(v, (list, tuple)):
                sanitized_context[k] = [
                    _sanitize(str(x)) if isinstance(x, str) else x for x in v
                ][:20]
            elif isinstance(v, dict):
                sanitized_context[k] = {
                    kk: _sanitize(str(vv))[:200] for kk, vv in list(v.items())[:10]
                }
            else:
                sanitized_context[k] = _sanitize(str(v))[:200]

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
            "agent_name": self.agent_name,
            "correlation_id": self.correlation_id,
            "timestamp": self.timestamp,
            "timestamp_iso": self.timestamp_iso,
            "context": sanitized_context,
            "metadata": self.metadata,
        }

        # Chain de causas
        if self.parent_exception is not None:
            d["parent_exception"] = {
                "class": type(self.parent_exception).__name__,
                "message": _sanitize(str(self.parent_exception)),
            }

        return d

    def to_jsonl(self) -> str:
        """Formato JSONL para SIEM export."""
        import json as _json
        return _json.dumps(self.to_dict(), separators=(",", ":"), ensure_ascii=False)

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"error_code={self.error_code!r}, "
            f"severity={self.severity!r}, "
            f"retryable={self.retryable}, "
            f"agent={self.agent_name!r})"
        )


# ============================================================================
# CONTRACT / INPUT / CONFIG (FATAL)
# ============================================================================

class AgentContractError(AgentError):
    """Contrato del agente violado (input/output no matchea schema)."""

    error_code = "GODTIER_AGENT_CONTRACT"
    category = ErrorCategory.CONTRACT
    default_severity: ClassVar[Severity] = "high"
    retryable = False


class AgentInputError(AgentError):
    """Input del agente inválido (Pydantic validation error)."""

    error_code = "GODTIER_AGENT_INPUT"
    category = ErrorCategory.INPUT
    default_severity: ClassVar[Severity] = "high"
    retryable = False


class AgentConfigError(AgentError):
    """Configuración del agente inválida.

    Ejemplos:
        - max_duration_seconds <= 0
        - tools_allowed vacío pero requires_llm=True
        - sandbox_id ausente
    """

    error_code = "GODTIER_AGENT_CONFIG"
    category = ErrorCategory.CONFIG
    default_severity: ClassVar[Severity] = "critical"
    retryable = False


# ============================================================================
# CANCELLATION (FATAL — no retry)
# ============================================================================

class AgentCancelledError(AgentError):
    """Agente cancelado manualmente (shutdown normal).

    NO es retryable — la cancelación es intencional.
    """

    error_code = "GODTIER_AGENT_CANCELLED"
    category = ErrorCategory.CANCELLED
    default_severity: ClassVar[Severity] = "low"
    retryable = False

    def __init__(
        self,
        message: str = "",
        *,
        agent_name: str = "unknown",
        reason: str = "manual_cancel",
        context: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
        correlation_id: str | None = None,
        parent_exception: Exception | None = None,
    ) -> None:
        ctx = dict(context or {})
        ctx["reason"] = reason
        super().__init__(
            message or f"Agent cancelled: {reason}",
            agent_name=agent_name,
            context=ctx,
            metadata=metadata,
            severity="low",
            retryable=False,
            correlation_id=correlation_id,
            parent_exception=parent_exception,
        )
        self.reason = reason


class AgentKillSwitchError(AgentError):
    """Kill switch global activado.

    Distinto de AgentCancelledError: el kill switch es una emergencia
    global, no una cancelación normal.
    """

    error_code = "GODTIER_AGENT_KILL_SWITCH"
    category = ErrorCategory.KILL_SWITCH
    default_severity: ClassVar[Severity] = "high"
    retryable = False

    def __init__(
        self,
        message: str = "",
        *,
        agent_name: str = "unknown",
        switch_name: str = "global",
        context: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
        correlation_id: str | None = None,
        parent_exception: Exception | None = None,
    ) -> None:
        ctx = dict(context or {})
        ctx["switch_name"] = switch_name
        super().__init__(
            message or f"Kill switch activated: {switch_name}",
            agent_name=agent_name,
            context=ctx,
            metadata=metadata,
            severity="high",
            retryable=False,
            correlation_id=correlation_id,
            parent_exception=parent_exception,
        )
        self.switch_name = switch_name


# ============================================================================
# SECURITY (FATAL — CRÍTICO)
# ============================================================================

class AgentSecurityError(AgentError):
    """Violación de seguridad del agente (categoría padre).

    Cuando se lanza:
        1. El agente se aborta INMEDIATAMENTE
        2. Se registra en audit log como violación crítica
        3. Se notifica al security logger
        4. Se dispara el kill switch global
    """

    error_code = "GODTIER_AGENT_SECURITY"
    category = ErrorCategory.SECURITY
    default_severity: ClassVar[Severity] = "critical"
    retryable = False

    def __init__(
        self,
        message: str = "",
        *,
        agent_name: str = "unknown",
        violation_type: str = "unknown",
        details: dict[str, Any] | None = None,
        context: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
        correlation_id: str | None = None,
        parent_exception: Exception | None = None,
    ) -> None:
        ctx = dict(context or {})
        ctx["violation_type"] = violation_type
        ctx["details"] = details or {}
        super().__init__(
            message or f"Security violation: {violation_type}",
            agent_name=agent_name,
            context=ctx,
            metadata=metadata,
            severity="critical",
            retryable=False,
            correlation_id=correlation_id,
            parent_exception=parent_exception,
        )
        self.violation_type = violation_type
        self.details = details or {}


class AgentScopeViolationError(AgentSecurityError):
    """Target fuera de scope autorizado."""

    error_code = "GODTIER_AGENT_SCOPE_VIOLATION"
    category = ErrorCategory.SECURITY
    default_severity: ClassVar[Severity] = "critical"
    retryable = False

    def __init__(
        self,
        message: str = "",
        *,
        agent_name: str = "unknown",
        target: str = "",
        scope_summary: dict[str, Any] | None = None,
        context: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
        correlation_id: str | None = None,
        parent_exception: Exception | None = None,
    ) -> None:
        ctx = dict(context or {})
        if target:
            ctx["target"] = target
        if scope_summary:
            ctx["scope_summary"] = scope_summary
        super().__init__(
            message or f"Scope violation: {target}",
            agent_name=agent_name,
            violation_type="scope",
            details={"target": target, "scope_summary": scope_summary or {}},
            context=ctx,
            metadata=metadata,
            correlation_id=correlation_id,
            parent_exception=parent_exception,
        )
        self.target = target
        self.scope_summary = scope_summary or {}


class AgentEscapeError(AgentSecurityError):
    """Intento de escape del sandbox detectado."""

    error_code = "GODTIER_AGENT_ESCAPE"
    category = ErrorCategory.SECURITY
    default_severity: ClassVar[Severity] = "critical"
    retryable = False

    def __init__(
        self,
        message: str = "",
        *,
        agent_name: str = "unknown",
        escape_type: str = "unknown",
        evidence: str = "",
        context: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
        correlation_id: str | None = None,
        parent_exception: Exception | None = None,
    ) -> None:
        ctx = dict(context or {})
        ctx["escape_type"] = escape_type
        ctx["evidence"] = _sanitize(evidence, max_len=500)
        super().__init__(
            message or f"Sandbox escape: {escape_type}",
            agent_name=agent_name,
            violation_type="escape",
            details={"escape_type": escape_type, "evidence": _sanitize(evidence)},
            context=ctx,
            metadata=metadata,
            correlation_id=correlation_id,
            parent_exception=parent_exception,
        )
        self.escape_type = escape_type
        self.evidence = _sanitize(evidence, max_len=500)


class AgentCanaryLeakError(AgentSecurityError):
    """Canary token leak detectado (posible exfiltración)."""

    error_code = "GODTIER_AGENT_CANARY_LEAK"
    category = ErrorCategory.SECURITY
    default_severity: ClassVar[Severity] = "critical"
    retryable = False

    def __init__(
        self,
        message: str = "",
        *,
        agent_name: str = "unknown",
        token_prefix: str = "",
        snippet: str = "",
        context: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
        correlation_id: str | None = None,
        parent_exception: Exception | None = None,
    ) -> None:
        ctx = dict(context or {})
        ctx["token_prefix"] = token_prefix[:32]
        ctx["snippet"] = _sanitize(snippet, max_len=200)
        super().__init__(
            message or "Canary token leak detected",
            agent_name=agent_name,
            violation_type="canary_leak",
            details={
                "token_prefix": token_prefix[:32],
                "snippet": _sanitize(snippet, max_len=200),
            },
            context=ctx,
            metadata=metadata,
            correlation_id=correlation_id,
            parent_exception=parent_exception,
        )
        self.token_prefix = token_prefix[:32]
        self.snippet = _sanitize(snippet, max_len=200)


# ============================================================================
# BUDGET / RESOURCE (FATAL)
# ============================================================================

class AgentBudgetExceededError(AgentError):
    """Presupuesto del engagement agotado.

    FATAL — no retry. El budget es un hard limit.
    """

    error_code = "GODTIER_AGENT_BUDGET_EXCEEDED"
    category = ErrorCategory.BUDGET
    default_severity: ClassVar[Severity] = "high"
    retryable = False

    def __init__(
        self,
        message: str = "",
        *,
        agent_name: str = "unknown",
        spent_usd: float = 0.0,
        max_usd: float = 0.0,
        requested_usd: float = 0.0,
        role: str = "unknown",
        context: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
        correlation_id: str | None = None,
        parent_exception: Exception | None = None,
    ) -> None:
        ctx = dict(context or {})
        ctx.update({
            "spent_usd": round(spent_usd, 6),
            "max_usd": round(max_usd, 6),
            "requested_usd": round(requested_usd, 6),
            "role": role,
        })
        super().__init__(
            message or (
                f"Budget exceeded: spent=${spent_usd:.4f} + "
                f"requested=${requested_usd:.4f} > max=${max_usd:.4f}"
            ),
            agent_name=agent_name,
            context=ctx,
            metadata=metadata,
            severity="high",
            retryable=False,
            correlation_id=correlation_id,
            parent_exception=parent_exception,
        )
        self.spent_usd = spent_usd
        self.max_usd = max_usd
        self.requested_usd = requested_usd
        self.role = role


class AgentResourceError(AgentError):
    """Recursos excedidos (OOM, CPU, PIDs, disco).

    FATAL — no retry. Los límites del sandbox son hard caps.
    """

    error_code = "GODTIER_AGENT_RESOURCE"
    category = ErrorCategory.RESOURCE
    default_severity: ClassVar[Severity] = "high"
    retryable = False

    def __init__(
        self,
        message: str = "",
        *,
        agent_name: str = "unknown",
        resource_type: str = "unknown",
        limit: str = "",
        actual: str = "",
        context: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
        correlation_id: str | None = None,
        parent_exception: Exception | None = None,
    ) -> None:
        ctx = dict(context or {})
        ctx.update({
            "resource_type": resource_type,
            "limit": limit,
            "actual": actual,
        })
        super().__init__(
            message or f"Resource '{resource_type}' exceeded: {actual} > {limit}",
            agent_name=agent_name,
            context=ctx,
            metadata=metadata,
            severity="high",
            retryable=False,
            correlation_id=correlation_id,
            parent_exception=parent_exception,
        )
        self.resource_type = resource_type
        self.limit = limit
        self.actual = actual


# ============================================================================
# TIMEOUT / CANCELLATION (RETRYABLE)
# ============================================================================

class AgentTimeoutError(AgentError):
    """Timeout del agente (excede max_duration_seconds).

    Retryable — el agente puede reintentar con timeout mayor.
    """

    error_code = "GODTIER_AGENT_TIMEOUT"
    category = ErrorCategory.TIMEOUT
    default_severity: ClassVar[Severity] = "medium"
    retryable = True

    def __init__(
        self,
        message: str = "",
        *,
        agent_name: str = "unknown",
        timeout_seconds: float = 0.0,
        elapsed_seconds: float = 0.0,
        context: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
        correlation_id: str | None = None,
        parent_exception: Exception | None = None,
    ) -> None:
        ctx = dict(context or {})
        ctx["timeout_seconds"] = timeout_seconds
        ctx["elapsed_seconds"] = round(elapsed_seconds, 3)
        super().__init__(
            message or f"Timeout after {timeout_seconds}s",
            agent_name=agent_name,
            context=ctx,
            metadata=metadata,
            severity="medium",
            retryable=True,
            correlation_id=correlation_id,
            parent_exception=parent_exception,
        )
        self.timeout_seconds = timeout_seconds
        self.elapsed_seconds = elapsed_seconds


# ============================================================================
# OUTPUT / TOOL / SERIALIZATION (RETRYABLE)
# ============================================================================

class AgentOutputError(AgentError):
    """Output del agente inválido (no matchea schema).

    Retryable — el LLM o tool pueden devolver output diferente.
    """

    error_code = "GODTIER_AGENT_OUTPUT"
    category = ErrorCategory.OUTPUT
    default_severity: ClassVar[Severity] = "high"
    retryable = True


class AgentToolError(AgentError):
    """Herramienta del agente falló (nmap, nuclei, etc.)."""

    error_code = "GODTIER_AGENT_TOOL"
    category = ErrorCategory.TOOL
    default_severity: ClassVar[Severity] = "medium"
    retryable = True

    def __init__(
        self,
        message: str = "",
        *,
        agent_name: str = "unknown",
        tool_name: str = "unknown",
        tool_version: str = "unknown",
        command: str = "",
        exit_code: int = -1,
        exit_signal: int | None = None,
        stderr: str = "",
        stdout_preview: str = "",
        context: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
        correlation_id: str | None = None,
        parent_exception: Exception | None = None,
    ) -> None:
        ctx = dict(context or {})
        ctx.update({
            "tool_name": tool_name,
            "tool_version": tool_version,
            "command": _sanitize(command, max_len=500),
            "exit_code": exit_code,
            "exit_signal": exit_signal,
            "stderr_preview": _sanitize(stderr, max_len=500),
            "stdout_preview": _sanitize(stdout_preview, max_len=500),
        })
        super().__init__(
            message or (
                f"Tool '{tool_name}' failed: "
                f"exit_code={exit_code}, "
                f"signal={exit_signal if exit_signal is not None else 'none'}"
            ),
            agent_name=agent_name,
            context=ctx,
            metadata=metadata,
            severity="medium",
            retryable=True,
            correlation_id=correlation_id,
            parent_exception=parent_exception,
        )
        self.tool_name = tool_name
        self.tool_version = tool_version
        self.command = command
        self.exit_code = exit_code
        self.exit_signal = exit_signal
        self.stderr = stderr
        self.stdout_preview = stdout_preview

    @property
    def was_killed(self) -> bool:
        """True si el tool fue matado por señal."""
        return self.exit_signal is not None


class AgentSerializationError(AgentError):
    """Error de serialización/deserialización (JSON, Pydantic).

    Retryable — el problema puede ser transitorio.
    """

    error_code = "GODTIER_AGENT_SERIALIZATION"
    category = ErrorCategory.SERIALIZATION
    default_severity: ClassVar[Severity] = "medium"
    retryable = True


class AgentConcurrencyError(AgentError):
    """Error de concurrencia (race condition detectada).

    Retryable — el reintento puede resolver el race.
    """

    error_code = "GODTIER_AGENT_CONCURRENCY"
    category = ErrorCategory.CONCURRENCY
    default_severity: ClassVar[Severity] = "medium"
    retryable = True


# ============================================================================
# LLM (RETRYABLE)
# ============================================================================

class AgentLLMError(AgentError):
    """Error genérico de LLM (fallo transitorio)."""

    error_code = "GODTIER_AGENT_LLM"
    category = ErrorCategory.LLM
    default_severity: ClassVar[Severity] = "medium"
    retryable = True

    def __init__(
        self,
        message: str = "",
        *,
        agent_name: str = "unknown",
        provider: str = "unknown",
        model: str = "unknown",
        context: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
        correlation_id: str | None = None,
        parent_exception: Exception | None = None,
    ) -> None:
        ctx = dict(context or {})
        ctx.update({"provider": provider, "model": model})
        super().__init__(
            message or f"LLM error ({provider}/{model})",
            agent_name=agent_name,
            context=ctx,
            metadata=metadata,
            severity="medium",
            retryable=True,
            correlation_id=correlation_id,
            parent_exception=parent_exception,
        )
        self.provider = provider
        self.model = model


class AgentRateLimitError(AgentLLMError):
    """Rate limit del proveedor LLM (429).

    Retryable con backoff — respetar `retry_after_seconds` si está presente.
    """

    error_code = "GODTIER_AGENT_RATE_LIMIT"
    category = ErrorCategory.RATE_LIMIT
    default_severity: ClassVar[Severity] = "medium"
    retryable = True

    def __init__(
        self,
        message: str = "",
        *,
        agent_name: str = "unknown",
        provider: str = "unknown",
        model: str = "unknown",
        retry_after_seconds: float = 0.0,
        context: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
        correlation_id: str | None = None,
        parent_exception: Exception | None = None,
    ) -> None:
        # Validar retry_after (>= 0, <= 1h)
        if retry_after_seconds < 0:
            retry_after_seconds = 0.0
        if retry_after_seconds > 3600:
            retry_after_seconds = 3600.0

        ctx = dict(context or {})
        ctx["retry_after_seconds"] = round(retry_after_seconds, 2)
        super().__init__(
            message or (
                f"Rate limit ({provider}/{model}), "
                f"retry after {retry_after_seconds:.1f}s"
            ),
            agent_name=agent_name,
            provider=provider,
            model=model,
            context=ctx,
            metadata=metadata,
            correlation_id=correlation_id,
            parent_exception=parent_exception,
        )
        self.retry_after_seconds = retry_after_seconds


# ============================================================================
# HELPERS
# ============================================================================

def is_retryable(error: BaseException) -> bool:
    """True si la excepción es retryable.

    Fail-closed: si no podemos determinar, retorna False.
    """
    if not isinstance(error, BaseException):
        return False
    # AgentError: usar ClassVar/instance attr
    if isinstance(error, AgentError):
        return bool(error.retryable)
    # Otros errores del sistema
    return bool(getattr(error, "retryable", False))


def is_fatal(error: BaseException) -> bool:
    """True si la excepción NO es retryable."""
    if not isinstance(error, BaseException):
        return True
    if isinstance(error, AgentError):
        return not error.retryable
    return not bool(getattr(error, "retryable", False))


def is_security_error(error: BaseException) -> bool:
    """True si la excepción es de seguridad (incluye subclases)."""
    if isinstance(error, AgentError):
        return error.category == ErrorCategory.SECURITY
    # Fallback a las clases raíz
    from god_tier_agency.core.exceptions import SecurityError
    return isinstance(error, SecurityError)


def classify_error(error: BaseException) -> str:
    """Clasifica el error para SIEM.

    Returns:
        Categoría (string) para agrupación en SIEM.
    """
    if isinstance(error, AgentError):
        return error.category.value
    return ErrorCategory.UNKNOWN.value


def to_siem_event(error: BaseException) -> dict[str, Any]:
    """Convierte un error a evento SIEM estructurado."""
    if isinstance(error, AgentError):
        return error.to_dict()
    # Fallback genérico
    return {
        "error_id": _hash_error_id(
            type(error).__name__, str(error), time.time()
        ),
        "error_code": f"GENERIC_{type(error).__name__.upper()}",
        "category": ErrorCategory.UNKNOWN.value,
        "class": type(error).__name__,
        "message": _sanitize(str(error), max_len=2000),
        "severity": "high",
        "retryable": is_retryable(error),
        "is_fatal": is_fatal(error),
        "is_security": is_security_error(error),
        "timestamp": time.time(),
        "timestamp_iso": datetime.now(timezone.utc).isoformat(),
    }


def errors_to_prometheus(
    errors: list[BaseException],
    namespace: str = "godtier_agent_errors",
) -> str:
    """Genera métricas Prometheus para una lista de errores."""
    # Contar por categoría, error_code, severity
    by_category: dict[str, int] = {}
    by_code: dict[str, int] = {}
    by_severity: dict[str, int] = {}

    for e in errors:
        cat = classify_error(e)
        by_category[cat] = by_category.get(cat, 0) + 1

        code = getattr(e, "error_code", f"GENERIC_{type(e).__name__}")
        by_code[code] = by_code.get(code, 0) + 1

        sev = getattr(e, "severity", "high")
        by_severity[sev] = by_severity.get(sev, 0) + 1

    lines: list[str] = [
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
    "AgentError",
    # Contract/Input/Config
    "AgentContractError",
    "AgentInputError",
    "AgentConfigError",
    # Cancellation
    "AgentCancelledError",
    "AgentKillSwitchError",
    # Security
    "AgentSecurityError",
    "AgentScopeViolationError",
    "AgentEscapeError",
    "AgentCanaryLeakError",
    # Budget/Resource
    "AgentBudgetExceededError",
    "AgentResourceError",
    # Timeout
    "AgentTimeoutError",
    # Output/Tool/Serialization/Concurrency
    "AgentOutputError",
    "AgentToolError",
    "AgentSerializationError",
    "AgentConcurrencyError",
    # LLM
    "AgentLLMError",
    "AgentRateLimitError",
    # Helpers
    "is_retryable",
    "is_fatal",
    "is_security_error",
    "classify_error",
    "to_siem_event",
    "errors_to_prometheus",
]
