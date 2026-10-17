"""Excepciones específicas del orquestador — God-Tier v2.

Jerarquía en 2 ejes:
    1. Retry: RetryableError vs FatalError
    2. Dominio: Planner, Executor, State, Agent, Budget, Checkpoint, Recovery

Estructura:
    GodTierError
    └── OrchestratorError                          (base del orquestador)
        ├── RetryableError                          (base: se puede reintentar)
        │   ├── PlannerError                        (LLM timeout, rate limit)
        │   ├── ExecutorError                       (task transient failure)
        │   └── AgentError                          (agente transient failure)
        ├── FatalError                              (base: NO se puede reintentar)
        │   ├── StateError                          (estado inconsistente)
        │   ├── ScopeValidationError                (target fuera de scope)
        │   ├── PlanValidationError                 (plan malformado)
        │   ├── BudgetExceededError                 (presupuesto agotado)
        │   ├── CheckpointError                     (fallo persistir/reanudar)
        │   ├── RecoveryError                       (fallo reanudar tras crash)
        │   └── TaskAbortedError                    (abort manual)
        └── PipelineError                           (error del pipeline completo)

Características:
    - Cada excepción tiene error_code único (para SIEM)
    - Severity default (para alertas automáticas)
    - Retryable (bool, para política de retry)
    - Context (dict, para forense)
    - Metadata (dict, para datos estructurados adicionales)
"""

from __future__ import annotations

from typing import Any, Literal

from god_tier_agency.core.exceptions import GodTierError

Severity = Literal["low", "medium", "high", "critical"]


# ============================================================================
# BASE
# ============================================================================
class OrchestratorError(GodTierError):
    """Base de todas las excepciones del orquestador."""

    error_code = "GODTIER_ORCHESTRATOR"
    default_severity: Severity = "medium"
    retryable = False

    def __init__(
        self,
        message: str = "",
        *,
        context: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
        severity: Severity | None = None,
        retryable: bool | None = None,
    ) -> None:
        super().__init__(
            message or self.__class__.__doc__ or self.error_code,
            context=context,
            severity=severity,
            retryable=retryable,
        )
        self.metadata: dict[str, Any] = metadata or {}

    def to_dict(self) -> dict[str, Any]:
        """Serializa con metadata incluido."""
        d = super().to_dict()
        if self.metadata:
            d["metadata"] = self.metadata
        return d


# ============================================================================
# EJE 1: RETRY vs FATAL
# ============================================================================
class RetryableError(OrchestratorError):
    """Base para errores que SE PUEDEN reintentar.

    Ejemplos:
        - LLM timeout / rate limit
        - Network transient failure
        - Sandbox startup failure

    Política de retry:
        - Exponential backoff
        - Max N intentos
        - Jitter para evitar thundering herd
    """

    error_code = "GODTIER_RETRYABLE"
    default_severity: Severity = "medium"
    retryable = True


class FatalError(OrchestratorError):
    """Base para errores que NO se pueden reintentar.

    Ejemplos:
        - Plan fuera de scope
        - Estado inconsistente
        - Presupuesto agotado

    Política:
        - Fail-fast
        - Log crítico
        - Abortar el engagement si es necesario
    """

    error_code = "GODTIER_FATAL"
    default_severity: Severity = "high"
    retryable = False


# ============================================================================
# EJE 2: DOMINIO (Retryable)
# ============================================================================
class PlannerError(RetryableError):
    """Error generando el plan de ataque.

    Ejemplos:
        - LLM timeout
        - LLM rate limit
        - JSON malformado en respuesta del LLM
    """

    error_code = "GODTIER_PLANNER"
    default_severity: Severity = "high"
    retryable = True


class ExecutorError(RetryableError):
    """Error ejecutando un task del plan.

    Ejemplos:
        - Sandbox startup timeout
        - Docker daemon transient failure
        - Task cancellation por sistema
    """

    error_code = "GODTIER_EXECUTOR"
    default_severity: Severity = "high"
    retryable = True


class AgentError(RetryableError):
    """Error específico de un agente (recon, exploit, cloud, etc.).

    Attributes:
        agent_name: Nombre del agente que falló.
    """

    error_code = "GODTIER_AGENT"
    default_severity: Severity = "high"
    retryable = True

    def __init__(
        self,
        message: str = "",
        *,
        agent_name: str = "unknown",
        context: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
        severity: Severity | None = None,
        retryable: bool | None = None,
    ) -> None:
        ctx = dict(context or {})
        ctx["agent_name"] = agent_name
        super().__init__(
            message,
            context=ctx,
            metadata=metadata,
            severity=severity,
            retryable=retryable,
        )
        self.agent_name = agent_name


# ============================================================================
# EJE 2: DOMINIO (Fatal)
# ============================================================================
class StateError(FatalError):
    """Estado inconsistente o corrupto.

    Ejemplos:
        - JSON corrupto en disco
        - Transición inválida
        - Task no encontrado
    """

    error_code = "GODTIER_STATE"
    default_severity: Severity = "critical"
    retryable = False


class ScopeValidationError(FatalError):
    """El plan incluye un target fuera del scope autorizado.

    Attributes:
        target: El target que causó el fallo.
    """

    error_code = "GODTIER_SCOPE_VALIDATION"
    default_severity: Severity = "critical"
    retryable = False

    def __init__(
        self,
        message: str = "",
        *,
        target: str = "",
        context: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
        severity: Severity | None = None,
        retryable: bool | None = None,
    ) -> None:
        ctx = dict(context or {})
        if target:
            ctx["target"] = target
        super().__init__(
            message,
            context=ctx,
            metadata=metadata,
            severity=severity,
            retryable=retryable,
        )
        self.target = target


class PlanValidationError(FatalError):
    """El plan está malformado (JSON inválido, esquema roto).

    Attributes:
        raw_plan: El plan crudo que falló (para debug).
    """

    error_code = "GODTIER_PLAN_VALIDATION"
    default_severity: Severity = "high"
    retryable = False

    def __init__(
        self,
        message: str = "",
        *,
        raw_plan: str = "",
        context: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
        severity: Severity | None = None,
        retryable: bool | None = None,
    ) -> None:
        ctx = dict(context or {})
        if raw_plan:
            ctx["raw_plan"] = raw_plan[:500]  # truncar
        super().__init__(
            message,
            context=ctx,
            metadata=metadata,
            severity=severity,
            retryable=retryable,
        )
        self.raw_plan = raw_plan


class BudgetExceededError(FatalError):
    """Presupuesto del engagement agotado."""

    error_code = "GODTIER_BUDGET_EXCEEDED"
    default_severity: Severity = "high"
    retryable = False


class CheckpointError(FatalError):
    """Error al persistir o cargar un checkpoint.

    Ejemplos:
        - Disco lleno
        - Permisos denegados
        - JSON corrupto
    """

    error_code = "GODTIER_CHECKPOINT"
    default_severity: Severity = "high"
    retryable = False


class RecoveryError(FatalError):
    """Error al reanudar tras un crash.

    Ejemplos:
        - Checkpoint incompleto
        - Estado inconsistente post-crash
    """

    error_code = "GODTIER_RECOVERY"
    default_severity: Severity = "critical"
    retryable = False


class TaskAbortedError(FatalError):
    """Task abortado manualmente (no es un fallo).

    Attributes:
        reason: Razón del abort (por defecto "manual_abort").
    """

    error_code = "GODTIER_TASK_ABORTED"
    default_severity: Severity = "low"
    retryable = False

    def __init__(
        self,
        message: str = "",
        *,
        reason: str = "manual_abort",
        context: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
        severity: Severity | None = None,
        retryable: bool | None = None,
    ) -> None:
        ctx = dict(context or {})
        ctx["reason"] = reason
        super().__init__(
            message or f"Task abortado: {reason}",
            context=ctx,
            metadata=metadata,
            severity=severity,
            retryable=retryable,
        )
        self.reason = reason


# ============================================================================
# PIPELINE (end-to-end)
# ============================================================================
class PipelineError(OrchestratorError):
    """Error del pipeline completo (plan → execute → report).

    Attributes:
        phase: Fase del pipeline donde falló (planning, executing, reporting).
    """

    error_code = "GODTIER_PIPELINE"
    default_severity: Severity = "critical"
    retryable = False

    def __init__(
        self,
        message: str = "",
        *,
        phase: str = "unknown",
        context: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
        severity: Severity | None = None,
        retryable: bool | None = None,
    ) -> None:
        ctx = dict(context or {})
        ctx["pipeline_phase"] = phase
        super().__init__(
            message,
            context=ctx,
            metadata=metadata,
            severity=severity,
            retryable=retryable,
        )
        self.phase = phase


# ============================================================================
# HELPERS
# ============================================================================
def is_retryable(error: Exception) -> bool:
    """Verifica si una excepción es retryable.

    Uso:
        >>> try:
        ...     await planner.plan(...)
        ... except Exception as e:
        ...     if is_retryable(e):
        ...         await retry_with_backoff()
        ...     else:
        ...         raise
    """
    return getattr(error, "retryable", False)


def is_fatal(error: Exception) -> bool:
    """Verifica si una excepción es fatal (no retryable)."""
    return isinstance(error, FatalError) or (
        isinstance(error, OrchestratorError) and not error.retryable
    )


__all__ = [
    # Base
    "OrchestratorError",
    # Eje 1: Retry vs Fatal
    "RetryableError",
    "FatalError",
    # Eje 2: Dominio (Retryable)
    "PlannerError",
    "ExecutorError",
    "AgentError",
    # Eje 2: Dominio (Fatal)
    "StateError",
    "ScopeValidationError",
    "PlanValidationError",
    "BudgetExceededError",
    "CheckpointError",
    "RecoveryError",
    "TaskAbortedError",
    # Pipeline
    "PipelineError",
    # Helpers
    "is_retryable",
    "is_fatal",
    "Severity",
]
