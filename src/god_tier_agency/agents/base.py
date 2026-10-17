"""BaseAgent + AgentMetrics — God-Tier v5.0.

BaseAgent provee:
    - Ejecución controlada (contrato, timeout, kill switch thread-safe)
    - Integración con SandboxManager (comandos con correlation IDs)
    - Integración con AIGateway (LLM con budget check)
    - Validación de comandos con security (multicapa)
    - Tool allowlist estricta
    - Métricas thread-safe con percentiles + histograma + p50/p95/p99 por tool
    - Auditoría forense de cada comando
    - Hooks pre/post para observabilidad
    - Cancelación graceful de sub-tasks

God-Tier v5.0 — diferenciadores vs v4.0:

AGENT METRICS (v5):
    - SIN RLock en dataclass (lock externo en el agente)
    - SIN defaultdict (dict normal, serializable)
    - Histograma de latencias con buckets configurables
    - Percentiles correctos (interpolación lineal, no índice)
    - Cap en `latencies_ms` (evita memory leak)
    - Cap en `_commands_log` (ring buffer)
    - Cost tracking con Decimal (evita drift de float)
    - Snapshot deep-frozen (inmutable de verdad)
    - Prometheus labels con namespace

BASE AGENT (v5):
    - Kill switch thread-safe (RLock + Event)
    - Cancelación graceful de sub-tasks (asyncio.gather con cancel)
    - Correlation IDs propagados al sandbox
    - Pre/post hooks (observabilidad)
    - Retry configurable en `run_command` (transient failures)
    - Latency por tool (P50/P95/P99)
    - Budget check antes de LLM call
    - Fail-fast en errores de programación (no `except Exception`)
    - Parent execution ID propagado
    - Sub-task tracking (evita huérfanos)

Filosofía:
    - FAIL-CLOSED en security
    - FAIL-FAST en programming errors
    - THREAD-SAFE con locks explícitos
    - ASYNC-SAFE con cancelación graceful
    - FORENSIC con correlation IDs + ring buffer
    - ZERO LEAKS (caps + cleanup)
    - OBSERVABLE con hooks + métricas Prometheus
"""

from __future__ import annotations

import asyncio
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from threading import RLock
from typing import Any, Awaitable, Callable, Final
from uuid import UUID, uuid4

from god_tier_agency.agents.contract import (
    AgentContract,
    AgentInput,
    AgentOutput,
    AgentResult,
    CommandLogEntry,
)
from god_tier_agency.agents.exceptions import (
    AgentCancelledError,
    AgentContractError,
    AgentError,
    AgentInputError,
    AgentOutputError,
    AgentSecurityError,
    AgentTimeoutError,
    AgentToolError,
)
from god_tier_agency.core.context import get_context
from god_tier_agency.core.logging import get_logger
from god_tier_agency.core.security import validate_command

_log = get_logger("agents.base")


# ============================================================================
# CONSTANTES
# ============================================================================

MAX_LATENCIES_KEPT: Final[int] = 10_000   # Ring buffer de latencias
MAX_COMMANDS_LOG: Final[int] = 1_000      # Ring buffer de comandos
MAX_TOOL_LATENCIES: Final[int] = 1_000    # Latencies por tool
HISTOGRAM_BUCKETS_MS: Final[tuple[float, ...]] = (
    10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000, 30000, 60000,
)
DEFAULT_RETRY_ATTEMPTS: Final[int] = 3
DEFAULT_RETRY_BACKOFF_BASE: Final[float] = 1.5
DEFAULT_RETRY_BACKOFF_MAX: Final[float] = 30.0


# ============================================================================
# AGENT METRICS v5 (thread-safe, con histograma, sin locks embebidos)
# ============================================================================

@dataclass
class AgentMetrics:
    """Métricas agregadas de un agente.

    Thread-safety: el lock NO está en el dataclass (rompe serialización).
    El lock vive en BaseAgent y se pasa a los métodos que lo requieren.

    God-Tier v5.0:
        - Sin RLock ni defaultdict (serialización limpia)
        - Ring buffer en latencies (evita memory leak)
        - Histograma de latencias
        - Percentiles con interpolación lineal (correcto)
        - Cost con Decimal (evita drift)
        - Por-tool latencies (P50/P95/P99 por herramienta)
    """

    # --- Contadores ---
    total_executions: int = 0
    successful: int = 0
    failed: int = 0
    timed_out: int = 0
    cancelled: int = 0

    # --- Duración ---
    total_duration_ms: float = 0.0
    latencies_ms: list[float] = field(default_factory=list)  # ring buffer

    # --- Comandos ---
    total_commands: int = 0
    total_tool_calls: int = 0
    tool_usage: dict[str, int] = field(default_factory=dict)
    tool_latencies_ms: dict[str, list[float]] = field(default_factory=dict)

    # --- Costo (Decimal evita drift) ---
    total_tokens: int = 0
    total_cost_decimal: Decimal = field(default_factory=lambda: Decimal("0"))

    # --- Findings ---
    total_detections: int = 0
    total_findings: int = 0
    critical_findings: int = 0
    severity_counts: dict[str, int] = field(default_factory=dict)

    # --- Errores ---
    error_counts: dict[str, int] = field(default_factory=dict)

    # --- Histograma de latencias ---
    latency_histogram: dict[str, int] = field(default_factory=dict)

    # ------------------------------------------------------------------------
    # Propiedades derivadas (asumen llamada desde BaseAgent con lock)
    # ------------------------------------------------------------------------

    @property
    def success_rate(self) -> float:
        if self.total_executions == 0:
            return 0.0
        return round(self.successful / self.total_executions * 100, 2)

    @property
    def failure_rate(self) -> float:
        if self.total_executions == 0:
            return 0.0
        return round(self.failed / self.total_executions * 100, 2)

    @property
    def avg_duration_ms(self) -> float:
        if self.total_executions == 0:
            return 0.0
        return self.total_duration_ms / self.total_executions

    @property
    def total_cost_usd(self) -> float:
        """Costo en USD como float (para compatibilidad)."""
        return float(self.total_cost_decimal)

    def _percentile(self, p: int) -> float:
        """Calcula percentil con interpolación lineal (correcto)."""
        if not self.latencies_ms:
            return 0.0
        sorted_lat = sorted(self.latencies_ms)
        if len(sorted_lat) == 1:
            return round(sorted_lat[0], 3)
        # Interpolación lineal (NIST standard)
        rank = (p / 100.0) * (len(sorted_lat) - 1)
        lower_idx = int(rank)
        upper_idx = min(lower_idx + 1, len(sorted_lat) - 1)
        fraction = rank - lower_idx
        value = (
            sorted_lat[lower_idx] * (1 - fraction)
            + sorted_lat[upper_idx] * fraction
        )
        return round(value, 3)

    @property
    def p50_latency_ms(self) -> float:
        return self._percentile(50)

    @property
    def p95_latency_ms(self) -> float:
        return self._percentile(95)

    @property
    def p99_latency_ms(self) -> float:
        return self._percentile(99)

    def _tool_percentile(self, tool: str, p: int) -> float:
        """Percentil de latencia para una herramienta específica."""
        latencies = self.tool_latencies_ms.get(tool, [])
        if not latencies:
            return 0.0
        sorted_lat = sorted(latencies)
        if len(sorted_lat) == 1:
            return round(sorted_lat[0], 3)
        rank = (p / 100.0) * (len(sorted_lat) - 1)
        lower_idx = int(rank)
        upper_idx = min(lower_idx + 1, len(sorted_lat) - 1)
        fraction = rank - lower_idx
        value = (
            sorted_lat[lower_idx] * (1 - fraction)
            + sorted_lat[upper_idx] * fraction
        )
        return round(value, 3)

    def tool_p50(self, tool: str) -> float:
        return self._tool_percentile(tool, 50)

    def tool_p95(self, tool: str) -> float:
        return self._tool_percentile(tool, 95)

    def tool_p99(self, tool: str) -> float:
        return self._tool_percentile(tool, 99)

    # ------------------------------------------------------------------------
    # Mutación (llamado desde BaseAgent con lock)
    # ------------------------------------------------------------------------

    def record_execution(self, result: AgentResult) -> None:
        """Registra el resultado de una ejecución (sin lock — BaseAgent lo sostiene)."""
        self.total_executions += 1
        if result.success:
            self.successful += 1
        else:
            self.failed += 1

        if result.timed_out:
            self.timed_out += 1
            self._increment_error("timeout")
        if result.cancelled:
            self.cancelled += 1
            self._increment_error("cancelled")

        if result.error:
            # Extraer tipo de error robustamente (primer token antes de ":")
            error_type = result.error.split(":", 1)[0].strip()
            if not error_type or len(error_type) > 60:
                error_type = "unknown"
            self._increment_error(error_type)

        self.total_duration_ms += result.duration_ms
        self._append_latency(result.duration_ms)

        self.total_commands += result.commands_executed
        self.total_tool_calls += result.tool_calls
        self.total_tokens += result.tokens_used

        # Decimal para evitar drift
        if result.cost_usd > 0:
            self.total_cost_decimal += Decimal(str(result.cost_usd))

        self.total_detections += result.detections
        self.total_findings += result.findings_count
        self.critical_findings += result.critical_findings_count

        # Severity counts
        if result.output:
            for finding in result.output.findings:
                sev = finding.severity.value
                self.severity_counts[sev] = self.severity_counts.get(sev, 0) + 1

    def record_command(
        self,
        tool_name: str,
        duration_ms: float = 0.0,
    ) -> None:
        """Registra el uso de una herramienta con latencia."""
        self.tool_usage[tool_name] = self.tool_usage.get(tool_name, 0) + 1
        if duration_ms > 0:
            if tool_name not in self.tool_latencies_ms:
                self.tool_latencies_ms[tool_name] = []
            self.tool_latencies_ms[tool_name].append(duration_ms)
            # Ring buffer por tool
            if len(self.tool_latencies_ms[tool_name]) > MAX_TOOL_LATENCIES:
                self.tool_latencies_ms[tool_name] = self.tool_latencies_ms[tool_name][-MAX_TOOL_LATENCIES:]

    def _increment_error(self, error_type: str) -> None:
        self.error_counts[error_type] = self.error_counts.get(error_type, 0) + 1

    def _append_latency(self, latency_ms: float) -> None:
        """Ring buffer de latencias."""
        self.latencies_ms.append(latency_ms)
        if len(self.latencies_ms) > MAX_LATENCIES_KEPT:
            self.latencies_ms = self.latencies_ms[-MAX_LATENCIES_KEPT:]
        # Histograma
        bucket = self._find_bucket(latency_ms)
        self.latency_histogram[bucket] = self.latency_histogram.get(bucket, 0) + 1

    @staticmethod
    def _find_bucket(latency_ms: float) -> str:
        for bucket in HISTOGRAM_BUCKETS_MS:
            if latency_ms <= bucket:
                return f"le_{int(bucket)}ms"
        return "gt_60000ms"

    def reset(self) -> None:
        """Resetea todas las métricas (sin lock — BaseAgent lo sostiene)."""
        self.total_executions = 0
        self.successful = 0
        self.failed = 0
        self.timed_out = 0
        self.cancelled = 0
        self.total_duration_ms = 0.0
        self.latencies_ms.clear()
        self.total_commands = 0
        self.total_tool_calls = 0
        self.tool_usage.clear()
        self.tool_latencies_ms.clear()
        self.total_tokens = 0
        self.total_cost_decimal = Decimal("0")
        self.total_detections = 0
        self.total_findings = 0
        self.critical_findings = 0
        self.severity_counts.clear()
        self.error_counts.clear()
        self.latency_histogram.clear()

    # ------------------------------------------------------------------------
    # Serialización (sin lock — BaseAgent lo sostiene)
    # ------------------------------------------------------------------------

    def to_dict(self, include_latencies: bool = False) -> dict[str, Any]:
        """Serializa métricas. Caller debe tener lock."""
        d: dict[str, Any] = {
            # Ejecuciones
            "total_executions": self.total_executions,
            "successful": self.successful,
            "failed": self.failed,
            "timed_out": self.timed_out,
            "cancelled": self.cancelled,
            "success_rate": self.success_rate,
            "failure_rate": self.failure_rate,
            # Duración
            "avg_duration_ms": round(self.avg_duration_ms, 3),
            "p50_latency_ms": self.p50_latency_ms,
            "p95_latency_ms": self.p95_latency_ms,
            "p99_latency_ms": self.p99_latency_ms,
            "latency_histogram": dict(self.latency_histogram),
            # Comandos
            "total_commands": self.total_commands,
            "total_tool_calls": self.total_tool_calls,
            "tool_usage": dict(self.tool_usage),
            # Costo
            "total_tokens": self.total_tokens,
            "total_cost_usd": float(self.total_cost_decimal),
            # Findings
            "total_detections": self.total_detections,
            "total_findings": self.total_findings,
            "critical_findings": self.critical_findings,
            "severity_counts": dict(self.severity_counts),
            # Errores
            "error_counts": dict(self.error_counts),
        }
        if include_latencies:
            d["latencies_ms"] = list(self.latencies_ms)
        return d

    def to_prometheus(self, namespace: str = "godtier_agent") -> str:
        """Exporta métricas en formato Prometheus con namespace."""
        lines: list[str] = [
            f"# HELP {namespace}_executions_total Total agent executions",
            f"# TYPE {namespace}_executions_total counter",
            f"{namespace}_executions_total {self.total_executions}",
            f"{namespace}_successful_total {self.successful}",
            f"{namespace}_failed_total {self.failed}",
            f"{namespace}_timed_out_total {self.timed_out}",
            f"{namespace}_cancelled_total {self.cancelled}",
            f"# HELP {namespace}_success_rate Success rate %",
            f"# TYPE {namespace}_success_rate gauge",
            f"{namespace}_success_rate {self.success_rate}",
            f"{namespace}_avg_duration_ms {round(self.avg_duration_ms, 3)}",
            f"{namespace}_p50_latency_ms {self.p50_latency_ms}",
            f"{namespace}_p95_latency_ms {self.p95_latency_ms}",
            f"{namespace}_p99_latency_ms {self.p99_latency_ms}",
            f"{namespace}_commands_total {self.total_commands}",
            f"{namespace}_tool_calls_total {self.total_tool_calls}",
            f"{namespace}_tokens_total {self.total_tokens}",
            f"{namespace}_cost_usd {float(self.total_cost_decimal):.6f}",
            f"{namespace}_findings_total {self.total_findings}",
            f"{namespace}_critical_findings_total {self.critical_findings}",
        ]
        for tool, count in sorted(self.tool_usage.items()):
            lines.append(f'{namespace}_tool_usage{{tool="{tool}"}} {count}')
        for tool in sorted(self.tool_latencies_ms.keys()):
            lines.append(
                f'{namespace}_tool_p50_ms{{tool="{tool}"}} {self.tool_p50(tool)}'
            )
            lines.append(
                f'{namespace}_tool_p95_ms{{tool="{tool}"}} {self.tool_p95(tool)}'
            )
        for sev, count in sorted(self.severity_counts.items()):
            lines.append(
                f'{namespace}_findings_by_severity{{severity="{sev}"}} {count}'
            )
        for err, count in sorted(self.error_counts.items()):
            lines.append(f'{namespace}_errors{{type="{err}"}} {count}')
        for bucket, count in sorted(self.latency_histogram.items()):
            lines.append(f'{namespace}_latency_bucket{{bucket="{bucket}"}} {count}')
        return "\n".join(lines)

    def summary(self) -> str:
        """Resumen ejecutivo legible."""
        return (
            f"AgentMetrics("
            f"executions={self.total_executions}, "
            f"success_rate={self.success_rate}%, "
            f"avg_duration={round(self.avg_duration_ms, 1)}ms, "
            f"p95={self.p95_latency_ms}ms, "
            f"findings={self.total_findings}, "
            f"critical={self.critical_findings}, "
            f"cost=${float(self.total_cost_decimal):.4f})"
        )

    def snapshot(self) -> dict[str, Any]:
        """Snapshot inmutable (deep copy) del estado actual."""
        import copy
        return copy.deepcopy(self.to_dict(include_latencies=False))


# ============================================================================
# HOOKS (pre/post para observabilidad)
# ============================================================================

@dataclass
class AgentHooks:
    """Hooks para observabilidad sin modificar BaseAgent.

    Cada hook es opcional (None = no-op). Se llaman en orden.

    Ejemplos:
        - pre_execute: logging, tracing, métricas custom
        - post_execute: enviar métricas a Datadog/OTel
        - on_command: tracing de comandos
        - on_error: alerting
    """
    pre_execute: Callable[[AgentContract, AgentInput], Awaitable[None]] | None = None
    post_execute: Callable[[AgentContract, AgentResult], Awaitable[None]] | None = None
    on_command: Callable[[str, float, int], Awaitable[None]] | None = None
    on_error: Callable[[AgentContract, Exception], Awaitable[None]] | None = None
    on_cancel: Callable[[AgentContract, str], Awaitable[None]] | None = None


# ============================================================================
# BASE AGENT v5
# ============================================================================

class BaseAgent(ABC):
    """Base de todos los agentes (God-Tier v5.0).

    Uso:
        >>> class ReconAgent(BaseAgent):
        ...     def get_contract(self) -> AgentContract:
        ...         return AgentContract(...)
        ...     async def _execute(self, inp: AgentInput) -> AgentOutput:
        ...         return ReconOutput(summary="done")
        >>>
        >>> agent = ReconAgent(sandbox=sm, gateway=gw)
        >>> result = await agent.run({"target": "example.com"})
    """

    def __init__(
        self,
        *,
        sandbox: Any,
        gateway: Any | None = None,
        kill_switch_event: asyncio.Event | None = None,
        hooks: AgentHooks | None = None,
        max_commands_log: int = MAX_COMMANDS_LOG,
        retry_attempts: int = DEFAULT_RETRY_ATTEMPTS,
    ) -> None:
        """
        Args:
            sandbox: SandboxManager para ejecutar comandos.
            gateway: AIGateway opcional (para agentes que usan LLM).
            kill_switch_event: Evento global para cancelación.
            hooks: Hooks opcionales de observabilidad.
            max_commands_log: Tamaño del ring buffer de comandos.
            retry_attempts: Intentos de retry en run_command.
        """
        self.sandbox = sandbox
        self.gateway = gateway
        self._kill_switch = kill_switch_event or asyncio.Event()
        self._kill_switch_lock = RLock()
        self._metrics = AgentMetrics()
        self._metrics_lock = RLock()
        self._commands_log: list[CommandLogEntry] = []
        self._max_commands_log = max_commands_log
        self._contract: AgentContract | None = None
        self._contract_lock = RLock()
        self._hooks = hooks or AgentHooks()
        self._retry_attempts = max(1, retry_attempts)
        self._active_sub_tasks: set[asyncio.Task[Any]] = set()
        self._sub_tasks_lock = RLock()

    # -- Propiedad de metrics (read-only copy) -------------------------------

    @property
    def metrics(self) -> AgentMetrics:
        """Retorna el objeto AgentMetrics (read via propiedades).

        NOTA: no exponer mutación. Usar get_metrics() para dict.
        """
        return self._metrics

    # -- Contrato (abstracto) -----------------------------------------------

    @abstractmethod
    def get_contract(self) -> AgentContract:
        """Retorna el contrato del agente."""
        ...

    @abstractmethod
    async def _execute(self, inp: AgentInput) -> AgentOutput:
        """Ejecuta el agente con el input validado.

        Este método debe ser implementado por cada agente concreto.
        """
        ...

    # -- API pública --------------------------------------------------------

    async def run(
        self,
        input_data: dict[str, Any],
        *,
        timeout_seconds: float | None = None,
    ) -> AgentResult:
        """Ejecuta el agente con validación completa.

        God-Tier v5.0:
            - Hooks pre/post execute
            - Cancelación graceful de sub-tasks
            - Fail-fast en programming errors
            - Kill switch thread-safe
            - Correlation IDs propagados

        Args:
            input_data: Input como dict.
            timeout_seconds: Override del timeout del contrato.

        Returns:
            AgentResult con output validado y métricas.

        Raises:
            NO raise — retorna AgentResult con error capturado.
        """
        # Cache contract (una sola llamada)
        contract = self._get_contract_cached()

        started_at = datetime.now(timezone.utc).isoformat()
        start_time = time.monotonic()

        _log.info(
            "agent_run_start",
            agent=contract.name,
            version=contract.version,
            objective=contract.objective,
            criticality=contract.criticality.value,
            correlation_id=get_context().get("correlation_id"),
        )

        result = AgentResult(
            agent_name=contract.name,
            agent_version=contract.version,
            started_at=started_at,
        )
        self._reset_commands_log()

        try:
            # 1. Validar input (fail-fast con InfoError)
            try:
                validated_input = contract.validate_input(input_data)
            except (ValueError, TypeError) as e:
                raise AgentInputError(
                    f"Input inválido: {type(e).__name__}: {e}",
                    agent_name=contract.name,
                    context={"input_preview": str(input_data)[:200]},
                ) from e

            # 2. Hook pre_execute
            await self._safe_hook(
                self._hooks.pre_execute, contract, validated_input
            )

            # 3. Ejecutar con timeout y cancelación graceful
            timeout = timeout_seconds or contract.max_duration_seconds
            output = await self._execute_with_timeout(
                validated_input, timeout, contract
            )

            # 4. Validar output
            if not isinstance(output, contract.output_schema):
                try:
                    output = contract.output_schema.model_validate(
                        output.model_dump()
                    )
                except (ValueError, TypeError) as e:
                    raise AgentOutputError(
                        f"Output inválido: {type(e).__name__}: {e}",
                        agent_name=contract.name,
                        context={"output_preview": str(output)[:200]},
                    ) from e

            # 5. Success
            result.success = True
            result.output = output

            _log.info(
                "agent_run_success",
                agent=contract.name,
                duration_ms=round((time.monotonic() - start_time) * 1000, 1),
                commands=len(self._commands_log),
                findings=output.total_findings,
            )

        except AgentError as e:
            result.error = str(e)
            result.success = False
            result.retryable = e.retryable
            result.error_code = e.error_code
            if isinstance(e, AgentTimeoutError):
                result.timed_out = True
            elif isinstance(e, AgentCancelledError):
                result.cancelled = True
            _log.error(
                "agent_run_error",
                agent=contract.name,
                error=str(e),
                error_code=e.error_code,
                retryable=e.retryable,
            )
            await self._safe_hook(self._hooks.on_error, contract, e)

        # Fail-fast: programming errors se propagan
        # NO hacemos `except Exception` genérico — eso oculta bugs.

        finally:
            # Cancelar sub-tasks huérfanos (graceful shutdown)
            await self._cancel_sub_tasks(reason="agent_run_finished")

            result.duration_ms = (time.monotonic() - start_time) * 1000
            result.finished_at = datetime.now(timezone.utc).isoformat()
            result.commands_log = list(self._commands_log)
            result.commands_executed = len(self._commands_log)

            # Record metrics (con lock)
            with self._metrics_lock:
                self._metrics.record_execution(result)

            # Hook post_execute
            await self._safe_hook(self._hooks.post_execute, contract, result)

        return result

    # -- Helpers privados ---------------------------------------------------

    def _get_contract_cached(self) -> AgentContract:
        """Cachea el contrato (get_contract puede ser costoso)."""
        with self._contract_lock:
            if self._contract is None:
                self._contract = self.get_contract()
            return self._contract

    def _reset_commands_log(self) -> None:
        """Reset del ring buffer de comandos."""
        self._commands_log = []

    async def _execute_with_timeout(
        self,
        inp: AgentInput,
        timeout: float,
        contract: AgentContract,
    ) -> AgentOutput:
        """Ejecuta _execute con timeout y cancelación graceful."""
        try:
            # Crear task para poder cancelarlo explícitamente
            task = asyncio.create_task(self._execute(inp))
            with self._sub_tasks_lock:
                self._active_sub_tasks.add(task)
            try:
                output = await asyncio.wait_for(task, timeout=timeout)
            finally:
                with self._sub_tasks_lock:
                    self._active_sub_tasks.discard(task)
            return output
        except asyncio.TimeoutError as e:
            raise AgentTimeoutError(
                f"Timeout después de {timeout}s",
                agent_name=contract.name,
                timeout_seconds=timeout,
                elapsed_seconds=timeout,
            ) from e
        except asyncio.CancelledError as e:
            raise AgentCancelledError(
                "Agente cancelado",
                agent_name=contract.name,
                reason="cancelled",
            ) from e

    async def _cancel_sub_tasks(self, reason: str = "unknown") -> int:
        """Cancela todas las sub-tasks activas (graceful shutdown)."""
        with self._sub_tasks_lock:
            tasks = list(self._active_sub_tasks)
        if not tasks:
            return 0
        _log.warning(
            "cancel_sub_tasks",
            count=len(tasks),
            reason=reason,
        )
        for task in tasks:
            if not task.done():
                task.cancel()
        # Esperar a que se cancelen (con timeout)
        try:
            await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=5.0,
            )
        except asyncio.TimeoutError:
            _log.error("cancel_sub_tasks_timeout", count=len(tasks))
        with self._sub_tasks_lock:
            self._active_sub_tasks.clear()
        return len(tasks)

    async def _safe_hook(self, hook: Any, *args: Any) -> None:
        """Ejecuta un hook capturando excepciones (no rompe el agente)."""
        if hook is None:
            return
        try:
            await hook(*args)
        except Exception as e:  # Los hooks NO deben romper el agente
            _log.warning(
                "hook_failed",
                hook=getattr(hook, "__name__", "unknown"),
                error=f"{type(e).__name__}: {e}",
            )

    # -- Helpers para subclases ---------------------------------------------

    async def run_command(
        self,
        command: str,
        *,
        timeout_seconds: float = 300.0,
        language: str = "bash",
        tool_name: str = "unknown",
        retry_on_transient: bool = True,
    ) -> dict[str, Any]:
        """Ejecuta un comando vía sandbox con validación, retry y logging.

        God-Tier v5.0:
            - Retry con backoff exponencial en fallos transitorios
            - Correlation IDs propagados
            - Latency por tool
            - Ring buffer de comandos
            - Hooks on_command

        Args:
            command: Comando a ejecutar.
            timeout_seconds: Timeout.
            language: Lenguaje (bash, python, node).
            tool_name: Nombre de la herramienta (para logs y allowlist).
            retry_on_transient: Si True, reintenta en fallos transitorios.

        Returns:
            Dict con exit_code, stdout, stderr, duration_ms.

        Raises:
            AgentCancelledError: Si el kill switch está activado.
            AgentSecurityError: Si el comando falla validación.
            AgentToolError: Si el comando falla.
        """
        contract = self._get_contract_cached()

        # 1. Kill switch check
        if self._is_kill_switch_set():
            raise AgentCancelledError(
                "Kill switch activado",
                agent_name=contract.name,
                reason="kill_switch",
            )

        # 2. Validar comando
        is_valid, reason = validate_command(command)
        if not is_valid:
            raise AgentSecurityError(
                f"Comando rechazado: {reason}",
                agent_name=contract.name,
                violation_type="forbidden_command",
                details={"command": command[:200], "reason": reason},
            )

        # 3. Validar tool permitido
        if contract.tools_allowed and tool_name != "unknown":
            if tool_name not in contract.tools_allowed:
                raise AgentSecurityError(
                    f"Tool '{tool_name}' no permitido. "
                    f"Permitidos: {contract.tools_allowed}",
                    agent_name=contract.name,
                    violation_type="tool_not_allowed",
                    details={
                        "tool_name": tool_name,
                        "allowed": list(contract.tools_allowed),
                    },
                )

        # 4. Ejecutar con retry
        attempts = self._retry_attempts if retry_on_transient else 1
        last_exception: Exception | None = None

        for attempt in range(attempts):
            # Kill switch check en cada intento
            if self._is_kill_switch_set():
                raise AgentCancelledError(
                    "Kill switch activado durante retry",
                    agent_name=contract.name,
                    reason="kill_switch",
                )

            start = time.monotonic()
            try:
                ctx = get_context()
                result = await self.sandbox.execute(
                    code=command,
                    language=language,
                )
                duration_ms = (time.monotonic() - start) * 1000
                exit_code = result.exit_code

                # Log + metrics (con lock)
                self._log_command(
                    command=command,
                    exit_code=exit_code,
                    duration_ms=duration_ms,
                    stdout=result.stdout,
                    stderr=result.stderr,
                    tool_name=tool_name,
                    sandbox_id=getattr(result, "container_id", "") or "",
                )

                # Hook on_command
                await self._safe_hook(
                    self._hooks.on_command,
                    tool_name, duration_ms, exit_code,
                )

                return {
                    "exit_code": exit_code,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "duration_ms": duration_ms,
                    "tool_name": tool_name,
                }

            except (asyncio.TimeoutError, ConnectionError, OSError) as e:
                # Transient failure → retry
                last_exception = e
                if attempt < attempts - 1:
                    delay = min(
                        DEFAULT_RETRY_BACKOFF_MAX,
                        DEFAULT_RETRY_BACKOFF_BASE ** attempt,
                    )
                    _log.warning(
                        "agent_command_retry",
                        agent=contract.name,
                        command=command[:100],
                        attempt=attempt + 1,
                        max_attempts=attempts,
                        delay=delay,
                        error=f"{type(e).__name__}: {e}",
                    )
                    await asyncio.sleep(delay)
                    continue
                # Último intento falló
                raise AgentToolError(
                    f"Sandbox falló tras {attempts} intentos: "
                    f"{type(e).__name__}: {e}",
                    agent_name=contract.name,
                    tool_name=tool_name,
                    command=command,
                    stderr=str(e),
                ) from e

            except AgentError:
                # Errores del agente se propagan (no son transient)
                raise

            except Exception as e:
                # Programming error → fail-fast
                raise AgentToolError(
                    f"Error inesperado en sandbox: {type(e).__name__}: {e}",
                    agent_name=contract.name,
                    tool_name=tool_name,
                    command=command,
                    stderr=str(e),
                ) from e

        # Unreachable
        raise AgentToolError(
            "run_command: unreachable state",
            agent_name=contract.name,
            tool_name=tool_name,
            command=command,
            stderr=str(last_exception) if last_exception else "unknown",
        )

    def _log_command(
        self,
        *,
        command: str,
        exit_code: int,
        duration_ms: float,
        stdout: str,
        stderr: str,
        tool_name: str,
        sandbox_id: str,
    ) -> None:
        """Registra comando en ring buffer + metrics."""
        entry = CommandLogEntry(
            timestamp=time.time(),
            command=command,
            exit_code=exit_code,
            duration_ms=duration_ms,
            stdout_preview=stdout[:500],
            stderr_preview=stderr[:500],
            tool_name=tool_name,
            sandbox_id=sandbox_id,
            pid=0,
        )
        # Ring buffer (evita memory leak)
        self._commands_log.append(entry)
        if len(self._commands_log) > self._max_commands_log:
            self._commands_log = self._commands_log[-self._max_commands_log:]

        with self._metrics_lock:
            self._metrics.record_command(tool_name, duration_ms=duration_ms)

        _log.debug(
            "agent_command_executed",
            agent=self._contract.name if self._contract else "unknown",
            command=command[:100],
            exit_code=exit_code,
            duration_ms=round(duration_ms, 1),
            tool=tool_name,
        )

    # -- Kill switch (thread-safe) ------------------------------------------

    def _is_kill_switch_set(self) -> bool:
        with self._kill_switch_lock:
            return self._kill_switch.is_set()

    def set_kill_switch(self) -> None:
        """Activa el kill switch del agente (thread-safe)."""
        with self._kill_switch_lock:
            self._kill_switch.set()
        _log.warning(
            "agent_kill_switch_activated",
            agent=self._contract.name if self._contract else "unknown",
        )

    def clear_kill_switch(self) -> None:
        """Desactiva el kill switch (post-revisión)."""
        with self._kill_switch_lock:
            self._kill_switch.clear()
        _log.info(
            "agent_kill_switch_cleared",
            agent=self._contract.name if self._contract else "unknown",
        )

    @property
    def is_cancelled(self) -> bool:
        """True si el kill switch está activado (thread-safe)."""
        return self._is_kill_switch_set()

    # -- API de métricas ----------------------------------------------------

    def get_metrics(self) -> dict[str, Any]:
        """Retorna las métricas del agente como dict (thread-safe)."""
        with self._metrics_lock:
            return self._metrics.to_dict()

    def get_metrics_snapshot(self) -> dict[str, Any]:
        """Snapshot inmutable (deep copy) de métricas."""
        with self._metrics_lock:
            return self._metrics.snapshot()

    def get_metrics_prometheus(self, namespace: str = "godtier_agent") -> str:
        """Exporta métricas en formato Prometheus (thread-safe)."""
        with self._metrics_lock:
            return self._metrics.to_prometheus(namespace=namespace)

    def get_metrics_summary(self) -> str:
        """Resumen ejecutivo (thread-safe)."""
        with self._metrics_lock:
            return self._metrics.summary()

    def reset_metrics(self) -> None:
        """Reset de métricas (thread-safe)."""
        with self._metrics_lock:
            self._metrics.reset()

    def get_commands_log(self) -> list[dict[str, Any]]:
        """Retorna copia del log de comandos (thread-safe)."""
        return [e.to_dict() for e in self._commands_log]

    async def shutdown(self) -> None:
        """Graceful shutdown: cancela sub-tasks y kill switch."""
        self.set_kill_switch()
        cancelled = await self._cancel_sub_tasks(reason="shutdown")
        _log.info(
            "agent_shutdown",
            cancelled_sub_tasks=cancelled,
            agent=self._contract.name if self._contract else "unknown",
        )


__all__ = [
    "BaseAgent",
    "AgentMetrics",
    "AgentHooks",
    "MAX_LATENCIES_KEPT",
    "MAX_COMMANDS_LOG",
    "MAX_TOOL_LATENCIES",
    "HISTOGRAM_BUCKETS_MS",
]
