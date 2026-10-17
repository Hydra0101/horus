"""Executor del orquestador — God-Tier v3.

Ejecuta los tasks del plan con:
    - Concurrencia controlada (semáforo)
    - Dependencias respetadas (solo tasks ready)
    - Timeout por task
    - Retry con backoff exponencial
    - Circuit breaker (si > N fallos, pausa)
    - Graceful shutdown
    - Métricas por task y globales
    - Dry-run mode para testing

Filosofía:
    - Concurrencia segura (semáforo + lock)
    - Fail-fast en errores fatales
    - Retry en errores transitorios
    - Circuit breaker para proteger contra fallos en cascada
    - Auditoría de cada task

Uso:
    >>> async def run_agent(task: Task) -> dict:
    ...     # lógica del agente
    ...     return {"output": "..."}
    >>>
    >>> executor = Executor(
    ...     state_machine=sm,
    ...     agent_runner=run_agent,
    ...     max_concurrent=4,
    ... )
    >>> summary = await executor.run()
    >>> print(summary.successful)
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable
from uuid import UUID

from god_tier_agency.core.logging import get_logger
from god_tier_agency.orchestrator.exceptions import (
    ExecutorError,
    RetryableError,
    TaskAbortedError,
)
from god_tier_agency.orchestrator.state import (
    StateMachine,
    Task,
    TaskStatus,
)

_log = get_logger("orchestrator.executor")

# Firma del agent_runner: recibe un Task, retorna un dict con el resultado
AgentRunner = Callable[[Task], Awaitable[dict[str, Any]]]


# ============================================================================
# DATACLASSES
# ============================================================================
@dataclass(frozen=True)
class ExecutionResult:
    """Resultado de ejecutar un task."""

    task_id: UUID
    task_name: str
    status: TaskStatus
    result: dict[str, Any] | None
    error: str | None
    attempts: int
    duration_ms: float
    started_at: str
    finished_at: str

    @property
    def success(self) -> bool:
        return self.status == TaskStatus.SUCCESS

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": str(self.task_id),
            "task_name": self.task_name,
            "status": self.status.value,
            "success": self.success,
            "error": self.error,
            "attempts": self.attempts,
            "duration_ms": round(self.duration_ms, 3),
            "started_at": self.started_at,
            "finished_at": self.finished_at,
        }


@dataclass
class ExecutionSummary:
    """Resumen completo de la ejecución."""

    total_tasks: int = 0
    successful: int = 0
    failed: int = 0
    skipped: int = 0
    blocked: int = 0
    duration_ms: float = 0.0
    started_at: str = ""
    finished_at: str = ""
    results: list[ExecutionResult] = field(default_factory=list)
    circuit_breaker_tripped: bool = False

    @property
    def success_rate(self) -> float:
        if self.total_tasks == 0:
            return 0.0
        return round(self.successful / self.total_tasks * 100, 1)

    @property
    def is_complete(self) -> bool:
        return (
            self.successful + self.failed + self.skipped + self.blocked
            == self.total_tasks
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_tasks": self.total_tasks,
            "successful": self.successful,
            "failed": self.failed,
            "skipped": self.skipped,
            "blocked": self.blocked,
            "success_rate": self.success_rate,
            "duration_ms": round(self.duration_ms, 3),
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "circuit_breaker_tripped": self.circuit_breaker_tripped,
            "results": [r.to_dict() for r in self.results],
        }


@dataclass
class ExecutorMetrics:
    """Métricas agregadas del executor."""

    total_executions: int = 0
    total_tasks_executed: int = 0
    total_retries: int = 0
    total_timeouts: int = 0
    circuit_breaker_trips: int = 0
    total_duration_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_executions": self.total_executions,
            "total_tasks_executed": self.total_tasks_executed,
            "total_retries": self.total_retries,
            "total_timeouts": self.total_timeouts,
            "circuit_breaker_trips": self.circuit_breaker_trips,
            "avg_duration_ms": (
                self.total_duration_ms / self.total_executions
                if self.total_executions > 0 else 0.0
            ),
        }


# ============================================================================
# EXECUTOR
# ============================================================================
class Executor:
    """Ejecutor de tasks con concurrencia, retry, y circuit breaker.

    Uso:
        >>> executor = Executor(
        ...     state_machine=sm,
        ...     agent_runner=my_agent_runner,
        ...     max_concurrent=4,
        ... )
        >>> summary = await executor.run()
    """

    def __init__(
        self,
        *,
        state_machine: StateMachine,
        agent_runner: AgentRunner,
        max_concurrent: int = 4,
        task_timeout_seconds: float = 300.0,
        max_task_retries: int = 3,
        circuit_breaker_threshold: int = 5,
        dry_run: bool = False,
    ) -> None:
        """
        Args:
            state_machine: StateMachine con los tasks a ejecutar.
            agent_runner: Callable async que ejecuta un Task.
            max_concurrent: Máximo de tasks concurrentes.
            task_timeout_seconds: Timeout por task.
            max_task_retries: Reintentos máximos por task.
            circuit_breaker_threshold: Fallos consecutivos antes de pausar.
            dry_run: Si True, simula ejecución sin llamar al agent_runner.
        """
        self.state_machine = state_machine
        self.agent_runner = agent_runner
        self.max_concurrent = max_concurrent
        self.task_timeout_seconds = task_timeout_seconds
        self.max_task_retries = max_task_retries
        self.circuit_breaker_threshold = circuit_breaker_threshold
        self.dry_run = dry_run

        self._sema = asyncio.Semaphore(max_concurrent)
        self._lock = asyncio.Lock()
        self._consecutive_failures = 0
        self._circuit_breaker_open = False
        self._kill_switch_triggered = False
        self._active_tasks: dict[UUID, asyncio.Task] = {}
        self.metrics = ExecutorMetrics()

    async def run(self) -> ExecutionSummary:
        """Ejecuta todos los tasks del StateMachine hasta completarlos.

        Returns:
            ExecutionSummary con resultados de cada task.
        """
        summary = ExecutionSummary(
            started_at=datetime.now(timezone.utc).isoformat(),
        )
        start_time = time.time()
        self.metrics.total_executions += 1

        _log.info(
            "executor_start",
            total_tasks=self.state_machine.state.total_tasks,
            max_concurrent=self.max_concurrent,
            task_timeout=self.task_timeout_seconds,
            dry_run=self.dry_run,
        )

        while True:
            # 1. Verificar kill switch
            if self._kill_switch_triggered:
                _log.warning("executor_killed")
                break

            # 2. Verificar circuit breaker
            if self._circuit_breaker_open:
                _log.error("executor_circuit_breaker_open")
                summary.circuit_breaker_tripped = True
                break

            # 3. Obtener tasks ready (deps resueltas)
            ready_tasks = self._get_ready_tasks()

            if not ready_tasks:
                # No hay tasks ready
                if not self.state_machine.pending_tasks() and not self.state_machine.running_tasks():
                    # Todo terminó
                    break
                # Hay tasks pending pero no ready (deps sin resolver)
                # Chequear si hay running tasks (esperar)
                if self.state_machine.running_tasks():
                    await asyncio.sleep(0.1)
                    continue
                # Deadlock: pending sin deps resueltas ni running
                _log.error("executor_deadlock_detected", pending=len(self.state_machine.pending_tasks()))
                break

            # 4. Ejecutar tasks ready en paralelo (respetando semáforo)
            await asyncio.gather(*[
                self._run_task_with_semaphore(t.id) for t in ready_tasks
            ], return_exceptions=True)

        # 5. Esperar cualquier task activo
        if self._active_tasks:
            await asyncio.gather(*self._active_tasks.values(), return_exceptions=True)

        # 6. Recopilar resultados
        summary.duration_ms = (time.time() - start_time) * 1000
        summary.finished_at = datetime.now(timezone.utc).isoformat()
        self._collect_results(summary)
        self.metrics.total_duration_ms += summary.duration_ms

        _log.info(
            "executor_done",
            total=summary.total_tasks,
            successful=summary.successful,
            failed=summary.failed,
            duration_ms=round(summary.duration_ms, 1),
        )

        return summary

    def _get_ready_tasks(self) -> list[Task]:
        """Retorna tasks pending cuyas dependencias están resueltas."""
        ready: list[Task] = []
        for task in self.state_machine.pending_tasks():
            # Verificar que todas las dependencias estén SUCCESS
            all_deps_ok = True
            for dep_id in task.depends_on:
                dep = self.state_machine.get_task(dep_id)
                if dep is None or dep.status != TaskStatus.SUCCESS:
                    all_deps_ok = False
                    break
            if all_deps_ok:
                ready.append(task)
        return ready

    def _collect_results(self, summary: ExecutionSummary) -> None:
        """Recopila resultados de todos los tasks en el summary."""
        for ps in self.state_machine.state.phases.values():
            for task in ps.tasks:
                result = ExecutionResult(
                    task_id=task.id,
                    task_name=task.name,
                    status=task.status,
                    result=task.result,
                    error=task.error,
                    attempts=task.attempts,
                    duration_ms=task.duration_ms or 0.0,
                    started_at=(
                        datetime.fromtimestamp(task.started_at, tz=timezone.utc).isoformat()
                        if task.started_at else ""
                    ),
                    finished_at=(
                        datetime.fromtimestamp(task.finished_at, tz=timezone.utc).isoformat()
                        if task.finished_at else ""
                    ),
                )
                summary.results.append(result)

                if task.status == TaskStatus.SUCCESS:
                    summary.successful += 1
                elif task.status == TaskStatus.FAILED:
                    summary.failed += 1
                elif task.status == TaskStatus.SKIPPED:
                    summary.skipped += 1
                elif task.status == TaskStatus.BLOCKED:
                    summary.blocked += 1

        summary.total_tasks = len(summary.results)

    async def _run_task_with_semaphore(self, task_id: UUID) -> None:
        """Ejecuta un task respetando el semáforo."""
        async with self._sema:
            await self._run_task_worker(task_id)

    async def _run_task_worker(self, task_id: UUID) -> None:
        """Worker que ejecuta un task con retry, timeout, y circuit breaker."""
        task = self.state_machine.get_task(task_id)
        if task is None:
            _log.error("executor_task_not_found", task_id=str(task_id))
            return

        # Marcar como running
        try:
            self.state_machine.start_task(task_id)
        except Exception as e:
            _log.error("executor_start_failed", task_id=str(task_id), error=str(e))
            return

        started_at = time.time()
        last_error: Exception | None = None

        # Registrar task activo
        current_task = asyncio.current_task()
        if current_task:
            self._active_tasks[task_id] = current_task

        try:
            for attempt in range(self.max_task_retries):
                # Incrementar attempts en cada intento
                task.attempts = attempt + 1
                try:
                    # Ejecutar con timeout
                    result = await asyncio.wait_for(
                        self._execute_agent(task),
                        timeout=self.task_timeout_seconds,
                    )

                    # Success
                    self.state_machine.complete_task(task_id, result=result)
                    async with self._lock:
                        self._consecutive_failures = 0
                    self.metrics.total_tasks_executed += 1
                    _log.info(
                        "executor_task_success",
                        task_id=str(task_id),
                        task_name=task.name,
                        attempt=attempt + 1,
                        duration_ms=round((time.time() - started_at) * 1000, 1),
                    )
                    return

                except asyncio.TimeoutError:
                    last_error = ExecutorError(
                        f"Task timeout después de {self.task_timeout_seconds}s",
                        context={"task_id": str(task_id), "timeout": self.task_timeout_seconds},
                        retryable=True,
                    )
                    self.metrics.total_timeouts += 1
                    _log.warning(
                        "executor_task_timeout",
                        task_id=str(task_id),
                        attempt=attempt + 1,
                        timeout=self.task_timeout_seconds,
                    )

                except RetryableError as e:
                    last_error = e
                    _log.warning(
                        "executor_task_retryable",
                        task_id=str(task_id),
                        attempt=attempt + 1,
                        error=str(e),
                    )

                except TaskAbortedError as e:
                    # No reintentar
                    self.state_machine.block_task(task_id, f"Aborted: {e}")
                    _log.warning("executor_task_aborted", task_id=str(task_id))
                    return

                except Exception as e:
                    last_error = e
                    _log.error(
                        "executor_task_error",
                        task_id=str(task_id),
                        attempt=attempt + 1,
                        error=str(e),
                        error_type=type(e).__name__,
                    )

                # Backoff antes del siguiente intento
                if attempt < self.max_task_retries - 1:
                    self.metrics.total_retries += 1
                    delay = min(30, 2 ** attempt)
                    await asyncio.sleep(delay)

            # Todos los intentos fallaron
            error_msg = str(last_error) if last_error else "Unknown error"
            self.state_machine.fail_task(task_id, error_msg)
            async with self._lock:
                self._consecutive_failures += 1
                if self._consecutive_failures >= self.circuit_breaker_threshold:
                    self._circuit_breaker_open = True
                    self.metrics.circuit_breaker_trips += 1
                    _log.critical(
                        "executor_circuit_breaker_tripped",
                        consecutive_failures=self._consecutive_failures,
                        threshold=self.circuit_breaker_threshold,
                    )

        finally:
            self._active_tasks.pop(task_id, None)


    async def _execute_agent(self, task: Task) -> dict[str, Any]:
        """Ejecuta el agent_runner (o simula en dry_run)."""
        if self.dry_run:
            # Simular ejecución
            await asyncio.sleep(0.01)
            return {
                "status": "dry_run",
                "task_name": task.name,
                "agent": task.agent,
                "message": f"[DRY RUN] Task '{task.name}' simulado",
            }

        return await self.agent_runner(task)

    # -- Kill switch --------------------------------------------------------

    async def kill_switch(self) -> int:
        """Cancela TODOS los tasks en ejecución.

        Returns:
            Número de tasks cancelados.
        """
        self._kill_switch_triggered = True
        cancelled = 0

        async with self._lock:
            for task_id, task in list(self._active_tasks.items()):
                try:
                    task.cancel()
                    cancelled += 1
                except Exception as e:
                    _log.error(
                        "executor_cancel_failed",
                        task_id=str(task_id),
                        error=str(e),
                    )

        _log.critical("executor_kill_switch_triggered", cancelled=cancelled)
        return cancelled

    # -- Helpers ------------------------------------------------------------

    @property
    def is_circuit_breaker_open(self) -> bool:
        return self._circuit_breaker_open

    @property
    def active_tasks_count(self) -> int:
        return len(self._active_tasks)

    def reset_circuit_breaker(self) -> None:
        """Resetea el circuit breaker (para reintentar)."""
        with_sync_lock = None  # Placeholder
        self._consecutive_failures = 0
        self._circuit_breaker_open = False
        _log.info("executor_circuit_breaker_reset")

    def get_metrics(self) -> dict[str, Any]:
        """Retorna métricas agregadas."""
        return self.metrics.to_dict()

    def stats(self) -> dict[str, Any]:
        """Status actual del executor."""
        return {
            "active_tasks": self.active_tasks_count,
            "max_concurrent": self.max_concurrent,
            "consecutive_failures": self._consecutive_failures,
            "circuit_breaker_open": self._circuit_breaker_open,
            "circuit_breaker_threshold": self.circuit_breaker_threshold,
            "kill_switch_triggered": self._kill_switch_triggered,
            "dry_run": self.dry_run,
            "metrics": self.metrics.to_dict(),
        }


__all__ = [
    "Executor",
    "ExecutorMetrics",
    "ExecutionResult",
    "ExecutionSummary",
    "AgentRunner",
]
