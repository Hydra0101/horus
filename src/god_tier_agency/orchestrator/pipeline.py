"""Pipeline del orquestador — God-Tier v3.

Pipeline end-to-end: plan → execute → collect → report.

Integra:
    - planner.py (generación de plan)
    - executor.py (ejecución de tasks)
    - state.py (state machine)
    - budget.py (presupuesto)

Filosofía:
    - Pipeline end-to-end
    - Manejo de errores por fase
    - Métricas agregadas
    - Kill switch propagado
    - Persistencia del resultado
    - Dry-run mode

Uso:
    >>> pipeline = Pipeline(
    ...     gateway=AIGateway(max_cost=100.0),
    ...     state_machine=sm,
    ...     budget=bm,
    ...     agent_runner=my_agent_runner,
    ...     scope_targets=["example.com"],
    ... )
    >>> result = await pipeline.run(engagement)
    >>> print(result.success)
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from god_tier_agency.core.logging import get_logger
from god_tier_agency.orchestrator.budget import BudgetManager
from god_tier_agency.orchestrator.exceptions import (
    ExecutorError,
    PipelineError,
    PlannerError,
    StateError,
)
from god_tier_agency.orchestrator.executor import (
    AgentRunner,
    ExecutionSummary,
    Executor,
)
from god_tier_agency.orchestrator.planner import (
    AttackPlan,
    Planner,
)
from god_tier_agency.orchestrator.state import (
    EngagementStatus,
    StateMachine,
)

_log = get_logger("orchestrator.pipeline")


# ============================================================================
# PIPELINE RESULT
# ============================================================================
@dataclass
class PipelineResult:
    """Resultado completo del pipeline."""

    engagement_id: UUID
    plan: AttackPlan | None = None
    execution_summary: ExecutionSummary | None = None
    state_summary: dict[str, Any] = field(default_factory=dict)
    budget_status: dict[str, Any] = field(default_factory=dict)
    planner_metrics: dict[str, Any] = field(default_factory=dict)
    executor_metrics: dict[str, Any] = field(default_factory=dict)
    total_duration_ms: float = 0.0
    success: bool = False
    error: str | None = None
    phases_completed: list[str] = field(default_factory=list)
    started_at: str = ""
    finished_at: str = ""

    @property
    def plan_hash(self) -> str:
        return self.plan.plan_hash() if self.plan else ""

    @property
    def is_success(self) -> bool:
        return self.success

    def to_dict(self) -> dict[str, Any]:
        return {
            "engagement_id": str(self.engagement_id),
            "success": self.success,
            "error": self.error,
            "phases_completed": self.phases_completed,
            "total_duration_ms": round(self.total_duration_ms, 3),
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "plan_hash": self.plan_hash,
            "plan": self.plan.to_dict() if self.plan else None,
            "execution_summary": (
                self.execution_summary.to_dict()
                if self.execution_summary else None
            ),
            "state_summary": self.state_summary,
            "budget_status": self.budget_status,
            "planner_metrics": self.planner_metrics,
            "executor_metrics": self.executor_metrics,
        }

    def summary(self) -> str:
        """Resumen legible para logs."""
        status = "OK" if self.success else "FAIL"
        phases = " → ".join(self.phases_completed) or "none"
        return (
            f"PipelineResult({status}, duration={self.total_duration_ms:.0f}ms, "
            f"phases=[{phases}])"
        )


# ============================================================================
# PIPELINE
# ============================================================================
class Pipeline:
    """Orquestador end-to-end: plan → execute → collect → report.

    Uso:
        >>> pipeline = Pipeline(
        ...     gateway=AIGateway(max_cost=100.0),
        ...     state_machine=sm,
        ...     budget=bm,
        ...     agent_runner=my_runner,
        ... )
        >>> result = await pipeline.run(engagement)
    """

    def __init__(
        self,
        *,
        gateway: Any,
        state_machine: StateMachine,
        agent_runner: AgentRunner,
        budget: BudgetManager | None = None,
        scope_targets: list[str] | None = None,
        scope_excluded: list[str] | None = None,
        max_concurrent: int = 4,
        task_timeout_seconds: float = 300.0,
        max_task_retries: int = 3,
        dry_run: bool = False,
    ) -> None:
        self.gateway = gateway
        self.state_machine = state_machine
        self.budget = budget
        self.scope_targets = scope_targets or []
        self.scope_excluded = scope_excluded or []
        self.max_concurrent = max_concurrent
        self.task_timeout_seconds = task_timeout_seconds
        self.max_task_retries = max_task_retries
        self.dry_run = dry_run
        self._agent_runner = agent_runner

        # Construir planner
        self.planner = Planner(
            gateway=gateway,
            state_machine=state_machine,
            budget=budget,
            scope_targets=scope_targets,
            scope_excluded=scope_excluded,
        )

        # Executor se construye en runtime (necesita state actualizado)
        self.executor: Executor | None = None

    async def run(
        self,
        engagement: Any,
        context: dict[str, Any] | None = None,
        *,
        skip_execution: bool = False,
    ) -> PipelineResult:
        """Ejecuta el pipeline completo.

        Args:
            engagement: Engagement model.
            context: Contexto adicional.
            skip_execution: Si True, solo planifica (no ejecuta).

        Returns:
            PipelineResult con todo el estado final.
        """
        start_time = time.time()
        started_at_iso = datetime.now(timezone.utc).isoformat()
        result = PipelineResult(
            engagement_id=engagement.id,
            started_at=started_at_iso,
        )

        _log.info(
            "pipeline_start",
            engagement_id=str(engagement.id),
            client_name=engagement.client_name,
            dry_run=self.dry_run,
            skip_execution=skip_execution,
        )

        try:
            # ================================================================
            # FASE 1: PLAN
            # ================================================================
            _log.info("pipeline_phase_plan_start")
            plan = await self.planner.plan(
                engagement, context, dry_run=self.dry_run,
            )
            result.plan = plan
            result.phases_completed.append("plan")
            _log.info(
                "pipeline_phase_plan_done",
                phases=len(plan.phases),
                tasks=plan.total_tasks,
                plan_hash=plan.plan_hash()[:16],
            )

            if skip_execution:
                _log.info("pipeline_skip_execution")
                result.success = True
                result.phases_completed.append("skip_execution")
                return self._finalize(result, start_time)

            # ================================================================
            # FASE 2: EXECUTE
            # ================================================================
            _log.info("pipeline_phase_execute_start")
            self.executor = Executor(
                state_machine=self.state_machine,
                agent_runner=self._agent_runner,
                max_concurrent=self.max_concurrent,
                task_timeout_seconds=self.task_timeout_seconds,
                max_task_retries=self.max_task_retries,
                dry_run=self.dry_run,
            )
            execution_summary = await self.executor.run()
            result.execution_summary = execution_summary
            result.phases_completed.append("execute")
            _log.info(
                "pipeline_phase_execute_done",
                total=execution_summary.total_tasks,
                successful=execution_summary.successful,
                failed=execution_summary.failed,
                duration_ms=round(execution_summary.duration_ms, 1),
            )

            # ================================================================
            # FASE 3: COLLECT
            # ================================================================
            _log.info("pipeline_phase_collect_start")
            result.state_summary = self.state_machine.summary()
            if self.budget is not None:
                result.budget_status = self.budget.status()
            result.planner_metrics = self.planner.get_metrics()
            result.executor_metrics = self.executor.get_metrics()
            result.phases_completed.append("collect")

            # ================================================================
            # SUCCESS
            # ================================================================
            result.success = (
                execution_summary.successful > 0
                and execution_summary.failed == 0
            )

            _log.info(
                "pipeline_success" if result.success else "pipeline_partial",
                successful=execution_summary.successful,
                failed=execution_summary.failed,
            )

        except PlannerError as e:
            result.error = f"PlannerError: {e}"
            _log.error("pipeline_planner_error", error=str(e))

        except ExecutorError as e:
            result.error = f"ExecutorError: {e}"
            _log.error("pipeline_executor_error", error=str(e))

        except StateError as e:
            result.error = f"StateError: {e}"
            _log.error("pipeline_state_error", error=str(e))

        except Exception as e:
            result.error = f"{type(e).__name__}: {e}"
            _log.critical(
                "pipeline_unexpected_error",
                error=str(e),
                error_type=type(e).__name__,
            )

        return self._finalize(result, start_time)

    # -- Helpers ------------------------------------------------------------

    @property
    def agent_runner(self) -> AgentRunner:
        """Getter para agent_runner (inyectable)."""
        if not hasattr(self, "_agent_runner"):
            raise PipelineError(
                "agent_runner no configurado",
                phase="init",
            )
        return self._agent_runner

    @agent_runner.setter
    def agent_runner(self, runner: AgentRunner) -> None:
        self._agent_runner = runner

    def _finalize(
        self,
        result: PipelineResult,
        start_time: float,
    ) -> PipelineResult:
        """Finaliza el pipeline: calcula duración, persistencia."""
        result.total_duration_ms = (time.time() - start_time) * 1000
        result.finished_at = datetime.now(timezone.utc).isoformat()

        # Persistir el resultado (best-effort)
        try:
            self.state_machine.state.metadata["last_pipeline_result"] = {
                "success": result.success,
                "error": result.error,
                "phases_completed": result.phases_completed,
                "total_duration_ms": round(result.total_duration_ms, 3),
                "plan_hash": result.plan_hash,
            }
        except Exception as e:
            _log.warning("pipeline_persist_failed", error=str(e))

        _log.info(
            "pipeline_done",
            success=result.success,
            duration_ms=round(result.total_duration_ms, 1),
            phases=result.phases_completed,
            error=result.error,
        )

        return result

    # -- Kill switch --------------------------------------------------------

    async def kill_switch(self) -> int:
        """Propaga kill switch al executor."""
        if self.executor is None:
            return 0
        cancelled = await self.executor.kill_switch()
        _log.critical("pipeline_kill_switch", cancelled=cancelled)
        return cancelled

    # -- State --------------------------------------------------------------

    def stats(self) -> dict[str, Any]:
        """Estadísticas del pipeline."""
        return {
            "dry_run": self.dry_run,
            "max_concurrent": self.max_concurrent,
            "task_timeout_seconds": self.task_timeout_seconds,
            "max_task_retries": self.max_task_retries,
            "scope_targets_count": len(self.scope_targets),
            "scope_excluded_count": len(self.scope_excluded),
            "executor_active": self.executor is not None,
        }


__all__ = [
    "Pipeline",
    "PipelineResult",
]
