"""Módulo orchestrator — God-Tier v3.

Orquestación end-to-end de red teaming:
    - State machine persistente (state.py)
    - Budget management multi-rol (budget.py)
    - Planner con DeepSeek (planner.py)
    - Executor asíncrono (executor.py)
    - Pipeline end-to-end (pipeline.py)

Arquitectura:
    ┌─────────────────────────────────────────────┐
    │  Pipeline (entry point)                     │
    │  ┌───────────────────────────────────────┐  │
    │  │  1. Planner.plan()                    │  │
    │  │     ├── scope validation              │  │
    │  │     ├── LLM (DeepSeek)                │  │
    │  │     └── populate StateMachine         │  │
    │  ├───────────────────────────────────────┤  │
    │  │  2. Executor.run()                    │  │
    │  │     ├── dependency resolution         │  │
    │  │     ├── concurrency control           │  │
    │  │     ├── retry with backoff            │  │
    │  │     └── circuit breaker               │  │
    │  ├───────────────────────────────────────┤  │
    │  │  3. Collect results                   │  │
    │  │     ├── state summary                 │  │
    │  │     ├── budget status                 │  │
    │  │     └── metrics (planner + executor)  │  │
    │  └───────────────────────────────────────┘  │
    └─────────────────────────────────────────────┘

Uso:
    >>> from god_tier_agency.orchestrator import (
    ...     Pipeline, StateMachine, BudgetManager,
    ... )
    >>>
    >>> sm = StateMachine(Path("/tmp/engagement.json"))
    >>> bm = BudgetManager(
    ...     engagement_id=uuid4(),
    ...     total_budget_usd=100.0,
    ...     role_limits={"planner": 20.0, "exploiter": 40.0},
    ... )
    >>>
    >>> pipeline = Pipeline(
    ...     gateway=AIGateway(),
    ...     state_machine=sm,
    ...     budget=bm,
    ...     agent_runner=my_agent_runner,
    ...     scope_targets=["example.com"],
    ... )
    >>>
    >>> result = await pipeline.run(engagement)
    >>> if result.success:
    ...     print(f"Plan: {result.plan_hash}")
    ...     print(f"Tasks: {result.execution_summary.successful}")

Features:
    - Pipeline end-to-end (plan → execute → collect)
    - State machine persistente con hash chain
    - Budget multi-rol con alertas progresivas
    - Planner con scope validation (CIDR + wildcards)
    - Executor con retry, timeout, circuit breaker
    - Correlation IDs end-to-end
    - Audit log de cada transición
    - Kill switch global
    - Dry-run mode para testing
"""

# ============================================================================
# VERSIÓN
# ============================================================================
__version__ = "0.1.0"


# ============================================================================
# EXCEPCIONES (TODAS)
# ============================================================================
from god_tier_agency.orchestrator.exceptions import (
    # Base
    OrchestratorError,
    # Eje 1
    RetryableError,
    FatalError,
    # Retryable
    PlannerError,
    ExecutorError,
    AgentError,
    # Fatal
    StateError,
    ScopeValidationError,
    PlanValidationError,
    BudgetExceededError,
    CheckpointError,
    RecoveryError,
    TaskAbortedError,
    # Pipeline
    PipelineError,
    # Helpers
    is_retryable,
    is_fatal,
    Severity,
)


# ============================================================================
# STATE MACHINE
# ============================================================================
from god_tier_agency.orchestrator.state import (
    # Enums
    Phase,
    TaskStatus,
    EngagementStatus,
    CriticalityLevel,
    # Dataclasses
    Transition,
    Task,
    PhaseState,
    EngagementState,
    # Machine
    StateMachine,
    # Constantes
    GENESIS_HASH,
)


# ============================================================================
# BUDGET
# ============================================================================
from god_tier_agency.orchestrator.budget import (
    BudgetManager,
    BudgetRecord,
    RoleBudget,
)


# ============================================================================
# PLANNER
# ============================================================================
from god_tier_agency.orchestrator.planner import (
    Planner,
    PlannerMetrics,
    ScopeMatcher,
    AttackPlan,
    PlanPhase,
    PlanTask,
    VALID_AGENTS,
    VALID_PHASES,
    PROMPT_VERSION,
)


# ============================================================================
# EXECUTOR
# ============================================================================
from god_tier_agency.orchestrator.executor import (
    Executor,
    ExecutorMetrics,
    ExecutionResult,
    ExecutionSummary,
    AgentRunner,
)


# ============================================================================
# PIPELINE
# ============================================================================
from god_tier_agency.orchestrator.pipeline import (
    Pipeline,
    PipelineResult,
)


# ============================================================================
# API PÚBLICA
# ============================================================================
__all__ = [
    # Versión
    "__version__",
    # --- Excepciones (base) ---
    "OrchestratorError",
    "RetryableError",
    "FatalError",
    # --- Excepciones (retryable) ---
    "PlannerError",
    "ExecutorError",
    "AgentError",
    # --- Excepciones (fatal) ---
    "StateError",
    "ScopeValidationError",
    "PlanValidationError",
    "BudgetExceededError",
    "CheckpointError",
    "RecoveryError",
    "TaskAbortedError",
    # --- Excepciones (pipeline) ---
    "PipelineError",
    # --- Excepciones (helpers) ---
    "is_retryable",
    "is_fatal",
    "Severity",
    # --- State machine ---
    "Phase",
    "TaskStatus",
    "EngagementStatus",
    "CriticalityLevel",
    "Transition",
    "Task",
    "PhaseState",
    "EngagementState",
    "StateMachine",
    "GENESIS_HASH",
    # --- Budget ---
    "BudgetManager",
    "BudgetRecord",
    "RoleBudget",
    # --- Planner ---
    "Planner",
    "PlannerMetrics",
    "ScopeMatcher",
    "AttackPlan",
    "PlanPhase",
    "PlanTask",
    "VALID_AGENTS",
    "VALID_PHASES",
    "PROMPT_VERSION",
    # --- Executor ---
    "Executor",
    "ExecutorMetrics",
    "ExecutionResult",
    "ExecutionSummary",
    "AgentRunner",
    # --- Pipeline ---
    "Pipeline",
    "PipelineResult",
]
