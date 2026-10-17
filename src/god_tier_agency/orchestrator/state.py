"""State machine persistente del orquestador — God-Tier v2.

Gestiona el estado completo de un engagement:
    - Fases del plan (recon, scan, exploit, post-exploit)
    - Tasks por fase (pending, running, success, failed)
    - Findings descubiertos (reales, no solo count)
    - Attack chains construidas
    - Budget consumido
    - Hash chain de transiciones (anti-tampering)

Fix v2:
    - Hash chain de transiciones (blockchain-style)
    - Findings y attack_chains reales (no solo count)
    - Task.metadata + Task.parent_task_id + Task.depends_on
    - mark_critical_path() para camino crítico
    - verify_integrity() con hash chain
    - checkpoint() / rollback() granular
    - export_forensics() con metadata completa
    - Transition log con prev_hash

Filosofía:
    - State machine explícita (transiciones validadas)
    - Persistencia atómica (os.replace + fsync)
    - Thread-safe (RLock)
    - Reanudable (load desde disco)
    - Auditable (hash chain de transiciones)
    - Forense (export completo)

Uso:
    >>> from pathlib import Path
    >>> from uuid import uuid4
    >>> sm = StateMachine(Path("/tmp/engagement.json"))
    >>> sm.initialize(uuid4(), client_name="ACME Corp")
    >>> sm.transition_engagement(EngagementStatus.RUNNING)
    >>> sm.add_phase(Phase.RECON)
    >>> task = sm.add_task(Phase.RECON, name="nmap scan", agent="recon")
    >>> sm.start_task(task.id)
    >>> sm.complete_task(task.id, result={"open_ports": [22, 80]})
    >>> ok, reason = sm.verify_integrity()
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from threading import RLock
from typing import Any, Final, Literal
from uuid import UUID, uuid4

from god_tier_agency.core.logging import get_logger
from god_tier_agency.orchestrator.exceptions import StateError

_log = get_logger("orchestrator.state")

GENESIS_HASH: Final[str] = "GENESIS"
"""Hash inicial de la cadena de transiciones."""


# ============================================================================
# ENUMS
# ============================================================================
class Phase(str, Enum):
    """Fases del plan de ataque."""

    RECON = "recon"
    SCAN = "scan"
    EXPLOIT = "exploit"
    POST_EXPLOIT = "post_exploit"
    PERSISTENCE = "persistence"
    EXFIL = "exfil"
    REPORT = "report"


class TaskStatus(str, Enum):
    """Estado de un task individual."""

    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    BLOCKED = "blocked"


class EngagementStatus(str, Enum):
    """Estado del engagement completo."""

    PLANNING = "planning"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    ABORTED = "aborted"


class CriticalityLevel(str, Enum):
    """Nivel de criticidad de un task."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ============================================================================
# TRANSICIONES VÁLIDAS
# ============================================================================
_VALID_TASK_TRANSITIONS: Final[dict[TaskStatus, frozenset[TaskStatus]]] = {
    TaskStatus.PENDING: frozenset({
        TaskStatus.RUNNING, TaskStatus.SKIPPED, TaskStatus.BLOCKED,
    }),
    TaskStatus.RUNNING: frozenset({
        TaskStatus.SUCCESS, TaskStatus.FAILED, TaskStatus.BLOCKED,
    }),
    TaskStatus.SUCCESS: frozenset(),
    TaskStatus.FAILED: frozenset({
        TaskStatus.PENDING, TaskStatus.BLOCKED,
    }),
    TaskStatus.SKIPPED: frozenset(),
    TaskStatus.BLOCKED: frozenset(),
}

_VALID_ENGAGEMENT_TRANSITIONS: Final[dict[EngagementStatus, frozenset[EngagementStatus]]] = {
    EngagementStatus.PLANNING: frozenset({
        EngagementStatus.RUNNING, EngagementStatus.ABORTED,
    }),
    EngagementStatus.RUNNING: frozenset({
        EngagementStatus.PAUSED, EngagementStatus.COMPLETED, EngagementStatus.ABORTED,
    }),
    EngagementStatus.PAUSED: frozenset({
        EngagementStatus.RUNNING, EngagementStatus.ABORTED,
    }),
    EngagementStatus.COMPLETED: frozenset(),
    EngagementStatus.ABORTED: frozenset(),
}


# ============================================================================
# HASH CHAIN
# ============================================================================
def _compute_transition_hash(
    *,
    prev_hash: str,
    timestamp: float,
    event: str,
    entity_id: str,
    from_state: str,
    to_state: str,
    metadata: dict[str, Any],
) -> str:
    """Calcula el hash de una transición (parte del chain)."""
    payload = {
        "prev_hash": prev_hash,
        "timestamp": timestamp,
        "event": event,
        "entity_id": entity_id,
        "from_state": from_state,
        "to_state": to_state,
        "metadata": metadata,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ============================================================================
# DATACLASSES
# ============================================================================
@dataclass
class Transition:
    """Un evento de transición en el hash chain."""

    index: int
    timestamp: float
    event: str
    entity_id: str
    from_state: str
    to_state: str
    prev_hash: str
    entry_hash: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "timestamp_iso": datetime.fromtimestamp(
                self.timestamp, tz=timezone.utc
            ).isoformat(),
            "event": self.event,
            "entity_id": self.entity_id,
            "from_state": self.from_state,
            "to_state": self.to_state,
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Transition":
        d = dict(d)
        d.pop("timestamp_iso", None)
        return cls(**d)


@dataclass
class Task:
    """Un task dentro de una fase del plan (v2 con metadata + deps)."""

    id: UUID
    phase: Phase
    name: str
    description: str
    agent: str
    status: TaskStatus = TaskStatus.PENDING
    result: dict[str, Any] | None = None
    error: str | None = None
    started_at: float | None = None
    finished_at: float | None = None
    duration_ms: float | None = None
    attempts: int = 0
    max_attempts: int = 3
    criticality: CriticalityLevel = CriticalityLevel.MEDIUM
    metadata: dict[str, Any] = field(default_factory=dict)
    parent_task_id: UUID | None = None
    depends_on: list[UUID] = field(default_factory=list)

    @property
    def can_retry(self) -> bool:
        return self.status == TaskStatus.FAILED and self.attempts < self.max_attempts

    @property
    def is_terminal(self) -> bool:
        return self.status in (
            TaskStatus.SUCCESS, TaskStatus.SKIPPED, TaskStatus.BLOCKED,
        )

    @property
    def is_critical(self) -> bool:
        return self.criticality in (CriticalityLevel.HIGH, CriticalityLevel.CRITICAL)

    def to_dict(self) -> dict[str, Any]:
        d = dict(self.__dict__)
        d["id"] = str(self.id)
        d["phase"] = self.phase.value
        d["status"] = self.status.value
        d["criticality"] = self.criticality.value
        d["parent_task_id"] = str(self.parent_task_id) if self.parent_task_id else None
        d["depends_on"] = [str(x) for x in self.depends_on]
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Task":
        d = dict(d)
        d["id"] = UUID(d["id"])
        d["phase"] = Phase(d["phase"])
        d["status"] = TaskStatus(d["status"])
        d["criticality"] = CriticalityLevel(d.get("criticality", "medium"))
        d["parent_task_id"] = (
            UUID(d["parent_task_id"]) if d.get("parent_task_id") else None
        )
        d["depends_on"] = [UUID(x) for x in d.get("depends_on", [])]
        return cls(**d)


@dataclass
class PhaseState:
    """Estado de una fase del plan."""

    phase: Phase
    tasks: list[Task] = field(default_factory=list)

    @property
    def total_tasks(self) -> int:
        return len(self.tasks)

    @property
    def completed_tasks(self) -> int:
        return sum(1 for t in self.tasks if t.status == TaskStatus.SUCCESS)

    @property
    def failed_tasks(self) -> int:
        return sum(1 for t in self.tasks if t.status == TaskStatus.FAILED)

    @property
    def is_complete(self) -> bool:
        return all(t.is_terminal for t in self.tasks)

    @property
    def progress_pct(self) -> float:
        if not self.tasks:
            return 100.0
        done = sum(1 for t in self.tasks if t.is_terminal)
        return round(done / self.total_tasks * 100, 1)


@dataclass
class EngagementState:
    """Estado completo del engagement (v2)."""

    engagement_id: UUID
    client_name: str
    status: EngagementStatus
    phases: dict[Phase, PhaseState] = field(default_factory=dict)
    findings: list[dict[str, Any]] = field(default_factory=list)
    attack_chains: list[dict[str, Any]] = field(default_factory=list)
    total_tasks: int = 0
    completed_tasks: int = 0
    failed_tasks: int = 0
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)
    transitions: list[Transition] = field(default_factory=list)
    last_transition_hash: str = GENESIS_HASH

    @property
    def findings_count(self) -> int:
        return len(self.findings)

    @property
    def attack_chains_count(self) -> int:
        return len(self.attack_chains)

    @property
    def progress_pct(self) -> float:
        if self.total_tasks == 0:
            return 0.0
        return round(self.completed_tasks / self.total_tasks * 100, 1)

    @property
    def is_complete(self) -> bool:
        return all(p.is_complete for p in self.phases.values())

    def to_dict(self) -> dict[str, Any]:
        return {
            "engagement_id": str(self.engagement_id),
            "client_name": self.client_name,
            "status": self.status.value,
            "phases": {
                p.value: {
                    "phase": ps.phase.value,
                    "tasks": [t.to_dict() for t in ps.tasks],
                    "total_tasks": ps.total_tasks,
                    "completed_tasks": ps.completed_tasks,
                    "failed_tasks": ps.failed_tasks,
                    "progress_pct": ps.progress_pct,
                }
                for p, ps in self.phases.items()
            },
            "findings": self.findings,
            "findings_count": self.findings_count,
            "attack_chains": self.attack_chains,
            "attack_chains_count": self.attack_chains_count,
            "total_tasks": self.total_tasks,
            "completed_tasks": self.completed_tasks,
            "failed_tasks": self.failed_tasks,
            "progress_pct": self.progress_pct,
            "created_at": self.created_at,
            "created_at_iso": datetime.fromtimestamp(
                self.created_at, tz=timezone.utc
            ).isoformat(),
            "updated_at": self.updated_at,
            "updated_at_iso": datetime.fromtimestamp(
                self.updated_at, tz=timezone.utc
            ).isoformat(),
            "metadata": self.metadata,
            "transitions": [t.to_dict() for t in self.transitions],
            "last_transition_hash": self.last_transition_hash,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "EngagementState":
        phases: dict[Phase, PhaseState] = {}
        for p_str, ps_data in d.get("phases", {}).items():
            phase = Phase(p_str)
            tasks = [Task.from_dict(t) for t in ps_data.get("tasks", [])]
            phases[phase] = PhaseState(phase=phase, tasks=tasks)

        transitions = [
            Transition.from_dict(t) for t in d.get("transitions", [])
        ]

        return cls(
            engagement_id=UUID(d["engagement_id"]),
            client_name=d["client_name"],
            status=EngagementStatus(d["status"]),
            phases=phases,
            findings=d.get("findings", []),
            attack_chains=d.get("attack_chains", []),
            total_tasks=d.get("total_tasks", 0),
            completed_tasks=d.get("completed_tasks", 0),
            failed_tasks=d.get("failed_tasks", 0),
            created_at=d.get("created_at", time.time()),
            updated_at=d.get("updated_at", time.time()),
            metadata=d.get("metadata", {}),
            transitions=transitions,
            last_transition_hash=d.get("last_transition_hash", GENESIS_HASH),
        )


# ============================================================================
# STATE MACHINE
# ============================================================================
class StateMachine:
    """Máquina de estados persistente, thread-safe, con hash chain.

    Uso:
        >>> sm = StateMachine(Path("/tmp/engagement.json"))
        >>> sm.initialize(engagement_id, client_name)
        >>> sm.transition_engagement(EngagementStatus.RUNNING)
        >>> sm.add_phase(Phase.RECON)
        >>> task = sm.add_task(Phase.RECON, name="nmap scan", agent="recon")
        >>> sm.start_task(task.id)
        >>> sm.complete_task(task.id, result={"open_ports": [22, 80]})
        >>> ok, reason = sm.verify_integrity()
    """

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()
        self._state: EngagementState | None = None
        self._checkpoints: dict[str, dict[str, Any]] = {}
        self._load_existing()

    # -- Persistencia --------------------------------------------------------

    def _load_existing(self) -> None:
        """Carga estado existente (si hay)."""
        if not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            self._state = EngagementState.from_dict(data)
            _log.info(
                "state_loaded",
                path=str(self.path),
                engagement_id=str(self._state.engagement_id),
                status=self._state.status.value,
                total_tasks=self._state.total_tasks,
                transitions=len(self._state.transitions),
            )
        except (json.JSONDecodeError, KeyError, ValueError, TypeError) as e:
            _log.error("state_load_failed", path=str(self.path), error=str(e))
            raise StateError(
                f"No se pudo cargar el estado: {e}",
                context={"path": str(self.path)},
            ) from e

    def _persist(self) -> None:
        """Persiste el estado a disco (atómico con fsync)."""
        if self._state is None:
            return
        self._state.updated_at = time.time()
        tmp_path = self.path.with_suffix(self.path.suffix + ".tmp")
        try:
            data = json.dumps(self._state.to_dict(), indent=2, sort_keys=True)
            with open(tmp_path, "w", encoding="utf-8") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, self.path)
        except OSError as e:
            _log.error("state_persist_failed", path=str(self.path), error=str(e))
            raise StateError(
                f"No se pudo persistir el estado: {e}",
                context={"path": str(self.path)},
            ) from e

    def _record_transition(
        self,
        *,
        event: str,
        entity_id: str,
        from_state: str,
        to_state: str,
        metadata: dict[str, Any] | None = None,
    ) -> Transition:
        """Registra una transición en el hash chain."""
        if self._state is None:
            raise StateError("State machine no inicializada")

        index = len(self._state.transitions)
        timestamp = time.time()
        prev_hash = self._state.last_transition_hash

        entry_hash = _compute_transition_hash(
            prev_hash=prev_hash,
            timestamp=timestamp,
            event=event,
            entity_id=entity_id,
            from_state=from_state,
            to_state=to_state,
            metadata=metadata or {},
        )

        transition = Transition(
            index=index,
            timestamp=timestamp,
            event=event,
            entity_id=entity_id,
            from_state=from_state,
            to_state=to_state,
            prev_hash=prev_hash,
            entry_hash=entry_hash,
            metadata=metadata or {},
        )

        self._state.transitions.append(transition)
        self._state.last_transition_hash = entry_hash
        return transition

    # -- API pública --------------------------------------------------------

    @property
    def state(self) -> EngagementState:
        """Estado actual (raise si no inicializado)."""
        if self._state is None:
            raise StateError("State machine no inicializada")
        return self._state

    @property
    def is_initialized(self) -> bool:
        return self._state is not None

    def initialize(
        self,
        engagement_id: UUID,
        client_name: str,
        metadata: dict[str, Any] | None = None,
    ) -> EngagementState:
        """Inicializa el estado para un nuevo engagement."""
        with self._lock:
            if self._state is not None:
                raise StateError(
                    "State machine ya inicializada",
                    context={"existing_id": str(self._state.engagement_id)},
                )
            self._state = EngagementState(
                engagement_id=engagement_id,
                client_name=client_name,
                status=EngagementStatus.PLANNING,
                metadata=metadata or {},
            )
            self._record_transition(
                event="initialize",
                entity_id=str(engagement_id),
                from_state="none",
                to_state=EngagementStatus.PLANNING.value,
                metadata={"client_name": client_name},
            )
            self._persist()
            _log.info(
                "state_initialized",
                engagement_id=str(engagement_id),
                client_name=client_name,
            )
            return self._state

    def transition_engagement(
        self,
        new_status: EngagementStatus,
    ) -> EngagementState:
        """Transiciona el engagement (valida transición)."""
        with self._lock:
            if self._state is None:
                raise StateError("State machine no inicializada")
            current = self._state.status
            if new_status not in _VALID_ENGAGEMENT_TRANSITIONS[current]:
                raise StateError(
                    f"Transición inválida: {current.value} → {new_status.value}",
                    context={"from": current.value, "to": new_status.value},
                )
            self._state.status = new_status
            self._record_transition(
                event="engagement_transition",
                entity_id=str(self._state.engagement_id),
                from_state=current.value,
                to_state=new_status.value,
            )
            self._persist()
            _log.info(
                "engagement_transition",
                from_status=current.value,
                to_status=new_status.value,
            )
            return self._state

    def add_phase(self, phase: Phase) -> PhaseState:
        """Añade una fase al plan."""
        with self._lock:
            if self._state is None:
                raise StateError("State machine no inicializada")
            if phase in self._state.phases:
                return self._state.phases[phase]
            ps = PhaseState(phase=phase)
            self._state.phases[phase] = ps
            self._record_transition(
                event="phase_added",
                entity_id=phase.value,
                from_state="none",
                to_state="created",
            )
            self._persist()
            return ps

    def add_task(
        self,
        phase: Phase,
        name: str,
        agent: str,
        description: str = "",
        max_attempts: int = 3,
        criticality: CriticalityLevel = CriticalityLevel.MEDIUM,
        metadata: dict[str, Any] | None = None,
        parent_task_id: UUID | None = None,
        depends_on: list[UUID] | None = None,
    ) -> Task:
        """Añade un task a una fase."""
        with self._lock:
            if self._state is None:
                raise StateError("State machine no inicializada")
            if phase not in self._state.phases:
                self.add_phase(phase)
            task = Task(
                id=uuid4(),
                phase=phase,
                name=name,
                agent=agent,
                description=description,
                max_attempts=max_attempts,
                criticality=criticality,
                metadata=metadata or {},
                parent_task_id=parent_task_id,
                depends_on=depends_on or [],
            )
            self._state.phases[phase].tasks.append(task)
            self._state.total_tasks += 1
            self._record_transition(
                event="task_added",
                entity_id=str(task.id),
                from_state="none",
                to_state=TaskStatus.PENDING.value,
                metadata={"name": name, "phase": phase.value, "agent": agent},
            )
            self._persist()
            return task

    def get_task(self, task_id: UUID) -> Task | None:
        """Busca un task por ID."""
        with self._lock:
            if self._state is None:
                return None
            for ps in self._state.phases.values():
                for t in ps.tasks:
                    if t.id == task_id:
                        return t
            return None

    def start_task(self, task_id: UUID) -> Task:
        """Marca un task como running."""
        return self._transition_task(task_id, TaskStatus.RUNNING)

    def complete_task(
        self,
        task_id: UUID,
        result: dict[str, Any] | None = None,
    ) -> Task:
        """Marca un task como success."""
        task = self._transition_task(task_id, TaskStatus.SUCCESS)
        task.result = result
        task.duration_ms = (
            (task.finished_at - task.started_at) * 1000
            if task.started_at
            else 0
        )
        with self._lock:
            self._state.completed_tasks += 1
            self._persist()
        return task

    def fail_task(self, task_id: UUID, error: str) -> Task:
        """Marca un task como failed."""
        task = self._transition_task(task_id, TaskStatus.FAILED)
        task.error = error
        with self._lock:
            self._state.failed_tasks += 1
            self._persist()
        return task

    def skip_task(self, task_id: UUID, reason: str = "") -> Task:
        """Marca un task como skipped."""
        task = self._transition_task(task_id, TaskStatus.SKIPPED)
        task.error = reason
        with self._lock:
            self._persist()
        return task

    def block_task(self, task_id: UUID, reason: str) -> Task:
        """Marca un task como blocked (no reintentable)."""
        task = self._transition_task(task_id, TaskStatus.BLOCKED)
        task.error = reason
        with self._lock:
            self._persist()
        return task

    def retry_task(self, task_id: UUID) -> Task:
        """Reinicia un task failed para reintentarlo."""
        with self._lock:
            task = self.get_task(task_id)
            if task is None:
                raise StateError(f"Task no encontrado: {task_id}")
            if not task.can_retry:
                raise StateError(
                    f"Task no puede reintentarse (attempts={task.attempts}/{task.max_attempts})",
                    context={"task_id": str(task_id)},
                )
            return self._transition_task(task_id, TaskStatus.PENDING)

    # -- Findings + chains --------------------------------------------------

    def add_finding(self, finding: dict[str, Any]) -> None:
        """Añade un finding al estado."""
        with self._lock:
            if self._state is None:
                raise StateError("State machine no inicializada")
            self._state.findings.append(finding)
            self._record_transition(
                event="finding_added",
                entity_id=finding.get("id", "unknown"),
                from_state="none",
                to_state="added",
                metadata={"title": finding.get("title", "")[:100]},
            )
            self._persist()

    def add_attack_chain(self, chain: dict[str, Any]) -> None:
        """Añade una attack chain al estado."""
        with self._lock:
            if self._state is None:
                raise StateError("State machine no inicializada")
            self._state.attack_chains.append(chain)
            self._record_transition(
                event="chain_added",
                entity_id=chain.get("id", "unknown"),
                from_state="none",
                to_state="added",
            )
            self._persist()

    # -- Análisis -----------------------------------------------------------

    def mark_critical_path(self) -> list[UUID]:
        """Identifica los task IDs del camino crítico.

        Un task es crítico si:
            1. criticality es HIGH o CRITICAL, O
            2. Es prerequisito (dependencia) de un crítico, O
            3. Depende de un crítico (necesario para el camino)

        Returns:
            Lista de task IDs críticos.
        """
        with self._lock:
            if self._state is None:
                return []

            critical: set[UUID] = set()
            # Index de tasks por ID para búsqueda rápida
            tasks_by_id: dict[UUID, Task] = {}
            for ps in self._state.phases.values():
                for t in ps.tasks:
                    tasks_by_id[t.id] = t

            # 1. Críticos por nivel
            for t in tasks_by_id.values():
                if t.is_critical:
                    critical.add(t.id)

            # 2. Propagación transitiva en AMBAS direcciones
            changed = True
            while changed:
                changed = False
                for t in tasks_by_id.values():
                    # 2a. Si t es crítico, sus dependencias son críticas
                    if t.id in critical:
                        for dep_id in t.depends_on:
                            if dep_id not in critical and dep_id in tasks_by_id:
                                critical.add(dep_id)
                                changed = True
                    # 2b. Si t DEPENDE de un crítico, t es crítico
                    for dep_id in t.depends_on:
                        if dep_id in critical and t.id not in critical:
                            critical.add(t.id)
                            changed = True

            # 3. Marcar en metadata
            for t in tasks_by_id.values():
                if t.id in critical:
                    t.metadata["_critical_path"] = True

            return list(critical)

    # -- Integridad ---------------------------------------------------------

    def verify_integrity(self) -> tuple[bool, str]:
        """Verifica la integridad del hash chain de transiciones.

        Returns:
            (True, "OK") si todo correcto.
            (False, reason) si hay tampering.
        """
        with self._lock:
            if self._state is None:
                return (False, "State machine no inicializada")

            expected_prev = GENESIS_HASH
            for i, transition in enumerate(self._state.transitions):
                # Verificar index
                if transition.index != i:
                    return (
                        False,
                        f"Transición {i} tiene index incorrecto: {transition.index}",
                    )
                # Verificar prev_hash
                if transition.prev_hash != expected_prev:
                    return (
                        False,
                        f"Transición {i} prev_hash roto: "
                        f"esperado {expected_prev[:16]}, "
                        f"encontrado {transition.prev_hash[:16]}",
                    )
                # Verificar entry_hash
                computed = _compute_transition_hash(
                    prev_hash=transition.prev_hash,
                    timestamp=transition.timestamp,
                    event=transition.event,
                    entity_id=transition.entity_id,
                    from_state=transition.from_state,
                    to_state=transition.to_state,
                    metadata=transition.metadata,
                )
                if computed != transition.entry_hash:
                    return (
                        False,
                        f"Transición {i} entry_hash no coincide "
                        f"(tampering detectado)",
                    )
                expected_prev = transition.entry_hash

            return (True, "OK")

    # -- Checkpoints --------------------------------------------------------

    def checkpoint(self, name: str) -> dict[str, Any]:
        """Crea un checkpoint in-memory del estado actual."""
        with self._lock:
            if self._state is None:
                raise StateError("State machine no inicializada")
            snapshot = self._state.to_dict()
            self._checkpoints[name] = snapshot
            _log.info("checkpoint_created", name=name, tasks=self._state.total_tasks)
            return snapshot

    def rollback(self, name: str) -> EngagementState:
        """Restaura el estado desde un checkpoint."""
        with self._lock:
            if name not in self._checkpoints:
                raise StateError(
                    f"Checkpoint no encontrado: {name}",
                    context={"available": list(self._checkpoints.keys())},
                )
            self._state = EngagementState.from_dict(self._checkpoints[name])
            self._record_transition(
                event="rollback",
                entity_id=str(self._state.engagement_id),
                from_state="current",
                to_state="rollback",
                metadata={"checkpoint": name},
            )
            self._persist()
            _log.warning("checkpoint_rolled_back", name=name)
            return self._state

    def list_checkpoints(self) -> list[str]:
        """Lista los checkpoints disponibles."""
        with self._lock:
            return list(self._checkpoints.keys())

    # -- Forense ------------------------------------------------------------

    def export_forensics(self) -> dict[str, Any]:
        """Exportación forense completa."""
        with self._lock:
            if self._state is None:
                return {"initialized": False}
            ok, reason = self.verify_integrity()
            return {
                "initialized": True,
                "exported_at": datetime.now(timezone.utc).isoformat(),
                "state": self._state.to_dict(),
                "chain_valid": ok,
                "chain_reason": reason,
                "total_transitions": len(self._state.transitions),
                "last_transition_hash": self._state.last_transition_hash,
                "checkpoints_available": list(self._checkpoints.keys()),
            }

    # -- Internals ----------------------------------------------------------

    def _transition_task(self, task_id: UUID, new_status: TaskStatus) -> Task:
        """Transiciona un task validando la transición."""
        with self._lock:
            task = self.get_task(task_id)
            if task is None:
                raise StateError(f"Task no encontrado: {task_id}")
            current = task.status
            if new_status not in _VALID_TASK_TRANSITIONS[current]:
                raise StateError(
                    f"Transición inválida: {current.value} → {new_status.value}",
                    context={
                        "task_id": str(task_id),
                        "from": current.value,
                        "to": new_status.value,
                    },
                )
            task.status = new_status
            now = time.time()
            if new_status == TaskStatus.RUNNING:
                task.started_at = now
            elif new_status in (TaskStatus.SUCCESS, TaskStatus.FAILED):
                task.finished_at = now
            self._record_transition(
                event="task_transition",
                entity_id=str(task_id),
                from_state=current.value,
                to_state=new_status.value,
            )
            self._persist()
            return task

    # -- Helpers ------------------------------------------------------------

    def pending_tasks(self) -> list[Task]:
        """Retorna todos los tasks pendientes."""
        with self._lock:
            if self._state is None:
                return []
            return [
                t
                for ps in self._state.phases.values()
                for t in ps.tasks
                if t.status == TaskStatus.PENDING
            ]

    def running_tasks(self) -> list[Task]:
        """Retorna todos los tasks corriendo."""
        with self._lock:
            if self._state is None:
                return []
            return [
                t
                for ps in self._state.phases.values()
                for t in ps.tasks
                if t.status == TaskStatus.RUNNING
            ]

    def tasks_by_phase(self, phase: Phase) -> list[Task]:
        """Retorna todos los tasks de una fase."""
        with self._lock:
            if self._state is None or phase not in self._state.phases:
                return []
            return list(self._state.phases[phase].tasks)

    def to_dict(self) -> dict[str, Any]:
        """Serializa el estado."""
        with self._lock:
            if self._state is None:
                return {}
            return self._state.to_dict()

    def snapshot(self) -> dict[str, Any]:
        """Snapshot para reproducibilidad forense."""
        with self._lock:
            ok, _ = self.verify_integrity()
            return {
                "state": self.to_dict(),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "path": str(self.path),
                "is_initialized": self.is_initialized,
                "chain_valid": ok,
            }

    def summary(self) -> dict[str, Any]:
        """Resumen ejecutivo del estado."""
        with self._lock:
            if self._state is None:
                return {"initialized": False}
            ok, _ = self.verify_integrity()
            return {
                "initialized": True,
                "engagement_id": str(self._state.engagement_id),
                "client_name": self._state.client_name,
                "status": self._state.status.value,
                "progress_pct": self._state.progress_pct,
                "total_tasks": self._state.total_tasks,
                "completed_tasks": self._state.completed_tasks,
                "failed_tasks": self._state.failed_tasks,
                "phases": len(self._state.phases),
                "findings": self._state.findings_count,
                "attack_chains": self._state.attack_chains_count,
                "transitions": len(self._state.transitions),
                "chain_valid": ok,
            }


__all__ = [
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
]
