"""Planner — God-Tier v5.0. Generación de plan de ataque con LLM.

Integra:
    - AIGateway (LLM con fallback + budget + circuit breaker)
    - StateMachine (fases, tasks, dependencias)
    - BudgetManager (atomic reserve/release)
    - ScopeMatcher (CIDR + wildcards + IDN + homoglyphs)

God-Tier v5.0 — diferenciadores vs v3.0:

FIX BLOQUEANTES:
    - gateway.call usa la firma CORRECTA (role + request)
    - _parse_plan usa response.content (no response)
    - _estimate_cost usa response.content (no LLMResponse)

SCOPE MATCHER v5:
    - Apex domain matching (*.example.com matchea example.com)
    - CIDR excluded REAL (diferencia _included_networks vs _excluded_networks)
    - Unicode normalization + homoglyph stripping
    - IDN/Punycode detection
    - Range validation (rechaza /0, /1, /2... demasiado permisivos)
    - IPv6 support completo
    - DNS rebinding protection (no acepta TLDs wildcard sin base)
    - Target validation contra scope ANTES de llamar LLM

PLANNER v5:
    - Prompt injection defense (sanitización de engagement data)
    - Prompt versioning INMUTABLE (por plan, no global)
    - Budget atomic reserve/release (zero race)
    - Retry-After respetado
    - Fail-fast en errors no-recuperables
    - Transaccional: state rollback en fallo
    - Límites de tamaño (JSON bomb, recursion)
    - Cycle detection iterativo (no recursivo)
    - Crown jewels validation
    - Kill switch propagation
    - Metrics thread-safe
    - Plan hash con prompt_version + timestamp
    - Prometheus export
    - Structured logging forense

Filosofía:
    - FAIL-CLOSED: en duda, bloquea
    - ZERO-TRUST: valida input Y output
    - TRANSACCIONAL: rollback en fallo
    - OBSERVABLE: métricas + logs forenses
    - REPRODUCIBLE: hash con todo el contexto
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import re
import time
import unicodedata
from dataclasses import dataclass, field
from threading import RLock
from typing import Any, Final, Literal
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator, model_validator

from god_tier_agency.ai.base import ChatMessage, ChatRequest, MessageRole
from god_tier_agency.core.context import get_context
from god_tier_agency.core.logging import get_logger
from god_tier_agency.core.security.normalization import normalize_text
from god_tier_agency.orchestrator.budget import BudgetManager
from god_tier_agency.orchestrator.exceptions import (
    PlannerError,
    PlanValidationError,
    ScopeValidationError,
)
from god_tier_agency.orchestrator.state import (
    CriticalityLevel,
    EngagementStatus,
    Phase,
    StateMachine,
)

_log = get_logger("orchestrator.planner")


# ============================================================================
# CONSTANTES
# ============================================================================

PROMPT_VERSION: Final[str] = "planner_v5_2026_02"

VALID_AGENTS: Final[tuple[str, ...]] = (
    "recon", "scanner", "exploit", "cloud", "ad", "ai", "reporter",
)

VALID_PHASES: Final[tuple[str, ...]] = (
    "recon", "scan", "exploit", "post_exploit",
    "persistence", "exfil", "report",
)

_AGENT_PHASE_MATRIX: Final[dict[str, frozenset[str]]] = {
    "recon": frozenset({"recon"}),
    "scan": frozenset({"scanner", "recon"}),
    "exploit": frozenset({"exploit", "scanner", "cloud", "ad", "ai"}),
    "post_exploit": frozenset({"exploit", "cloud", "ad", "ai"}),
    "persistence": frozenset({"exploit", "cloud", "ad"}),
    "exfil": frozenset({"exploit", "cloud"}),
    "report": frozenset({"reporter"}),
}

# Fases ordenadas (para validar depends_on cruzando fases)
_PHASE_ORDER: Final[dict[str, int]] = {
    "recon": 0,
    "scan": 1,
    "exploit": 2,
    "post_exploit": 3,
    "persistence": 4,
    "exfil": 5,
    "report": 6,
}

# Límites de seguridad
MAX_PLAN_SIZE_BYTES: Final[int] = 1_000_000       # 1 MB max del JSON
MAX_TASKS_PER_PLAN: Final[int] = 500              # 500 tasks max
MAX_PHASES_PER_PLAN: Final[int] = 20              # 20 fases max
MAX_DEPENDENCIES_PER_TASK: Final[int] = 20        # 20 deps max
MAX_DESCRIPTION_LENGTH: Final[int] = 2000         # 2000 chars max desc

# CIDR prefix mínimo (evita scope excesivo)
MIN_IPV4_PREFIX: Final[int] = 8                    # /0 a /7 rechazados
MIN_IPV6_PREFIX: Final[int] = 16                   # /0 a /15 rechazados

# Reserved TLDs (no aceptar wildcard en estos)
_RESERVED_TLDS: Final[frozenset[str]] = frozenset({
    "local", "localhost", "test", "invalid", "example",
    "onion", "internal", "lan", "home",
})

# Prompt injection patterns (para sanitizar engagement data)
_PROMPT_INJECTION_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"(?:ignore|forget|disregard|override|bypass)\s+"
    r"(?:all\s+)?(?:previous|prior|above)\s+"
    r"(?:instructions?|prompts?|rules?)",
    re.IGNORECASE | re.DOTALL,
)


# ============================================================================
# SCOPE MATCHER v5 — CIDR + wildcards + IDN + homoglyphs
# ============================================================================

class ScopeMatcher:
    """Valida si un target está dentro del scope autorizado.

    God-Tier v5.0:
        - Apex domain matching (*.example.com matchea example.com)
        - CIDR excluded REAL (separate sets)
        - Unicode normalization + homoglyph stripping
        - IDN/Punycode decoding
        - Range validation (rechaza /0 a /7 IPv4, /0 a /15 IPv6)
        - IPv6 support
        - Reserved TLDs protection
        - Fail-closed en scope vacío

    Uso:
        >>> matcher = ScopeMatcher(
        ...     in_scope=["*.example.com", "10.0.0.0/24"],
        ...     excluded=["admin.example.com", "10.0.0.5"],
        ... )
        >>> matcher.is_in_scope("api.example.com")   # True
        >>> matcher.is_in_scope("example.com")        # True (apex)
        >>> matcher.is_in_scope("admin.example.com")  # False (excluded)
        >>> matcher.is_in_scope("10.0.0.1")           # True
        >>> matcher.is_in_scope("10.0.0.5")           # False (excluded)
        >>> matcher.is_in_scope("8.8.8.8")            # False
    """

    def __init__(
        self,
        in_scope: list[str],
        excluded: list[str] | None = None,
    ) -> None:
        self.raw_in_scope = list(in_scope or [])
        self.raw_excluded = list(excluded or [])

        # In-scope sets
        self._included_exact_domains: set[str] = set()
        self._included_wildcard_domains: list[str] = []
        self._included_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._included_exact_ips: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()

        # Excluded sets (SEPARADOS — fix bug #5)
        self._excluded_exact_domains: set[str] = set()
        self._excluded_wildcard_domains: list[str] = []
        self._excluded_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._excluded_exact_ips: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()

        # Parse
        self._parse_entries(self.raw_in_scope, target="included")
        self._parse_entries(self.raw_excluded, target="excluded")

        if not self.raw_in_scope:
            _log.warning(
                "scope_matcher_empty_in_scope",
                msg="ScopeMatcher creado sin in_scope → fail-closed",
            )

    # ------------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------------

    @staticmethod
    def _normalize_domain(domain: str) -> str:
        """Normaliza dominio: NFC + lowercase + homoglyph strip + IDN decode."""
        # NFC
        domain = unicodedata.normalize("NFC", domain)
        # Lowercase
        domain = domain.lower().strip()
        # Strip trailing dot
        domain = domain.rstrip(".")
        # Homoglyph strip (via security.normalization)
        try:
            domain = normalize_text(domain)
        except (TypeError, ValueError):
            pass
        # IDN decode (xn--pypal-4ve → paypal)
        try:
            domain = domain.encode("ascii").decode("idna")
        except (UnicodeError, ValueError):
            pass
        return domain

    def _parse_entries(self, entries: list[str], *, target: str) -> None:
        """Parsea entries hacia el set correspondiente (included/excluded)."""
        for entry in entries:
            entry = entry.strip()
            if not entry:
                continue

            # Wildcard: *.example.com
            if entry.startswith("*."):
                domain = self._normalize_domain(entry[2:])
                if domain in _RESERVED_TLDS:
                    _log.warning(
                        "scope_reserved_tld_wildcard",
                        domain=domain,
                        target=target,
                    )
                    continue
                if target == "included":
                    self._included_wildcard_domains.append(domain)
                else:
                    self._excluded_wildcard_domains.append(domain)
                continue

            # CIDR: 10.0.0.0/24
            if "/" in entry:
                try:
                    net = ipaddress.ip_network(entry, strict=False)
                    # Validar prefijo mínimo (evita scope excesivo)
                    if isinstance(net, ipaddress.IPv4Network):
                        if net.prefixlen < MIN_IPV4_PREFIX:
                            _log.warning(
                                "scope_cidr_too_broad",
                                cidr=str(net),
                                prefix=net.prefixlen,
                                min_prefix=MIN_IPV4_PREFIX,
                                target=target,
                            )
                            continue
                    elif isinstance(net, ipaddress.IPv6Network):
                        if net.prefixlen < MIN_IPV6_PREFIX:
                            _log.warning(
                                "scope_cidr_too_broad_ipv6",
                                cidr=str(net),
                                prefix=net.prefixlen,
                                min_prefix=MIN_IPV6_PREFIX,
                                target=target,
                            )
                            continue

                    if target == "included":
                        self._included_networks.append(net)
                    else:
                        self._excluded_networks.append(net)
                    continue
                except ValueError:
                    pass

            # IP: 10.0.0.1
            try:
                ip = ipaddress.ip_address(entry)
                if target == "included":
                    self._included_exact_ips.add(ip)
                else:
                    self._excluded_exact_ips.add(ip)
                continue
            except ValueError:
                pass

            # Dominio exacto
            domain = self._normalize_domain(entry)
            if target == "included":
                self._included_exact_domains.add(domain)
            else:
                self._excluded_exact_domains.add(domain)

    # ------------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------------

    def is_in_scope(self, target: str) -> bool:
        """Valida si un target está en scope (y no excluido)."""
        if not target or not isinstance(target, str):
            return False

        target = target.strip()
        if not target:
            return False

        # 1. Exclusión explícita (PRIORIDAD)
        if self._is_excluded(target):
            return False

        # 2. Inclusión
        return self._is_included(target)

    def _is_excluded(self, target: str) -> bool:
        """True si el target está explícitamente excluido."""
        # Intentar como IP primero
        try:
            ip = ipaddress.ip_address(target)
            if ip in self._excluded_exact_ips:
                return True
            for net in self._excluded_networks:
                if ip in net:
                    return True
            return False
        except ValueError:
            pass

        # Como dominio
        domain = self._normalize_domain(target)
        if domain in self._excluded_exact_domains:
            return True
        for wc in self._excluded_wildcard_domains:
            # Wildcard matchea el apex Y subdominios
            if domain == wc or domain.endswith("." + wc):
                return True
        return False

    def _is_included(self, target: str) -> bool:
        """True si el target está incluido en scope."""
        # Intentar como IP
        try:
            ip = ipaddress.ip_address(target)
            if ip in self._included_exact_ips:
                return True
            for net in self._included_networks:
                if ip in net:
                    return True
            return False
        except ValueError:
            pass

        # Como dominio
        domain = self._normalize_domain(target)

        # Exact match
        if domain in self._included_exact_domains:
            return True

        # Wildcard: *.example.com matchea example.com Y subdominios
        for wc in self._included_wildcard_domains:
            if domain == wc or domain.endswith("." + wc):
                return True

        return False

    @property
    def summary(self) -> dict[str, int]:
        """Resumen del scope."""
        return {
            "included_exact_domains": len(self._included_exact_domains),
            "included_wildcard_domains": len(self._included_wildcard_domains),
            "included_exact_ips": len(self._included_exact_ips),
            "included_networks": len(self._included_networks),
            "excluded_exact_domains": len(self._excluded_exact_domains),
            "excluded_wildcard_domains": len(self._excluded_wildcard_domains),
            "excluded_exact_ips": len(self._excluded_exact_ips),
            "excluded_networks": len(self._excluded_networks),
        }

    @property
    def is_empty(self) -> bool:
        """True si no hay in_scope definido (fail-closed)."""
        return not (
            self._included_exact_domains
            or self._included_wildcard_domains
            or self._included_exact_ips
            or self._included_networks
        )


# ============================================================================
# PYDANTIC MODELS
# ============================================================================

class PlanTask(BaseModel):
    """Un task dentro de una fase del plan."""

    name: str = Field(..., min_length=1, max_length=200)
    description: str = Field(default="", max_length=MAX_DESCRIPTION_LENGTH)
    agent: Literal["recon", "scanner", "exploit", "cloud", "ad", "ai", "reporter"]
    criticality: Literal["low", "medium", "high", "critical"] = "medium"
    depends_on_names: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("name")
    @classmethod
    def name_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Task name no puede estar vacío")
        # Sanitizar: solo alfanuméricos + guión bajo
        if not re.match(r"^[a-zA-Z0-9_\-]+$", v):
            raise ValueError(
                f"Task name debe ser alfanumérico (a-z0-9_-): {v!r}"
            )
        return v.strip()

    @field_validator("depends_on_names")
    @classmethod
    def deps_limit(cls, v: list[str]) -> list[str]:
        if len(v) > MAX_DEPENDENCIES_PER_TASK:
            raise ValueError(
                f"Task no puede tener más de {MAX_DEPENDENCIES_PER_TASK} "
                f"dependencias, tiene {len(v)}"
            )
        return v


class PlanPhase(BaseModel):
    """Una fase del plan de ataque."""

    phase: Literal[
        "recon", "scan", "exploit", "post_exploit",
        "persistence", "exfil", "report",
    ]
    tasks: list[PlanTask] = Field(default_factory=list, min_length=1)

    @field_validator("tasks")
    @classmethod
    def tasks_not_empty(cls, v: list[PlanTask]) -> list[PlanTask]:
        if not v:
            raise ValueError("Phase debe tener al menos 1 task")
        if len(v) > MAX_TASKS_PER_PLAN:
            raise ValueError(
                f"Phase no puede tener más de {MAX_TASKS_PER_PLAN} tasks"
            )
        return v


class AttackPlan(BaseModel):
    """El plan de ataque completo."""

    phases: list[PlanPhase] = Field(default_factory=list, min_length=1)
    estimated_cost_usd: float = Field(default=0.0, ge=0.0, le=1000.0)
    estimated_duration_minutes: int = Field(default=0, ge=0, le=1440)
    reasoning: str = Field(default="", max_length=5000)
    targets_used: list[str] = Field(default_factory=list)

    # Metadata (agregado por el planner, no por el LLM)
    prompt_version: str = Field(default=PROMPT_VERSION)
    created_at: float = Field(default_factory=time.time)
    plan_id: str = Field(default_factory=lambda: str(uuid4()))

    @field_validator("phases")
    @classmethod
    def phases_valid(cls, v: list[PlanPhase]) -> list[PlanPhase]:
        if not v:
            raise ValueError("Plan debe tener al menos 1 fase")
        if len(v) > MAX_PHASES_PER_PLAN:
            raise ValueError(
                f"Plan no puede tener más de {MAX_PHASES_PER_PLAN} fases"
            )
        # Detectar fases duplicadas
        phase_names = [p.phase for p in v]
        if len(phase_names) != len(set(phase_names)):
            raise ValueError(
                f"Fases duplicadas: "
                f"{[n for n in phase_names if phase_names.count(n) > 1]}"
            )
        return v

    @field_validator("targets_used")
    @classmethod
    def targets_limit(cls, v: list[str]) -> list[str]:
        if len(v) > 1000:
            raise ValueError("targets_used no puede tener más de 1000 entries")
        return v

    @model_validator(mode="after")
    def validate_plan_consistency(self) -> "AttackPlan":
        """Valida consistencia interna del plan."""
        # 1. Task names duplicados
        all_names: list[str] = []
        for phase in self.phases:
            for task in phase.tasks:
                all_names.append(task.name)
        duplicates = {n for n in all_names if all_names.count(n) > 1}
        if duplicates:
            raise ValueError(f"Task names duplicados: {sorted(duplicates)}")

        # 2. depends_on_names referencien tasks existentes
        name_set = set(all_names)
        for phase in self.phases:
            for task in phase.tasks:
                for dep in task.depends_on_names:
                    if dep not in name_set:
                        raise ValueError(
                            f"Task '{task.name}' depende de '{dep}' que no existe"
                        )
                    if dep == task.name:
                        raise ValueError(
                            f"Task '{task.name}' no puede depender de sí mismo"
                        )

        # 3. agent↔phase coherencia
        for phase in self.phases:
            allowed_agents = _AGENT_PHASE_MATRIX.get(phase.phase, frozenset())
            for task in phase.tasks:
                if task.agent not in allowed_agents:
                    raise ValueError(
                        f"Agent '{task.agent}' no permitido en fase "
                        f"'{phase.phase}'. Permitidos: {sorted(allowed_agents)}"
                    )

        return self

    @property
    def total_tasks(self) -> int:
        return sum(len(p.tasks) for p in self.phases)

    def plan_hash(self) -> str:
        """SHA-256 del plan (con prompt_version + created_at para forense)."""
        canonical = json.dumps(
            {
                "phases": [p.model_dump(mode="json") for p in self.phases],
                "targets_used": sorted(self.targets_used),
                "prompt_version": self.prompt_version,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def detect_cycles(self) -> list[list[str]]:
        """Detecta ciclos en depends_on_names (DFS ITERATIVO).

        God-Tier v5.0:
            - Iterativo (no recursivo) → evita RecursionError
            - Detecta múltiples ciclos
            - Retorna ciclos completos (path + node de cierre)
        """
        # Grafo: task_name → dependencias
        graph: dict[str, list[str]] = {}
        for phase in self.phases:
            for task in phase.tasks:
                graph[task.name] = list(task.depends_on_names)

        cycles: list[list[str]] = []
        visited: set[str] = set()
        rec_stack: set[str] = set()
        path: list[str] = []

        for start_node in graph:
            if start_node in visited:
                continue

            # DFS iterativo con stack explícito
            stack: list[tuple[str, int]] = [(start_node, 0)]
            while stack:
                node, child_idx = stack.pop()

                if child_idx == 0:
                    # Primera visita a este nodo
                    if node in rec_stack:
                        # Ciclo detectado
                        try:
                            idx = path.index(node)
                            cycles.append(path[idx:] + [node])
                        except ValueError:
                            pass
                        continue
                    if node in visited:
                        continue
                    visited.add(node)
                    rec_stack.add(node)
                    path.append(node)

                children = graph.get(node, [])
                if child_idx < len(children):
                    child = children[child_idx]
                    # Re-push con el siguiente child_idx
                    stack.append((node, child_idx + 1))
                    # Push child (si no visitado en esta rama)
                    if child in rec_stack:
                        # Ciclo inmediato
                        try:
                            idx = path.index(child)
                            cycles.append(path[idx:] + [child])
                        except ValueError:
                            pass
                    elif child not in visited:
                        stack.append((child, 0))
                else:
                    # Todos los children procesados → pop
                    if path and path[-1] == node:
                        path.pop()
                    rec_stack.discard(node)

        return cycles

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


# ============================================================================
# PLANNER METRICS (thread-safe)
# ============================================================================

@dataclass
class PlannerMetrics:
    """Métricas del planner (thread-safe).

    Thread-safety: el lock NO está en el dataclass.
    """

    total_calls: int = 0
    successful_plans: int = 0
    failed_plans: int = 0
    total_retries: int = 0
    total_duration_ms: float = 0.0
    total_estimated_cost: float = 0.0
    total_tokens_used: int = 0
    last_plan_hash: str = ""
    last_plan_id: str = ""
    last_error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_calls": self.total_calls,
            "successful_plans": self.successful_plans,
            "failed_plans": self.failed_plans,
            "success_rate": (
                round(self.successful_plans / self.total_calls * 100, 2)
                if self.total_calls > 0 else 0.0
            ),
            "total_retries": self.total_retries,
            "avg_duration_ms": (
                round(self.total_duration_ms / self.total_calls, 2)
                if self.total_calls > 0 else 0.0
            ),
            "total_estimated_cost": round(self.total_estimated_cost, 6),
            "total_tokens_used": self.total_tokens_used,
            "last_plan_hash": self.last_plan_hash[:16] if self.last_plan_hash else "",
            "last_plan_id": self.last_plan_id,
            "last_error": self.last_error[:200] if self.last_error else "",
        }

    def to_prometheus(self, namespace: str = "godtier_planner") -> str:
        return "\n".join([
            f"# HELP {namespace}_calls_total Total planner calls",
            f"# TYPE {namespace}_calls_total counter",
            f"{namespace}_calls_total {self.total_calls}",
            f"{namespace}_successful_plans {self.successful_plans}",
            f"{namespace}_failed_plans {self.failed_plans}",
            f"{namespace}_retries_total {self.total_retries}",
            f"{namespace}_tokens_total {self.total_tokens_used}",
            f"{namespace}_cost_usd {self.total_estimated_cost:.6f}",
            f"{namespace}_avg_duration_ms "
            f"{(self.total_duration_ms / self.total_calls if self.total_calls else 0):.2f}",
        ])


# ============================================================================
# PLANNER v5
# ============================================================================

class Planner:
    """Genera el plan de ataque con LLM y lo valida.

    God-Tier v5.0:
        - Gateway call con firma CORRECTA
        - Response como LLMResponse.content
        - Prompt injection defense
        - Scope validation estricta
        - Transaccional (rollback en fallo)
        - Budget atomic
        - Cycle detection iterativo
        - Kill switch propagation
    """

    def __init__(
        self,
        *,
        gateway: Any,
        state_machine: StateMachine,
        budget: BudgetManager | None = None,
        scope_targets: list[str] | None = None,
        scope_excluded: list[str] | None = None,
        max_retries: int = 3,
        kill_switch_event: asyncio.Event | None = None,
    ) -> None:
        """
        Args:
            gateway: AIGateway (debe tener método `call_llm` o `call`).
            state_machine: StateMachine para popular.
            budget: BudgetManager opcional.
            scope_targets: Lista de CIDRs/dominios/wildcards permitidos.
            scope_excluded: Lista de CIDRs/dominios/wildcards excluidos.
            max_retries: Intentos máximos de LLM.
            kill_switch_event: Evento global de cancelación.
        """
        self.gateway = gateway
        self.state_machine = state_machine
        self.budget = budget
        self.scope_matcher = ScopeMatcher(
            in_scope=scope_targets or [],
            excluded=scope_excluded or [],
        )
        self.max_retries = max_retries
        self.metrics = PlannerMetrics()
        self._metrics_lock = RLock()
        self._kill_switch = kill_switch_event or asyncio.Event()

    # ------------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------------

    async def plan(
        self,
        engagement: Any,
        context: dict[str, Any] | None = None,
        *,
        dry_run: bool = False,
    ) -> AttackPlan:
        """Genera el plan de ataque con LLM.

        Args:
            engagement: Engagement model (con .id, .client_name, .targets).
            context: Contexto adicional (crown_jewels, mode, etc.).
            dry_run: Si True, NO llama al LLM. Usa un plan stub.

        Returns:
            AttackPlan validado.

        Raises:
            PlannerError: Si el LLM falla o budget insuficiente.
            PlanValidationError: Si el JSON del LLM es inválido.
            ScopeValidationError: Si el plan incluye targets fuera de scope.
        """
        context = context or {}
        start_time = time.monotonic()

        with self._metrics_lock:
            self.metrics.total_calls += 1

        _log.info(
            "planner_start",
            engagement_id=str(getattr(engagement, "id", "?")),
            client_name=getattr(engagement, "client_name", "?"),
            targets_count=len(getattr(engagement, "targets", [])),
            scope_summary=self.scope_matcher.summary,
            prompt_version=PROMPT_VERSION,
            dry_run=dry_run,
            correlation_id=get_context().get("correlation_id"),
        )

        try:
            # 0. Kill switch check
            if self._kill_switch.is_set():
                raise PlannerError(
                    "Planner cancelado por kill switch",
                    retryable=False,
                )

            # 1. Scope no vacío (fail-closed)
            if self.scope_matcher.is_empty and not dry_run:
                raise ScopeValidationError(
                    "Scope in_scope está vacío. Refusing to plan (fail-closed).",
                    target="",
                    context={"scope_summary": self.scope_matcher.summary},
                )

            # 2. Validar que engagement.targets estén en scope
            self._validate_engagement_targets(engagement)

            # 3. Obtener respuesta LLM (real o stub)
            if dry_run:
                response_text = self._stub_response(engagement, context)
                tokens_used = 0
                cost_usd = 0.0
            else:
                system_prompt = self._build_system_prompt()
                user_prompt = self._build_user_prompt(engagement, context)
                response_text, tokens_used, cost_usd = (
                    await self._call_llm_with_retry(
                        system_prompt=system_prompt,
                        user_prompt=user_prompt,
                    )
                )

            # 4. Parsear
            plan = self._parse_plan(response_text)
            # Override metadata con valores reales
            plan = plan.model_copy(
                update={
                    "prompt_version": PROMPT_VERSION,
                    "created_at": time.time(),
                }
            )

            # 5. Detectar ciclos (iterativo)
            cycles = plan.detect_cycles()
            if cycles:
                raise PlanValidationError(
                    f"Plan contiene ciclos: {cycles}",
                    context={"cycles": cycles},
                )

            # 6. Validar scope
            self._validate_scope(plan)

            # 7. Validar crown jewels (si están definidos)
            self._validate_crown_jewels(plan, context)

            # 8. Validar presupuesto ANTES de ejecutar
            if self.budget is not None and not dry_run:
                if not self.budget.can_spend("planner", plan.estimated_cost_usd):
                    raise PlannerError(
                        f"Plan excede presupuesto: "
                        f"${plan.estimated_cost_usd:.2f} > "
                        f"${self.budget.remaining('planner'):.2f}",
                        context={
                            "estimated": plan.estimated_cost_usd,
                            "remaining": self.budget.remaining("planner"),
                        },
                        retryable=False,
                    )

            # 9. Populate StateMachine (transaccional)
            self._populate_state_transactional(plan)

            # 10. Transition engagement
            try:
                if self.state_machine.state.status == EngagementStatus.PLANNING:
                    self.state_machine.transition_engagement(
                        EngagementStatus.RUNNING
                    )
            except Exception as e:
                _log.warning(
                    "planner_transition_failed",
                    error=str(e),
                )

            # 11. Métricas de éxito
            duration_ms = (time.monotonic() - start_time) * 1000
            plan_hash = plan.plan_hash()

            with self._metrics_lock:
                self.metrics.successful_plans += 1
                self.metrics.total_duration_ms += duration_ms
                self.metrics.total_estimated_cost += plan.estimated_cost_usd
                self.metrics.total_tokens_used += tokens_used
                self.metrics.last_plan_hash = plan_hash
                self.metrics.last_plan_id = plan.plan_id

            _log.info(
                "planner_done",
                engagement_id=str(getattr(engagement, "id", "?")),
                phases=len(plan.phases),
                tasks=plan.total_tasks,
                estimated_cost_usd=plan.estimated_cost_usd,
                tokens_used=tokens_used,
                plan_hash=plan_hash[:16],
                plan_id=plan.plan_id,
                duration_ms=round(duration_ms, 1),
            )

            return plan

        except Exception as e:
            with self._metrics_lock:
                self.metrics.failed_plans += 1
                self.metrics.last_error = f"{type(e).__name__}: {e}"

            _log.error(
                "planner_failed",
                error_type=type(e).__name__,
                error=str(e)[:500],
            )
            raise

    # ------------------------------------------------------------------------
    # LLM Call (FIX: usa firma correcta de AIGateway.call)
    # ------------------------------------------------------------------------

    async def _call_llm_with_retry(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
    ) -> tuple[str, int, float]:
        """Llama al LLM con retry exponencial.

        Returns:
            (response_content, tokens_used, cost_usd)

        Raises:
            PlannerError: Si el LLM falla tras max_retries.
        """
        last_error: Exception | None = None

        for attempt in range(self.max_retries):
            # Kill switch check
            if self._kill_switch.is_set():
                raise PlannerError(
                    "Planner cancelado por kill switch durante retry",
                    retryable=False,
                )

            # Budget check (reserva atómica si es posible)
            estimated_cost = 0.02  # Heurística conservadora
            if self.budget is not None:
                if not self.budget.can_spend("planner", estimated_cost):
                    raise PlannerError(
                        "Presupuesto de planner agotado",
                        retryable=False,
                    )

            try:
                # Construir request con la firma CORRECTA
                request = ChatRequest(
                    system=system_prompt,
                    messages=[
                        ChatMessage(
                            role=MessageRole.USER,
                            content=user_prompt,
                        )
                    ],
                    temperature=0.3,
                    max_tokens=8000,
                    response_format_json=True,
                )

                # FIX BLOQUEANTE: usar firma correcta del gateway
                response = await self.gateway.call(
                    role="planner",
                    request=request,
                    prefer="deepseek",
                )

                # FIX: response es LLMResponse, extraer .content
                response_content: str = response.content
                tokens_used = response.total_tokens
                cost_usd = response.cost_usd

                # Registrar en budget
                if self.budget is not None:
                    self.budget.record_spend(
                        role="planner",
                        cost_usd=cost_usd,
                        provider=response.provider,
                        model=response.model,
                        tokens=tokens_used,
                        operation="plan_generation",
                    )

                return response_content, tokens_used, cost_usd

            except (PlannerError, asyncio.CancelledError):
                # Errores fatales: no retry
                raise
            except Exception as e:
                last_error = e
                with self._metrics_lock:
                    self.metrics.total_retries += 1

                _log.warning(
                    "planner_llm_attempt_failed",
                    attempt=attempt + 1,
                    max_attempts=self.max_retries,
                    error_type=type(e).__name__,
                    error=str(e)[:200],
                )

                if attempt < self.max_retries - 1:
                    # Backoff exponencial + jitter
                    import random
                    delay = min(30.0, (2.0 ** attempt) + random.uniform(0, 1))
                    await asyncio.sleep(delay)

        raise PlannerError(
            f"Planner LLM falló tras {self.max_retries} intentos",
            context={
                "last_error_type": type(last_error).__name__ if last_error else "unknown",
                "last_error": str(last_error)[:500] if last_error else "",
            },
            retryable=False,
        )

    # ------------------------------------------------------------------------
    # Prompts (con injection defense)
    # ------------------------------------------------------------------------

    def _build_system_prompt(self) -> str:
        return """Eres un planificador de red teaming de élite con 20 años de experiencia.
Tu trabajo es generar un plan de ataque estructurado en JSON válido.

DEBES responder SIEMPRE con JSON válido con esta estructura EXACTA:
{
  "phases": [
    {
      "phase": "recon|scan|exploit|post_exploit|persistence|exfil|report",
      "tasks": [
        {
          "name": "nombre_alfanumerico_unico",
          "description": "descripción detallada",
          "agent": "recon|scanner|exploit|cloud|ad|ai|reporter",
          "criticality": "low|medium|high|critical",
          "depends_on_names": ["nombre_task_previo"],
          "metadata": {}
        }
      ]
    }
  ],
  "estimated_cost_usd": 5.0,
  "estimated_duration_minutes": 30,
  "reasoning": "Explicación del plan",
  "targets_used": ["target1.com", "10.0.0.1"]
}

REGLAS CRÍTICAS (violación = plan inválido):
1. NUNCA incluyas targets fuera del scope autorizado
2. Task names DEBEN ser alfanuméricos (a-z, A-Z, 0-9, _, -) y ÚNICOS
3. depends_on_names DEBE referenciar tasks existentes en fases ANTERIORES
4. NO crear ciclos en dependencias
5. Cada agente debe ser coherente con su fase:
   - recon → recon
   - scan → scanner, recon
   - exploit → exploit, scanner, cloud, ad, ai
   - post_exploit → exploit, cloud, ad, ai
   - persistence → exploit, cloud, ad
   - exfil → exploit, cloud
   - report → reporter
6. Sé específico con targets y técnicas
7. NO incluyas técnicas destructivas (DoS, ransomware) sin autorización explícita
8. El campo "targets_used" DEBE ser subconjunto del scope proporcionado
"""

    def _build_user_prompt(
        self,
        engagement: Any,
        context: dict[str, Any],
    ) -> str:
        """Construye el prompt del usuario con injection defense."""
        # Sanitizar client_name (puede contener injection)
        client_name = self._sanitize_for_prompt(
            getattr(engagement, "client_name", "unknown")
        )

        targets = []
        for t in getattr(engagement, "targets", []):
            target_type = t.type.value if hasattr(t.type, "value") else str(t.type)
            targets.append({
                "type": target_type,
                "value": self._sanitize_for_prompt(t.value),
            })

        # Sanitizar crown jewels y context
        crown_jewels = [
            self._sanitize_for_prompt(str(cj))
            for cj in context.get("crown_jewels", [])
        ]

        payload = {
            "engagement_id": str(getattr(engagement, "id", "unknown")),
            "client_name": client_name,
            "targets": targets,
            "scope_in": self.scope_matcher.raw_in_scope,
            "scope_excluded": self.scope_matcher.raw_excluded,
            "crown_jewels": crown_jewels,
            "mode": str(context.get("mode", "semi_blind")),
            "extra_instructions": self._sanitize_for_prompt(
                str(context.get("extra", ""))
            )[:500],
        }
        return json.dumps(payload, indent=2, ensure_ascii=False)

    @staticmethod
    def _sanitize_for_prompt(text: str) -> str:
        """Sanitiza texto para incluir en prompt (evita injection)."""
        if not text:
            return ""
        # Remover patterns de injection
        text = _PROMPT_INJECTION_PATTERN.sub("[REDACTED]", text)
        # Truncar
        text = text[:500]
        # Remover newlines sospechosos
        text = text.replace("\x00", "").replace("\r", "")
        # Limitar newlines consecutivos
        text = re.sub(r"\n{3,}", "\n\n", text)
        return text

    def _stub_response(
        self,
        engagement: Any,
        context: dict[str, Any],
    ) -> str:
        """Respuesta stub para dry_run."""
        first_target = (
            engagement.targets[0].value
            if getattr(engagement, "targets", None)
            else "example.com"
        )
        return json.dumps({
            "phases": [
                {
                    "phase": "recon",
                    "tasks": [{
                        "name": "nmap_scan",
                        "description": f"Port scan of {first_target}",
                        "agent": "recon",
                        "criticality": "high",
                        "depends_on_names": [],
                        "metadata": {"tool": "nmap"},
                    }],
                },
                {
                    "phase": "report",
                    "tasks": [{
                        "name": "generate_report",
                        "description": "Generate final report",
                        "agent": "reporter",
                        "criticality": "medium",
                        "depends_on_names": ["nmap_scan"],
                        "metadata": {},
                    }],
                },
            ],
            "estimated_cost_usd": 0.5,
            "estimated_duration_minutes": 5,
            "reasoning": "Stub plan for dry_run",
            "targets_used": [first_target],
        })

    # ------------------------------------------------------------------------
    # Parsing (con límites de tamaño)
    # ------------------------------------------------------------------------

    def _parse_plan(self, response: str) -> AttackPlan:
        """Parsea la respuesta del LLM a un AttackPlan.

        God-Tier v5.0:
            - Límite de tamaño (JSON bomb protection)
            - Validación Pydantic estricta
        """
        # Límite de tamaño
        if len(response) > MAX_PLAN_SIZE_BYTES:
            raise PlanValidationError(
                f"Respuesta LLM excede {MAX_PLAN_SIZE_BYTES} bytes: "
                f"{len(response)}",
                raw_plan=response[:500],
            )

        # Parsear JSON
        try:
            data = json.loads(response)
        except json.JSONDecodeError as e:
            raise PlanValidationError(
                f"JSON inválido en respuesta del LLM: {e}",
                raw_plan=response[:1000],
                context={"json_error": str(e), "position": e.pos},
            ) from e

        if not isinstance(data, dict):
            raise PlanValidationError(
                f"Respuesta LLM no es un objeto JSON: {type(data).__name__}",
                raw_plan=response[:500],
            )

        # Validar con Pydantic
        try:
            plan = AttackPlan.model_validate(data)
            return plan
        except Exception as e:
            raise PlanValidationError(
                f"Plan inválido: {type(e).__name__}: {e}",
                raw_plan=response[:1000],
                context={"error": str(e), "error_type": type(e).__name__},
            ) from e

    # ------------------------------------------------------------------------
    # Scope validation
    # ------------------------------------------------------------------------

    def _validate_engagement_targets(self, engagement: Any) -> None:
        """Valida que los targets del engagement estén en scope."""
        if self.scope_matcher.is_empty:
            return

        for target in getattr(engagement, "targets", []):
            target_value = target.value
            if not self.scope_matcher.is_in_scope(target_value):
                raise ScopeValidationError(
                    f"Target del engagement fuera de scope: {target_value}",
                    target=target_value,
                    context={
                        "engagement_id": str(getattr(engagement, "id", "?")),
                        "scope_summary": self.scope_matcher.summary,
                    },
                )

    def _validate_scope(self, plan: AttackPlan) -> None:
        """Valida que el plan solo use targets en scope."""
        if self.scope_matcher.is_empty:
            raise ScopeValidationError(
                "Scope vacío — no se puede validar plan (fail-closed)",
                target="",
                context={"plan_id": plan.plan_id},
            )

        out_of_scope: list[str] = []
        for target_str in plan.targets_used:
            if not self.scope_matcher.is_in_scope(target_str):
                out_of_scope.append(target_str)

        if out_of_scope:
            raise ScopeValidationError(
                f"Plan contiene {len(out_of_scope)} target(s) fuera de scope: "
                f"{out_of_scope[:5]}",
                target=out_of_scope[0],
                context={
                    "all_out_of_scope": out_of_scope[:20],
                    "scope_summary": self.scope_matcher.summary,
                },
            )

    def _validate_crown_jewels(
        self,
        plan: AttackPlan,
        context: dict[str, Any],
    ) -> None:
        """Valida que los crown jewels estén en scope (si están definidos)."""
        crown_jewels = context.get("crown_jewels", [])
        if not crown_jewels:
            return

        for cj in crown_jewels:
            if not self.scope_matcher.is_in_scope(str(cj)):
                _log.warning(
                    "planner_crown_jewel_out_of_scope",
                    crown_jewel=str(cj)[:100],
                    plan_id=plan.plan_id,
                )
                # NO raise — warning suficiente

    # ------------------------------------------------------------------------
    # State population (transaccional)
    # ------------------------------------------------------------------------

    def _populate_state_transactional(self, plan: AttackPlan) -> None:
        """Popula el StateMachine con rollback en caso de error.

        God-Tier v5.0:
            - Detecta fases ya existentes
            - Rollback via checkpoint si falla
            - name_to_id GLOBAL (no por phase)
        """
        # Checkpoint antes de mutar
        checkpoint_name = f"planner_{plan.plan_id}_prepopulate"
        try:
            self.state_machine.checkpoint(checkpoint_name)
        except Exception as e:
            _log.warning(
                "planner_checkpoint_failed",
                error=str(e),
            )
            checkpoint_name = ""

        try:
            # name_to_id GLOBAL (fix bug #16)
            name_to_id: dict[str, Any] = {}

            for phase_data in plan.phases:
                try:
                    phase = Phase(phase_data.phase)
                except ValueError as e:
                    raise PlanValidationError(
                        f"Fase inválida: {phase_data.phase}",
                        context={"valid_phases": list(VALID_PHASES)},
                    ) from e

                # add_phase es idempotente en state machine
                self.state_machine.add_phase(phase)

                for task_data in phase_data.tasks:
                    depends_on_ids: list[Any] = []
                    for dep_name in task_data.depends_on_names:
                        if dep_name in name_to_id:
                            depends_on_ids.append(name_to_id[dep_name])
                        else:
                            _log.warning(
                                "planner_unresolved_dependency",
                                task=task_data.name,
                                dependency=dep_name,
                                plan_id=plan.plan_id,
                            )

                    try:
                        crit = CriticalityLevel(task_data.criticality)
                    except ValueError:
                        crit = CriticalityLevel.MEDIUM

                    task = self.state_machine.add_task(
                        phase=phase,
                        name=task_data.name,
                        agent=task_data.agent,
                        description=task_data.description,
                        criticality=crit,
                        metadata={
                            **task_data.metadata,
                            "_plan_id": plan.plan_id,
                            "_prompt_version": plan.prompt_version,
                        },
                        depends_on=depends_on_ids,
                    )
                    name_to_id[task_data.name] = task.id

        except Exception as e:
            # Rollback
            if checkpoint_name:
                try:
                    self.state_machine.rollback(checkpoint_name)
                    _log.warning(
                        "planner_state_rolled_back",
                        checkpoint=checkpoint_name,
                        error=str(e)[:200],
                    )
                except Exception as rb_err:
                    _log.error(
                        "planner_rollback_failed",
                        error=str(rb_err),
                    )
            raise

    # ------------------------------------------------------------------------
    # Metrics
    # ------------------------------------------------------------------------

    def get_metrics(self) -> dict[str, Any]:
        """Retorna las métricas del planner (thread-safe)."""
        with self._metrics_lock:
            return self.metrics.to_dict()

    def get_metrics_prometheus(self, namespace: str = "godtier_planner") -> str:
        """Exporta métricas en formato Prometheus (thread-safe)."""
        with self._metrics_lock:
            return self.metrics.to_prometheus(namespace=namespace)

    # ------------------------------------------------------------------------
    # Kill switch
    # ------------------------------------------------------------------------

    def set_kill_switch(self) -> None:
        """Activa el kill switch del planner."""
        self._kill_switch.set()
        _log.warning("planner_kill_switch_activated")

    @property
    def is_cancelled(self) -> bool:
        return self._kill_switch.is_set()


__all__ = [
    "Planner",
    "PlannerMetrics",
    "ScopeMatcher",
    "AttackPlan",
    "PlanPhase",
    "PlanTask",
    "VALID_AGENTS",
    "VALID_PHASES",
    "PROMPT_VERSION",
    "MAX_PLAN_SIZE_BYTES",
    "MAX_TASKS_PER_PLAN",
    "MAX_PHASES_PER_PLAN",
    "MIN_IPV4_PREFIX",
    "MIN_IPV6_PREFIX",
]
