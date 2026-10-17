"""Budget manager del orquestador — God-Tier v2.

Gestiona el presupuesto de un engagement con:
    - Presupuesto global + por rol
    - Alertas progresivas (80%, 90%, 95%)
    - Circuit breakers automáticos por rol agotado
    - Proyección de consumo basada en tasa
    - Thread-safe (RLock)
    - Persistencia (to_dict/from_dict)
    - Auditoría de cada gasto

Uso:
    >>> bm = BudgetManager(
    ...     engagement_id=uuid4(),
    ...     total_budget_usd=100.0,
    ...     role_limits={
    ...         "planner": 20.0,
    ...         "exploiter": 40.0,
    ...         "reporter": 10.0,
    ...     },
    ... )
    >>> if bm.can_spend("planner", estimated_cost=0.05):
    ...     # hacer llamada al LLM
    ...     bm.record_spend("planner", 0.05, "deepseek", "deepseek-chat", 1000, "plan")
    >>> bm.status()
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from threading import RLock
from typing import Any, Final
from uuid import UUID

from god_tier_agency.core.logging import get_logger
from god_tier_agency.orchestrator.exceptions import BudgetExceededError

_log = get_logger("orchestrator.budget")

# Umbrales de alertas (porcentaje de uso)
_ALERT_THRESHOLD_WARNING: Final[float] = 0.80  # 80%
_ALERT_THRESHOLD_HIGH: Final[float] = 0.90     # 90%
_ALERT_THRESHOLD_CRITICAL: Final[float] = 0.95  # 95%


# ============================================================================
# DATACLASSES
# ============================================================================
@dataclass(frozen=True)
class BudgetRecord:
    """Un gasto individual."""

    role: str
    provider: str
    model: str
    cost_usd: float
    tokens: int
    operation: str
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "provider": self.provider,
            "model": self.model,
            "cost_usd": round(self.cost_usd, 6),
            "tokens": self.tokens,
            "operation": self.operation,
            "timestamp": self.timestamp,
            "timestamp_iso": datetime.fromtimestamp(
                self.timestamp, tz=timezone.utc
            ).isoformat(),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "BudgetRecord":
        d = dict(d)
        d.pop("timestamp_iso", None)
        return cls(**d)


@dataclass
class RoleBudget:
    """Presupuesto de un rol específico."""

    role: str
    max_cost_usd: float
    spent_usd: float = 0.0
    calls: int = 0
    tokens: int = 0
    first_call_at: float | None = None
    last_call_at: float | None = None

    @property
    def remaining_usd(self) -> float:
        return max(0.0, self.max_cost_usd - self.spent_usd)

    @property
    def utilization(self) -> float:
        if self.max_cost_usd == 0:
            return 0.0
        return min(1.0, self.spent_usd / self.max_cost_usd)

    @property
    def is_exhausted(self) -> bool:
        return self.spent_usd >= self.max_cost_usd

    @property
    def avg_cost_per_call(self) -> float:
        return self.spent_usd / self.calls if self.calls > 0 else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "max_cost_usd": round(self.max_cost_usd, 6),
            "spent_usd": round(self.spent_usd, 6),
            "remaining_usd": round(self.remaining_usd, 6),
            "utilization": round(self.utilization, 4),
            "calls": self.calls,
            "tokens": self.tokens,
            "is_exhausted": self.is_exhausted,
            "avg_cost_per_call": round(self.avg_cost_per_call, 6),
            "first_call_at": self.first_call_at,
            "last_call_at": self.last_call_at,
        }


# ============================================================================
# BUDGET MANAGER
# ============================================================================
class BudgetManager:
    """Gestor de presupuesto multi-nivel, thread-safe, con alertas.

    Uso:
        >>> bm = BudgetManager(
        ...     engagement_id=uuid4(),
        ...     total_budget_usd=100.0,
        ...     role_limits={"planner": 20.0, "exploiter": 40.0},
        ... )
        >>> bm.can_spend("planner", 0.05)
        True
        >>> bm.record_spend("planner", 0.05, "deepseek", "deepseek-chat", 1000, "plan")
        >>> bm.remaining()
        99.95
    """

    def __init__(
        self,
        *,
        engagement_id: UUID,
        total_budget_usd: float,
        role_limits: dict[str, float] | None = None,
        default_role_limit: float | None = None,
    ) -> None:
        """
        Args:
            engagement_id: UUID del engagement.
            total_budget_usd: Presupuesto total en USD.
            role_limits: Límites por rol (opcional).
            default_role_limit: Límite default para roles sin límite específico.
        """
        if total_budget_usd <= 0:
            raise BudgetExceededError(
                "total_budget_usd debe ser > 0",
                context={"total_budget_usd": total_budget_usd},
            )

        self.engagement_id = engagement_id
        self.total_budget_usd = total_budget_usd
        self.default_role_limit = default_role_limit

        self._lock = RLock()
        self._records: list[BudgetRecord] = []
        self._spent_usd: float = 0.0
        self._created_at: float = time.time()
        self._alerts_triggered: set[str] = set()

        # Inicializar RoleBudgets
        self._role_budgets: dict[str, RoleBudget] = {}
        if role_limits:
            for role, limit in role_limits.items():
                self._role_budgets[role] = RoleBudget(
                    role=role, max_cost_usd=limit,
                )
        if default_role_limit is not None:
            self._default_role_budget = RoleBudget(
                role="__default__", max_cost_usd=default_role_limit,
            )
        else:
            self._default_role_budget = None

    # -- API pública --------------------------------------------------------

    @property
    def spent_usd(self) -> float:
        with self._lock:
            return self._spent_usd

    @property
    def remaining_usd(self) -> float:
        with self._lock:
            return max(0.0, self.total_budget_usd - self._spent_usd)

    @property
    def utilization(self) -> float:
        with self._lock:
            if self.total_budget_usd == 0:
                return 0.0
            return min(1.0, self._spent_usd / self.total_budget_usd)

    @property
    def is_exhausted(self) -> bool:
        with self._lock:
            return self._spent_usd >= self.total_budget_usd

    @property
    def calls(self) -> int:
        with self._lock:
            return len(self._records)

    @property
    def tokens(self) -> int:
        with self._lock:
            return sum(r.tokens for r in self._records)

    def _get_role_budget(self, role: str) -> RoleBudget:
        """Retorna el RoleBudget para un rol (crea si no existe)."""
        if role in self._role_budgets:
            return self._role_budgets[role]
        if self._default_role_budget is not None:
            return self._default_role_budget
        # Sin límite específico, usar el total como límite
        # Crear un RoleBudget virtual con el total como max
        rb = RoleBudget(role=role, max_cost_usd=self.total_budget_usd)
        self._role_budgets[role] = rb
        return rb

    def can_spend(self, role: str, estimated_cost: float = 0.0) -> bool:
        """Verifica si un rol puede gastar `estimated_cost`.

        Returns:
            True si hay presupuesto global Y del rol.
        """
        with self._lock:
            # 1. Verificar presupuesto global
            if self._spent_usd + estimated_cost > self.total_budget_usd:
                return False
            # 2. Verificar presupuesto del rol
            rb = self._get_role_budget(role)
            if rb.spent_usd + estimated_cost > rb.max_cost_usd:
                return False
            return True

    def record_spend(
        self,
        *,
        role: str,
        cost_usd: float,
        provider: str,
        model: str,
        tokens: int,
        operation: str,
    ) -> BudgetRecord:
        """Registra un gasto.

        Raises:
            BudgetExceededError: Si el gasto excede el presupuesto.
        """
        if cost_usd < 0:
            raise BudgetExceededError(
                "cost_usd no puede ser negativo",
                context={"cost_usd": cost_usd},
            )

        with self._lock:
            # Verificar presupuesto
            if not self.can_spend(role, cost_usd):
                # Determinar cuál límite se excedió
                if self._spent_usd + cost_usd > self.total_budget_usd:
                    raise BudgetExceededError(
                        f"Presupuesto global agotado: "
                        f"${self._spent_usd:.4f} + ${cost_usd:.4f} > "
                        f"${self.total_budget_usd:.2f}",
                        context={
                            "scope": "global",
                            "spent": self._spent_usd,
                            "requested": cost_usd,
                            "total": self.total_budget_usd,
                        },
                    )
                rb = self._get_role_budget(role)
                raise BudgetExceededError(
                    f"Presupuesto de rol '{role}' agotado: "
                    f"${rb.spent_usd:.4f} + ${cost_usd:.4f} > "
                    f"${rb.max_cost_usd:.2f}",
                    context={
                        "scope": "role",
                        "role": role,
                        "spent": rb.spent_usd,
                        "requested": cost_usd,
                        "max": rb.max_cost_usd,
                    },
                )

            # Registrar
            record = BudgetRecord(
                role=role,
                provider=provider,
                model=model,
                cost_usd=cost_usd,
                tokens=tokens,
                operation=operation,
            )
            self._records.append(record)
            self._spent_usd += cost_usd

            rb = self._get_role_budget(role)
            rb.spent_usd += cost_usd
            rb.calls += 1
            rb.tokens += tokens
            now = time.time()
            if rb.first_call_at is None:
                rb.first_call_at = now
            rb.last_call_at = now

            # Verificar alertas
            self._check_alerts()

            return record

    def _check_alerts(self) -> None:
        """Verifica y dispara alertas de umbral."""
        util = self.utilization
        if util >= _ALERT_THRESHOLD_CRITICAL and "critical" not in self._alerts_triggered:
            self._alerts_triggered.add("critical")
            _log.critical(
                "budget_critical",
                utilization=round(util, 4),
                spent=self._spent_usd,
                total=self.total_budget_usd,
            )
        elif util >= _ALERT_THRESHOLD_HIGH and "high" not in self._alerts_triggered:
            self._alerts_triggered.add("high")
            _log.error(
                "budget_high",
                utilization=round(util, 4),
                spent=self._spent_usd,
                total=self.total_budget_usd,
            )
        elif util >= _ALERT_THRESHOLD_WARNING and "warning" not in self._alerts_triggered:
            self._alerts_triggered.add("warning")
            _log.warning(
                "budget_warning",
                utilization=round(util, 4),
                spent=self._spent_usd,
                total=self.total_budget_usd,
            )

    # -- Reportes -----------------------------------------------------------

    def remaining(self, role: str | None = None) -> float:
        """Presupuesto restante (global o por rol)."""
        with self._lock:
            if role is None:
                return self.remaining_usd
            rb = self._get_role_budget(role)
            return rb.remaining_usd

    def utilization_of(self, role: str) -> float:
        """Utilización de un rol específico."""
        with self._lock:
            rb = self._get_role_budget(role)
            return rb.utilization

    def projection(self) -> dict[str, Any]:
        """Proyección de consumo basada en tasa actual.

        Returns:
            Dict con proyección de costo final, tiempo restante, etc.
        """
        with self._lock:
            if not self._records or self._spent_usd == 0:
                return {
                    "projected_total_usd": 0.0,
                    "projected_exhaustion_at": None,
                    "avg_cost_per_call": 0.0,
                    "estimated_calls_remaining": 0,
                }

            elapsed = time.time() - self._created_at
            rate_per_sec = self._spent_usd / elapsed if elapsed > 0 else 0.0
            avg_cost_per_call = self._spent_usd / len(self._records)

            # Proyección: cuándo se agota el presupuesto
            if rate_per_sec > 0:
                seconds_to_exhaustion = self.remaining_usd / rate_per_sec
                exhaustion_at = time.time() + seconds_to_exhaustion
            else:
                seconds_to_exhaustion = None
                exhaustion_at = None

            # Calls restantes estimadas
            calls_remaining = (
                int(self.remaining_usd / avg_cost_per_call)
                if avg_cost_per_call > 0
                else 0
            )

            return {
                "projected_total_usd": round(self.total_budget_usd, 4),
                "elapsed_seconds": round(elapsed, 2),
                "rate_usd_per_sec": round(rate_per_sec, 6),
                "avg_cost_per_call": round(avg_cost_per_call, 6),
                "estimated_calls_remaining": calls_remaining,
                "seconds_to_exhaustion": (
                    round(seconds_to_exhaustion, 2)
                    if seconds_to_exhaustion
                    else None
                ),
                "projected_exhaustion_at": exhaustion_at,
            }

    def status(self) -> dict[str, Any]:
        """Status completo del budget."""
        with self._lock:
            return {
                "engagement_id": str(self.engagement_id),
                "total_budget_usd": round(self.total_budget_usd, 4),
                "spent_usd": round(self._spent_usd, 4),
                "remaining_usd": round(self.remaining_usd, 4),
                "utilization": round(self.utilization, 4),
                "is_exhausted": self.is_exhausted,
                "calls": self.calls,
                "tokens": self.tokens,
                "alerts_triggered": list(self._alerts_triggered),
                "roles": {
                    role: rb.to_dict()
                    for role, rb in self._role_budgets.items()
                },
                "projection": self.projection(),
            }

    def get_records(
        self,
        *,
        role: str | None = None,
        limit: int | None = None,
    ) -> list[BudgetRecord]:
        """Retorna los registros de gasto, con filtros opcionales."""
        with self._lock:
            records = list(self._records)
        if role is not None:
            records = [r for r in records if r.role == role]
        if limit is not None:
            records = records[-limit:]
        return records

    # -- Serialización ------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Serializa el budget manager."""
        with self._lock:
            return {
                "engagement_id": str(self.engagement_id),
                "total_budget_usd": self.total_budget_usd,
                "spent_usd": self._spent_usd,
                "created_at": self._created_at,
                "default_role_limit": self.default_role_limit,
                "role_budgets": {
                    role: {
                        "role": rb.role,
                        "max_cost_usd": rb.max_cost_usd,
                        "spent_usd": rb.spent_usd,
                        "calls": rb.calls,
                        "tokens": rb.tokens,
                        "first_call_at": rb.first_call_at,
                        "last_call_at": rb.last_call_at,
                    }
                    for role, rb in self._role_budgets.items()
                },
                "records": [r.to_dict() for r in self._records],
                "alerts_triggered": list(self._alerts_triggered),
            }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "BudgetManager":
        """Reconstruye desde dict."""
        bm = cls(
            engagement_id=UUID(d["engagement_id"]),
            total_budget_usd=d["total_budget_usd"],
            default_role_limit=d.get("default_role_limit"),
        )
        bm._spent_usd = d.get("spent_usd", 0.0)
        bm._created_at = d.get("created_at", time.time())
        bm._alerts_triggered = set(d.get("alerts_triggered", []))

        for role, rb_data in d.get("role_budgets", {}).items():
            bm._role_budgets[role] = RoleBudget(
                role=rb_data["role"],
                max_cost_usd=rb_data["max_cost_usd"],
                spent_usd=rb_data.get("spent_usd", 0.0),
                calls=rb_data.get("calls", 0),
                tokens=rb_data.get("tokens", 0),
                first_call_at=rb_data.get("first_call_at"),
                last_call_at=rb_data.get("last_call_at"),
            )

        bm._records = [
            BudgetRecord.from_dict(r) for r in d.get("records", [])
        ]
        return bm


__all__ = [
    "BudgetManager",
    "BudgetRecord",
    "RoleBudget",
]
