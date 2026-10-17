"""Gestión de límites de recursos del sandbox God-Tier.

Traduce SandboxConfig a parámetros del Docker SDK + añade validaciones
de seguridad para límites peligrosos (fork bombs, disk fill, CPU abuse).

Integra:
    - ulimits: previene fork bombs, core dumps, file descriptor exhaustion
    - storage_opt: limita el writable layer (evita disk fill)
    - tmpfs: /tmp y /run con noexec+nosuid+nodev
    - CPU: period + quota (limit fraccional)
    - RAM: mem_limit + memswap_limit (sin swap adicional)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Final

from god_tier_agency.sandbox.config import SandboxConfig
from god_tier_agency.sandbox.exceptions import SandboxConfigError

# ============================================================================
# CONSTANTES
# ============================================================================
CPU_PERIOD_US: Final[int] = 100_000  # 100ms
"""Periodo de CPU en microsegundos (estándar Linux CFS)."""

# ulimits: (soft, hard) por tipo
_ULIMIT_NOFILE: Final[tuple[int, int]] = (1024, 2048)
"""File descriptors: soft 1024, hard 2048."""

_ULIMIT_NPROC: Final[tuple[int, int]] = (1000, 2000)
"""Procesos por usuario: soft 100, hard 200."""

_ULIMIT_CORE: Final[tuple[int, int]] = (0, 0)
"""Core dumps: deshabilitados."""

_ULIMIT_FSIZE_MB: Final[int] = 100
"""Tamaño máximo de archivo: 100 MB."""

_ULIMIT_MEMLOCK: Final[tuple[int, int]] = (0, 0)
"""Memlock: deshabilitado."""


# ============================================================================
# RESOURCE LIMITS
# ============================================================================
@dataclass(frozen=True)
class ResourceLimits:
    """Límites de recursos traducidos a parámetros Docker.

    Todos los valores son inmutables (frozen) para garantizar que una vez
    computados, no cambian (defensa TOCTOU).
    """

    mem_limit: str
    memswap_limit: str
    cpu_period: int
    cpu_quota: int
    pids_limit: int
    tmpfs: dict[str, str]
    ulimits: list[dict[str, Any]]
    storage_opt: dict[str, str]

    @classmethod
    def from_config(cls, config: SandboxConfig) -> "ResourceLimits":
        """Construye límites desde SandboxConfig con validación."""
        # --- Validación de CPU ---
        if not 0.1 <= config.cpu_limit <= 8.0:
            raise SandboxConfigError(
                f"cpu_limit fuera de rango: {config.cpu_limit}",
                context={"cpu_limit": config.cpu_limit},
            )

        # CPU: period 100ms, quota = limit * period
        cpu_period = CPU_PERIOD_US
        cpu_quota = int(config.cpu_limit * cpu_period)

        # --- Memoria ---
        mem_limit = f"{config.memory_limit_mb}m"
        memswap_limit = mem_limit  # sin swap adicional

        # --- tmpfs: /tmp y /run read-write noexec nosuid nodev ---
        tmpfs = {
            "/tmp": f"rw,nosuid,nodev,size={config.tmpfs_size_mb}m",
            "/run": "rw,noexec,nosuid,nodev,size=16m",
        }

        # --- ulimits: previenen fork bombs, core dumps, FD exhaustion ---
        ulimits = [
            {"Name": "nofile", "Soft": _ULIMIT_NOFILE[0], "Hard": _ULIMIT_NOFILE[1]},
            {"Name": "nproc", "Soft": _ULIMIT_NPROC[0], "Hard": _ULIMIT_NPROC[1]},
            {"Name": "core", "Soft": _ULIMIT_CORE[0], "Hard": _ULIMIT_CORE[1]},
            {"Name": "fsize", "Soft": _ULIMIT_FSIZE_MB * 1024 * 1024,
             "Hard": _ULIMIT_FSIZE_MB * 2 * 1024 * 1024},
            {"Name": "memlock", "Soft": _ULIMIT_MEMLOCK[0], "Hard": _ULIMIT_MEMLOCK[1]},
        ]

        # --- storage_opt: limita el writable layer ---
        storage_opt = {
            "size": f"{config.disk_limit_mb}m",
        }

        return cls(
            mem_limit=mem_limit,
            memswap_limit=memswap_limit,
            cpu_period=cpu_period,
            cpu_quota=cpu_quota,
            pids_limit=config.pids_limit,
            tmpfs=tmpfs,
            ulimits=ulimits,
            storage_opt=storage_opt,
        )

    def to_docker_kwargs(self) -> dict[str, Any]:
        """Convierte a kwargs del Docker SDK."""
        return {
            "mem_limit": self.mem_limit,
            "memswap_limit": self.memswap_limit,
            "cpu_period": self.cpu_period,
            "cpu_quota": self.cpu_quota,
            "pids_limit": self.pids_limit,
            "tmpfs": self.tmpfs,
            "ulimits": self.ulimits,
            "storage_opt": self.storage_opt,
        }

    def to_dict(self) -> dict[str, Any]:
        """Serializa para audit log."""
        tmpfs_total = 0
        for v in self.tmpfs.values():
            if "size=" in v:
                size_str = v.split("size=")[1].split("m")[0]
                tmpfs_total += int(size_str)
        return {
            "mem_limit": self.mem_limit,
            "cpu_quota": self.cpu_quota,
            "cpu_period": self.cpu_period,
            "pids_limit": self.pids_limit,
            "tmpfs_size_mb": tmpfs_total,
            "disk_limit": self.storage_opt.get("size"),
            "ulimits_count": len(self.ulimits),
        }

    def cpu_limit_fraction(self) -> float:
        """Retorna el límite de CPU como fracción (0.0-8.0)."""
        return self.cpu_quota / self.cpu_period


__all__ = ["ResourceLimits", "CPU_PERIOD_US"]
