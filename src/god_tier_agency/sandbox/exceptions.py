"""Excepciones específicas del sandbox.

Todas heredan de SandboxError (que hereda de GodTierError).

Jerarquía:
    GodTierError
    └── SandboxError
        ├── SandboxEscapeDetected      (crítico — kill switch)
        ├── SandboxResourceExceeded    (CPU/RAM/PIDs excedido)
        ├── SandboxTimeout             (timeout de ejecución)
        ├── SandboxNetworkViolation    (intento de red no autorizado)
        ├── SandboxImageNotAllowed     (imagen no en allowlist)
        └── SandboxConfigError         (configuración inválida)
"""

from __future__ import annotations

from typing import Any, Literal

from god_tier_agency.core.exceptions import SandboxError

Severity = Literal["low", "medium", "high", "critical"]


class SandboxEscapeDetected(SandboxError):
    """Intento de escape del sandbox detectado.

    ESTA ES LA EXCEPCIÓN MÁS CRÍTICA.
    Cuando se lanza:
        1. El contenedor es matado inmediatamente (SIGKILL)
        2. El audit log registra el intento con toda la telemetría
        3. Se notifica al security logger
        4. Se marca el engagement como comprometido
    """

    error_code = "GODTIER_SANDBOX_ESCAPE"
    default_severity: Severity = "critical"
    retryable = False


class SandboxResourceExceeded(SandboxError):
    """El contenedor excedió un límite de recursos (CPU/RAM/PIDs/disco)."""

    error_code = "GODTIER_SANDBOX_RESOURCE"
    default_severity: Severity = "high"
    retryable = False


class SandboxTimeout(SandboxError):
    """El contenedor excedió el timeout configurado."""

    error_code = "GODTIER_SANDBOX_TIMEOUT"
    default_severity: Severity = "medium"
    retryable = True  # puede reintentarse con timeout más largo


class SandboxNetworkViolation(SandboxError):
    """Intento de acceso a red no autorizada."""

    error_code = "GODTIER_SANDBOX_NETWORK"
    default_severity: Severity = "high"
    retryable = False


class SandboxImageNotAllowed(SandboxError):
    """La imagen Docker no está en el allowlist."""

    error_code = "GODTIER_SANDBOX_IMAGE"
    default_severity: Severity = "high"
    retryable = False


class SandboxConfigError(SandboxError):
    """Configuración del sandbox inválida."""

    error_code = "GODTIER_SANDBOX_CONFIG"
    default_severity: Severity = "critical"
    retryable = False


__all__ = [
    "SandboxError",
    "SandboxEscapeDetected",
    "SandboxResourceExceeded",
    "SandboxTimeout",
    "SandboxNetworkViolation",
    "SandboxImageNotAllowed",
    "SandboxConfigError",
]
