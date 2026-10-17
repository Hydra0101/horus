"""Sandbox multi-capa God-Tier — API pública.

Módulo completo de sandboxing con:
    - Configuración validada (SandboxConfig)
    - Límites de recursos (ResourceLimits)
    - Perfiles seccomp dinámicos (SeccompProfile)
    - Aislamiento de red (NetworkPolicy)
    - Auditoría forense con hash chain (SandboxAuditLog)
    - Orquestación Docker/Podman (SandboxManager)
    - Detección de escape multi-capa (EscapeDetector)

Arquitectura:
    ┌─────────────────────────────────────────┐
    │  SandboxManager                         │
    │  ┌───────────────────────────────────┐  │
    │  │  1. SandboxConfig (validación)    │  │
    │  │  2. ResourceLimits (CPU, RAM)     │  │
    │  │  3. SeccompProfile (syscalls)     │  │
    │  │  4. NetworkPolicy (aislamiento)   │  │
    │  │  5. SandboxAuditLog (forense)     │  │
    │  │  6. Docker/Podman (runtime)       │  │
    │  │  7. EscapeDetector (runtime)      │  │
    │  └───────────────────────────────────┘  │
    └─────────────────────────────────────────┘

Uso:
    >>> from pathlib import Path
    >>> from god_tier_agency.sandbox import (
    ...     SandboxManager, SandboxConfig, SandboxAuditLog,
    ... )
    >>>
    >>> log = SandboxAuditLog(
    ...     Path("/var/log/godtier/audit.jsonl"),
    ...     hmac_key=b"x" * 32,
    ... )
    >>> manager = SandboxManager(audit_log=log)
    >>>
    >>> result = await manager.execute(
    ...     code="print('hello')",
    ...     language="python",
    ... )
    >>> if result.success:
    ...     print(result.stdout)

Features:
    - Contenedor efímero por ejecución
    - Validación pre-flight por lenguaje (Python AST, bash allowlist)
    - Auto-pull de imágenes (Podman compatible)
    - Seccomp strict/permissive
    - Red aislada con DNS sinkhole
    - Audit log con hash chain + HMAC
    - Detección de escape en 6 capas
    - Fallbacks para Podman (storage_opt, apparmor, nproc)
    - Env vars Python para read-only FS
"""

# ============================================================================
# VERSIÓN
# ============================================================================
__version__ = "0.1.0"


# ============================================================================
# CONFIGURACIÓN
# ============================================================================
from god_tier_agency.sandbox.config import SandboxConfig


# ============================================================================
# LÍMITES DE RECURSOS
# ============================================================================
from god_tier_agency.sandbox.limits import (
    CPU_PERIOD_US,
    ResourceLimits,
)


# ============================================================================
# SECCOMP
# ============================================================================
from god_tier_agency.sandbox.seccomp import (
    SeccompProfile,
    build_seccomp_profile,
    clear_cache as clear_seccomp_cache,
    get_seccomp_profile,
    validate_seccomp_profile,
)


# ============================================================================
# NETWORK
# ============================================================================
from god_tier_agency.sandbox.network import (
    DEFAULT_SANDBOX_NETWORK,
    DNSMASQ_LOCAL_PORT,
    NetworkMode,
    NetworkPolicy,
    apply_network_policy,
    build_network_policy,
    generate_dnsmasq_config,
    generate_etc_hosts,
    generate_iptables_rules,
    generate_nftables_rules,
    validate_network_policy,
)


# ============================================================================
# AUDITORÍA FORENSE
# ============================================================================
from god_tier_agency.sandbox.audit import (
    GENESIS_HASH,
    HASH_ALGO,
    HMAC_ALGO,
    AuditEntry,
    EventType,
    SandboxAuditLog,
    ViolationCategory,
)


# ============================================================================
# EXCEPCIONES
# ============================================================================
from god_tier_agency.sandbox.exceptions import (
    SandboxConfigError,
    SandboxError,
    SandboxEscapeDetected,
    SandboxImageNotAllowed,
    SandboxNetworkViolation,
    SandboxResourceExceeded,
    SandboxTimeout,
)


# ============================================================================
# ORQUESTADOR (Manager)
# ============================================================================
from god_tier_agency.sandbox.manager import (
    DEFAULT_EXECUTION_TIMEOUT,
    DEFAULT_MAX_CONCURRENT,
    MAX_OUTPUT_BYTES,
    SandboxManager,
    SandboxResult,
    Severity,
)


# ============================================================================
# DETECCIÓN DE ESCAPE
# ============================================================================
from god_tier_agency.sandbox.escape_detection import (
    EscapeDetectionResult,
    EscapeDetector,
    EscapeIndicator,
    detect_escape_in_result,
    log_escape_detection,
)


# ============================================================================
# API PÚBLICA
# ============================================================================
__all__ = [
    # Versión
    "__version__",
    # --- Configuración ---
    "SandboxConfig",
    # --- Límites de recursos ---
    "ResourceLimits",
    "CPU_PERIOD_US",
    # --- Seccomp ---
    "SeccompProfile",
    "get_seccomp_profile",
    "build_seccomp_profile",
    "validate_seccomp_profile",
    "clear_seccomp_cache",
    # --- Network ---
    "NetworkMode",
    "NetworkPolicy",
    "build_network_policy",
    "apply_network_policy",
    "validate_network_policy",
    "generate_iptables_rules",
    "generate_nftables_rules",
    "generate_dnsmasq_config",
    "generate_etc_hosts",
    "DNSMASQ_LOCAL_PORT",
    "DEFAULT_SANDBOX_NETWORK",
    # --- Auditoría forense ---
    "AuditEntry",
    "SandboxAuditLog",
    "EventType",
    "ViolationCategory",
    "GENESIS_HASH",
    "HASH_ALGO",
    "HMAC_ALGO",
    # --- Excepciones ---
    "SandboxError",
    "SandboxEscapeDetected",
    "SandboxResourceExceeded",
    "SandboxTimeout",
    "SandboxNetworkViolation",
    "SandboxImageNotAllowed",
    "SandboxConfigError",
    # --- Orquestador ---
    "SandboxManager",
    "SandboxResult",
    "Severity",
    "DEFAULT_MAX_CONCURRENT",
    "DEFAULT_EXECUTION_TIMEOUT",
    "MAX_OUTPUT_BYTES",
    # --- Detección de escape ---
    "EscapeDetector",
    "EscapeDetectionResult",
    "EscapeIndicator",
    "detect_escape_in_result",
    "log_escape_detection",
]
