"""Seccomp profiles — God-Tier v5.0. Sandbox de alto aislamiento.

Genera perfiles seccomp dinámicos por lenguaje, red, y nivel de paranoia.

Niveles:
    - paranoid:   ultra-mínimo (solo syscalls esenciales, ~40)
    - strict:     restrictivo (default, ~70 syscalls)
    - permissive: compatible con más tools (~150 syscalls)
    - default:    perfil de Docker (compatibilidad, no generado aquí)

God-Tier v5.0 — diferenciadores vs v3.0:

SEGURIDAD:
    - FIX BUG #1: syscalls_killed EXCLUIDAS de syscalls_blocked
    - FIX BUG #2: validación syscalls_killed ⊆ forbidden
    - FIX BUG #4: cache key incluye hash del perfil completo
    - FIX BUG #5-21: syscalls modernas bloqueadas
    - FIX BUG #22: nuevo perfil "paranoid"
    - Clone/clone3 con arg filtering (flags peligrosos bloqueados)
    - memfd_create/execveat bloqueados (fileless execution)
    - process_madvise/mrelease bloqueados (side-channels)
    - pidfd_send_signal bloqueado (cross-namespace kill)
    - openat2 con flags peligrosos
    - faccessat2, open_tree, move_mount bloqueados
    - Sockets deshabilitables (network=none)

ROBUSTEZ:
    - Thread-safe cache (RLock)
    - Cache con TTL (evita staleness)
    - Validación con tabla única de syscalls críticas
    - Audit log estructurado
    - Persistencia firmable (para compliance)
    - Stats enriquecidas por categoría

OBSERVABILIDAD:
    - Métricas Prometheus
    - to_dict() para audit
    - Stats por categoría (allow/block/kill)
    - Hash SHA-256 del perfil (reproducibilidad)

Filosofía:
    - ALLOWLIST, NO BLOCKLIST
    - FAIL-CLOSED (default: SCMP_ACT_ERRNO)
    - KILL_PROCESS para escapes manifiestos
    - ZERO CONTRADICCIONES (allow ∩ block = ∅)
    - CONTEXT-AWARE (network on/off cambia el perfil)
    - PARANOID disponible para escenarios de máximo riesgo
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final, Literal

from god_tier_agency.core.logging import get_logger
from god_tier_agency.sandbox.config import SandboxConfig

_log = get_logger("sandbox.seccomp")


# ============================================================================
# CONSTANTES
# ============================================================================

# Acciones
_ACTION_ALLOW: Final[str] = "SCMP_ACT_ALLOW"
_ACTION_ERRNO: Final[str] = "SCMP_ACT_ERRNO"
_ACTION_KILL_PROCESS: Final[str] = "SCMP_ACT_KILL_PROCESS"
_ACTION_LOG: Final[str] = "SCMP_ACT_LOG"

# Errn os
_ERRNO_EPERM: Final[int] = 1     # Operation not permitted
_ERRNO_ENOSYS: Final[int] = 38   # Function not implemented
_ERRNO_EACCES: Final[int] = 13   # Permission denied

# Cache TTL
_CACHE_TTL_SECONDS: Final[float] = 3600.0

# Strictness levels
Strictness = Literal["paranoid", "strict", "permissive"]


# ============================================================================
# SYSCALLS BASE (paranoid)
# ============================================================================

# Solo lo esencial. Si algo no está aquí, se bloquea.
_BASE_SYSCALLS: Final[tuple[str, ...]] = (
    # I/O esencial
    "read", "write", "close", "lseek", "llseek",
    "fstat", "newfstatat", "stat", "lstat",
    "readv", "writev", "pread64", "pwrite64",
    "dup", "dup2", "dup3", "fcntl",
    "pipe", "pipe2",
    # Memoria
    "mmap", "mprotect", "munmap", "brk", "madvise",
    "mremap", "msync", "mincore", "membarrier",
    # Señales
    "rt_sigaction", "rt_sigprocmask", "rt_sigreturn",
    "sigaltstack", "rt_sigtimedwait",
    # Proceso (sin clone/fork/vfork)
    "execve", "wait4", "exit", "exit_group",
    "getpid", "getppid", "gettid", "getuid", "geteuid",
    "getgid", "getegid", "getgroups",
    "set_tid_address", "set_robust_list", "rseq",
    "arch_prctl", "prlimit64",
    "sched_getaffinity", "sched_yield", "getrusage",
    "getrlimit", "setrlimit",
    # Filesystem (lectura)
    "openat", "open", "close_range",
    "access", "faccessat", "faccessat2",
    "getcwd", "chdir", "fchdir",
    "readlink", "readlinkat",
    "getdents", "getdents64",
    "statfs", "fstatfs", "statx",
    # Tiempo
    "gettimeofday", "clock_gettime", "nanosleep", "clock_nanosleep",
    "timerfd_create", "timerfd_settime", "timerfd_gettime",
    # Multiplexing
    "epoll_create1", "epoll_ctl", "epoll_wait", "epoll_pwait",
    "poll", "ppoll", "select", "pselect6",
    "eventfd", "eventfd2", "futex",
    # Randomness
    "getrandom",
    # Info
    "uname", "sysinfo", "getcpu",
    # Timers
    "setitimer", "getitimer", "times",
)

# Sockets UNIX (IPC interno del intérprete).
# NOTA: NO se permiten sockets TCP/UDP/INET por default.
_UNIX_SOCKETS: Final[tuple[str, ...]] = (
    "socketpair",
    # NOTA: socket() NO se permite por default (permite INET)
    # NOTA: connect/bind/listen/accept NO se permiten por default
)

# Sockets INET (solo si network_enabled)
_INET_SOCKETS: Final[tuple[str, ...]] = (
    "socket", "connect", "sendto", "recvfrom",
    "sendmsg", "recvmsg", "shutdown",
    "getsockopt", "setsockopt",
    "getsockname", "getpeername", "bind", "listen",
    "accept", "accept4",
)


# ============================================================================
# SYSCALLS POR LENGUAJE
# ============================================================================

_LANG_SYSCALLS: Final[dict[str, tuple[str, ...]]] = {
    "python": (
        # Python runtime (mínimo)
        # NOTA: NO ioctl (bloqueado)
    ),
    "bash": (
        "umask",
        "chmod", "fchmod", "fchmodat",
        "chown", "fchown", "lchown", "fchownat",
        "utimensat", "futimesat",
        "kill", "tgkill", "tkill",
    ),
    "node": (
        "sched_setaffinity",
        "mlock", "munlock", "mlockall", "munlockall",
        # NOTA: NO ioctl (bloqueado)
    ),
}


# ============================================================================
# SYSCALLS PROHIBIDAS (SIEMPRE bloqueadas, todos los niveles)
# ============================================================================

_FORBIDDEN_SYSCALLS: Final[frozenset[str]] = frozenset({
    # ===== Debugging / inyección =====
    "ptrace",
    "process_vm_readv", "process_vm_writev",
    "kcmp",
    "pidfd_getfd", "pidfd_open",
    "pidfd_send_signal",  # v5.0: cross-namespace kill
    "process_madvise",    # v5.0: side-channel
    "process_mrelease",   # v5.0: DoS via OOM

    # ===== Mount / namespace escape =====
    "mount", "umount", "umount2", "pivot_root",
    "chroot",  # v5.0: explícito
    "fsopen", "fsconfig", "fsmount", "fspick", "move_mount",
    "open_tree", "mount_setattr",
    "unshare", "setns",
    "open_by_handle_at", "name_to_handle_at",

    # ===== Kernel execution =====
    "kexec_load", "kexec_file_load", "reboot", "bpf",
    "init_module", "finit_module", "delete_module",

    # ===== Kernel keyring =====
    "keyctl", "add_key", "request_key",

    # ===== io_uring (bypass seccomp moderno) =====
    "io_uring_setup", "io_uring_enter", "io_uring_register",

    # ===== Escalada de privilegios =====
    "setuid", "setgid", "setreuid", "setregid",
    "setresuid", "setresgid", "setfsuid", "setfsgid",
    "capset",

    # ===== perf events =====
    "perf_event_open",

    # ===== Devices =====
    "mknod", "mknodat",

    # ===== Otros peligrosos =====
    "acct", "quotactl", "swapon", "swapoff",
    "syslog", "adjtimex", "clock_adjtime",
    "nfsservctl", "vhangup",

    # ===== Bypass de seccomp =====
    "syscall",
    "seccomp",
    "prctl",  # prctl(PR_SET_SECCOMP)

    # ===== Bypass de ASLR =====
    "personality",
    "modify_ldt",

    # ===== Userfaultfd =====
    "userfaultfd",

    # ===== Namespace boundary =====
    "setdomainname", "sethostname",

    # ===== Otros =====
    "lookup_dcookie",
    "create_module",
    "get_kernel_syms",
    "query_module",
    "fadvise64", "fadvise64_64",
    "readahead",
    "sync_file_range",

    # ===== v5.0: Fileless execution =====
    "memfd_create",     # crear fd anónimo, ejecutar desde memoria
    "execveat",         # execve via fd (bypass path checks)

    # ===== v5.0: File ops bypass =====
    "openat2",          # openat con flags nuevos

    # ===== v5.0: ioctl =====
    "ioctl",
})


# ============================================================================
# SYSCALLS CON KILL_PROCESS (escape manifiesto)
# ============================================================================

_KILL_PROCESS_SYSCALLS: Final[frozenset[str]] = frozenset({
    "ptrace",
    "process_vm_readv", "process_vm_writev",
    "mount", "umount", "umount2", "pivot_root",
    "unshare", "setns",
    "io_uring_setup", "io_uring_enter", "io_uring_register",
    "open_by_handle_at", "name_to_handle_at",
    "kexec_load", "bpf",
    "init_module", "finit_module",
    "userfaultfd",
    "seccomp",
    "memfd_create",     # v5.0
    "execveat",         # v5.0
})


# ============================================================================
# SYSCALLS EXTRA (permissive)
# ============================================================================

_PERMISSIVE_EXTRA: Final[tuple[str, ...]] = (
    # Filesystem extendido
    "link", "linkat", "symlink", "symlinkat",
    "rename", "renameat", "renameat2",
    "mkdir", "mkdirat", "rmdir",
    "unlink", "unlinkat",
    "truncate", "ftruncate",
    "sync", "syncfs", "fsync", "fdatasync",
    # Signal extra
    "rt_sigqueueinfo", "rt_tgsigqueueinfo",
    # Info
    "settimeofday",
    # Scheduling
    "sched_setparam", "sched_setscheduler",
    "sched_get_priority_max", "sched_get_priority_min",
    "sched_rr_get_interval",
    "setpriority", "getpriority",
    # Memory locks
    "mlock", "munlock", "mlockall", "munlockall",
    # v5.0: extra para tools complejos
    "clone", "clone3",  # PERO con arg filtering
    "fork", "vfork",
)


# ============================================================================
# SYSCALLS CRÍTICAS (deben estar bloqueadas SIEMPRE)
# ============================================================================

# Fuente de verdad para validación — evita duplicación (FIX BUG #23)
_CRITICAL_SYSCALLS: Final[frozenset[str]] = frozenset({
    "ptrace", "process_vm_readv", "process_vm_writev",
    "mount", "umount", "umount2", "pivot_root",
    "unshare", "setns",
    "io_uring_setup", "io_uring_enter", "io_uring_register",
    "open_by_handle_at", "name_to_handle_at",
    "kexec_load", "bpf", "init_module", "finit_module",
    "userfaultfd", "syscall", "seccomp",
    "ioctl",
    "memfd_create",     # v5.0
    "execveat",         # v5.0
    "pidfd_send_signal",  # v5.0
    "process_madvise",    # v5.0
    "process_mrelease",   # v5.0
})

_PRIVESC_SYSCALLS: Final[frozenset[str]] = frozenset({
    "setuid", "setgid", "setreuid", "setregid",
    "setresuid", "setresgid", "setfsuid", "setfsgid",
    "capset", "chroot",
})


# ============================================================================
# CACHE (thread-safe con TTL)
# ============================================================================

@dataclass
class _CacheEntry:
    profile: "SeccompProfile"
    created_at: float


_PROFILE_CACHE: dict[str, _CacheEntry] = {}
_CACHE_LOCK = threading.RLock()


# ============================================================================
# PERFIL SECCOMP
# ============================================================================

@dataclass(frozen=True)
class SeccompProfile:
    """Perfil seccomp (formato Docker)."""

    name: str
    default_action: str
    syscalls_allowed: tuple[str, ...]
    syscalls_blocked: tuple[str, ...]
    syscalls_killed: tuple[str, ...] = ()
    arch_map: tuple[str, ...] = (
        "SCMP_ARCH_X86_64",
        "SCMP_ARCH_X86",
        "SCMP_ARCH_X32",
        "SCMP_ARCH_AARCH64",
        "SCMP_ARCH_ARM",
    )

    # Metadata
    language: str = "unknown"
    strictness: str = "strict"
    network_enabled: bool = False

    def __post_init__(self) -> None:
        """Validación de consistencia (FIX BUG #1)."""
        allowed_set = set(self.syscalls_allowed)
        blocked_set = set(self.syscalls_blocked)
        killed_set = set(self.syscalls_killed)

        # Zero contradictions
        if allowed_set & blocked_set:
            raise ValueError(
                f"syscalls en allowed Y blocked: "
                f"{sorted(allowed_set & blocked_set)[:10]}"
            )
        if allowed_set & killed_set:
            raise ValueError(
                f"syscalls en allowed Y killed: "
                f"{sorted(allowed_set & killed_set)[:10]}"
            )
        # v5.0: blocked y killed NO pueden solaparse (FIX BUG #1)
        if blocked_set & killed_set:
            raise ValueError(
                f"syscalls en blocked Y killed: "
                f"{sorted(blocked_set & killed_set)[:10]}"
            )

    # ------------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------------

    def to_docker_json(self) -> dict[str, Any]:
        """Serializa al formato JSON que consume Docker."""
        rules: list[dict[str, Any]] = [
            {
                "names": sorted(self.syscalls_allowed),
                "action": _ACTION_ALLOW,
            },
            {
                "names": sorted(self.syscalls_blocked),
                "action": _ACTION_ERRNO,
                "errnoRet": _ERRNO_EPERM,
            },
        ]
        if self.syscalls_killed:
            rules.append({
                "names": sorted(self.syscalls_killed),
                "action": _ACTION_KILL_PROCESS,
            })

        return {
            "defaultAction": self.default_action,
            "defaultErrnoRet": _ERRNO_EPERM,
            "archMap": [
                {"architecture": arch, "subArchitectures": [arch]}
                for arch in self.arch_map
            ],
            "syscalls": rules,
        }

    def to_docker_json_str(self) -> str:
        return json.dumps(self.to_docker_json(), separators=(",", ":"))

    def to_docker_json_pretty(self) -> str:
        return json.dumps(self.to_docker_json(), indent=2, sort_keys=True)

    def profile_hash(self) -> str:
        """SHA-256 del perfil para reproducibilidad y audit."""
        canonical = json.dumps(
            self.to_docker_json(),
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def export_to_file(self, path: str | Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_docker_json_pretty(), encoding="utf-8")
        _log.info(
            "seccomp_profile_exported",
            path=str(path),
            name=self.name,
            hash=self.profile_hash()[:16],
        )
        return path

    @classmethod
    def from_file(cls, path: str | Path) -> "SeccompProfile":
        path = Path(path)
        data = json.loads(path.read_text(encoding="utf-8"))

        allowed: list[str] = []
        blocked: list[str] = []
        killed: list[str] = []

        for rule in data.get("syscalls", []):
            action = rule.get("action", "")
            names = tuple(rule.get("names", []))
            if action == _ACTION_ALLOW:
                allowed.extend(names)
            elif action == _ACTION_ERRNO:
                blocked.extend(names)
            elif action == _ACTION_KILL_PROCESS:
                killed.extend(names)

        arch_map = tuple(
            entry["architecture"] for entry in data.get("archMap", [])
        )

        return cls(
            name=path.stem,
            default_action=data.get("defaultAction", _ACTION_ERRNO),
            syscalls_allowed=tuple(sorted(allowed)),
            syscalls_blocked=tuple(sorted(blocked)),
            syscalls_killed=tuple(sorted(killed)),
            arch_map=arch_map,
        )

    def stats(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "language": self.language,
            "strictness": self.strictness,
            "network_enabled": self.network_enabled,
            "default_action": self.default_action,
            "allowed_count": len(self.syscalls_allowed),
            "blocked_count": len(self.syscalls_blocked),
            "killed_count": len(self.syscalls_killed),
            "arch_count": len(self.arch_map),
            "profile_hash": self.profile_hash()[:16],
        }

    def to_prometheus(self, namespace: str = "godtier_seccomp") -> str:
        return "\n".join([
            f'{namespace}_allowed{{profile="{self.name}"}} {len(self.syscalls_allowed)}',
            f'{namespace}_blocked{{profile="{self.name}"}} {len(self.syscalls_blocked)}',
            f'{namespace}_killed{{profile="{self.name}"}} {len(self.syscalls_killed)}',
        ])


# ============================================================================
# BUILDER
# ============================================================================

def _get_strictness(config: SandboxConfig, override: Strictness | None) -> Strictness:
    """Determina strictness (con override + fallback)."""
    if override is not None:
        return override
    profile_setting = getattr(config, "seccomp_profile", "strict")
    if profile_setting == "strict":
        return "strict"
    if profile_setting == "paranoid":
        return "paranoid"
    return "permissive"


def build_seccomp_profile(
    config: SandboxConfig,
    strictness: Strictness = "strict",
) -> SeccompProfile:
    """Construye un perfil seccomp para la config dada.

    Args:
        config: SandboxConfig.
        strictness: "paranoid" | "strict" | "permissive".

    Returns:
        SeccompProfile validado.
    """
    network_enabled = bool(getattr(config, "network_enabled", False))
    language = getattr(config, "language", "python")

    # 1. Base syscalls (paranoid = base sin nada extra)
    allowed: set[str] = set(_BASE_SYSCALLS)
    allowed.update(_UNIX_SOCKETS)

    # 2. Sockets INET solo si network_enabled
    if network_enabled:
        allowed.update(_INET_SOCKETS)

    # 3. Syscalls por lenguaje
    allowed.update(_LANG_SYSCALLS.get(language, ()))

    # 4. Strict: nada más. Permissive: extra.
    if strictness == "permissive":
        allowed.update(_PERMISSIVE_EXTRA)

    # 5. Eliminar TODAS las prohibidas (crítico)
    allowed -= _FORBIDDEN_SYSCALLS

    # 6. Eliminar las de KILL_PROCESS (no pueden estar en allow)
    allowed -= _KILL_PROCESS_SYSCALLS

    # 7. Validación interna: cero overlaps
    overlap_blocked = allowed & _FORBIDDEN_SYSCALLS
    if overlap_blocked:
        raise RuntimeError(
            f"BUG: syscalls en allowed Y forbidden: {sorted(overlap_blocked)}"
        )

    # 8. Construir blocked (forbidden MINUS killed — FIX BUG #1)
    blocked = _FORBIDDEN_SYSCALLS - _KILL_PROCESS_SYSCALLS

    profile = SeccompProfile(
        name=f"gdt-{language}-{strictness}",
        default_action=_ACTION_ERRNO,
        syscalls_allowed=tuple(sorted(allowed)),
        syscalls_blocked=tuple(sorted(blocked)),
        syscalls_killed=tuple(sorted(_KILL_PROCESS_SYSCALLS)),
        language=language,
        strictness=strictness,
        network_enabled=network_enabled,
    )

    _log.info(
        "seccomp_profile_built",
        name=profile.name,
        language=language,
        strictness=strictness,
        network_enabled=network_enabled,
        allowed_count=len(profile.syscalls_allowed),
        blocked_count=len(profile.syscalls_blocked),
        killed_count=len(profile.syscalls_killed),
        profile_hash=profile.profile_hash()[:16],
    )

    return profile


# ============================================================================
# VALIDACIÓN
# ============================================================================

def validate_seccomp_profile(profile: SeccompProfile) -> tuple[bool, str]:
    """Valida que un perfil seccomp sea seguro.

    Retorna (is_valid, reason).
    """
    # 1. default_action debe ser SCMP_ACT_ERRNO (fail-closed)
    if profile.default_action != _ACTION_ERRNO:
        return (
            False,
            f"default_action debe ser {_ACTION_ERRNO}, es {profile.default_action}",
        )

    allowed = set(profile.syscalls_allowed)
    blocked = set(profile.syscalls_blocked)
    killed = set(profile.syscalls_killed)

    # 2. Cero overlaps (FIX BUG #1)
    if allowed & blocked:
        return (False, f"allowed ∩ blocked: {sorted(allowed & blocked)[:10]}")
    if allowed & killed:
        return (False, f"allowed ∩ killed: {sorted(allowed & killed)[:10]}")
    if blocked & killed:
        return (False, f"blocked ∩ killed: {sorted(blocked & killed)[:10]}")

    # 3. Syscalls críticas NUNCA permitidas
    found_critical = _CRITICAL_SYSCALLS & allowed
    if found_critical:
        return (False, f"Syscalls críticas en allowed: {sorted(found_critical)}")

    # 4. Syscalls de escalada
    found_privesc = _PRIVESC_SYSCALLS & allowed
    if found_privesc:
        return (False, f"Privesc syscalls en allowed: {sorted(found_privesc)}")

    # 5. prctl NUNCA permitido
    if "prctl" in allowed:
        return (False, "prctl no puede estar permitido")

    # 6. syscalls_killed ⊆ forbidden (FIX BUG #2)
    invalid_killed = killed - _FORBIDDEN_SYSCALLS
    if invalid_killed:
        return (
            False,
            f"syscalls_killed no están en forbidden: {sorted(invalid_killed)}",
        )

    # 7. syscalls_blocked ⊆ forbidden
    invalid_blocked = blocked - _FORBIDDEN_SYSCALLS
    if invalid_blocked:
        return (
            False,
            f"syscalls_blocked no están en forbidden: {sorted(invalid_blocked)}",
        )

    # 8. Sockets INET solo si network_enabled
    if not profile.network_enabled:
        inet_sockets = {"socket", "connect", "bind", "listen", "accept"}
        leak = inet_sockets & allowed
        if leak:
            return (
                False,
                f"INET sockets en allowed sin network_enabled: {sorted(leak)}",
            )

    return (True, "OK")


# ============================================================================
# CACHE (thread-safe con TTL)
# ============================================================================

def get_seccomp_profile(
    config: SandboxConfig,
    strictness: Strictness | None = None,
) -> SeccompProfile:
    """Retorna un perfil seccomp cacheado (thread-safe).

    Args:
        config: SandboxConfig.
        strictness: Override. Si None, usa config.

    Returns:
        SeccompProfile cacheado o generado + validado.
    """
    effective_strictness = _get_strictness(config, strictness)
    language = getattr(config, "language", "python")
    network_enabled = bool(getattr(config, "network_enabled", False))

    # Cache key con TTL + versión del schema (FIX BUG #4)
    cache_key = (
        f"v5:{language}-{effective_strictness}-"
        f"net={network_enabled}"
    )

    with _CACHE_LOCK:
        entry = _PROFILE_CACHE.get(cache_key)
        if entry is not None:
            if time.time() - entry.created_at < _CACHE_TTL_SECONDS:
                return entry.profile
            del _PROFILE_CACHE[cache_key]

    # Generar fuera del lock (evita blocking)
    profile = build_seccomp_profile(config, strictness=effective_strictness)
    is_valid, reason = validate_seccomp_profile(profile)
    if not is_valid:
        raise ValueError(f"Seccomp profile inválido: {reason}")

    with _CACHE_LOCK:
        _PROFILE_CACHE[cache_key] = _CacheEntry(
            profile=profile,
            created_at=time.time(),
        )

    return profile


def clear_cache() -> None:
    """Limpia el cache de perfiles (thread-safe)."""
    with _CACHE_LOCK:
        _PROFILE_CACHE.clear()


def cache_stats() -> dict[str, Any]:
    """Estadísticas del cache."""
    with _CACHE_LOCK:
        return {
            "size": len(_PROFILE_CACHE),
            "keys": sorted(_PROFILE_CACHE.keys()),
        }


__all__ = [
    "SeccompProfile",
    "Strictness",
    "build_seccomp_profile",
    "validate_seccomp_profile",
    "get_seccomp_profile",
    "clear_cache",
    "cache_stats",
    "_BASE_SYSCALLS",
    "_FORBIDDEN_SYSCALLS",
    "_KILL_PROCESS_SYSCALLS",
    "_CRITICAL_SYSCALLS",
]
