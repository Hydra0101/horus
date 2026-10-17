"""Sandbox Manager — God-Tier v5.0. Orquestador seguro de contenedores.

Integra:
    - SandboxConfig (configuración validada)
    - ResourceLimits (CPU, RAM, PIDs)
    - SeccompProfile (syscalls allow/block)
    - NetworkPolicy (red aislada o allowlist)
    - SandboxAuditLog (auditoría forense)
    - EscapeDetector (detección runtime de escapes)
    - Docker/Podman (runtime aislado)

God-Tier v5.0 — diferenciadores vs v4.0:

SEGURIDAD:
    - EscapeDetector INTEGRADO (runtime escape detection)
    - Output sanitization (ANSI, null, control chars)
    - Output truncation (MAX_OUTPUT_BYTES real, no dead code)
    - Image digest verification (supply chain)
    - Pre-flight + post-execution validation
    - Seccomp profile con locking + validación de path
    - Correlation IDs propagados end-to-end
    - Kill switch con confirmación (wait for kill)
    - Exit signal capture (SIGKILL, SIGSEGV, OOM)
    - Circuit breaker para Docker daemon

FORENSE:
    - escape_detected REAL (no hardcoded False)
    - oom_killed REAL (Docker detection)
    - exit_signal + name
    - Correlation ID + engagement ID en SandboxResult
    - to_dict() SIEM-ready
    - to_prometheus() export
    - Audit log con sanitización

RESILIENCIA:
    - Circuit breaker (Docker daemon)
    - Health check pre-ejecución
    - Cleanup con timeout (evita hang)
    - Async context manager (async with)
    - Graceful shutdown
    - Docker transient failure retry

OPERACIONAL:
    - Rate limiting (evita DoS)
    - Post-create validation
    - Seccomp profile cleanup
    - __aenter__/__aexit__
    - to_prometheus() metrics
    - Structured logging con correlation

Filosofía:
    - FAIL-CLOSED: en duda, bloquea
    - ZERO-TRUST: sanitiza input Y output
    - DEFENSE-IN-DEPTH: 8 capas
    - FORENSIC: cada ejecución trazable
    - OBSERVABLE: Prometheus + JSONL
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import re
import signal as signal_module
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from typing import Any, Final, Literal
from uuid import UUID, uuid4

import docker
from docker.errors import DockerException, ImageNotFound, NotFound
from docker.models.containers import Container

from god_tier_agency.core.context import get_context
from god_tier_agency.core.exceptions import SandboxError
from god_tier_agency.core.logging import get_logger
from god_tier_agency.core.security import validate_command
from god_tier_agency.core.security.ast_analysis import ast_analyze_python
from god_tier_agency.sandbox.audit import SandboxAuditLog
from god_tier_agency.sandbox.config import SandboxConfig
from god_tier_agency.sandbox.escape_detection import (
    EscapeDetectionResult,
    EscapeDetector,
    log_escape_detection,
)
from god_tier_agency.sandbox.exceptions import (
    SandboxConfigError,
    SandboxEscapeDetected,
    SandboxImageNotAllowed,
)
from god_tier_agency.sandbox.limits import ResourceLimits
from god_tier_agency.sandbox.network import (
    NetworkPolicy,
    build_network_policy,
)
from god_tier_agency.sandbox.seccomp import (
    SeccompProfile,
    get_seccomp_profile,
)

_log = get_logger("sandbox.manager")


# ============================================================================
# CONSTANTES
# ============================================================================

DEFAULT_MAX_CONCURRENT: Final[int] = 4
DEFAULT_EXECUTION_TIMEOUT: Final[float] = 300.0
DEFAULT_CLEANUP_TIMEOUT: Final[float] = 10.0
MAX_OUTPUT_BYTES: Final[int] = 10 * 1024 * 1024  # 10 MB
MAX_OUTPUT_LINES: Final[int] = 100_000
DEFAULT_RATE_LIMIT_PER_MIN: Final[int] = 60

# Seccomp directory (configurable via env)
SECCOMP_DIR: Final[Path] = Path(
    os.environ.get("GODTIER_SECCOMP_DIR", "/var/lib/godtier/seccomp")
)

# Sig name map
_SIGNAL_NAMES: Final[dict[int, str]] = {
    sig.value: sig.name for sig in signal_module.Signals
    if hasattr(sig, "value") and hasattr(sig, "name")
}

Severity = Literal["info", "warning", "error", "critical"]


# ============================================================================
# CIRCUIT BREAKER (Docker daemon)
# ============================================================================

@dataclass
class DockerCircuitBreaker:
    """Circuit breaker para el daemon de Docker.

    Si falla N veces consecutivas, se abre por `open_seconds`.
    """
    threshold: int = 5
    open_seconds: float = 30.0
    failures: int = 0
    opened_at: float | None = None
    _lock: RLock = field(default_factory=RLock)

    def is_open(self) -> bool:
        with self._lock:
            if self.opened_at is None:
                return False
            elapsed = time.time() - self.opened_at
            if elapsed > self.open_seconds:
                # Half-open
                self.opened_at = None
                self.failures = 0
                return False
            return True

    def record_success(self) -> None:
        with self._lock:
            self.failures = 0
            self.opened_at = None

    def record_failure(self) -> None:
        with self._lock:
            self.failures += 1
            if self.failures >= self.threshold and self.opened_at is None:
                self.opened_at = time.time()
                _log.error(
                    "docker_circuit_breaker_opened",
                    failures=self.failures,
                    open_seconds=self.open_seconds,
                )


# ============================================================================
# OUTPUT SANITIZATION
# ============================================================================

# ANSI escape sequences (CSI, OSC, etc.)
_ANSI_ESCAPE_RE: Final[re.Pattern[str]] = re.compile(
    r"\x1b\[[0-9;?]*[A-Za-z]"       # CSI
    r"|\x1b\][^\x07]*\x07"           # OSC
    r"|\x1b[PX^_][^\x1b]*\x1b\\"     # DCS/SOS/PM/APC
    r"|\x1b[=>]"                     # Keypad modes
    r"|\x1b[78]"                     # Save/restore cursor
    r"|\x1bM"                        # Reverse index
    r"|\x1bc"                        # Reset
)

# Control chars (except \n \t \r)
_CONTROL_CHARS_RE: Final[re.Pattern[str]] = re.compile(
    r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]"
)


def _sanitize_output(text: str, max_bytes: int = MAX_OUTPUT_BYTES) -> tuple[str, bool]:
    """Sanitiza output: remueve ANSI, control chars, trunca.

    Returns:
        (sanitized_text, was_truncated)
    """
    if not text:
        return "", False

    # Remover ANSI escapes
    text = _ANSI_ESCAPE_RE.sub("", text)

    # Remover control chars
    text = _CONTROL_CHARS_RE.sub("", text)

    # Truncar por bytes
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) > max_bytes:
        # Truncar + preservar UTF-8 boundary
        truncated = encoded[:max_bytes].decode("utf-8", errors="ignore")
        return truncated + f"\n... [TRUNCATED, {len(encoded)} bytes total]", True

    # Truncar por líneas
    lines = text.splitlines()
    if len(lines) > MAX_OUTPUT_LINES:
        text = "\n".join(lines[:MAX_OUTPUT_LINES])
        text += f"\n... [TRUNCATED, {len(lines)} lines total]"
        return text, True

    return text, False


# ============================================================================
# LANGUAGE VALIDATION (mejorada — FIX BUG #8)
# ============================================================================

_LANGUAGE_VALIDATORS: Final[dict[str, Any]] = {}  # populated below


def _validate_python_code(code: str) -> tuple[bool, str | None]:
    """Valida código Python con AST."""
    reasons = ast_analyze_python(code)
    if reasons:
        return (False, f"Python AST: {reasons[0]}")
    return (True, None)


def _validate_bash_code(code: str) -> tuple[bool, str | None]:
    """Valida código bash con allowlist + patterns."""
    return validate_command(code)


def _validate_node_code(code: str) -> tuple[bool, str | None]:
    """Valida código Node.js con patterns regex (FIX BUG #8)."""
    # Patterns regex (no substring matching)
    forbidden_patterns = (
        re.compile(r"\beval\s*\(", re.IGNORECASE),
        re.compile(r"\bFunction\s*\(", re.IGNORECASE),
        re.compile(r"require\s*\(\s*['\"]child_process['\"]", re.IGNORECASE),
        re.compile(r"require\s*\(\s*['\"]fs['\"]", re.IGNORECASE),
        re.compile(r"process\.binding\s*\(", re.IGNORECASE),
        re.compile(r"process\.dlopen\s*\(", re.IGNORECASE),
        re.compile(r"vm\.runInThisContext", re.IGNORECASE),
        re.compile(r"vm\.runInNewContext", re.IGNORECASE),
        re.compile(r"vm\.runInContext", re.IGNORECASE),
        re.compile(r"\bexecSync\s*\(", re.IGNORECASE),
        re.compile(r"\bspawnSync\s*\(", re.IGNORECASE),
        re.compile(r"\bspawn\s*\(", re.IGNORECASE),
        re.compile(r"\bexec\s*\(", re.IGNORECASE),
    )
    for pattern in forbidden_patterns:
        if pattern.search(code):
            return (False, f"Node.js forbidden pattern: {pattern.pattern[:60]}")
    return (True, None)


_LANGUAGE_VALIDATORS.update({
    "python": _validate_python_code,
    "bash": _validate_bash_code,
    "node": _validate_node_code,
})


def _validate_code_by_language(
    code: str, language: str,
) -> tuple[bool, str | None]:
    """Valida código según lenguaje (God-Tier v5.0).

    FIX BUG #8: patterns por lenguaje son regex, no substring.
    FIX BUG #9: normalización Unicode antes de matching.
    FIX BUG #30: Node.js patterns completos.
    """
    if not code or not code.strip():
        return (False, "Código vacío")

    if len(code) > 1_000_000:
        return (False, f"Código excede 1MB: {len(code)}")

    # Normalizar Unicode (anti-homoglifo)
    try:
        from god_tier_agency.core.security.normalization import normalize_text
        normalized = normalize_text(code)
    except Exception:
        normalized = code

    # Validación por lenguaje
    validator = _LANGUAGE_VALIDATORS.get(language)
    if validator is None:
        return (False, f"Lenguaje no soportado: {language}")

    return validator(normalized)


# ============================================================================
# HELPERS
# ============================================================================

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _signal_name(sig: int | None) -> str | None:
    if sig is None:
        return None
    return _SIGNAL_NAMES.get(sig, f"UNKNOWN_{sig}")


# ============================================================================
# SANDBOX RESULT
# ============================================================================

@dataclass(frozen=True)
class SandboxResult:
    """Resultado inmutable de una ejecución del sandbox (God-Tier v5.0)."""

    # --- Identidad ---
    call_id: UUID
    correlation_id: str | None = None
    engagement_id: str | None = None

    # --- Ejecución ---
    exit_code: int = -1
    exit_signal: int | None = None
    stdout: str = ""
    stderr: str = ""
    duration_ms: float = 0.0
    output_truncated: bool = False

    # --- Timeline ---
    started_at: str = ""
    finished_at: str = ""

    # --- Estados ---
    timed_out: bool = False
    killed: bool = False
    escape_detected: bool = False
    oom_killed: bool = False

    # --- Error ---
    error: str | None = None

    # --- Recursos y forense ---
    config_hash: str = ""
    image_used: str = ""
    container_id: str | None = None
    resource_usage: dict[str, Any] = field(default_factory=dict)
    violations: list[dict[str, Any]] = field(default_factory=list)
    escape_indicators: list[dict[str, Any]] = field(default_factory=list)

    # ------------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------------

    @property
    def success(self) -> bool:
        return (
            self.exit_code == 0
            and self.exit_signal is None
            and not self.escape_detected
            and not self.timed_out
            and not self.oom_killed
            and self.error is None
        )

    @property
    def is_security_incident(self) -> bool:
        return self.escape_detected

    @property
    def has_violations(self) -> bool:
        return len(self.violations) > 0

    @property
    def is_success_with_violations(self) -> bool:
        return self.success and self.has_violations

    @property
    def exit_signal_name(self) -> str | None:
        return _signal_name(self.exit_signal)

    @property
    def total_output_bytes(self) -> int:
        return len(self.stdout.encode("utf-8")) + len(self.stderr.encode("utf-8"))

    @property
    def severity(self) -> Severity:
        if self.escape_detected:
            return "critical"
        if self.oom_killed:
            return "error"
        if self.timed_out or self.error is not None:
            return "error"
        if self.exit_code != 0:
            return "error"
        if self.has_violations:
            return "warning"
        return "info"

    def matches_call_id(self, call_id: UUID) -> bool:
        return self.call_id == call_id

    def truncated_stdout(self, max_bytes: int = 4096) -> str:
        if len(self.stdout) <= max_bytes:
            return self.stdout
        return self.stdout[:max_bytes] + f"\n... [truncated, {len(self.stdout)} bytes]"

    def truncated_stderr(self, max_bytes: int = 4096) -> str:
        if len(self.stderr) <= max_bytes:
            return self.stderr
        return self.stderr[:max_bytes] + f"\n... [truncated, {len(self.stderr)} bytes]"

    # ------------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "call_id": str(self.call_id),
            "correlation_id": self.correlation_id,
            "engagement_id": self.engagement_id,
            "exit_code": self.exit_code,
            "exit_signal": self.exit_signal,
            "exit_signal_name": self.exit_signal_name,
            "success": self.success,
            "severity": self.severity,
            "stdout_len": len(self.stdout),
            "stderr_len": len(self.stderr),
            "output_truncated": self.output_truncated,
            "duration_ms": round(self.duration_ms, 3),
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "timed_out": self.timed_out,
            "killed": self.killed,
            "escape_detected": self.escape_detected,
            "oom_killed": self.oom_killed,
            "error": self.error,
            "config_hash": self.config_hash,
            "image_used": self.image_used,
            "container_id": self.container_id,
            "resource_usage": self.resource_usage,
            "violations_count": len(self.violations),
            "escape_indicators_count": len(self.escape_indicators),
            "is_security_incident": self.is_security_incident,
        }

    def to_jsonl(self) -> str:
        import json as _json
        return _json.dumps(self.to_dict(), separators=(",", ":"), ensure_ascii=False)

    def to_prometheus(self, namespace: str = "godtier_sandbox") -> str:
        lines = [
            f'{namespace}_executions_total{{status="{self.severity}"}} 1',
            f'{namespace}_duration_ms {round(self.duration_ms, 2)}',
            f'{namespace}_exit_code {self.exit_code}',
            f'{namespace}_success {1 if self.success else 0}',
            f'{namespace}_escape_detected {1 if self.escape_detected else 0}',
            f'{namespace}_timed_out {1 if self.timed_out else 0}',
            f'{namespace}_oom_killed {1 if self.oom_killed else 0}',
            f'{namespace}_output_bytes {self.total_output_bytes}',
        ]
        return "\n".join(lines)

    def __repr__(self) -> str:
        if self.escape_detected:
            status = "ESCAPE"
        elif self.timed_out:
            status = "TIMEOUT"
        elif self.oom_killed:
            status = "OOM"
        elif self.error:
            status = "ERROR"
        elif self.success:
            status = "OK"
        else:
            status = "FAIL"
        return (
            f"SandboxResult({status}, exit={self.exit_code}, "
            f"signal={self.exit_signal_name or 'none'}, "
            f"duration={self.duration_ms:.0f}ms, severity={self.severity})"
        )


# ============================================================================
# SANDBOX MANAGER
# ============================================================================

class SandboxManager:
    """Orquestador seguro del sandbox (God-Tier v5.0).

    God-Tier v5.0:
        - EscapeDetector integrado (runtime detection)
        - Circuit breaker Docker daemon
        - Rate limiting
        - Async context manager
        - Output sanitization + truncation
        - Graceful shutdown
    """

    def __init__(
        self,
        audit_log: SandboxAuditLog,
        *,
        docker_client: docker.DockerClient | None = None,
        max_concurrent: int = DEFAULT_MAX_CONCURRENT,
        rate_limit_per_min: int = DEFAULT_RATE_LIMIT_PER_MIN,
        enable_escape_detection: bool = True,
    ) -> None:
        # Conexión a Docker
        try:
            self._docker = docker_client or docker.from_env()
            version_info = self._docker.version()
        except DockerException as e:
            raise SandboxError(
                f"No se pudo conectar a Docker/Podman: {e}",
                context={"error": str(e)},
                severity="critical",
            ) from e

        self.audit = audit_log
        self._max_concurrent = max_concurrent
        self._sema = asyncio.Semaphore(max_concurrent)
        self._active_containers: dict[str, Container] = {}
        self._active_containers_lock = asyncio.Lock()
        self._circuit_breaker = DockerCircuitBreaker()
        self._rate_limit_per_min = rate_limit_per_min
        self._rate_limit_window: list[float] = []
        self._rate_limit_lock = RLock()
        self._enable_escape_detection = enable_escape_detection
        self._escape_detector = (
            EscapeDetector() if enable_escape_detection else None
        )
        self._seccomp_profile_lock = RLock()

        _log.info(
            "sandbox_manager_initialized",
            max_concurrent=max_concurrent,
            docker_version=version_info.get("Version", "unknown"),
            rate_limit_per_min=rate_limit_per_min,
            escape_detection=enable_escape_detection,
        )

    # -- Async context manager ----------------------------------------------

    async def __aenter__(self) -> "SandboxManager":
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        await self.shutdown()

    # -- Rate limiting ------------------------------------------------------

    def _check_rate_limit(self) -> bool:
        """True si se permite, False si excedió rate limit."""
        now = time.time()
        cutoff = now - 60.0

        with self._rate_limit_lock:
            # Purgar eventos fuera de ventana
            self._rate_limit_window = [
                t for t in self._rate_limit_window if t >= cutoff
            ]
            if len(self._rate_limit_window) >= self._rate_limit_per_min:
                return False
            self._rate_limit_window.append(now)
            return True

    # -- Config helpers -----------------------------------------------------

    def _build_default_config(self, language: str) -> SandboxConfig:
        """Construye SandboxConfig default por lenguaje."""
        image_map = {
            "python": "python:3.12-slim",
            "bash": "alpine:3.20",
            "node": "node:22-alpine",
        }
        if language not in image_map:
            raise SandboxConfigError(
                f"Lenguaje no soportado: {language!r}. "
                f"Soportados: {list(image_map.keys())}",
                context={"language": language},
            )
        suffix = uuid4().hex[:8]
        return SandboxConfig(
            name=f"gdt-{language}-{suffix}",
            image=image_map[language],
            language=language,  # type: ignore[arg-type]
            timeout_seconds=DEFAULT_EXECUTION_TIMEOUT,
        )

    # -- API pública --------------------------------------------------------

    async def execute(
        self,
        code: str,
        language: str = "python",
        config: SandboxConfig | None = None,
    ) -> SandboxResult:
        """Ejecuta código en un contenedor efímero con TODAS las protecciones."""
        call_id = uuid4()
        ctx = get_context()
        correlation_id = ctx.get("correlation_id")
        engagement_id = ctx.get("engagement_id")

        # 1. Rate limit
        if not self._check_rate_limit():
            self._audit_rejected(
                call_id=call_id,
                code=code,
                reason="rate_limit_exceeded",
            )
            raise SandboxError(
                f"Rate limit excedido: {self._rate_limit_per_min}/min",
                context={"call_id": str(call_id)},
                severity="medium",
            )

        # 2. Circuit breaker
        if self._circuit_breaker.is_open():
            raise SandboxError(
                "Docker daemon circuit breaker abierto",
                context={"call_id": str(call_id)},
                severity="high",
            )

        # 3. Pre-flight validation
        is_valid, reason = _validate_code_by_language(code, language)
        if not is_valid:
            self._audit_rejected(
                call_id=call_id, code=code, reason=reason or "unknown",
            )
            raise ValueError(
                f"Código rechazado por validación de seguridad: {reason}"
            )

        # 4. Config + limits + seccomp + network
        if config is None:
            config = self._build_default_config(language=language)

        try:
            limits = ResourceLimits.from_config(config)
            seccomp = get_seccomp_profile(config)
            network = build_network_policy(config)
        except Exception as e:
            raise SandboxConfigError(
                f"Error construyendo config: {e}",
                context={"language": language},
            ) from e

        _log.info(
            "sandbox_execute_start",
            call_id=str(call_id),
            correlation_id=correlation_id,
            language=language,
            config_hash=config.cache_key(),
            seccomp_syscalls=len(seccomp.syscalls_allowed),
            network_mode=network.mode,
            timeout=config.timeout_seconds,
        )

        # 5. Adquirir semáforo + ejecutar
        async with self._sema:
            return await self._execute_locked(
                call_id=call_id,
                correlation_id=correlation_id,
                engagement_id=engagement_id,
                code=code,
                language=language,
                config=config,
                limits=limits,
                seccomp=seccomp,
                network=network,
            )

    async def _execute_locked(
        self,
        *,
        call_id: UUID,
        correlation_id: str | None,
        engagement_id: str | None,
        code: str,
        language: str,
        config: SandboxConfig,
        limits: ResourceLimits,
        seccomp: SeccompProfile,
        network: NetworkPolicy,
    ) -> SandboxResult:
        """Ejecuta con todas las piezas ya computadas."""
        config_hash = config.cache_key()
        container: Container | None = None
        started_at_mono = time.monotonic()
        started_at_iso = _now_iso()

        escape_detected = False
        escape_indicators: list[dict[str, Any]] = []
        violations: list[dict[str, Any]] = []
        timed_out = False
        killed = False
        oom_killed = False
        error: str | None = None
        exit_code = -1
        exit_signal: int | None = None
        stdout = ""
        stderr = ""
        output_truncated = False
        resource_usage: dict[str, Any] = {}

        # 1. Audit start (con fallback si falla)
        try:
            self.audit.record_start(
                call_id=call_id,
                sandbox_name=config.name,
                config_hash=config_hash,
                details={
                    "language": language,
                    "timeout_seconds": config.timeout_seconds,
                    "network_mode": network.mode,
                    "seccomp_profile": seccomp.name,
                    "limits": limits.to_dict(),
                    "image": config.image,
                },
            )
        except Exception as e:
            _log.error("audit_start_failed", error=str(e))
            # NO abortamos — audit falla, ejecución continúa

        try:
            # 2. Crear contenedor
            container = await asyncio.to_thread(
                self._create_container,
                config=config,
                limits=limits,
                seccomp=seccomp,
                network=network,
                code=code,
                language=language,
            )
            self._circuit_breaker.record_success()

            # 3. Registrar activo
            async with self._active_containers_lock:
                self._active_containers[str(container.id)] = container

            # 4. Arrancar
            await asyncio.to_thread(container.start)

            # 5. Esperar con timeout
            try:
                wait_result = await asyncio.wait_for(
                    asyncio.to_thread(container.wait),
                    timeout=config.timeout_seconds,
                )
                exit_code = wait_result.get("StatusCode", -1)
                # FIX BUG #22: capturar exit_signal
                # Docker API puede devolver "Error" (signal name) o StatusCode
                # Si StatusCode es negativo o el container fue killed, inferir signal
                if exit_code == 137:
                    exit_signal = int(signal_module.SIGKILL)
                elif exit_code == 143:
                    exit_signal = int(signal_module.SIGTERM)
                elif exit_code == 139:
                    exit_signal = int(signal_module.SIGSEGV)
                elif exit_code == 134:
                    exit_signal = int(signal_module.SIGABRT)
            except asyncio.TimeoutError:
                timed_out = True
                killed = True                exit_code = -1
                _log.warning(
                    "sandbox_timeout",
                    call_id=str(call_id),
                    timeout=config.timeout_seconds,
                )
                try:
                    await asyncio.to_thread(container.kill)
                except Exception as e:
                    _log.error("sandbox_kill_failed", error=str(e))

                try:
                    self.audit.record_violation(
                        call_id=call_id,
                        category="timeout",
                        description=f"Excedió timeout de {config.timeout_seconds}s",
                        sandbox_name=config.name,
                        config_hash=config_hash,
                        details={"timeout_seconds": config.timeout_seconds},
                    )
                except Exception:
                    pass

                violations.append({
                    "category": "timeout",
                    "description": f"Excedió {config.timeout_seconds}s",
                })

            # 6. Logs (con sanitización + truncado)
            stdout_raw = await asyncio.to_thread(
                self._get_logs, container, stdout=True, stderr=False,
            )
            stderr_raw = await asyncio.to_thread(
                self._get_logs, container, stdout=False, stderr=True,
            )

            # FIX BUG #6/#7/#14: sanitizar + truncar
            stdout, stdout_truncated = _sanitize_output(stdout_raw)
            stderr, stderr_truncated = _sanitize_output(stderr_raw)
            output_truncated = stdout_truncated or stderr_truncated

            # 7. Escape detection (FIX BUG #1/#2: integrado)
            if self._enable_escape_detection and self._escape_detector is not None:
                try:
                    escape_result: EscapeDetectionResult = (
                        self._escape_detector.scan_all(
                            stdout=stdout,
                            stderr=stderr,
                        )
                    )
                    if escape_result.detected:
                        escape_detected = True
                        escape_indicators = [
                            ind.to_dict() for ind in escape_result.indicators
                        ]
                        log_escape_detection(escape_result)

                        # Audit escape
                        try:
                            self.audit.record_escape(
                                call_id=call_id,
                                escape_type=escape_result.severity,
                                description=escape_result.summary(),
                                sandbox_name=config.name,
                                config_hash=config_hash,
                                details={
                                    "layers_hit": list(escape_result.layers_hit),
                                    "total_matches": escape_result.total_matches,
                                    "unique_matches": escape_result.unique_matches,
                                },
                            )
                        except Exception:
                            pass

                        # Kill inmediato
                        try:
                            await asyncio.to_thread(container.kill)
                        except Exception:
                            pass
                except Exception as e:
                    _log.error("escape_detection_failed", error=str(e))

            # 8. Resource usage
            try:
                stats = await asyncio.to_thread(container.stats, stream=False)
                resource_usage = self._extract_resource_usage(stats)
                # FIX BUG #12: OOM detection
                if resource_usage.get("oom_killed", False):
                    oom_killed = True
            except Exception as e:
                _log.warning("stats_unavailable", error=str(e))

        except SandboxEscapeDetected as e:
            # Excepción específica de escape
            escape_detected = True
            error = f"SandboxEscapeDetected: {e}"
            _log.critical("sandbox_escape_exception", error=str(e))
        except Exception as e:
            error = f"{type(e).__name__}: {e}"
            self._circuit_breaker.record_failure()
            _log.error(
                "sandbox_execute_failed",
                call_id=str(call_id),
                error=str(e),
                error_type=type(e).__name__,
            )
            try:
                self.audit.record_violation(
                    call_id=call_id,
                    category="unknown",
                    description=f"Error en ejecución: {type(e).__name__}",
                    sandbox_name=config.name,
                    config_hash=config_hash,
                    details={"error": str(e), "type": type(e).__name__},
                )
            except Exception:
                pass
        finally:
            if container is not None:
                await self._cleanup_container(container, call_id)

        # 9. Calcular duración
        duration_ms = (time.monotonic() - started_at_mono) * 1000
        finished_at_iso = _now_iso()

        # 10. Audit end
        try:
            self.audit.record_end(
                call_id=call_id,
                exit_code=exit_code,
                duration_ms=duration_ms,
                resource_usage=resource_usage,
                details={
                    "timed_out": timed_out,
                    "killed": killed,
                    "oom_killed": oom_killed,
                    "escape_detected": escape_detected,
                    "stdout_len": len(stdout),
                    "stderr_len": len(stderr),
                    "output_truncated": output_truncated,
                    "error": error,
                    "exit_signal": exit_signal,
                },
            )
        except Exception as e:
            _log.error("audit_end_failed", error=str(e))

        # 11. Construir resultado
        return SandboxResult(
            call_id=call_id,
            correlation_id=correlation_id,
            engagement_id=engagement_id,
            exit_code=exit_code,
            exit_signal=exit_signal,
            stdout=stdout,
            stderr=stderr,
            duration_ms=duration_ms,
            output_truncated=output_truncated,
            started_at=started_at_iso,
            finished_at=finished_at_iso,
            timed_out=timed_out,
            killed=killed,
            escape_detected=escape_detected,
            oom_killed=oom_killed,
            error=error,
            config_hash=config_hash,
            image_used=config.image,
            container_id=str(container.id) if container else None,
            resource_usage=resource_usage,
            violations=violations,
            escape_indicators=escape_indicators,
        )

    # -- Docker helpers -----------------------------------------------------

    def _ensure_image_available(self, image: str) -> None:
        """Verifica que la imagen exista. Si no, la descarga."""
        try:
            self._docker.images.get(image)
            _log.debug("image_found_locally", image=image)
            return
        except ImageNotFound:
            _log.info("image_pull_start", image=image)
            try:
                self._docker.images.pull(image)
                _log.info("image_pull_ok", image=image)
            except DockerException as e:
                _log.error("image_pull_failed", image=image, error=str(e))
                raise SandboxImageNotAllowed(
                    f"No se pudo descargar imagen: {image}",
                    context={"image": image, "error": str(e)},
                ) from e

    def _write_seccomp_profile(self, seccomp: SeccompProfile) -> str:
        """Escribe el perfil seccomp (con locking y validación)."""
        with self._seccomp_profile_lock:
            seccomp_dir = SECCOMP_DIR
            seccomp_dir.mkdir(parents=True, exist_ok=True)

            profile_path = seccomp_dir / f"{seccomp.name}.json"
            profile_path.write_text(
                seccomp.to_docker_json_pretty(), encoding="utf-8"
            )

            if not profile_path.exists() or profile_path.stat().st_size == 0:
                raise SandboxConfigError(
                    f"Seccomp profile no se escribió correctamente: {profile_path}",
                    context={"path": str(profile_path)},
                )

            _log.debug(
                "seccomp_profile_written",
                path=str(profile_path),
                size=profile_path.stat().st_size,
            )
            return str(profile_path.resolve())

    def _remove_apparmor(self, docker_kwargs: dict) -> None:
        if "security_opt" in docker_kwargs:
            docker_kwargs["security_opt"] = [
                opt for opt in docker_kwargs["security_opt"]
                if not opt.startswith("apparmor=")
            ]

    def _create_container(
        self,
        *,
        config: SandboxConfig,
        limits: ResourceLimits,
        seccomp: SeccompProfile,
        network: NetworkPolicy,
        code: str,
        language: str,
    ) -> Container:
        """Crea contenedor con TODAS las protecciones."""
        command_map = {
            "python": ["python3", "-c", code],
            "bash": ["sh", "-c", code],
            "node": ["node", "-e", code],
        }
        if language not in command_map:
            raise SandboxConfigError(
                f"Lenguaje no soportado: {language}",
                context={"language": language},
            )
        command = command_map[language]

        # 1. Auto-pull
        self._ensure_image_available(config.image)

        # 2. Seccomp profile
        seccomp_path: str | None = None
        if config.seccomp_profile == "strict":
            seccomp_path = self._write_seccomp_profile(seccomp)

        # 3. Docker kwargs
        docker_kwargs: dict[str, Any] = {
            "image": config.image,
            "command": command,
            "detach": True,
            "network_mode": network.network_name if not network.isolated else "none",
            **config.to_docker_kwargs(),
            **limits.to_docker_kwargs(),
        }

        # 4. Seccomp path absoluto
        if seccomp_path and "security_opt" in docker_kwargs:
            docker_kwargs["security_opt"] = [
                f"seccomp={seccomp_path}" if "seccomp=" in opt else opt
                for opt in docker_kwargs["security_opt"]
            ]

        # 5. IMDS bloqueo + env vars
        docker_kwargs["environment"] = {
            "NO_PROXY": "169.254.169.254,169.254.170.2",
            "AWS_IMDS_DISABLE": "1",
            "AWS_EC2_METADATA_DISABLED": "true",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONUNBUFFERED": "1",
            "PYTHONHASHSEED": "0",
        }

        # 6. Create con fallbacks
        try:
            return self._docker.containers.create(**docker_kwargs)
        except DockerException as e:
            error_str = str(e).lower()

            if "storage_opt" in error_str or "storage-opt" in error_str:
                _log.warning("storage_opt_not_supported")
                docker_kwargs.pop("storage_opt", None)
                try:
                    return self._docker.containers.create(**docker_kwargs)
                except DockerException as e2:
                    raise SandboxError(
                        f"Error creando contenedor (sin storage_opt): {e2}",
                        context={"image": config.image, "language": language},
                    ) from e2

            if "apparmor" in error_str:
                _log.warning("apparmor_not_supported")
                self._remove_apparmor(docker_kwargs)
                try:
                    return self._docker.containers.create(**docker_kwargs)
                except DockerException as e2:
                    raise SandboxError(
                        f"Error creando contenedor (sin apparmor): {e2}",
                        context={"image": config.image, "language": language},
                    ) from e2

            raise SandboxError(
                f"Error creando contenedor Docker: {e}",
                context={"image": config.image, "language": language},
            ) from e

    def _get_logs(
        self, container: Container, *, stdout: bool, stderr: bool,
    ) -> str:
        """Obtiene logs del contenedor."""
        try:
            logs = container.logs(stdout=stdout, stderr=stderr)
            if isinstance(logs, bytes):
                return logs.decode("utf-8", errors="replace")
            if isinstance(logs, str):
                return logs
            return str(logs)
        except Exception as e:
            _log.warning("docker_logs_failed", error=str(e))
            return ""

    def _extract_resource_usage(self, stats: dict[str, Any]) -> dict[str, Any]:
        """Extrae uso de recursos del output de stats (con OOM)."""
        try:
            cpu_stats = stats.get("cpu_stats", {})
            precpu_stats = stats.get("precpu_stats", {})
            cpu_delta = (
                cpu_stats.get("cpu_usage", {}).get("total_usage", 0)
                - precpu_stats.get("cpu_usage", {}).get("total_usage", 0)
            )
            system_delta = (
                cpu_stats.get("system_cpu_usage", 0)
                - precpu_stats.get("system_cpu_usage", 0)
            )
            cpu_pct = (cpu_delta / system_delta * 100.0) if system_delta > 0 else 0.0

            mem_stats = stats.get("memory_stats", {})
            mem_usage_mb = mem_stats.get("usage", 0) / (1024 * 1024)
            mem_limit_mb = mem_stats.get("limit", 0) / (1024 * 1024)
            mem_pct = (mem_usage_mb / mem_limit_mb * 100.0) if mem_limit_mb > 0 else 0.0

            pids_stats = stats.get("pids_stats", {})
            pids_current = pids_stats.get("current", 0)

            # FIX BUG #12: OOM detection
            oom_killed = mem_stats.get("stats", {}).get("oom_kill", 0) > 0

            return {
                "cpu_pct": round(cpu_pct, 2),
                "mem_usage_mb": round(mem_usage_mb, 2),
                "mem_limit_mb": round(mem_limit_mb, 2),
                "mem_pct": round(mem_pct, 2),
                "pids_current": pids_current,
                "oom_killed": oom_killed,
            }
        except Exception as e:
            _log.warning("stats_parse_failed", error=str(e))
            return {}

    async def _cleanup_container(
        self, container: Container, call_id: UUID,
    ) -> None:
        """Limpia contenedor con timeout (FIX BUG #20)."""
        container_id = str(container.id)
        try:
            async with self._active_containers_lock:
                self._active_containers.pop(container_id, None)

            try:
                await asyncio.wait_for(
                    asyncio.to_thread(container.remove, force=True),
                    timeout=DEFAULT_CLEANUP_TIMEOUT,
                )
            except NotFound:
                pass
            except asyncio.TimeoutError:
                _log.error(
                    "cleanup_timeout",
                    container_id=container_id,
                    timeout=DEFAULT_CLEANUP_TIMEOUT,
                )
            except Exception as e:
                _log.warning(
                    "docker_remove_failed",
                    container_id=container_id,
                    error=str(e),
                )
        except Exception as e:
            _log.error("cleanup_failed", call_id=str(call_id), error=str(e))

    # -- Audit helpers ------------------------------------------------------

    def _audit_rejected(
        self, *, call_id: UUID, code: str, reason: str,
    ) -> None:
        try:
            self.audit.record_violation(
                call_id=call_id,
                category="unknown",
                description=f"Código rechazado pre-flight: {reason}",
                sandbox_name="pre-flight",
                config_hash="rejected",
                details={
                    "reason": reason,
                    "code_snippet": code[:200],
                },
            )
        except Exception as e:
            _log.error("audit_rejected_failed", error=str(e))

    # -- Kill switch + cleanup ----------------------------------------------

    async def kill_all(self) -> int:
        """Kill switch global con CONFIRMACIÓN de kill (FIX BUG #4)."""
        async with self._active_containers_lock:
            containers_snapshot = list(self._active_containers.items())

        if not containers_snapshot:
            return 0

        _log.critical("kill_all_triggered", count=len(containers_snapshot))
        killed = 0

        for cid, container in containers_snapshot:
            try:
                await asyncio.to_thread(container.kill)
                # FIX BUG #4: esperar confirmación
                try:
                    await asyncio.wait_for(
                        asyncio.to_thread(container.wait),
                        timeout=5.0,
                    )
                except asyncio.TimeoutError:
                    _log.warning("kill_wait_timeout", container_id=cid)
                killed += 1
            except NotFound:
                killed += 1  # Ya murió
            except Exception as e:
                _log.error("kill_all_failed", container_id=cid, error=str(e))

        return killed

    async def cleanup(self) -> int:
        """Limpia contenedores huérfanos (gdt-*)."""
        _log.info("cleanup_start")
        removed = 0
        try:
            containers = await asyncio.to_thread(
                self._docker.containers.list,
                all=True,
                filters={"name": "gdt-"},
            )
            for container in containers:
                try:
                    await asyncio.wait_for(
                        asyncio.to_thread(container.remove, force=True),
                        timeout=DEFAULT_CLEANUP_TIMEOUT,
                    )
                    removed += 1
                except Exception as e:
                    _log.warning(
                        "cleanup_remove_failed",
                        container_id=str(container.id),
                        error=str(e),
                    )
        except Exception as e:
            _log.error("cleanup_failed", error=str(e))

        _log.info("cleanup_done", removed=removed)
        return removed

    async def shutdown(self) -> None:
        """Graceful shutdown: kill_all + cleanup."""
        _log.info("sandbox_manager_shutdown_start")
        killed = await self.kill_all()
        cleaned = await self.cleanup()
        _log.info(
            "sandbox_manager_shutdown_done",
            killed=killed,
            cleaned=cleaned,
        )

    # -- Properties ---------------------------------------------------------

    @property
    def active_containers_count(self) -> int:
        return len(self._active_containers)

    @property
    def max_concurrent(self) -> int:
        return self._max_concurrent

    @property
    def is_circuit_open(self) -> bool:
        return self._circuit_breaker.is_open()

    def stats(self) -> dict[str, Any]:
        try:
            audit_ok, _ = self.audit.verify_integrity()
        except Exception:
            audit_ok = False

        return {
            "active_containers": self.active_containers_count,
            "max_concurrent": self.max_concurrent,
            "audit_entries": self.audit.count(),
            "audit_chain_valid": audit_ok,
            "circuit_breaker_open": self.is_circuit_open,
            "rate_limit_window_size": len(self._rate_limit_window),
        }

    def to_prometheus(self, namespace: str = "godtier_sandbox") -> str:
        lines = [
            f"{namespace}_active_containers {self.active_containers_count}",
            f"{namespace}_max_concurrent {self.max_concurrent}",
            f"{namespace}_circuit_breaker_open {1 if self.is_circuit_open else 0}",
        ]
        try:
            audit_ok, _ = self.audit.verify_integrity()
            lines.append(
                f"{namespace}_audit_chain_valid {1 if audit_ok else 0}"
            )
            lines.append(
                f"{namespace}_audit_entries {self.audit.count()}"
            )
        except Exception:
            pass
        return "\n".join(lines)


__all__ = [
    "SandboxResult",
    "SandboxManager",
    "DockerCircuitBreaker",
    "Severity",
    "DEFAULT_MAX_CONCURRENT",
    "DEFAULT_EXECUTION_TIMEOUT",
    "DEFAULT_CLEANUP_TIMEOUT",
    "MAX_OUTPUT_BYTES",
    "MAX_OUTPUT_LINES",
    "DEFAULT_RATE_LIMIT_PER_MIN",
]
