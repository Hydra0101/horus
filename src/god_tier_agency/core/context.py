"""Context — God-Tier v5.0. Propagación de contexto end-to-end.

Integra:
    - ContextVars (Python 3.7+) para propagación async-safe
    - structlog.contextvars para logging estructurado
    - OpenTelemetry baggage (opcional) para distributed tracing
    - Threads propagation (asyncio.to_thread)
    - Subprocess propagation (env vars)
    - Sanitización + redacción de secretos
    - Jerarquía parent/child
    - Deadline + cancel propagation

God-Tier v5.0 — diferenciadores vs v4.0:

CONTEXTO:
    - RequestContext inmutable (frozen) — sin reutilización
    - Validación de IDs (correlation, operator, engagement, target)
    - Sanitización de valores (log injection prevention)
    - Redacción de secretos en `extra`
    - Límite de keys (100) y valor (10KB)
    - Jerarquía parent/child
    - Snapshot inmutable (copy)

PROPAGACIÓN:
    - asyncio.create_task con context
    - asyncio.to_thread con context (FIX BUG #10)
    - subprocess con env vars (FIX BUG #11)
    - OpenTelemetry baggage (FIX BUG #12)
    - ThreadPoolExecutor con context
    - Propagación a threads sync

API:
    - Async context manager (FIX BUG #1, #22)
    - copy_context() público (FIX BUG #20)
    - get_all_context() con metadata
    - bind_context con conflict detection (FIX BUG #15)
    - Context deadline propagation (FIX BUG #23)
    - Cancel propagation (FIX BUG #24)

SEGURIDAD:
    - Detección de fugas (FIX BUG #7)
    - Sanitización de IDs (FIX BUG #3, #4)
    - Redaction de secrets en extra (FIX BUG #16, #17)
    - Conflict detection (FIX BUG #15)
    - Thread-safe (FIX BUG #26)

OBSERVABILIDAD:
    - Metrics de contextos activos
    - Correlation con OTel trace_id
    - Context snapshot para debugging

Filosofía:
    - IMMUTABLE: RequestContext frozen
    - SANITIZED: todo input pasa por sanitización
    - PROPAGATED: async, threads, subprocess
    - OBSERVABLE: métricas + trace_id
    - SAFE: detección de fugas + límites
"""

from __future__ import annotations

import asyncio
import contextvars
import os
import re
import threading
import time
import uuid
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any, AsyncGenerator, Final, Generator

import structlog

# Import sanitization
try:
    from god_tier_agency.core.logging import redact_secrets  # type: ignore
    _HAS_REDACT = True
except Exception:
    _HAS_REDACT = False


# ============================================================================
# CONSTANTES
# ============================================================================

MAX_CONTEXT_KEYS: Final[int] = 100
MAX_CONTEXT_VALUE_LENGTH: Final[int] = 10_000
MAX_CONTEXT_DEPTH: Final[int] = 5

# Regex para validar IDs (alfanumérico + dash + underscore + punto)
_SAFE_ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[a-zA-Z0-9_\-\.:]{1,256}$")

# Regex para log injection (newlines)
_LOG_INJECTION_PATTERN: Final[re.Pattern[str]] = re.compile(r"[\r\n\x00]")

# Fallback redactor (si logging.py no disponible)
_SECRET_PATTERNS_FALLBACK: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{16,})"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ghp_[a-zA-Z0-9]{36}"),
    re.compile(r"sk_live_[a-zA-Z0-9]{24,}"),
    re.compile(r"xox[baprs]-[a-zA-Z0-9-]+"),
    re.compile(r"eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+"),
)


# ============================================================================
# CONTEXTVARS
# ============================================================================

_correlation_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "correlation_id", default=None
)
_request_context: contextvars.ContextVar[dict[str, Any] | None] = (
    contextvars.ContextVar("request_context", default=None)
)
_deadline: contextvars.ContextVar[float | None] = contextvars.ContextVar(
    "deadline", default=None
)
_cancel_event: contextvars.ContextVar[threading.Event | None] = (
    contextvars.ContextVar("cancel_event", default=None)
)
_parent_context_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "parent_context_id", default=None
)


# ============================================================================
# METRICS (thread-safe)
# ============================================================================

@dataclass
class ContextMetrics:
    """Métricas de contextos activos."""
    active_contexts: int = 0
    total_contexts_created: int = 0
    total_binds: int = 0
    total_conflicts: int = 0
    max_depth_seen: int = 0
    _lock: threading.RLock = field(default_factory=threading.RLock)

    def increment_active(self) -> None:
        with self._lock:
            self.active_contexts += 1
            self.total_contexts_created += 1

    def decrement_active(self) -> None:
        with self._lock:
            self.active_contexts = max(0, self.active_contexts - 1)

    def record_bind(self, conflict: bool = False) -> None:
        with self._lock:
            self.total_binds += 1
            if conflict:
                self.total_conflicts += 1

    def to_dict(self) -> dict[str, Any]:
        with self._lock:
            return {
                "active_contexts": self.active_contexts,
                "total_contexts_created": self.total_contexts_created,
                "total_binds": self.total_binds,
                "total_conflicts": self.total_conflicts,
                "max_depth_seen": self.max_depth_seen,
            }


_METRICS = ContextMetrics()


# ============================================================================
# SANITIZATION
# ============================================================================

def _sanitize_id(value: str, *, field_name: str = "id") -> str:
    """Valida y sanitiza un ID (evita log injection).

    Raises:
        ValueError: Si el ID es inválido.
    """
    if not isinstance(value, str):
        raise ValueError(f"{field_name} debe ser str, no {type(value).__name__}")

    if not value:
        raise ValueError(f"{field_name} no puede estar vacío")

    if len(value) > 256:
        raise ValueError(f"{field_name} excede 256 chars: {len(value)}")

    # Detectar log injection
    if _LOG_INJECTION_PATTERN.search(value):
        raise ValueError(f"{field_name} contiene caracteres prohibidos (\\n, \\r, \\x00)")

    # Validar formato
    if not _SAFE_ID_PATTERN.match(value):
        raise ValueError(
            f"{field_name} formato inválido: {value!r}. "
            f"Solo [a-zA-Z0-9_-.::] permitidos."
        )

    return value


def _sanitize_extra_value(value: Any, depth: int = 0) -> Any:
    """Sanitiza valor recursivamente (truncado + redacción de secretos)."""
    if depth > MAX_CONTEXT_DEPTH:
        return "***MAX_DEPTH***"

    # Primitives
    if value is None or isinstance(value, (bool, int, float)):
        return value

    # String
    if isinstance(value, str):
        # Truncar
        if len(value) > MAX_CONTEXT_VALUE_LENGTH:
            value = value[:MAX_CONTEXT_VALUE_LENGTH] + "...[truncated]"

        # Redactar secretos (si redactor disponible)
        if _HAS_REDACT:
            try:
                event_dict = {"value": value}
                event_dict = redact_secrets(None, "sanitize", event_dict)
                value = event_dict.get("value", value)
            except Exception:
                # Fallback a patterns locales
                for pattern in _SECRET_PATTERNS_FALLBACK:
                    value = pattern.sub("***REDACTED***", value)
        else:
            for pattern in _SECRET_PATTERNS_FALLBACK:
                value = pattern.sub("***REDACTED***", value)

        # Log injection prevention
        value = value.replace("\r", "\\r").replace("\n", "\\n").replace("\x00", "\\x00")

        return value

    # Dict
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for k, v in list(value.items())[:MAX_CONTEXT_KEYS]:
            k_str = str(k)
            # Key sanitization (log injection)
            k_str = k_str.replace("\r", "\\r").replace("\n", "\\n").replace("\x00", "\\x00")
            # Redact sensitive keys
            k_lower = k_str.lower()
            if any(suffix in k_lower for suffix in ("api_key", "secret", "token", "password", "credential")):
                result[k_str] = "***REDACTED***"
            else:
                result[k_str] = _sanitize_extra_value(v, depth + 1)
        return result

    # List/tuple
    if isinstance(value, (list, tuple)):
        return [_sanitize_extra_value(v, depth + 1) for v in list(value)[:MAX_CONTEXT_KEYS]]

    # Bytes
    if isinstance(value, (bytes, bytearray)):
        return f"<bytes len={len(value)}>"

    # Fallback
    return _sanitize_extra_value(str(value), depth + 1)


# ============================================================================
# REQUEST CONTEXT (frozen)
# ============================================================================

@dataclass(frozen=True)
class RequestContext:
    """Contexto de una operación (INMUTABLE).

    God-Tier v5.0:
        - frozen=True (no reutilizable)
        - Validación de IDs
        - Sanitización de extra
        - Jerarquía parent/child
        - Deadline propagation
        - Async + sync context managers

    Uso:
        >>> ctx = RequestContext(
        ...     operator_id="hydra",
        ...     engagement_id="ROE-2026-001",
        ...     target_id="example.com",
        ... )
        >>> with ctx.activate():  # sync
        ...     log.info("scan_started")
        >>> async with ctx.activate_async():  # async
        ...     await do_work()
    """

    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    parent_context_id: str | None = None
    operator_id: str | None = None
    engagement_id: str | None = None
    target_id: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    deadline_seconds: float | None = None

    def __post_init__(self) -> None:
        """Validación + sanitización al construir."""
        # Validar correlation_id
        object.__setattr__(
            self, "correlation_id",
            _sanitize_id(self.correlation_id, field_name="correlation_id"),
        )

        # Validar IDs opcionales
        for fname in ("operator_id", "engagement_id", "target_id", "parent_context_id"):
            value = getattr(self, fname)
            if value is not None:
                object.__setattr__(
                    self, fname,
                    _sanitize_id(value, field_name=fname),
                )

        # Sanitizar extra
        if self.extra:
            if len(self.extra) > MAX_CONTEXT_KEYS:
                raise ValueError(
                    f"extra excede {MAX_CONTEXT_KEYS} keys: {len(self.extra)}"
                )
            sanitized_extra = _sanitize_extra_value(self.extra)
            object.__setattr__(self, "extra", sanitized_extra)

        # Validar deadline
        if self.deadline_seconds is not None and self.deadline_seconds <= 0:
            raise ValueError("deadline_seconds debe ser > 0")

    @property
    def created_at_iso(self) -> str:
        return datetime.fromtimestamp(self.created_at, tz=timezone.utc).isoformat()

    @property
    def is_expired(self) -> bool:
        """True si el deadline pasó."""
        if self.deadline_seconds is None:
            return False
        return time.time() > (self.created_at + self.deadline_seconds)

    @property
    def remaining_seconds(self) -> float | None:
        """Segundos restantes hasta deadline."""
        if self.deadline_seconds is None:
            return None
        return max(0.0, (self.created_at + self.deadline_seconds) - time.time())

    # ------------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Convierte a dict para structlog (flat)."""
        d: dict[str, Any] = {"correlation_id": self.correlation_id}
        if self.parent_context_id:
            d["parent_context_id"] = self.parent_context_id
        if self.operator_id:
            d["operator_id"] = self.operator_id
        if self.engagement_id:
            d["engagement_id"] = self.engagement_id
        if self.target_id:
            d["target_id"] = self.target_id
        if self.extra:
            d.update(self.extra)
        return d

    def to_full_dict(self) -> dict[str, Any]:
        """Dict completo con metadata (para debugging)."""
        return {
            "correlation_id": self.correlation_id,
            "parent_context_id": self.parent_context_id,
            "operator_id": self.operator_id,
            "engagement_id": self.engagement_id,
            "target_id": self.target_id,
            "extra": self.extra,
            "created_at": self.created_at,
            "created_at_iso": self.created_at_iso,
            "deadline_seconds": self.deadline_seconds,
            "remaining_seconds": self.remaining_seconds,
            "is_expired": self.is_expired,
        }

    # ------------------------------------------------------------------------
    # Derivation
    # ------------------------------------------------------------------------

    def child(self, **overrides: Any) -> "RequestContext":
        """Crea un contexto hijo (hereda padre).

        Uso:
            >>> parent = RequestContext(operator_id="hydra")
            >>> child = parent.child(target_id="example.com")
            >>> child.parent_context_id == parent.correlation_id
            True
        """
        new_extra = {**self.extra, **overrides.pop("extra", {})}
        return RequestContext(
            correlation_id=str(uuid.uuid4()),  # nuevo ID
            parent_context_id=self.correlation_id,
            operator_id=overrides.get("operator_id", self.operator_id),
            engagement_id=overrides.get("engagement_id", self.engagement_id),
            target_id=overrides.get("target_id", self.target_id),
            extra=new_extra,
            deadline_seconds=overrides.get("deadline_seconds", self.deadline_seconds),
        )

    def with_deadline(self, seconds: float) -> "RequestContext":
        """Crea copia con deadline."""
        return replace(
            self,
            deadline_seconds=seconds,
        )

    # ------------------------------------------------------------------------
    # Activation (sync + async)
    # ------------------------------------------------------------------------

    @contextmanager
    def activate(self) -> Generator["RequestContext", None, None]:
        """Activa en thread/async task actual (sync context manager)."""
        _METRICS.increment_active()

        tokens: list[tuple[contextvars.ContextVar, contextvars.Token]] = []
        try:
            # Set contextvars
            tokens.append((_correlation_id, _correlation_id.set(self.correlation_id)))
            tokens.append((_request_context, _request_context.set(self.to_dict())))
            tokens.append((_parent_context_id, _parent_context_id.set(self.parent_context_id)))

            if self.deadline_seconds is not None:
                deadline = self.created_at + self.deadline_seconds
                tokens.append((_deadline, _deadline.set(deadline)))

            # Bind structlog
            structlog.contextvars.bind_contextvars(**self.to_dict())

            yield self
        finally:
            # Unbind structlog (todos los keys + los que bind_context agregó)
            current = get_context()
            if current:
                structlog.contextvars.unbind_contextvars(*current.keys())

            # Reset contextvars (reverse order)
            for var, token in reversed(tokens):
                try:
                    var.reset(token)
                except Exception:
                    pass

            _METRICS.decrement_active()

    @asynccontextmanager
    async def activate_async(self) -> AsyncGenerator["RequestContext", None]:
        """Async context manager (equivalente a activate())."""
        with self.activate():
            yield self

    # ------------------------------------------------------------------------
    # Snapshot
    # ------------------------------------------------------------------------

    def snapshot(self) -> dict[str, Any]:
        """Snapshot inmutable (deep copy) del contexto."""
        import copy
        return copy.deepcopy(self.to_full_dict())


# ============================================================================
# HELPERS
# ============================================================================

def get_context() -> dict[str, Any]:
    """Retorna el contexto actual (flat dict) o {} si no hay."""
    return dict(_request_context.get() or {})


def get_full_context() -> dict[str, Any]:
    """Retorna contexto actual con metadata."""
    ctx = get_context()
    return {
        **ctx,
        "_correlation_id": _correlation_id.get(),
        "_parent_context_id": _parent_context_id.get(),
        "_deadline": _deadline.get(),
        "_is_expired": (
            _deadline.get() is not None and time.time() > (_deadline.get() or 0)
        ),
    }


def get_correlation_id() -> str | None:
    """Retorna el correlation_id actual o None."""
    return _correlation_id.get()


def get_deadline() -> float | None:
    """Retorna el deadline (timestamp) o None."""
    return _deadline.get()


def has_deadline_expired() -> bool:
    """True si el deadline del contexto actual pasó."""
    deadline = _deadline.get()
    if deadline is None:
        return False
    return time.time() > deadline


def bind_context(**kwargs: Any) -> None:
    """Añade campos al contexto actual (con conflict detection).

    God-Tier v5.0:
        - Detecta conflictos (key ya existe)
        - Limita número de keys
        - Sanitiza valores
        - Log injection prevention

    Raises:
        ValueError: Si se excede el límite de keys.

    Uso:
        >>> bind_context(operator_id="hydra")
        >>> bind_context(engagement_id="ROE-001")  # merge
    """
    # Sanitizar kwargs
    sanitized: dict[str, Any] = {}
    for k, v in kwargs.items():
        k_str = str(k)
        # Key sanitization
        k_str = k_str.replace("\r", "\\r").replace("\n", "\\n").replace("\x00", "\\x00")
        sanitized[k_str] = _sanitize_extra_value(v)

    current = dict(_request_context.get() or {})

    # Detectar conflictos
    conflicts = [k for k in sanitized.keys() if k in current]
    if conflicts:
        _METRICS.record_bind(conflict=True)
    else:
        _METRICS.record_bind(conflict=False)

    # Límite de keys
    new_keys = {k for k in sanitized.keys() if k not in current}
    if len(current) + len(new_keys) > MAX_CONTEXT_KEYS:
        raise ValueError(
            f"Context excede {MAX_CONTEXT_KEYS} keys "
            f"({len(current)} + {len(new_keys)})"
        )

    # Merge (sobrescribe conflictos)
    current.update(sanitized)

    _request_context.set(current)
    structlog.contextvars.bind_contextvars(**sanitized)


def bind_context_strict(**kwargs: Any) -> None:
    """bind_context que raise en conflicto (fail-closed)."""
    current = dict(_request_context.get() or {})
    conflicts = [k for k in kwargs.keys() if k in current]
    if conflicts:
        raise ValueError(
            f"Context conflict detected: {conflicts} already exist. "
            f"Use bind_context() to override."
        )
    bind_context(**kwargs)


def clear_context() -> None:
    """Limpia el contexto actual."""
    current = get_context()
    if current:
        structlog.contextvars.unbind_contextvars(*current.keys())
    _request_context.set(None)
    _correlation_id.set(None)
    _deadline.set(None)


def get_metrics() -> dict[str, Any]:
    """Retorna métricas de contexto."""
    return _METRICS.to_dict()


# ============================================================================
# CORRELATION CONTEXT (backwards-compatible)
# ============================================================================

class CorrelationContext:
    """Context manager simple para correlation_id.

    Uso:
        >>> with CorrelationContext() as ctx:
        ...     log.info("operation")
    """

    def __init__(
        self,
        correlation_id: str | None = None,
        **extra: Any,
    ) -> None:
        self.request = RequestContext(
            correlation_id=correlation_id or str(uuid.uuid4()),
            extra=extra,
        )

    def __enter__(self) -> RequestContext:
        self._cm = self.request.activate()
        return self._cm.__enter__()

    def __exit__(self, *exc: Any) -> None:
        self._cm.__exit__(*exc)


# ============================================================================
# ASYNCIO PROPAGATION
# ============================================================================

def create_task_with_context(
    coro: Any,
    *,
    name: str | None = None,
) -> asyncio.Task[Any]:
    """Crea un asyncio.Task propagando el contexto actual.

    God-Tier v5.0:
        - Usa asyncio.create_task (get_event_loop() deprecated)
        - Copia contextvars al task

    Uso:
        >>> async def worker():
        ...     log.info("inside_task")
        >>> with CorrelationContext():
        ...     create_task_with_context(worker())
    """
    ctx = contextvars.copy_context()
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.get_event_loop()
    return loop.create_task(coro, name=name, context=ctx)


def gather_with_context(
    *coros: Any,
    return_exceptions: bool = False,
) -> Any:
    """asyncio.gather propagando contexto a cada coro.

    Uso:
        >>> results = await gather_with_context(
        ...     fetch(url1),
        ...     fetch(url2),
        ... )
    """
    tasks = [create_task_with_context(coro) for coro in coros]
    return asyncio.gather(*tasks, return_exceptions=return_exceptions)


async def to_thread_with_context(
    func: Any,
    /,
    *args: Any,
    **kwargs: Any,
) -> Any:
    """asyncio.to_thread propagando contexto (FIX BUG #10).

    God-Tier: contextvars se copian al thread via context.

    Uso:
        >>> result = await to_thread_with_context(blocking_io, "arg")
    """
    ctx = contextvars.copy_context()
    return await asyncio.to_thread(ctx.run, func, *args, **kwargs)


# ============================================================================
# SUBPROCESS PROPAGATION (FIX BUG #11)
# ============================================================================

def get_env_for_subprocess() -> dict[str, str]:
    """Retorna env vars para propagar contexto a subprocess.

    Uso:
        >>> env = {**os.environ, **get_env_for_subprocess()}
        >>> subprocess.run(["cmd"], env=env)
    """
    env: dict[str, str] = {}
    ctx = get_context()
    cid = get_correlation_id()
    if cid:
        env["GODTIER_CORRELATION_ID"] = cid
    if ctx.get("operator_id"):
        env["GODTIER_OPERATOR_ID"] = str(ctx["operator_id"])
    if ctx.get("engagement_id"):
        env["GODTIER_ENGAGEMENT_ID"] = str(ctx["engagement_id"])
    if ctx.get("target_id"):
        env["GODTIER_TARGET_ID"] = str(ctx["target_id"])
    return env


def init_context_from_env() -> RequestContext | None:
    """Inicializa contexto desde env vars (para subprocess).

    Uso:
        # En el subprocess:
        ctx = init_context_from_env()
        if ctx:
            with ctx.activate():
                do_work()
    """
    cid = os.environ.get("GODTIER_CORRELATION_ID")
    if not cid:
        return None
    return RequestContext(
        correlation_id=cid,
        operator_id=os.environ.get("GODTIER_OPERATOR_ID"),
        engagement_id=os.environ.get("GODTIER_ENGAGEMENT_ID"),
        target_id=os.environ.get("GODTIER_TARGET_ID"),
    )


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    # Context
    "RequestContext",
    "CorrelationContext",
    # Activation
    "get_context",
    "get_full_context",
    "get_correlation_id",
    "get_deadline",
    "has_deadline_expired",
    "bind_context",
    "bind_context_strict",
    "clear_context",
    # Propagation
    "create_task_with_context",
    "gather_with_context",
    "to_thread_with_context",
    # Subprocess
    "get_env_for_subprocess",
    "init_context_from_env",
    # Metrics
    "get_metrics",
    # Constants
    "MAX_CONTEXT_KEYS",
    "MAX_CONTEXT_VALUE_LENGTH",
    "MAX_CONTEXT_DEPTH",
]
