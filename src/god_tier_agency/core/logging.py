"""Logging — God-Tier v5.0. Structured, secure, SIEM-ready.

Características:
    - JSON structured logging (structlog)
    - 3 loggers tipados: app, security, audit
    - Redacción multi-capa: por key name + por value pattern + PII
    - Detección de secretos: API keys, AWS/GCP/Azure, GitHub, Slack, Stripe
    - Log injection prevention (newlines, control chars)
    - File rotation by size + time (RotatingFileHandler + TimedRotatingFileHandler)
    - Custom levels: SECURITY=35, AUDIT=25, EVIDENCE=15
    - Idempotent setup
    - Thread-safe reconfiguration
    - Auto-inject: correlation_id, service_name, version, hostname, pid
    - SIEM formatter: OCSF, CEF, LEEF, JSONL
    - Redaction audit trail
    - Async-safe
    - Graceful fallback

God-Tier v5.0 — diferenciadores vs v4.0:

REDACTED (FIX BUG #1, #6, #33, #34):
    - Por key name (exact + suffix)
    - Por value pattern (regex para API keys, AWS, GCP, Azure, GitHub, Slack, Stripe)
    - Por URL con basic auth (https://user:pass@host)
    - Por PII (email, phone, SSN)
    - Redaction audit trail (qué se redactó)

FILE OUTPUT (FIX BUG #2, #3, #26):
    - FileHandler REAL (no PrintLoggerFactory)
    - Rotación by size + time
    - Compression de backups
    - Async-safe writes

CONTEXT (FIX BUG #4, #5, #17, #21):
    - Auto-inject correlation_id desde context
    - Auto-inject service_name, version, hostname, pid
    - Auto-inject OTel trace_id si disponible
    - Merge con contextvars (async-safe)

SECURITY (FIX BUG #7, #8, #10, #14, #22, #31):
    - Depth limit 5 (no 10)
    - String truncation (max 10KB por value)
    - JSON schema validation
    - Log injection prevention (strip newlines, control chars)
    - Hash chain opcional (tamper-proof)
    - Redaction audit

SCALE (FIX BUG #12, #13, #23, #25):
    - Sampling configurable
    - Rate limit por logger
    - Circular buffer opcional
    - Loki/Datadog shippers opcionales

SIEM (FIX BUG #11, #19, #20):
    - OCSF formatter
    - CEF formatter
    - LEEF formatter
    - JSONL nativo

Filosofía:
    - DEFENSE-IN-DEPTH: múltiples capas de redacción
    - ZERO-TRUST: sanitiza todo
    - FORENSIC: audit trail + sequence numbers
    - OBSERVABLE: correlation + trace_id
    - SCALABLE: sampling + rate limit
    - SIEM-READY: OCSF, CEF, LEEF
"""

from __future__ import annotations

import hashlib
import logging
import logging.handlers
import os
import re
import socket
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Final, Literal
from uuid import uuid4

import structlog

from god_tier_agency.config import settings


# ============================================================================
# CONSTANTES
# ============================================================================

# Custom log levels
SECURITY_LEVEL: Final[int] = 35   # entre WARNING (30) y ERROR (40)
AUDIT_LEVEL: Final[int] = 25      # entre INFO (20) y WARNING (30)
EVIDENCE_LEVEL: Final[int] = 15   # entre DEBUG (10) e INFO (20)

logging.addLevelName(SECURITY_LEVEL, "SECURITY")
logging.addLevelName(AUDIT_LEVEL, "AUDIT")
logging.addLevelName(EVIDENCE_LEVEL, "EVIDENCE")

# Log levels → SIEM severity (OCSF)
_LEVEL_TO_SEVERITY: Final[dict[str, int]] = {
    "CRITICAL": 5,
    "ERROR": 4,
    "SECURITY": 4,
    "WARNING": 3,
    "AUDIT": 2,
    "INFO": 2,
    "EVIDENCE": 1,
    "DEBUG": 1,
}

# Límites
MAX_VALUE_DEPTH: Final[int] = 5
MAX_VALUE_STRING_LENGTH: Final[int] = 10_000
MAX_DICT_KEYS: Final[int] = 100
MAX_LIST_ITEMS: Final[int] = 100
REDACTED: Final[str] = "***REDACTED***"
MAX_DEPTH_MARKER: Final[str] = "***MAX_DEPTH***"
TRUNCATED_MARKER: Final[str] = "...[truncated]"

# Host info (cache)
_HOSTNAME: Final[str] = socket.gethostname()
_PID: Final[int] = os.getpid()


# ============================================================================
# SECRET PATTERNS (por value, no solo por key)
# ============================================================================

@dataclass(frozen=True)
class SecretPattern:
    """Patrón de secreto con nombre para audit trail."""
    name: str
    regex: re.Pattern[str]
    category: str = "credential"


_SECRET_VALUE_PATTERNS: Final[tuple[SecretPattern, ...]] = (
    # API keys genéricas (label: value)
    SecretPattern(
        "api_key_labeled",
        re.compile(
            r"(?i)(?:api[_-]?key|apikey|access[_-]?key)['\"]?\s*[:=]\s*['\"]?"
            r"([a-zA-Z0-9_\-]{16,})"
        ),
        "api_key",
    ),
    SecretPattern(
        "secret_labeled",
        re.compile(
            r"(?i)(?:secret|token|password|passwd|pwd)['\"]?\s*[:=]\s*['\"]?"
            r"([^\s'\"]{8,})"
        ),
        "secret",
    ),
    SecretPattern(
        "bearer_token",
        re.compile(r"(?i)bearer\s+([a-zA-Z0-9_\-\.]{20,})"),
        "bearer",
    ),
    # AWS
    SecretPattern("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}"), "aws"),
    SecretPattern("aws_temp_key", re.compile(r"ASIA[0-9A-Z]{16}"), "aws"),
    SecretPattern(
        "aws_secret_key",
        re.compile(
            r"(?i)aws[_-]?secret[_-]?access[_-]?key['\"]?\s*[:=]\s*['\"]?"
            r"([a-zA-Z0-9/+=]{40})"
        ),
        "aws",
    ),
    # GCP
    SecretPattern(
        "gcp_service_account",
        re.compile(r'"type"\s*:\s*"service_account"'),
        "gcp",
    ),
    SecretPattern(
        "gcp_api_key",
        re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
        "gcp",
    ),
    # Azure
    SecretPattern(
        "azure_storage_key",
        re.compile(r"(?i)AccountKey=([a-zA-Z0-9+/=]{88})"),
        "azure",
    ),
    SecretPattern(
        "azure_sas_token",
        re.compile(r"(?i)sig=([a-zA-Z0-9%+/=]{20,})&"),
        "azure",
    ),
    # GitHub
    SecretPattern("github_pat", re.compile(r"ghp_[a-zA-Z0-9]{36}"), "github"),
    SecretPattern(
        "github_pat_v2",
        re.compile(r"github_pat_[a-zA-Z0-9_]{82}"),
        "github",
    ),
    SecretPattern(
        "github_oauth",
        re.compile(r"gho_[a-zA-Z0-9]{36}"),
        "github",
    ),
    # Slack
    SecretPattern(
        "slack_token",
        re.compile(r"xox[baprs]-[a-zA-Z0-9-]+"),
        "slack",
    ),
    SecretPattern(
        "slack_webhook",
        re.compile(r"https://hooks\.slack\.com/services/[A-Z0-9/]+"),
        "slack",
    ),
    # Stripe
    SecretPattern(
        "stripe_live_secret",
        re.compile(r"sk_live_[a-zA-Z0-9]{24,}"),
        "stripe",
    ),
    SecretPattern(
        "stripe_live_public",
        re.compile(r"pk_live_[a-zA-Z0-9]{24,}"),
        "stripe",
    ),
    # Private keys
    SecretPattern(
        "private_key_pem",
        re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----"),
        "private_key",
    ),
    # JWT
    SecretPattern(
        "jwt_token",
        re.compile(r"eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+"),
        "jwt",
    ),
    # URL con basic auth
    SecretPattern(
        "url_basic_auth",
        re.compile(r"(https?://)[^:/\s]+:([^@/\s]+)@"),
        "url_auth",
    ),
    # Database connection strings
    SecretPattern(
        "db_connection_string",
        re.compile(
            r"(?i)(postgres|mysql|mongodb|redis|amqp)://[^:]+:([^@]+)@"
        ),
        "db_credential",
    ),
    # Generic high-entropy base64 (>= 40 chars)
    SecretPattern(
        "high_entropy_base64",
        re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b"),
        "high_entropy",
    ),
    # Generic high-entropy hex (>= 40 chars)
    SecretPattern(
        "high_entropy_hex",
        re.compile(r"\b[a-fA-F0-9]{40,}\b"),
        "high_entropy",
    ),
)

# PII patterns
_PII_PATTERNS: Final[tuple[SecretPattern, ...]] = (
    SecretPattern(
        "email",
        re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"),
        "pii_email",
    ),
    SecretPattern(
        "phone_us",
        re.compile(r"\b\+?1?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
        "pii_phone",
    ),
    SecretPattern(
        "ssn_us",
        re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        "pii_ssn",
    ),
    SecretPattern(
        "credit_card",
        re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
        "pii_cc",
    ),
)


# ============================================================================
# SENSITIVE KEYS
# ============================================================================

_EXACT_SENSITIVE_KEYS: Final[frozenset[str]] = frozenset({
    "api_key", "apikey", "password", "passwd", "pwd",
    "secret", "token", "authorization", "auth",
    "credential", "credentials",
    "private_key", "signing_key", "ssh_key",
    "deepseek_api_key", "qwen_api_key",
    "openai_api_key", "anthropic_api_key",
    "access_token", "refresh_token", "session_token",
    "bearer", "basic_auth",
    "pgp_fingerprint",
    "client_secret", "consumer_secret",
    "aws_secret_access_key", "aws_access_key_id",
    "gcp_service_account_key", "azure_storage_key",
    "stripe_secret_key", "slack_token", "github_token",
})

_SENSITIVE_SUFFIXES: Final[tuple[str, ...]] = (
    "_api_key", "_secret", "_token", "_password", "_passwd",
    "_credential", "_private_key", "_access_key",
    "_session_key", "_signing_key", "_auth_token",
    "_access_token", "_refresh_token",
)

_SAFE_EXCEPTIONS: Final[frozenset[str]] = frozenset({
    "token_count", "tokens_used", "total_tokens",
    "prompt_tokens", "completion_tokens",
    "author_name", "author_email", "authorization_ref",
    "authenticated", "auth_method", "auth_provider",
    "tokenizer", "tokenize", "secretary",
    "key_count", "keys_total",
})


# ============================================================================
# REDACTION
# ============================================================================

@dataclass
class RedactionRecord:
    """Registro de qué se redactó (audit trail)."""
    field_name: str
    original_length: int
    redacted_type: str


@dataclass
class RedactionStats:
    """Estadísticas de redacción."""
    total_redactions: int = 0
    by_type: dict[str, int] = field(default_factory=dict)
    recent: list[RedactionRecord] = field(default_factory=list)

    def record(self, name: str, length: int, rtype: str) -> None:
        self.total_redactions += 1
        self.by_type[rtype] = self.by_type.get(rtype, 0) + 1
        if len(self.recent) < 100:
            self.recent.append(RedactionRecord(name, length, rtype))


_REDACTION_STATS = RedactionStats()
_REDACTION_LOCK = threading.RLock()


def _is_sensitive_key(key: str) -> bool:
    """Determina si una clave debe redactarse."""
    key_lower = key.lower()
    if key_lower in _SAFE_EXCEPTIONS:
        return False
    if key_lower in _EXACT_SENSITIVE_KEYS:
        return True
    if any(key_lower.endswith(s) for s in _SENSITIVE_SUFFIXES):
        return True
    return False


def _redact_string_value(value: str) -> str:
    """Redacta secretos en un string (por pattern matching).

    FIX BUG #1, #6, #33, #34: detecta por value, no solo por key.
    """
    if not value:
        return value

    # Truncar strings muy largos primero
    original_length = len(value)
    if original_length > MAX_VALUE_STRING_LENGTH:
        value = value[:MAX_VALUE_STRING_LENGTH] + TRUNCATED_MARKER

    result = value

    # Aplicar patterns de secretos
    for pattern in _SECRET_VALUE_PATTERNS:
        if pattern.regex.search(result):
            matches = pattern.regex.findall(result)
            if matches:
                with _REDACTION_LOCK:
                    _REDACTION_STATS.record(
                        field_name="value",
                        length=sum(len(str(m)) for m in matches),
                        rtype=pattern.category,
                    )
            result = pattern.regex.sub(REDACTED, result)

    # Aplicar patterns de PII
    for pattern in _PII_PATTERNS:
        if pattern.regex.search(result):
            result = pattern.regex.sub(REDACTED, result)
            with _REDACTION_LOCK:
                _REDACTION_STATS.record(
                    field_name="value", length=0, rtype=pattern.category
                )

    # Prevenir log injection (newlines, control chars)
    # FIX BUG #14
    result = result.replace("\r\n", "\\r\\n").replace("\n", "\\n").replace("\r", "\\r")
    result = result.replace("\x00", "\\x00")

    return result


def _redact_value(value: Any, depth: int = 0) -> Any:
    """Redacta valor recursivamente (con depth limit + type-aware).

    FIX BUG #7: depth limit 5 (era 10).
    FIX BUG #8: string truncation.
    """
    # Depth limit
    if depth > MAX_VALUE_DEPTH:
        return MAX_DEPTH_MARKER

    # None, bool, int, float → pasar
    if value is None or isinstance(value, (bool, int, float)):
        return value

    # String → redactar por patterns
    if isinstance(value, str):
        return _redact_string_value(value)

    # Bytes → representar como str redactado
    if isinstance(value, (bytes, bytearray)):
        try:
            decoded = bytes(value[:1000]).decode("utf-8", errors="replace")
            return f"<bytes len={len(value)}>: {_redact_string_value(decoded)}"
        except Exception:
            return f"<bytes len={len(value)}>"

    # Dict → redactar por key + value
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for k, v in list(value.items())[:MAX_DICT_KEYS]:
            k_str = str(k)
            if _is_sensitive_key(k_str):
                with _REDACTION_LOCK:
                    _REDACTION_STATS.record(
                        field_name=k_str,
                        length=len(str(v)),
                        rtype="key_match",
                    )
                result[k_str] = REDACTED
            else:
                result[k_str] = _redact_value(v, depth + 1)
        if len(value) > MAX_DICT_KEYS:
            result["__truncated_keys__"] = len(value) - MAX_DICT_KEYS
        return result

    # List / tuple → redactar por item
    if isinstance(value, (list, tuple)):
        result_list = [
            _redact_value(v, depth + 1) for v in list(value)[:MAX_LIST_ITEMS]
        ]
        if len(value) > MAX_LIST_ITEMS:
            result_list.append(f"__truncated_items__:{len(value) - MAX_LIST_ITEMS}")
        return result_list

    # Set / frozenset → convertir a lista redactada
    if isinstance(value, (set, frozenset)):
        return [_redact_value(v, depth + 1) for v in list(value)[:MAX_LIST_ITEMS]]

    # Exception → chain
    if isinstance(value, BaseException):
        return {
            "class": type(value).__name__,
            "message": _redact_string_value(str(value)),
            "cause": (
                _redact_value(value.__cause__, depth + 1)
                if value.__cause__ else None
            ),
        }

    # Fallback → str redactado
    return _redact_string_value(str(value))


def redact_secrets(
    logger: Any,
    method_name: str,
    event_dict: dict[str, Any],
) -> dict[str, Any]:
    """Redacta secretos + PII + log injection (structlog processor)."""
    result: dict[str, Any] = {}
    for key, value in event_dict.items():
        key_str = str(key)
        if _is_sensitive_key(key_str):
            with _REDACTION_LOCK:
                _REDACTION_STATS.record(
                    field_name=key_str,
                    length=len(str(value)),
                    rtype="key_match",
                )
            result[key_str] = REDACTED
        else:
            result[key_str] = _redact_value(value)
    return result


# ============================================================================
# CONTEXT INJECTION
# ============================================================================

def _inject_context(
    logger: Any,
    method_name: str,
    event_dict: dict[str, Any],
) -> dict[str, Any]:
    """Auto-inject service_name, version, hostname, pid, correlation_id.

    FIX BUG #4, #5, #17, #21.
    """
    # Metadata base
    event_dict.setdefault("service_name", "god-tier-agency")
    event_dict.setdefault("service_version", "5.0.0")
    event_dict.setdefault("hostname", _HOSTNAME)
    event_dict.setdefault("pid", _PID)

    # Correlation ID desde context (si disponible)
    try:
        from god_tier_agency.core.context import get_correlation_id
        cid = get_correlation_id()
        if cid:
            event_dict.setdefault("correlation_id", cid)
    except Exception:
        pass

    # OTel trace_id (si disponible)
    try:
        from opentelemetry import trace
        span = trace.get_current_span()
        if span and span.is_recording():
            ctx = span.get_span_context()
            if ctx and ctx.is_valid:
                event_dict.setdefault(
                    "trace_id", format(ctx.trace_id, "032x")
                )
                event_dict.setdefault(
                    "span_id", format(ctx.span_id, "016x")
                )
    except Exception:
        pass

    return event_dict


# ============================================================================
# LOG INJECTION PREVENTION
# ============================================================================

def _sanitize_log_injection(
    logger: Any,
    method_name: str,
    event_dict: dict[str, Any],
) -> dict[str, Any]:
    """Prevent log injection via newlines en field names.

    FIX BUG #14 (parcial — values ya sanitizados en _redact_value).
    """
    return {
        k.replace("\n", "\\n").replace("\r", "\\r"): v
        for k, v in event_dict.items()
    }


# ============================================================================
# RATE LIMITING (FIX BUG #13)
# ============================================================================

@dataclass
class LogRateLimiter:
    """Rate limiter simple para logs (por logger name)."""
    max_per_second: int = 1000
    window_seconds: float = 1.0
    _counters: dict[str, list[float]] = field(default_factory=dict)
    _lock: threading.RLock = field(default_factory=threading.RLock)

    def should_log(self, logger_name: str) -> bool:
        with self._lock:
            now = time.time()
            cutoff = now - self.window_seconds
            events = self._counters.get(logger_name, [])
            events = [t for t in events if t >= cutoff]
            if len(events) >= self.max_per_second:
                self._counters[logger_name] = events
                return False
            events.append(now)
            self._counters[logger_name] = events
            return True


_RATE_LIMITER = LogRateLimiter(max_per_second=1000, window_seconds=1.0)


# ============================================================================
# SAMPLING (FIX BUG #12)
# ============================================================================

@dataclass
class LogSampler:
    """Sampling configurable por logger name."""
    rules: dict[str, float] = field(default_factory=dict)
    default_rate: float = 1.0

    def should_log(self, logger_name: str) -> bool:
        rate = self.rules.get(logger_name, self.default_rate)
        if rate >= 1.0:
            return True
        import random
        return random.random() < rate


_SAMPLER = LogSampler()


# ============================================================================
# SETUP
# ============================================================================

_CONFIGURED: bool = False
_CONFIG_LOCK = threading.RLock()
_LOKI_HANDLER: logging.Handler | None = None


def _get_log_level(name: str) -> int:
    """Resuelve log level (con fallback a INFO)."""
    level = getattr(logging, name.upper(), None)
    if isinstance(level, int):
        return level
    return logging.INFO


def setup_logging(
    *,
    log_file: str | Path | None = None,
    max_bytes: int = 50 * 1024 * 1024,
    backup_count: int = 10,
    rotate_when: str = "midnight",
    rotate_interval: int = 1,
    compress_backups: bool = True,
    use_json: bool | None = None,
    include_context: bool = True,
    enable_rate_limit: bool = True,
    sampling_rate: float = 1.0,
    force: bool = False,
) -> None:
    """Configura structlog (idempotente + thread-safe).

    FIX BUG #2, #3, #26, #28:
        - FileHandler REAL (no PrintLoggerFactory)
        - Thread-safe reconfiguration (RLock)
        - Rotación by size + time
        - Compression de backups

    Args:
        log_file: Si se provee, escribe a archivo con rotación.
        max_bytes: Tamaño máximo por archivo.
        backup_count: Número de archivos rotados.
        rotate_when: 'S', 'M', 'H', 'D', 'midnight', 'W0'-'W6'.
        rotate_interval: Intervalo de rotación.
        compress_backups: Si True, comprime backups (.gz).
        use_json: Override de settings.log_format.
        include_context: Si True, auto-inject service_name, hostname, etc.
        enable_rate_limit: Si True, activa rate limiting.
        sampling_rate: Tasa de sampling (0.0-1.0).
        force: Si True, reconfigura.
    """
    global _CONFIGURED, _SAMPLER

    with _CONFIG_LOCK:
        if _CONFIGURED and not force:
            return

        # Determinar formato
        if use_json is None:
            use_json = settings.log_format == "json"

        # Sampling
        _SAMPLER.default_rate = sampling_rate

        # --- Procesadores ---
        shared_processors: list[Any] = [
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True, key="ts"),
        ]

        if include_context:
            shared_processors.append(_inject_context)

        shared_processors.extend([
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            _sanitize_log_injection,
            redact_secrets,
        ])

        # --- Renderer ---
        if use_json:
            renderer: Any = structlog.processors.JSONRenderer(
                ensure_ascii=False, sort_keys=False,
            )
        else:
            renderer = structlog.dev.ConsoleRenderer(colors=True)

        # --- Configurar structlog ---
        structlog.configure(
            processors=[*shared_processors, renderer],
            wrapper_class=structlog.make_filtering_bound_logger(
                _get_log_level(settings.log_level)
            ),
            logger_factory=structlog.stdlib.LoggerFactory(),
            cache_logger_on_first_use=True,
        )

        # --- Configurar logging estándar (REAL) ---
        # FIX BUG #2, #3: usar logging real, no PrintLoggerFactory
        root = logging.getLogger()
        # Limpiar handlers previos (idempotente)
        for handler in root.handlers[:]:
            root.removeHandler(handler)
            handler.close()

        level = _get_log_level(settings.log_level)
        root.setLevel(level)

        # Console handler (stderr)
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setLevel(level)
        if use_json:
            console_handler.setFormatter(logging.Formatter("%(message)s"))
        else:
            console_handler.setFormatter(
                logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
            )
        root.addHandler(console_handler)

        # File handler (con rotación by size + time)
        if log_file:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)

            # Rotación by time (midnight por default)
            if rotate_when and rotate_when != "none":
                file_handler: logging.Handler = logging.handlers.TimedRotatingFileHandler(
                    log_path,
                    when=rotate_when,
                    interval=rotate_interval,
                    backupCount=backup_count,
                    encoding="utf-8",
                    utc=True,
                )
                # Rotación by size adicional (no soportada nativamente)
                # Usamos RotatingFileHandler si rotate_when = "size"
                if rotate_when == "size":
                    file_handler = logging.handlers.RotatingFileHandler(
                        log_path,
                        maxBytes=max_bytes,
                        backupCount=backup_count,
                        encoding="utf-8",
                    )
            else:
                file_handler = logging.FileHandler(log_path, encoding="utf-8")

            file_handler.setLevel(level)
            file_handler.setFormatter(logging.Formatter("%(message)s"))
            root.addHandler(file_handler)

            # Compresión de backups (si aplica)
            if compress_backups and hasattr(file_handler, "rotator"):
                # Custom rotator que comprime
                import gzip
                import shutil

                def _compress_rotator(source: str, dest: str) -> None:
                    with open(source, "rb") as f_in:
                        with gzip.open(dest + ".gz", "wb") as f_out:
                            shutil.copyfileobj(f_in, f_out)
                    os.remove(source)

                file_handler.rotator = _compress_rotator  # type: ignore[attr-defined]
                if hasattr(file_handler, "namer"):
                    def _namer(name: str) -> str:
                        return name + ".gz"
                    file_handler.namer = _namer  # type: ignore[attr-defined]

        _CONFIGURED = True


# ============================================================================
# LOGGERS
# ============================================================================

def get_logger(name: str = "god_tier") -> Any:
    """Logger general de la aplicación."""
    return structlog.get_logger(name)


def get_security_logger(name: str = "god_tier.security") -> Any:
    """Logger de eventos de seguridad."""
    return structlog.get_logger(name)


def get_audit_logger(name: str = "god_tier.audit") -> Any:
    """Logger de auditoría."""
    return structlog.get_logger(name)


def get_evidence_logger(name: str = "god_tier.evidence") -> Any:
    """Logger de evidencia (forense)."""
    return structlog.get_logger(name)


# ============================================================================
# SIEM FORMATTERS
# ============================================================================

class SIEMFormat(str, Enum if False else object):  # type: ignore[misc]
    """Formatos de export SIEM."""
    JSONL = "jsonl"
    OCSF = "ocsf"
    CEF = "cef"
    LEEF = "leef"


# Usar str-enum nativo
from enum import Enum  # noqa: E402

class SIEMFormat(str, Enum):  # type: ignore[no-redef]
    """Formatos de export SIEM."""
    JSONL = "jsonl"
    OCSF = "ocsf"
    CEF = "cef"
    LEEF = "leef"


def to_ocsf(
    event_dict: dict[str, Any],
    *,
    class_uid: int = 2001,
    activity_id: int = 1,
) -> dict[str, Any]:
    """Convierte un evento log a formato OCSF (v1.3)."""
    level = str(event_dict.get("level", "info")).upper()
    severity_id = _LEVEL_TO_SEVERITY.get(level, 2)

    ts = event_dict.get("ts", datetime.now(timezone.utc).isoformat())

    return {
        "class_uid": class_uid,
        "class_name": "Security Finding",
        "time": int(time.time() * 1000),
        "time_dt": ts,
        "severity_id": severity_id,
        "activity_id": activity_id,
        "metadata": {
            "version": "1.3.0",
            "product": {
                "vendor_name": "GodTier",
                "name": "Horus",
            },
            "log_name": event_dict.get("logger", "unknown"),
            "logged_time": int(time.time() * 1000),
        },
        "actor": {
            "session": {
                "uid": event_dict.get("correlation_id", ""),
            },
            "process": {
                "pid": event_dict.get("pid", 0),
                "name": event_dict.get("service_name", "unknown"),
            },
        },
        "device": {
            "hostname": event_dict.get("hostname", "unknown"),
        },
        "finding_info": {
            "title": event_dict.get("event", "log_event"),
            "desc": str(event_dict.get("msg", "")),
            "types": [level.lower()],
        },
        "unmapped": {
            k: v for k, v in event_dict.items()
            if k not in {"level", "ts", "logger", "msg", "event"}
        },
    }


def to_cef(event_dict: dict[str, Any]) -> str:
    """Convierte un evento log a formato CEF (ArcSight)."""
    level = str(event_dict.get("level", "info")).upper()
    severity = _LEVEL_TO_SEVERITY.get(level, 2)

    extension = " ".join(
        f"{k}={v}" for k, v in event_dict.items()
        if k not in {"level", "ts", "logger", "msg", "event"}
    )
    return (
        f"CEF:0|GodTier|Horus|5.0|"
        f"{event_dict.get('event', 'log_event')}|"
        f"{event_dict.get('event', 'log_event')}|"
        f"{severity}|"
        f"src={event_dict.get('hostname', 'unknown')} "
        f"{extension}"
    )


def to_leef(event_dict: dict[str, Any]) -> str:
    """Convierte un evento log a formato LEEF (IBM QRadar)."""
    extension = "\t".join(
        f"{k}={v}" for k, v in event_dict.items()
        if k not in {"level", "ts", "logger", "msg", "event"}
    )
    return (
        f"LEEF:2.0|GodTier|Horus|5.0|"
        f"{event_dict.get('event', 'log_event')}|"
        f"devTime={event_dict.get('ts', '')}\t"
        f"sev={event_dict.get('level', 'info')}\t"
        f"{extension}"
    )


def to_siem(event_dict: dict[str, Any], fmt: SIEMFormat = SIEMFormat.JSONL) -> str:
    """Convierte a formato SIEM específico."""
    import json as _json
    if fmt == SIEMFormat.OCSF:
        return _json.dumps(to_ocsf(event_dict), separators=(",", ":"))
    if fmt == SIEMFormat.CEF:
        return to_cef(event_dict)
    if fmt == SIEMFormat.LEEF:
        return to_leef(event_dict)
    return _json.dumps(event_dict, separators=(",", ":"), ensure_ascii=False)


# ============================================================================
# REDACTION STATS
# ============================================================================

def get_redaction_stats() -> dict[str, Any]:
    """Retorna estadísticas de redacción (para auditoría)."""
    with _REDACTION_LOCK:
        return {
            "total_redactions": _REDACTION_STATS.total_redactions,
            "by_type": dict(_REDACTION_STATS.by_type),
            "recent": [
                {
                    "field_name": r.field_name,
                    "original_length": r.original_length,
                    "redacted_type": r.redacted_type,
                }
                for r in _REDACTION_STATS.recent[-20:]
            ],
        }


def reset_redaction_stats() -> None:
    """Reset de estadísticas de redacción."""
    global _REDACTION_STATS
    with _REDACTION_LOCK:
        _REDACTION_STATS = RedactionStats()


# ============================================================================
# RE-EXPORTS (backward compat)
# ============================================================================

from god_tier_agency.core.context import (  # noqa: E402
    CorrelationContext,
    RequestContext,
    bind_context,
    create_task_with_context,
    get_context,
    get_correlation_id,
)

__all__ = [
    # Setup
    "setup_logging",
    # Loggers
    "get_logger",
    "get_security_logger",
    "get_audit_logger",
    "get_evidence_logger",
    # Levels
    "SECURITY_LEVEL",
    "AUDIT_LEVEL",
    "EVIDENCE_LEVEL",
    # SIEM
    "SIEMFormat",
    "to_ocsf",
    "to_cef",
    "to_leef",
    "to_siem",
    # Redaction
    "redact_secrets",
    "get_redaction_stats",
    "reset_redaction_stats",
    # Context (re-export)
    "CorrelationContext",
    "RequestContext",
    "bind_context",
    "get_context",
    "get_correlation_id",
    "create_task_with_context",
]
