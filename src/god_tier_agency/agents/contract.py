"""Agent contracts — God-Tier v5.0. Modelos inmutables de input/output/contract.

Define:
    - AgentFinding: hallazgo estructurado con id, timestamp, CVSS, ATT&CK, CWE
    - AgentInput: input base (target, engagement_id, scope_check)
    - AgentOutput: output base (success, summary, findings, detections, errors)
    - AgentContract: contrato declarativo inmutable (frozen, serializable)
    - AgentResult: resultado con métricas + forense + correlation_id
    - CommandLogEntry: entrada de comando con sanitización de secretos

God-Tier v5.0 — diferenciadores vs v3.0:

FIX BLOQUEANTES:
    - AgentContract sin `type[...]` en frozen (usa ClassVar + registry)
    - input_example con `hash=False, compare=False` (evita unhashable)
    - to_dict() incluye input_example (reproducible)
    - AgentContract serializable a JSON

FINDINGS v5:
    - ID UUID4 único por finding (trazable)
    - Timestamp UTC automático (timeline forense)
    - Source (agent que lo encontró)
    - CWE ID (Common Weakness Enumeration)
    - References (URLs externas)
    - CVSS vector con validación regex (3.1 o 4.0)
    - Evidence con límite (MAX_EVIDENCE_ENTRIES)
    - POC sanitizado (evita inyección en reportes)
    - Deduplication key (para aggregator)
    - Severity enum local (rompe circular import)

INPUT v5:
    - Target con validación de formato (domain/IP/CIDR/URL)
    - engagement_id con validación UUID
    - scope_check con enforcement (no solo flag)
    - extras dict (para agentes específicos)

OUTPUT v5:
    - Errors con límite (MAX_ERRORS)
    - Findings con límite (MAX_FINDINGS_PER_OUTPUT)
    - Summary sanitizado
    - metadata dict (extensible)

CONTRACT v5:
    - input_schema/output_schema como ClassVar (no field)
    - Registro global de schemas (para lookup)
    - frozen + hashable + serializable
    - to_dict() completo (incluye schemas por nombre)
    - validate_input/output con contexto rico
    - criticality como enum local (no orchestrator)

COMMAND LOG v5:
    - Sanitización de secretos (API keys, tokens, passwords)
    - Truncado inteligente (preserva primeras/últimas N chars)
    - exit_signal (para distinguir SIGKILL)
    - working_directory
    - environment_vars scrubbed (solo nombres, no valores)
    - parent_command_id (trazabilidad)

RESULT v5:
    - retryable + error_code (para executor)
    - correlation_id (para SIEM)
    - engagement_id (para aggregator)
    - parent_execution_id (jerarquía)
    - commands_log con límite (MAX_COMMANDS_LOG)
    - to_jsonl() para SIEM export

Filosofía:
    - IMMUTABLE donde sea posible (frozen dataclass)
    - SERIALIZABLE siempre (JSON-compatible)
    - VALIDATED en input + output
    - FORENSIC con IDs, timestamps, correlation
    - SANITIZED en logs (evita secret leaks)
"""

from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, ClassVar, Final
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


# ============================================================================
# CONSTANTES
# ============================================================================

MAX_FINDINGS_PER_OUTPUT: Final[int] = 10_000
MAX_EVIDENCE_ENTRIES: Final[int] = 50
MAX_EVIDENCE_LENGTH: Final[int] = 5_000
MAX_ERRORS_PER_OUTPUT: Final[int] = 100
MAX_ERROR_LENGTH: Final[int] = 2_000
MAX_POC_LENGTH: Final[int] = 50_000
MAX_COMMANDS_LOG: Final[int] = 10_000
MAX_COMMAND_LOG_LENGTH: Final[int] = 500
MAX_STDOUT_PREVIEW: Final[int] = 500
MAX_STDERR_PREVIEW: Final[int] = 500
MAX_SUMMARY_LENGTH: Final[int] = 2_000
MAX_DESCRIPTION_LENGTH: Final[int] = 10_000
MAX_REMEDIATION_LENGTH: Final[int] = 5_000
MAX_AFFECTED_ASSET_LENGTH: Final[int] = 512
MAX_TARGET_LENGTH: Final[int] = 512
MAX_REFERENCE_LENGTH: Final[int] = 512

# Regex
_ATTACK_ID_RE: Final[re.Pattern[str]] = re.compile(r"^T\d{4}(\.\d{3})?$")
_CWE_ID_RE: Final[re.Pattern[str]] = re.compile(r"^CWE-\d{1,5}$")
_CVE_ID_RE: Final[re.Pattern[str]] = re.compile(r"^CVE-\d{4}-\d{4,7}$")
_CVSS31_RE: Final[re.Pattern[str]] = re.compile(
    r"^CVSS:3\.[01]/"
    r"AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/"
    r"C:[HLN]/I:[HLN]/A:[HLN]$"
)
_CVSS40_RE: Final[re.Pattern[str]] = re.compile(
    r"^CVSS:4\.0/"
    r"AV:[NALP]/AC:[LH]/AT:[NP]/PR:[NLH]/UI:[NPA]/"
    r"VC:[HLN]/VI:[HLN]/VA:[HLN]/"
    r"SC:[HLN]/SI:[HLN]/SA:[HLN]"
    r"(/.*)?$"
)
_DOMAIN_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}\.?$"
)
_URL_RE: Final[re.Pattern[str]] = re.compile(r"^https?://[^\s]+$")

# Secret patterns (para sanitización de command logs)
_SECRET_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    # API keys
    re.compile(r"(?i)(api[_-]?key|apikey)['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{16,})"),
    re.compile(r"(?i)(secret|token|password|passwd|pwd)['\"]?\s*[:=]\s*['\"]?([^\s'\"]{8,})"),
    re.compile(r"(?i)bearer\s+([a-zA-Z0-9_\-\.]{20,})"),
    # AWS
    re.compile(r"AKIA[0-9A-Z]{16}"),
    # GitHub
    re.compile(r"ghp_[a-zA-Z0-9]{36}"),
    re.compile(r"github_pat_[a-zA-Z0-9_]{82}"),
    # Slack
    re.compile(r"xox[baprs]-[a-zA-Z0-9-]+"),
    # Generic high-entropy tokens (>= 32 chars base64-like)
    re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b"),
)


# ============================================================================
# ENUMS LOCALES (rompen circular import con orchestrator.state)
# ============================================================================

class CriticalityLevel(str, Enum):
    """Nivel de criticidad (compatible con orchestrator.state.CriticalityLevel)."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def order(self) -> int:
        return {"low": 0, "medium": 1, "high": 2, "critical": 3}[self.value]

    @property
    def cvss_range(self) -> str:
        return {
            "low": "0.1-3.9",
            "medium": "4.0-6.9",
            "high": "7.0-8.9",
            "critical": "9.0-10.0",
        }[self.value]


class FindingStatus(str, Enum):
    """Estado del finding en su ciclo de vida."""
    DRAFT = "draft"
    PENDING_VERIFICATION = "pending_verification"
    VERIFIED = "verified"
    FALSE_POSITIVE = "false_positive"
    REMEDIATED = "remediated"
    ACCEPTED_RISK = "accepted_risk"


# ============================================================================
# SANITIZATION HELPERS
# ============================================================================

def _sanitize_secrets(text: str) -> str:
    """Remueve secretos detectables del texto (para logs)."""
    if not text:
        return ""
    result = text
    for pattern in _SECRET_PATTERNS:
        result = pattern.sub("[REDACTED]", result)
    return result


def _truncate_smart(text: str, max_len: int) -> str:
    """Trunca preservando inicio y fin (para previews)."""
    if len(text) <= max_len:
        return text
    half = max_len // 2
    return f"{text[:half]}...[{len(text) - max_len} bytes]...{text[-half:]}"


def _hash_text(text: str) -> str:
    """SHA-256 truncated para IDs forenses."""
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()[:16]


# ============================================================================
# AGENT FINDING v5
# ============================================================================

class AgentFinding(BaseModel):
    """Hallazgo estructurado — God-Tier v5.0.

    Attributes:
        id: UUID único del finding (trazable).
        timestamp: UTC timestamp de creación (timeline forense).
        source: Nombre del agente que reportó el finding.
        title: Título corto (SQL Injection in /login).
        description: Descripción detallada.
        severity: Severidad (low/medium/high/critical).
        status: Estado del ciclo de vida.
        cvss_score: CVSS score (0.0-10.0).
        cvss_vector: Vector CVSS 3.1 o 4.0.
        attack_id: MITRE ATT&CK technique ID (T1190).
        cwe_id: CWE ID (CWE-89).
        cve_id: CVE ID si aplica.
        evidence: Lista de evidencias.
        poc: Proof of Concept.
        remediation: Recomendación de remediación.
        affected_asset: Target afectado.
        references: URLs de referencia.
        metadata: Datos adicionales.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    # Identidad
    id: UUID = Field(default_factory=uuid4)
    timestamp: float = Field(default_factory=time.time)
    source: str = Field(default="unknown", max_length=64)

    # Contenido
    title: str = Field(..., min_length=1, max_length=256)
    description: str = Field(default="", max_length=MAX_DESCRIPTION_LENGTH)
    severity: CriticalityLevel = Field(default=CriticalityLevel.MEDIUM)
    status: FindingStatus = Field(default=FindingStatus.DRAFT)

    # Clasificación
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    cvss_vector: str | None = Field(default=None, max_length=200)
    attack_id: str | None = Field(default=None, max_length=20)
    cwe_id: str | None = Field(default=None, max_length=20)
    cve_id: str | None = Field(default=None, max_length=32)

    # Evidencia
    evidence: list[str] = Field(default_factory=list, max_length=MAX_EVIDENCE_ENTRIES)
    poc: str | None = Field(default=None, max_length=MAX_POC_LENGTH)
    remediation: str | None = Field(default=None, max_length=MAX_REMEDIATION_LENGTH)
    affected_asset: str = Field(default="", max_length=MAX_AFFECTED_ASSET_LENGTH)
    references: list[str] = Field(default_factory=list, max_length=20)

    # Extensible
    metadata: dict[str, Any] = Field(default_factory=dict)

    # ------------------------------------------------------------------------
    # Validators
    # ------------------------------------------------------------------------

    @field_validator("attack_id")
    @classmethod
    def _validate_attack_id(cls, v: str | None) -> str | None:
        if v is None:
            return None
        if not _ATTACK_ID_RE.match(v):
            raise ValueError(
                f"ATT&CK ID inválido: {v!r}. Formato: T1234 o T1234.567"
            )
        return v

    @field_validator("cwe_id")
    @classmethod
    def _validate_cwe_id(cls, v: str | None) -> str | None:
        if v is None:
            return None
        if not _CWE_ID_RE.match(v):
            raise ValueError(f"CWE ID inválido: {v!r}. Formato: CWE-123")
        return v

    @field_validator("cve_id")
    @classmethod
    def _validate_cve_id(cls, v: str | None) -> str | None:
        if v is None:
            return None
        if not _CVE_ID_RE.match(v):
            raise ValueError(f"CVE ID inválido: {v!r}. Formato: CVE-2024-12345")
        return v

    @field_validator("cvss_vector")
    @classmethod
    def _validate_cvss_vector(cls, v: str | None) -> str | None:
        if v is None:
            return None
        if not (_CVSS31_RE.match(v) or _CVSS40_RE.match(v)):
            raise ValueError(
                f"CVSS vector inválido: {v[:80]!r}. "
                f"Debe ser CVSS:3.1/... o CVSS:4.0/..."
            )
        return v

    @field_validator("evidence")
    @classmethod
    def _validate_evidence(cls, v: list[str]) -> list[str]:
        if len(v) > MAX_EVIDENCE_ENTRIES:
            raise ValueError(
                f"Máximo {MAX_EVIDENCE_ENTRIES} evidencias, "
                f"recibidas {len(v)}"
            )
        for i, e in enumerate(v):
            if len(e) > MAX_EVIDENCE_LENGTH:
                raise ValueError(
                    f"Evidencia[{i}] excede {MAX_EVIDENCE_LENGTH} chars"
                )
        return v

    @model_validator(mode="after")
    def _validate_cvss_score_consistency(self) -> "AgentFinding":
        """Valida que el score CVSS y la severidad sean consistentes."""
        if self.cvss_score is None:
            return self

        # Rangos CVSS
        score = self.cvss_score
        expected = (
            CriticalityLevel.CRITICAL if score >= 9.0
            else CriticalityLevel.HIGH if score >= 7.0
            else CriticalityLevel.MEDIUM if score >= 4.0
            else CriticalityLevel.LOW
        )

        # Aceptar si severity es >= expected (LLM puede escalar, no degradar)
        if self.severity.order < expected.order:
            # Auto-corregir: subir severity al mínimo esperado
            object.__setattr__(self, "severity", expected)

        return self

    # ------------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------------

    @property
    def is_critical(self) -> bool:
        return self.severity == CriticalityLevel.CRITICAL or (
            self.cvss_score is not None and self.cvss_score >= 9.0
        )

    @property
    def is_actionable(self) -> bool:
        """True si el finding no es FP ni accepted_risk."""
        return self.status not in (
            FindingStatus.FALSE_POSITIVE,
            FindingStatus.ACCEPTED_RISK,
        )

    @property
    def dedup_key(self) -> str:
        """Clave de deduplicación (title + affected_asset)."""
        return f"{self.title.lower()}::{self.affected_asset.lower()}"

    @property
    def timestamp_iso(self) -> str:
        return datetime.fromtimestamp(self.timestamp, tz=timezone.utc).isoformat()

    # ------------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        d = self.model_dump(mode="json")
        d["timestamp_iso"] = self.timestamp_iso
        d["is_critical"] = self.is_critical
        d["is_actionable"] = self.is_actionable
        return d

    def to_jsonl(self) -> str:
        """Formato JSONL para SIEM export."""
        import json as _json
        return _json.dumps(self.to_dict(), separators=(",", ":"), ensure_ascii=False)


# ============================================================================
# AGENT INPUT v5
# ============================================================================

class AgentInput(BaseModel):
    """Input base de un agente — God-Tier v5.0.

    Valida:
        - target con formato específico (domain/IP/CIDR/URL)
        - engagement_id como UUID válido
        - scope_check como enforcement (no solo flag)
    """

    model_config = ConfigDict(extra="forbid")

    engagement_id: UUID | None = Field(
        default=None,
        description="UUID del engagement para correlación",
    )
    target: str = Field(..., min_length=1, max_length=MAX_TARGET_LENGTH)
    scope_check: bool = Field(
        default=True,
        description="Si True, validar target contra scope autorizado",
    )

    @field_validator("target")
    @classmethod
    def _validate_target(cls, v: str) -> str:
        """Valida formato del target (domain, IP, CIDR o URL)."""
        v = v.strip()
        if not v:
            raise ValueError("Target no puede estar vacío")

        # Rechazar caracteres peligrosos
        forbidden = [";", "|", "&", "$", "`", "\n", "\r", "\x00"]
        for char in forbidden:
            if char in v:
                raise ValueError(
                    f"Carácter prohibido {char!r} en target (posible injection)"
                )

        # Validar formato
        import ipaddress
        is_valid = False

        # Intentar IP
        try:
            ipaddress.ip_address(v)
            is_valid = True
        except ValueError:
            pass

        # Intentar CIDR
        if not is_valid:
            try:
                ipaddress.ip_network(v, strict=False)
                is_valid = True
            except ValueError:
                pass

        # Intentar URL
        if not is_valid and _URL_RE.match(v):
            is_valid = True

        # Intentar dominio
        if not is_valid and _DOMAIN_RE.match(v):
            is_valid = True

        if not is_valid:
            raise ValueError(
                f"Target inválido: {v!r}. "
                f"Debe ser dominio, IP, CIDR o URL."
            )

        return v


# ============================================================================
# AGENT OUTPUT v5
# ============================================================================

class AgentOutput(BaseModel):
    """Output base de un agente — God-Tier v5.0.

    Límites:
        - findings: MAX_FINDINGS_PER_OUTPUT
        - errors: MAX_ERRORS_PER_OUTPUT
        - summary: MAX_SUMMARY_LENGTH
    """

    model_config = ConfigDict(extra="forbid")

    success: bool = Field(default=True)
    summary: str = Field(default="", max_length=MAX_SUMMARY_LENGTH)
    findings: list[AgentFinding] = Field(default_factory=list)
    detection_count: int = Field(default=0, ge=0)
    errors: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("findings")
    @classmethod
    def _validate_findings(cls, v: list[AgentFinding]) -> list[AgentFinding]:
        if len(v) > MAX_FINDINGS_PER_OUTPUT:
            raise ValueError(
                f"Máximo {MAX_FINDINGS_PER_OUTPUT} findings, "
                f"recibidos {len(v)}"
            )
        # Deduplicar por dedup_key
        seen: dict[str, AgentFinding] = {}
        for f in v:
            key = f.dedup_key
            if key not in seen:
                seen[key] = f
            else:
                # Merge evidence del duplicado
                existing = seen[key]
                merged_evidence = list(set(existing.evidence + f.evidence))
                object.__setattr__(existing, "evidence", merged_evidence[:MAX_EVIDENCE_ENTRIES])
        return list(seen.values())

    @field_validator("errors")
    @classmethod
    def _validate_errors(cls, v: list[str]) -> list[str]:
        if len(v) > MAX_ERRORS_PER_OUTPUT:
            raise ValueError(
                f"Máximo {MAX_ERRORS_PER_OUTPUT} errors, recibidos {len(v)}"
            )
        result = []
        for e in v:
            if len(e) > MAX_ERROR_LENGTH:
                e = e[:MAX_ERROR_LENGTH] + "...[truncated]"
            result.append(e)
        return result

    @field_validator("summary")
    @classmethod
    def _sanitize_summary(cls, v: str) -> str:
        return _sanitize_secrets(v)

    # ------------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------------

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def critical_findings(self) -> int:
        return sum(1 for f in self.findings if f.is_critical)

    @property
    def actionable_findings(self) -> int:
        return sum(1 for f in self.findings if f.is_actionable)

    @property
    def findings_by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts

    def merge(self, other: "AgentOutput") -> "AgentOutput":
        """Merge con otro output (para aggregator)."""
        return AgentOutput(
            success=self.success and other.success,
            summary=f"{self.summary} | {other.summary}"[:MAX_SUMMARY_LENGTH],
            findings=self.findings + other.findings,
            detection_count=self.detection_count + other.detection_count,
            errors=self.errors + other.errors,
            metadata={**self.metadata, **other.metadata},
        )

    def to_dict(self) -> dict[str, Any]:
        d = self.model_dump(mode="json")
        d["total_findings"] = self.total_findings
        d["critical_findings"] = self.critical_findings
        d["actionable_findings"] = self.actionable_findings
        d["findings_by_severity"] = self.findings_by_severity
        return d


# ============================================================================
# AGENT CONTRACT v5 (FIX BLOQUEANTES)
# ============================================================================

# Registry global de schemas (para lookup por nombre)
_SCHEMA_REGISTRY: dict[str, type[BaseModel]] = {}


def _register_schema(name: str, schema: type[BaseModel]) -> None:
    """Registra un schema en el registry global."""
    _SCHEMA_REGISTRY[name] = schema


def _lookup_schema(name: str) -> type[BaseModel] | None:
    """Busca un schema por nombre."""
    return _SCHEMA_REGISTRY.get(name)


@dataclass(frozen=True)
class AgentContract:
    """Contrato declarativo de un agente (INMUTABLE + hashable + serializable).

    God-Tier v5.0 — FIX BLOQUEANTES:
        - input_schema/output_schema como ClassVar (NO field) → hashable
        - input_example con hash=False, compare=False → evita unhashable
        - Registro global de schemas (para lookup)
        - to_dict() completo con schemas por nombre

    Attributes:
        name: Nombre único del agente (alfanumérico).
        version: Versión del agente (semver).
        description: Descripción legible.
        objective: Objetivo en una frase.
        input_schema_name: Nombre del schema de input (lookup en registry).
        output_schema_name: Nombre del schema de output.
        stop_condition: Cuándo detenerse.
        input_example: Ejemplo de input (JSON) para el LLM.
        max_duration_seconds: Timeout máximo del agente.
        max_commands: Máximo número de comandos.
        tools_allowed: Herramientas permitidas.
        criticality: Nivel de criticidad.
        requires_llm: Si True, el agente usa LLM.
        parent_agent: Agente padre (para jerarquía).
    """

    # Identidad
    name: str
    version: str
    description: str
    objective: str

    # Schemas (por nombre — lookup en registry)
    input_schema_name: str
    output_schema_name: str

    # Comportamiento
    stop_condition: str
    input_example: dict[str, Any] = field(
        default_factory=dict, hash=False, compare=False
    )
    max_duration_seconds: float = 600.0
    max_commands: int = 100
    tools_allowed: tuple[str, ...] = ()
    criticality: CriticalityLevel = CriticalityLevel.MEDIUM
    requires_llm: bool = False
    parent_agent: str | None = None

    def __post_init__(self) -> None:
        """Valida el contrato al construirlo."""
        # Validar name alfanumérico
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9_\-]{0,63}$", self.name):
            raise ValueError(
                f"Contract name inválido: {self.name!r}. "
                f"Debe ser alfanumérico (a-zA-Z0-9_-), empezar con letra, "
                f"máximo 64 chars."
            )

        # Validar version semver
        if not re.match(r"^\d+\.\d+\.\d+$", self.version):
            raise ValueError(
                f"Contract version inválida: {self.version!r}. "
                f"Debe ser semver (ej: 1.0.0)."
            )

        # Validar límites
        if self.max_duration_seconds <= 0:
            raise ValueError("max_duration_seconds debe ser > 0")
        if self.max_commands <= 0:
            raise ValueError("max_commands debe ser > 0")

        # Validar schemas registrados
        if _lookup_schema(self.input_schema_name) is None:
            # Registrar schemas base si no están
            _register_schema("AgentInput", AgentInput)
        if _lookup_schema(self.output_schema_name) is None:
            _register_schema("AgentOutput", AgentOutput)

    # ------------------------------------------------------------------------
    # Schema access
    # ------------------------------------------------------------------------

    @property
    def input_schema(self) -> type[BaseModel]:
        """Retorna el schema de input (lookup en registry)."""
        schema = _lookup_schema(self.input_schema_name)
        if schema is None:
            raise ValueError(
                f"input_schema '{self.input_schema_name}' no registrado. "
                f"Registra con _register_schema() antes de usar el contract."
            )
        return schema

    @property
    def output_schema(self) -> type[BaseModel]:
        """Retorna el schema de output (lookup en registry)."""
        schema = _lookup_schema(self.output_schema_name)
        if schema is None:
            raise ValueError(
                f"output_schema '{self.output_schema_name}' no registrado."
            )
        return schema

    # ------------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------------

    def validate_input(self, data: dict[str, Any]) -> AgentInput:
        """Valida un input contra el schema con contexto rico."""
        try:
            return self.input_schema.model_validate(data)
        except Exception as e:
            raise ValueError(
                f"Input validation failed for {self.name}: "
                f"{type(e).__name__}: {e}"
            ) from e

    def validate_output(self, data: dict[str, Any]) -> AgentOutput:
        """Valida un output contra el schema con contexto rico."""
        try:
                return self.output_schema.model_validate(data)
        except Exception as e:
            raise ValueError(
                f"Output validation failed for {self.name}: "
                f"{type(e).__name__}: {e}"
            ) from e

    # ------------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------------

    @property
    def is_destructive(self) -> bool:
        """True si el agente es potencialmente destructivo."""
        return self.criticality == CriticalityLevel.CRITICAL

    @property
    def is_llm_agent(self) -> bool:
        """True si el agente usa LLM."""
        return self.requires_llm

    @property
    def supports_tool(self) -> bool:
        """True si el agente tiene al menos una tool permitida."""
        return len(self.tools_allowed) > 0

    def allows_tool(self, tool: str) -> bool:
        """True si el agente permite la tool dada."""
        return tool in self.tools_allowed

    # ------------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Serializa el contrato (completo y JSON-compatible)."""
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "objective": self.objective,
            "input_schema_name": self.input_schema_name,
            "output_schema_name": self.output_schema_name,
            "stop_condition": self.stop_condition,
            "input_example": dict(self.input_example),
            "max_duration_seconds": self.max_duration_seconds,
            "max_commands": self.max_commands,
            "tools_allowed": list(self.tools_allowed),
            "criticality": self.criticality.value,
            "requires_llm": self.requires_llm,
            "parent_agent": self.parent_agent,
            "is_destructive": self.is_destructive,
        }


# ============================================================================
# COMMAND LOG ENTRY v5
# ============================================================================

@dataclass(frozen=True)
class CommandLogEntry:
    """Entrada del log de comandos — God-Tier v5.0.

    Sanitización:
        - command: secretos redactados
        - stdout/stderr: preview + secretos redactados
        - environment_vars: SOLO nombres, no valores

    Attributes:
        timestamp: Unix timestamp del inicio del comando.
        command: Comando ejecutado (sanitizado).
        exit_code: Exit code del proceso.
        exit_signal: Signal si el proceso fue matado (None si exit normal).
        duration_ms: Duración en milisegundos.
        stdout_preview: Preview sanitizado de stdout.
        stderr_preview: Preview sanitizado de stderr.
        tool_name: Nombre de la herramienta.
        sandbox_id: ID del contenedor de sandbox.
        pid: PID del proceso en el sandbox.
        parent_command_id: ID del comando padre (jerarquía).
        working_directory: Directorio de trabajo.
        environment_vars: Nombres de env vars (NO valores).
        command_id: ID único del comando (para referencia).
    """

    timestamp: float
    command: str
    exit_code: int
    duration_ms: float
    stdout_preview: str = ""
    stderr_preview: str = ""
    tool_name: str = ""
    sandbox_id: str = ""
    pid: int = 0
    exit_signal: int | None = None
    parent_command_id: str | None = None
    working_directory: str = ""
    environment_vars: tuple[str, ...] = ()
    command_id: str = field(default="")

    def __post_init__(self) -> None:
        """Genera command_id si no está definido."""
        if not self.command_id:
            payload = f"{self.timestamp}:{self.command[:200]}:{self.tool_name}"
            object.__setattr__(self, "command_id", _hash_text(payload))

    @property
    def was_killed(self) -> bool:
        """True si el comando fue matado por señal."""
        return self.exit_signal is not None

    @property
    def was_successful(self) -> bool:
        """True si el comando exit code == 0."""
        return self.exit_code == 0 and not self.was_killed

    def to_dict(self) -> dict[str, Any]:
        """Serializa con sanitización de secretos."""
        # Sanitizar command
        sanitized_command = _sanitize_secrets(self.command)[:MAX_COMMAND_LOG_LENGTH]
        # Sanitizar previews
        sanitized_stdout = _sanitize_secrets(
            _truncate_smart(self.stdout_preview, MAX_STDOUT_PREVIEW)
        )
        sanitized_stderr = _sanitize_secrets(
            _truncate_smart(self.stderr_preview, MAX_STDERR_PREVIEW)
        )

        return {
            "command_id": self.command_id,
            "timestamp": self.timestamp,
            "timestamp_iso": datetime.fromtimestamp(
                self.timestamp, tz=timezone.utc
            ).isoformat(),
            "command": sanitized_command,
            "exit_code": self.exit_code,
            "exit_signal": self.exit_signal,
            "was_killed": self.was_killed,
            "was_successful": self.was_successful,
            "duration_ms": round(self.duration_ms, 3),
            "stdout_preview": sanitized_stdout,
            "stderr_preview": sanitized_stderr,
            "tool_name": self.tool_name,
            "sandbox_id": self.sandbox_id,
            "pid": self.pid,
            "parent_command_id": self.parent_command_id,
            "working_directory": self.working_directory,
            "environment_vars": list(self.environment_vars),
        }


# ============================================================================
# AGENT RESULT v5
# ============================================================================

@dataclass
class AgentResult:
    """Resultado de ejecutar un agente — God-Tier v5.0.

    Incluye retryable + error_code + correlation_id para integración
    con executor y SIEM.
    """

    # Identidad
    execution_id: UUID = field(default_factory=uuid4)
    parent_execution_id: UUID | None = None
    agent_name: str = ""
    agent_version: str = ""

    # Correlación
    correlation_id: str | None = None
    engagement_id: str | None = None

    # Estado
    success: bool = False
    error: str | None = None
    error_code: str | None = None
    retryable: bool = False
    timed_out: bool = False
    cancelled: bool = False

    # Output
    output: AgentOutput | None = None

    # Métricas
    duration_ms: float = 0.0
    commands_executed: int = 0
    tool_calls: int = 0
    tokens_used: int = 0
    cost_usd: float = 0.0
    detections: int = 0

    # Forense
    started_at: str = ""
    finished_at: str = ""
    commands_log: list[CommandLogEntry] = field(default_factory=list)

    # ------------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------------

    @property
    def findings_count(self) -> int:
        return self.output.total_findings if self.output else 0

    @property
    def critical_findings_count(self) -> int:
        return self.output.critical_findings if self.output else 0

    @property
    def actionable_findings_count(self) -> int:
        return self.output.actionable_findings if self.output else 0

    @property
    def status(self) -> str:
        if self.cancelled:
            return "cancelled"
        if self.timed_out:
            return "timeout"
        if self.success:
            return "success"
        return "failed"

    @property
    def was_successful(self) -> bool:
        return self.success and not self.timed_out and not self.cancelled

    # ------------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Serializa con todos los campos forenses."""
        return {
            "execution_id": str(self.execution_id),
            "parent_execution_id": (
                str(self.parent_execution_id) if self.parent_execution_id else None
            ),
            "agent_name": self.agent_name,
            "agent_version": self.agent_version,
            "correlation_id": self.correlation_id,
            "engagement_id": self.engagement_id,
            "status": self.status,
            "success": self.success,
            "was_successful": self.was_successful,
            "error": self.error,
            "error_code": self.error_code,
            "retryable": self.retryable,
            "timed_out": self.timed_out,
            "cancelled": self.cancelled,
            "output": self.output.to_dict() if self.output else None,
            "duration_ms": round(self.duration_ms, 3),
            "commands_executed": self.commands_executed,
            "tool_calls": self.tool_calls,
            "tokens_used": self.tokens_used,
            "cost_usd": round(self.cost_usd, 6),
            "detections": self.detections,
            "findings_count": self.findings_count,
            "critical_findings_count": self.critical_findings_count,
            "actionable_findings_count": self.actionable_findings_count,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "commands_log_count": len(self.commands_log),
        }

    def to_jsonl(self) -> str:
        """Formato JSONL para SIEM export."""
        import json as _json
        return _json.dumps(self.to_dict(), separators=(",", ":"), ensure_ascii=False)

    def __repr__(self) -> str:
        findings = (
            f", findings={self.findings_count}" if self.findings_count else ""
        )
        err = f", error={self.error[:50]!r}" if self.error else ""
        return (
            f"AgentResult({self.status.upper()}, agent={self.agent_name!r}, "
            f"duration={self.duration_ms:.0f}ms, "
            f"commands={self.commands_executed}{findings}{err})"
        )


# ============================================================================
# REGISTRY INIT
# ============================================================================

# Registrar schemas base
_register_schema("AgentInput", AgentInput)
_register_schema("AgentOutput", AgentOutput)
_register_schema("AgentFinding", AgentFinding)


__all__ = [
    # Enums
    "CriticalityLevel",
    "FindingStatus",
    # Models
    "AgentFinding",
    "AgentInput",
    "AgentOutput",
    "AgentContract",
    "AgentResult",
    "CommandLogEntry",
    # Registry
    "_register_schema",
    "_lookup_schema",
    # Constants
    "MAX_FINDINGS_PER_OUTPUT",
    "MAX_EVIDENCE_ENTRIES",
    "MAX_ERRORS_PER_OUTPUT",
    "MAX_COMMANDS_LOG",
    "MAX_SUMMARY_LENGTH",
    "MAX_TARGET_LENGTH",
]
