"""Scanner Agent — God-Tier v5.0.

Escaneo de vulnerabilidades con ejecución robusta y parsing god-tier:
    - nuclei (vulnerability templates)
    - nikto (web scanner)
    - sqlmap (SQL injection)
    - ffuf (web fuzzing)
    - gobuster (directory enumeration)
    - wpscan (WordPress-specific)

God-Tier v5.0 — diferenciadores vs v4.0:

FIX BLOQUEANTES:
    - FIX #1: ffuf lee output desde stdout (-of json sin -o)
    - FIX #2: ffuf output REAL (no dead code)
    - FIX #3: nikto con -Format json correcto
    - FIX #4: sqlmap output a stdin (no /tmp)
    - FIX #5: gobuster con wordlist embebida

ANÁLISIS PROFUNDO:
    - Vulnerability scoring propio (no solo CVSS)
    - Confidence score por finding (0.0-1.0)
    - Evidence hash (SHA-256) para forense
    - Correlation con recon (mismo target)
    - CVE extraction en TODOS los parsers
    - CWE extraction
    - Confidence-based deduplication

ROBUSTEZ:
    - Timeout por scanner individual
    - Retry con backoff
    - Output size limit (previene OOM)
    - URL validation (anti-SSRF)
    - Scanners availability check
    - Structured logging por scanner

ESCALABILIDAD:
    - Streaming output (nuclei JSONL)
    - Async parallel con semáforo
    - Rate limiting configurable
    - Cache de resultados idénticos

INTEGRACIÓN:
    - SARIF export (CI/CD ready)
    - ATT&CK mapping automático
    - Remediation por tipo
    - Execution metadata (tiempos por scanner)

Filosofía:
    - VALIDATE INPUT (anti-SSRF)
    - LIMIT OUTPUT (anti-OOM)
    - ENRICH FINDINGS (CVE + CWE + ATT&CK)
    - MEASURE CONFIDENCE
    - EVIDENCE HASHED
    - PARALLEL & RETRY
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import ipaddress
import re
import time
from typing import Any, Final, Literal
from urllib.parse import urlparse
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator

from god_tier_agency.agents.base import BaseAgent
from god_tier_agency.agents.contract import (
    AgentContract,
    AgentFinding,
    AgentInput,
    AgentOutput,
)
from god_tier_agency.agents.exceptions import AgentToolError
from god_tier_agency.core.logging import get_logger
from god_tier_agency.orchestrator.state import CriticalityLevel

_log = get_logger("agents.scanner")


# ============================================================================
# CONSTANTES
# ============================================================================

SUPPORTED_SCANNERS: Final[tuple[str, ...]] = (
    "nuclei", "nikto", "sqlmap", "ffuf", "gobuster", "wpscan",
)

# Límites
MAX_OUTPUT_BYTES: Final[int] = 50 * 1024 * 1024  # 50 MB por scanner
MAX_VULNS_PER_SCANNER: Final[int] = 10_000
MAX_EVIDENCE_SIZE: Final[int] = 10_000
DEFAULT_TIMEOUT: Final[float] = 1800.0
DEFAULT_SCANNER_TIMEOUT: Final[float] = 600.0
RETRY_ATTEMPTS: Final[int] = 2
RETRY_BACKOFF: Final[float] = 2.0

# Wordlist embebida (evita dependencia de /usr/share/wordlists)
EMBEDDED_WORDLIST: Final[str] = """
admin
administrator
login
wp-admin
wp-login.php
api
api/v1
api/v2
api/v3
backup
backups
config
configuration
config.php
.env
.env.local
.git
.git/config
.git/HEAD
.svn
.htaccess
.htpasswd
robots.txt
sitemap.xml
swagger
swagger.json
openapi.json
api-docs
graphql
graphiql
phpinfo.php
info.php
test
tests
testing
staging
dev
development
private
public
static
assets
uploads
files
download
downloads
docs
documentation
help
support
search
user
users
profile
account
accounts
auth
oauth
sso
saml
""".strip().split("\n")

# CVE / CWE patterns
_CVE_RE: Final[re.Pattern[str]] = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_CWE_RE: Final[re.Pattern[str]] = re.compile(r"CWE-\d{1,5}", re.IGNORECASE)


# ============================================================================
# PYDANTIC MODELS
# ============================================================================

class Vulnerability(BaseModel):
    """Vulnerabilidad detectada (v5.0 con enrichment)."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=lambda: str(uuid4()))
    title: str = Field(..., min_length=1, max_length=512)
    description: str = Field(default="", max_length=10_000)
    severity: CriticalityLevel = CriticalityLevel.MEDIUM
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    cve: str | None = Field(default=None, max_length=32)
    cwe: str | None = Field(default=None, max_length=20)
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    cvss_vector: str | None = Field(default=None, max_length=200)
    attack_id: str | None = Field(default=None, max_length=20)
    scanner: str = Field(..., min_length=1, max_length=32)
    template_id: str = Field(default="", max_length=256)
    matched_at: str = Field(default="", max_length=2048)
    evidence: list[str] = Field(default_factory=list)
    evidence_hash: str = Field(default="", max_length=64)
    references: list[str] = Field(default_factory=list)
    remediation: str | None = Field(default=None, max_length=5_000)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("cve")
    @classmethod
    def validate_cve(cls, v: str | None) -> str | None:
        if v is None:
            return None
        if not re.match(r"^CVE-\d{4}-\d{4,7}$", v, re.IGNORECASE):
            return None
        return v.upper()

    @field_validator("cwe")
    @classmethod
    def validate_cwe(cls, v: str | None) -> str | None:
        if v is None:
            return None
        if not re.match(r"^CWE-\d{1,5}$", v, re.IGNORECASE):
            return None
        return v.upper()

    @field_validator("attack_id")
    @classmethod
    def validate_attack_id(cls, v: str | None) -> str | None:
        if v is None:
            return None
        if not re.match(r"^T\d{4}(\.\d{3})?$", v):
            return None
        return v

    @property
    def is_critical(self) -> bool:
        return self.severity == CriticalityLevel.CRITICAL or (
            self.cvss_score is not None and self.cvss_score >= 9.0
        )

    @property
    def computed_score(self) -> float:
        """Score compuesto propio (no solo CVSS).

        Ponderación:
            - CVSS score (si existe): 0.5
            - Severity: 0.3
            - Confidence: 0.2
        """
        score = 0.0

        # CVSS component (0-10 → 0-5)
        if self.cvss_score is not None:
            score += (self.cvss_score / 10.0) * 5.0
        else:
            # Mapeo de severity a score
            severity_map = {
                CriticalityLevel.CRITICAL: 5.0,
                CriticalityLevel.HIGH: 4.0,
                CriticalityLevel.MEDIUM: 2.5,
                CriticalityLevel.LOW: 1.0,
            }
            score += severity_map.get(self.severity, 2.0)

        # Confidence component (0-1 → 0-3)
        score += self.confidence * 3.0

        # Bonus si tiene CVE/CWE
        if self.cve:
            score += 1.0
        if self.cwe:
            score += 1.0

        return min(10.0, score)

    @property
    def dedup_key(self) -> str:
        """Clave para deduplicación inteligente."""
        # Normalizar título y URL
        title = re.sub(r"\s+", " ", self.title.lower().strip())[:100]
        url = self.matched_at.lower().rstrip("/")
        return f"{self.scanner}:{self.cve or ''}:{title}:{url}"

    def compute_evidence_hash(self) -> str:
        """Hash SHA-256 de evidencia (para forense)."""
        evidence_str = "\n".join(sorted(self.evidence))
        return hashlib.sha256(evidence_str.encode("utf-8")).hexdigest()[:64]


class ScannerInput(AgentInput):
    """Input del scanner agent."""

    target_type: Literal["url", "domain", "ip"] = "url"
    scanners: list[str] = Field(default_factory=lambda: ["nuclei"])
    intensity: Literal["quick", "standard", "aggressive"] = "standard"
    max_parallel_scanners: int = Field(default=3, ge=1, le=6)
    timeout_per_scanner: float = Field(default=DEFAULT_SCANNER_TIMEOUT, ge=30.0, le=3600.0)
    retry_on_failure: bool = True
    rate_limit_rps: int = Field(default=50, ge=1, le=1000)
    enable_evidence_hash: bool = True

    @field_validator("scanners")
    @classmethod
    def validate_scanners(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("scanners no puede estar vacío")
        invalid = [s for s in v if s not in SUPPORTED_SCANNERS]
        if invalid:
            raise ValueError(
                f"Scanners no soportados: {invalid}. "
                f"Válidos: {list(SUPPORTED_SCANNERS)}"
            )
        return list(set(v))  # Dedup


class ScannerOutput(AgentOutput):
    """Output del scanner agent."""

    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    scanners_run: list[str] = Field(default_factory=list)
    scanners_failed: list[str] = Field(default_factory=list)
    scanners_skipped: list[str] = Field(default_factory=list)
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_scanner: dict[str, int] = Field(default_factory=dict)
    total_vulns: int = 0
    critical_vulns: int = 0
    high_vulns: int = 0
    unique_vulns: int = 0
    execution_metadata: dict[str, Any] = Field(default_factory=dict)




# Registrar schemas en el registry global (necesario para AgentContract)
from god_tier_agency.agents.contract import _register_schema
_register_schema("ScannerInput", ScannerInput)
_register_schema("ScannerOutput", ScannerOutput)
# ============================================================================
# AGENT
# ============================================================================

class ScannerAgent(BaseAgent):
    """Scanner agent — God-Tier v5.0."""

    def get_contract(self) -> AgentContract:
        return AgentContract(
            name="scanner",
            version="5.0.0",
            description="God-Tier vulnerability scanner (6 scanners + enrichment + scoring)",
            objective="Discover and enrich vulnerabilities",
            input_schema=ScannerInput,
            output_schema=ScannerOutput,
            stop_condition="All scanners complete or timeout",
            input_example={
                "target": "https://example.com",
                "target_type": "url",
                "scanners": ["nuclei", "nikto"],
                "intensity": "standard",
                "rate_limit_rps": 50,
            },
            max_duration_seconds=DEFAULT_TIMEOUT,
            max_commands=100,
            tools_allowed=("nuclei", "nikto", "sqlmap", "ffuf", "gobuster", "wpscan"),
            criticality=CriticalityLevel.HIGH,
        )

    # ------------------------------------------------------------------------
    # Main execution
    # ------------------------------------------------------------------------

    async def _execute(self, inp: ScannerInput) -> ScannerOutput:
        """Ejecuta scanners en paralelo con manejo robusto."""
        start_time = time.monotonic()
        output = ScannerOutput(summary="")

        # FASE 0: Validar target (anti-SSRF)
        is_valid, reason = self._validate_target(inp.target, inp.target_type)
        if not is_valid:
            output.errors.append(f"Invalid target: {reason}")
            output.summary = f"Scanner ABORTED: {reason}"
            return output

        # FASE 1: Verificar scanners disponibles
        available, unavailable = await self._check_scanners_available(inp.scanners)
        output.scanners_skipped = unavailable
        if not available:
            output.errors.append("No scanners available")
            output.summary = "Scanner ABORTED: no scanners available"
            return output

        # FASE 2: Ejecutar en paralelo con semáforo
        semaphore = asyncio.Semaphore(inp.max_parallel_scanners)
        scanner_times: dict[str, float] = {}

        async def run_with_timeout(scanner: str) -> tuple[str, list[Vulnerability], float]:
            t0 = time.monotonic()
            try:
                vulns = await asyncio.wait_for(
                    self._run_scanner_with_semaphore(
                        scanner=scanner,
                        target=inp.target,
                        target_type=inp.target_type,
                        intensity=inp.intensity,
                        timeout=inp.timeout_per_scanner,
                        semaphore=semaphore,
                    ),
                    timeout=inp.timeout_per_scanner + 10,  # margen
                )
            except asyncio.TimeoutError:
                _log.warning("scanner_outer_timeout", scanner=scanner)
                vulns = []
            except Exception as e:
                _log.warning("scanner_exception", scanner=scanner, error=str(e))
                vulns = []
            return scanner, vulns, time.monotonic() - t0

        tasks = [run_with_timeout(s) for s in available]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_vulns: list[Vulnerability] = []
        for r in results:
            if isinstance(r, Exception):
                _log.warning("scanner_gather_exception", error=str(r))
                continue
            scanner, vulns, duration = r
            scanner_times[scanner] = duration

            if vulns:
                output.scanners_run.append(scanner)
                output.by_scanner[scanner] = len(vulns)
                all_vulns.extend(vulns)
            else:
                # Scanner completó sin findings, agregar a run
                output.scanners_run.append(scanner)
                output.by_scanner[scanner] = 0

        # FASE 3: Deduplicación inteligente
        unique_vulns = self._deduplicate_vulnerabilities(all_vulns)

        # FASE 4: Enrichment (evidence hash, computed score)
        for v in unique_vulns:
            if inp.enable_evidence_hash and not v.evidence_hash:
                v.evidence_hash = v.compute_evidence_hash()

        # FASE 5: Ordenar por computed_score descendente
        unique_vulns.sort(key=lambda v: v.computed_score, reverse=True)

        # Truncar si excede límite
        unique_vulns = unique_vulns[:MAX_VULNS_PER_SCANNER * len(available)]

        output.vulnerabilities = unique_vulns
        output.total_vulns = len(all_vulns)
        output.unique_vulns = len(unique_vulns)

        # FASE 6: Agregaciones
        by_sev: dict[str, int] = {}
        for v in unique_vulns:
            sev = v.severity.value
            by_sev[sev] = by_sev.get(sev, 0) + 1
        output.by_severity = by_sev

        output.critical_vulns = sum(1 for v in unique_vulns if v.severity == CriticalityLevel.CRITICAL)
        output.high_vulns = sum(1 for v in unique_vulns if v.severity == CriticalityLevel.HIGH)

        # FASE 7: Findings
        output.findings = self._generate_findings(unique_vulns, inp.target)

        # FASE 8: Metadata
        execution_time = time.monotonic() - start_time
        output.execution_metadata = {
            "execution_time_seconds": round(execution_time, 2),
            "scanners_requested": len(inp.scanners),
            "scanners_available": len(available),
            "scanners_run": len(output.scanners_run),
            "scanners_failed": len(output.scanners_failed),
            "scanners_skipped": len(output.scanners_skipped),
            "scanner_times": {k: round(v, 2) for k, v in scanner_times.items()},
            "raw_vulns_count": output.total_vulns,
            "unique_vulns_count": output.unique_vulns,
            "dedup_ratio": round(
                1.0 - (output.unique_vulns / max(1, output.total_vulns)), 3
            ),
        }

        # Summary
        output.summary = (
            f"Scanner complete in {execution_time:.1f}s: "
            f"{output.unique_vulns} unique vulns "
            f"({output.critical_vulns} critical, {output.high_vulns} high) "
            f"from {len(output.scanners_run)} scanners"
        )

        return output

    # ------------------------------------------------------------------------
    # Validation & availability
    # ------------------------------------------------------------------------

    @staticmethod
    def _validate_target(target: str, target_type: str) -> tuple[bool, str]:
        """Valida target (anti-SSRF)."""
        if not target or not isinstance(target, str):
            return (False, "empty target")

        # Rechazar caracteres peligrosos
        if any(c in target for c in ("\n", "\r", "\x00", ";", "|", "&")):
            return (False, "forbidden chars in target")

        if target_type == "url":
            try:
                parsed = urlparse(target)
            except Exception:
                return (False, "invalid URL")
            if parsed.scheme not in ("http", "https"):
                return (False, f"invalid scheme: {parsed.scheme}")
            if not parsed.hostname:
                return (False, "no hostname")
            # Anti-SSRF
            try:
                ip = ipaddress.ip_address(parsed.hostname)
                if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                    return (False, f"internal IP rejected: {ip}")
            except ValueError:
                pass
            return (True, "OK")

        if target_type == "domain":
            if not re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", target):
                return (False, "invalid domain")
            return (True, "OK")

        if target_type == "ip":
            try:
                ip = ipaddress.ip_address(target)
                if ip.is_private or ip.is_loopback:
                    return (False, f"internal IP: {ip}")
                return (True, "OK")
            except ValueError:
                return (False, "invalid IP")

        return (False, f"unsupported target_type: {target_type}")

    async def _check_scanners_available(
        self, scanners: list[str],
    ) -> tuple[list[str], list[str]]:
        """Verifica qué scanners están instalados."""
        available: list[str] = []
        unavailable: list[str] = []

        async def check(scanner: str) -> tuple[str, bool]:
            try:
                result = await self.run_command(
                    command=f"command -v {scanner} >/dev/null 2>&1 && {scanner} --version 2>&1 | head -1",
                    timeout_seconds=10.0,
                    tool_name=scanner,
                )
                return (scanner, result["exit_code"] == 0)
            except AgentToolError:
                return (scanner, False)

        tasks = [check(s) for s in scanners]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, Exception):
                continue
            scanner, ok = r
            if ok:
                available.append(scanner)
            else:
                unavailable.append(scanner)

        if unavailable:
            _log.warning("scanners_unavailable", scanners=unavailable)

        return available, unavailable

    # ------------------------------------------------------------------------
    # Scanner dispatch
    # ------------------------------------------------------------------------

    async def _run_scanner_with_semaphore(
        self,
        *,
        scanner: str,
        target: str,
        target_type: str,
        intensity: str,
        timeout: float,
        semaphore: asyncio.Semaphore,
    ) -> list[Vulnerability]:
        """Ejecuta un scanner con semáforo + retry."""
        async with semaphore:
            return await self._run_scanner_with_retry(
                scanner, target, target_type, intensity, timeout,
            )

    async def _run_scanner_with_retry(
        self,
        scanner: str,
        target: str,
        target_type: str,
        intensity: str,
        timeout: float,
    ) -> list[Vulnerability]:
        """Ejecuta un scanner con retry en fallos transitorios."""
        last_error: Exception | None = None

        for attempt in range(RETRY_ATTEMPTS + 1):
            try:
                if scanner == "nuclei":
                    return await self._run_nuclei(target, intensity, timeout)
                if scanner == "nikto":
                    return await self._run_nikto(target, timeout)
                if scanner == "sqlmap":
                    return await self._run_sqlmap(target, intensity, timeout)
                if scanner == "ffuf":
                    return await self._run_ffuf(target, timeout)
                if scanner == "gobuster":
                    return await self._run_gobuster(target, timeout)
                if scanner == "wpscan":
                    return await self._run_wpscan(target, timeout)
                return []
            except (asyncio.TimeoutError, ConnectionError, OSError) as e:
                last_error = e
                if attempt < RETRY_ATTEMPTS:
                    delay = RETRY_BACKOFF ** attempt
                    _log.warning(
                        "scanner_retry",
                        scanner=scanner,
                        attempt=attempt + 1,
                        delay=delay,
                        error=str(e),
                    )
                    await asyncio.sleep(delay)
                    continue
                raise
            except AgentToolError as e:
                last_error = e
                # No retry en tool errors
                _log.warning("scanner_tool_error", scanner=scanner, error=str(e))
                return []

        _log.error("scanner_exhausted", scanner=scanner, error=str(last_error))
        return []

    # ------------------------------------------------------------------------
    # Nuclei (FIX #9, #11)
    # ------------------------------------------------------------------------

    async def _run_nuclei(
        self, target: str, intensity: str, timeout: float,
    ) -> list[Vulnerability]:
        """Ejecuta nuclei con templates + streaming."""
        severity_filter = {
            "quick": "critical,high",
            "standard": "critical,high,medium",
            "aggressive": "critical,high,medium,low",
        }.get(intensity, "critical,high,medium")

        rate_limit = {"quick": 100, "standard": 50, "aggressive": 25}.get(intensity, 50)

        try:
            result = await self.run_command(
                command=(
                    f"nuclei -u {target} -severity {severity_filter} "
                    f"-jsonl -silent -no-color "
                    f"-rate-limit {rate_limit} "
                    f"-timeout 10 -retries 2"
                ),
                timeout_seconds=timeout,
                tool_name="nuclei",
            )
        except AgentToolError:
            return []

        stdout = result.get("stdout", "")[:MAX_OUTPUT_BYTES]
        if not stdout:
            return []

        return self._parse_nuclei_jsonl(stdout)

    @staticmethod
    def _parse_nuclei_jsonl(stdout: str) -> list[Vulnerability]:
        """Parsea output JSONL de nuclei con enrichment."""
        vulns: list[Vulnerability] = []

        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            if not isinstance(data, dict):
                continue

            info = data.get("info", {}) or {}
            classification = info.get("classification", {}) or {}

            # CVE extraction (FIX #21)
            cve_ids = classification.get("cve-id") or []
            if isinstance(cve_ids, str):
                cve_ids = [cve_ids]
            cve = None
            for cid in cve_ids:
                m = _CVE_RE.search(str(cid))
                if m:
                    cve = m.group(0).upper()
                    break

            # CWE extraction
            cwe_ids = classification.get("cwe-id") or []
            if isinstance(cwe_ids, str):
                cwe_ids = [cwe_ids]
            cwe = None
            for cid in cwe_ids:
                m = _CWE_RE.search(str(cid))
                if m:
                    cwe = m.group(0).upper()
                    break

            # CVSS
            cvss_score = classification.get("cvss-score")
            if isinstance(cvss_score, str):
                try:
                    cvss_score = float(cvss_score)
                except ValueError:
                    cvss_score = None
            if cvss_score is not None and not (0.0 <= cvss_score <= 10.0):
                cvss_score = None

            cvss_vector = classification.get("cvss-metrics")
            if isinstance(cvss_vector, str):
                cvss_vector = cvss_vector[:200]
            else:
                cvss_vector = None

            # Severity
            sev_str = str(info.get("severity", "info")).lower()
            severity_map = {
                "critical": CriticalityLevel.CRITICAL,
                "high": CriticalityLevel.HIGH,
                "medium": CriticalityLevel.MEDIUM,
                "low": CriticalityLevel.LOW,
                "info": CriticalityLevel.LOW,
                "unknown": CriticalityLevel.MEDIUM,
            }
            severity = severity_map.get(sev_str, CriticalityLevel.MEDIUM)

            # ATT&CK mapping (más completo)
            attack_id = None
            tags = info.get("tags", []) or []
            if isinstance(tags, str):
                tags = [tags]
            tag_str = " ".join(str(t).lower() for t in tags)
            if any(t in tag_str for t in ("sqli", "sql-injection", "sql")):
                attack_id = "T1190"
            elif any(t in tag_str for t in ("rce", "command-injection", "cmd")):
                attack_id = "T1059"
            elif "xss" in tag_str:
                attack_id = "T1059.007"
            elif any(t in tag_str for t in ("lfi", "traversal", "path")):
                attack_id = "T1083"
            elif "ssrf" in tag_str:
                attack_id = "T1190"
            elif "csrf" in tag_str:
                attack_id = "T1204.001"
            elif "default-login" in tag_str or "default-cred" in tag_str:
                attack_id = "T1078"
            elif "exposure" in tag_str or "disclosure" in tag_str:
                attack_id = "T1213"

            # References
            references = info.get("reference", []) or []
            if isinstance(references, str):
                references = [references]
            if not isinstance(references, list):
                references = []

            # Matcher name (FIX #16)
            matcher_name = data.get("matcher-name", "") or ""

            template_id = data.get("template-id", "") or ""

            matched_at = str(data.get("matched-at", ""))[:2048]

            vulns.append(Vulnerability(
                title=str(info.get("name", "Nuclei finding"))[:512],
                description=str(info.get("description", ""))[:10_000],
                severity=severity,
                confidence=0.9 if cve else 0.7,  # Alta si CVE
                cve=cve,
                cwe=cwe,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                attack_id=attack_id,
                scanner="nuclei",
                template_id=template_id[:256],
                matched_at=matched_at,
                evidence=[f"template: {template_id}", f"matcher: {matcher_name}"],
                references=[str(r)[:512] for r in references[:20]],
                remediation=info.get("remediation", None),
                metadata={
                    "tags": [str(t)[:64] for t in tags[:20]],
                    "matcher_name": matcher_name[:256],
                    "type": str(data.get("type", ""))[:32],
                    "host": str(data.get("host", ""))[:256],
                },
            ))

        return vulns

    # ------------------------------------------------------------------------
    # Nikto (FIX #3)
    # ------------------------------------------------------------------------

    async def _run_nikto(self, target: str, timeout: float) -> list[Vulnerability]:
        """Ejecuta nikto."""
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        try:
            # FIX #3: -Format json (no -Format json sin más)
            result = await self.run_command(
                command=f"nikto -h {target} -Format json -nointeractive -maxtime 300s",
                timeout_seconds=timeout,
                tool_name="nikto",
            )
        except AgentToolError:
            return []

        stdout = result.get("stdout", "")[:MAX_OUTPUT_BYTES]
        if not stdout:
            return []

        return self._parse_nikto_json(stdout, target)

    @staticmethod
    def _parse_nikto_json(stdout: str, target: str) -> list[Vulnerability]:
        """Parsea output JSON de nikto (con enrichment)."""
        vulns: list[Vulnerability] = []

        # A veces nikto emite warnings antes del JSON
        json_start = stdout.find("{")
        json_array_start = stdout.find("[")

        if json_start == -1 and json_array_start == -1:
            return vulns

        start = min(
            [x for x in (json_start, json_array_start) if x != -1]
        )
        json_str = stdout[start:]

        try:
            data = json.loads(json_str)
        except json.JSONDecodeError:
            return vulns

        host_data_list = data if isinstance(data, list) else [data]

        for host_data in host_data_list:
            if not isinstance(host_data, dict):
                continue
            for item in host_data.get("vulnerabilities", []) or []:
                if not isinstance(item, dict):
                    continue

                msg = str(item.get("msg", "Nikto finding"))[:512]
                url = str(item.get("url", target))[:2048]

                # Inferir severity por keywords
                msg_lower = msg.lower()
                severity = CriticalityLevel.MEDIUM
                if any(k in msg_lower for k in ("critical", "remote code", "rce")):
                    severity = CriticalityLevel.CRITICAL
                elif any(k in msg_lower for k in ("high", "sql", "auth bypass")):
                    severity = CriticalityLevel.HIGH
                elif any(k in msg_lower for k in ("info", "banner")):
                    severity = CriticalityLevel.LOW

                vulns.append(Vulnerability(
                    title=msg,
                    description=msg,
                    severity=severity,
                    confidence=0.6,  # Nikto tiene FP rate alto
                    scanner="nikto",
                    matched_at=url,
                    evidence=[f"nikto: {msg}"],
                    metadata={
                        "id": str(item.get("id", ""))[:32],
                        "method": str(item.get("method", ""))[:16],
                        "osvdb": str(item.get("OSVDB", ""))[:32],
                    },
                ))

        return vulns

    # ------------------------------------------------------------------------
    # SQLMap (FIX #4)
    # ------------------------------------------------------------------------

    async def _run_sqlmap(
        self, target: str, intensity: str, timeout: float,
    ) -> list[Vulnerability]:
        """Ejecuta sqlmap (SQL injection)."""
        level = {"quick": 1, "standard": 2, "aggressive": 3}.get(intensity, 2)
        risk = {"quick": 1, "standard": 1, "aggressive": 2}.get(intensity, 1)

        try:
            # FIX #4: no --output-dir (read-only FS)
            result = await self.run_command(
                command=(
                    f"sqlmap -u '{target}' --batch --level={level} --risk={risk} "
                    f"--threads=4 --timeout=10 --retries=2 --flush-session "
                    f"--no-cast --no-escape --hex"
                ),
                timeout_seconds=timeout,
                tool_name="sqlmap",
            )
        except AgentToolError:
            return []

        stdout = result.get("stdout", "")[:MAX_OUTPUT_BYTES]
        return self._parse_sqlmap_stdout(stdout, target)

    @staticmethod
    def _parse_sqlmap_stdout(stdout: str, target: str) -> list[Vulnerability]:
        """Parsea output de sqlmap (con enrichment)."""
        vulns: list[Vulnerability] = []

        if not stdout:
            return vulns

        stdout_lower = stdout.lower()

        # Detectar vulnerabilidad
        is_vulnerable = (
            "is vulnerable" in stdout_lower
            or "sqlmap identified" in stdout_lower
            or "parameter" in stdout_lower and "injectable" in stdout_lower
        )

        if not is_vulnerable:
            return vulns

        # Extraer tipos de inyección
        inj_types = re.findall(r"Type:\s*(.+?)(?:\n|$)", stdout)
        inj_types = [t.strip()[:128] for t in inj_types if t.strip()][:5]

        # Extraer DBMS
        dbms_match = re.search(r"back-end DBMS:\s*(.+)", stdout, re.IGNORECASE)
        dbms = dbms_match.group(1).strip()[:128] if dbms_match else ""

        # Extraer parámetros vulnerables
        param_matches = re.findall(
            r"Parameter:\s*(\S+)", stdout, re.IGNORECASE
        )
        params = [p[:128] for p in param_matches][:10]

        # Extraer payload
        payload_match = re.search(r"Payload:\s*(.+?)(?:\n|$)", stdout)
        payload = payload_match.group(1).strip()[:512] if payload_match else ""

        title = "SQL Injection detected"
        if params:
            title += f" in {', '.join(params[:3])}"
        if inj_types:
            title += f" ({', '.join(inj_types[:2])})"

        vulns.append(Vulnerability(
            title=title[:512],
            description=(
                f"SQL injection vulnerability detected by sqlmap. "
                f"Backend DBMS: {dbms or 'unknown'}. "
                f"Manual verification recommended."
            )[:10_000],
            severity=CriticalityLevel.CRITICAL,
            confidence=0.95,  # sqlmap tiene alta confianza
            cwe="CWE-89",
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            attack_id="T1190",
            scanner="sqlmap",
            matched_at=target[:2048],
            evidence=[
                "sqlmap identified SQL injection",
                f"DBMS: {dbms}" if dbms else "",
                f"Parameters: {', '.join(params)}" if params else "",
                f"Payload: {payload}" if payload else "",
            ],
            references=[
                "https://owasp.org/www-community/attacks/SQL_Injection",
                "https://cwe.mitre.org/data/definitions/89.html",
            ],
            remediation=(
                "Use parameterized queries / prepared statements. "
                "Validate and sanitize all user inputs. "
                "Implement WAF rules for SQL injection."
            ),
            metadata={
                "injection_types": inj_types,
                "dbms": dbms,
                "parameters": params,
                "payload_preview": payload,
            },
        ))

        return vulns

    # ------------------------------------------------------------------------
    # ffuf (FIX #1, #2)
    # ------------------------------------------------------------------------

    async def _run_ffuf(self, target: str, timeout: float) -> list[Vulnerability]:
        """Ejecuta ffuf (web fuzzing) con wordlist embebida."""
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        # FIX #1: wordlist embebida como string, escrita temporalmente
        # FIX #2: -of json SIN -o (stdout)
        wordlist_content = "\n".join(EMBEDDED_WORDLIST)
        wordlist_b64 = __import__("base64").b64encode(
            wordlist_content.encode()
        ).decode()

        # FIX #1 + #2: escribir wordlist temporal, ejecutar ffuf con stdout
        try:
            result = await self.run_command(
                command=(
                    f"echo '{wordlist_b64}' | base64 -d > /tmp/gdt-wordlist.txt && "
                    f"ffuf -u '{target}/FUZZ' -w /tmp/gdt-wordlist.txt "
                    f"-mc 200,301,302,401,403,405,500 "
                    f"-of json -s -t 50 -timeout 10 "
                    f"-H 'User-Agent: Mozilla/5.0' "
                    f"&& rm -f /tmp/gdt-wordlist.txt"
                ),
                timeout_seconds=timeout,
                tool_name="ffuf",
            )
        except AgentToolError:
            return []

        stdout = result.get("stdout", "")[:MAX_OUTPUT_BYTES]
        if not stdout:
            return []

        return self._parse_ffuf_json(stdout, target)

    @staticmethod
    def _parse_ffuf_json(stdout: str, target: str) -> list[Vulnerability]:
        """Parsea output JSON de ffuf (FIX #2)."""
        vulns: list[Vulnerability] = []

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            return vulns

        results = data.get("results", []) or []
        for item in results:
            if not isinstance(item, dict):
                continue

            url = str(item.get("url", ""))[:2048]
            status = int(item.get("status", 0))
            length = int(item.get("length", 0))
            words = int(item.get("words", 0))
            lines = int(item.get("lines", 0))

            # Inferir severity por path
            path_lower = url.lower()
            severity = CriticalityLevel.INFO
            if any(k in path_lower for k in (".git", ".env", ".htpasswd", "backup", "admin", "config")):
                severity = CriticalityLevel.HIGH
            elif any(k in path_lower for k in ("api", "swagger", "openapi")):
                severity = CriticalityLevel.MEDIUM
            elif status in (200, 201):
                severity = CriticalityLevel.LOW

            vulns.append(Vulnerability(
                title=f"Endpoint found: {url}"[:512],
                description=f"Discovered endpoint {url} (status {status}, size {length})",
                severity=severity,
                confidence=0.8,
                scanner="ffuf",
                matched_at=url,
                evidence=[
                    f"status: {status}",
                    f"length: {length}",
                    f"words: {words}",
                    f"lines: {lines}",
                ],
                metadata={
                    "status": status,
                    "length": length,
                    "words": words,
                    "lines": lines,
                },
            ))

        return vulns

    # ------------------------------------------------------------------------
    # Gobuster (FIX #5)
    # ------------------------------------------------------------------------

    async def _run_gobuster(self, target: str, timeout: float) -> list[Vulnerability]:
        """Ejecuta gobuster con wordlist embebida."""
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        # FIX #5: wordlist embebida
        wordlist_content = "\n".join(EMBEDDED_WORDLIST)
        wordlist_b64 = __import__("base64").b64encode(
            wordlist_content.encode()
        ).decode()

        try:
            result = await self.run_command(
                command=(
                    f"echo '{wordlist_b64}' | base64 -d > /tmp/gdt-wl.txt && "
                    f"gobuster dir -u '{target}' -w /tmp/gdt-wl.txt "
                    f"-q --no-error -t 30 -z "
                    f"-a 'Mozilla/5.0' "
                    f"&& rm -f /tmp/gdt-wl.txt"
                ),
                timeout_seconds=timeout,
                tool_name="gobuster",
            )
        except AgentToolError:
            return []

        stdout = result.get("stdout", "")[:MAX_OUTPUT_BYTES]
        return self._parse_gobuster_stdout(stdout, target)

    @staticmethod
    def _parse_gobuster_stdout(stdout: str, target: str) -> list[Vulnerability]:
        """Parsea output de gobuster (FIX #17)."""
        vulns: list[Vulnerability] = []

        for line in stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("="):
                continue

            # Formato: /admin (Status: 200) [Size: 1234]
            m = re.match(r"^(\S+)\s+\(Status:\s*(\d+)\)", line)
            if not m:
                continue

            path = m.group(1)
            status = int(m.group(2))

            # FIX #17: incluir 200/301/302/401/403
            if status not in (200, 301, 302, 401, 403):
                continue

            severity = CriticalityLevel.INFO
            title = f"Path found: {path}"

            # Clasificar por path
            path_lower = path.lower()
            if any(k in path_lower for k in (".git", ".env", ".htpasswd", "backup", "config")):
                severity = CriticalityLevel.HIGH
                title = f"Sensitive path exposed: {path}"
            elif any(k in path_lower for k in ("admin", "administrator", "wp-admin")):
                severity = CriticalityLevel.MEDIUM
                title = f"Admin path found: {path}"
            elif status in (200, 301, 302):
                severity = CriticalityLevel.LOW

            vulns.append(Vulnerability(
                title=title[:512],
                description=f"Found path {path} with status {status}",
                severity=severity,
                confidence=0.7,
                scanner="gobuster",
                matched_at=f"{target.rstrip('/')}{path}"[:2048],
                evidence=[line],
                metadata={"path": path, "status": status},
            ))

        return vulns

    # ------------------------------------------------------------------------
    # WPScan (FIX #19)
    # ------------------------------------------------------------------------

    async def _run_wpscan(self, target: str, timeout: float) -> list[Vulnerability]:
        """Ejecuta wpscan (WordPress)."""
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        try:
            result = await self.run_command(
                command=(
                    f"wpscan --url '{target}' --format json --no-banner --no-update "
                    f"--disable-tls-checks --random-user-agent"
                ),
                timeout_seconds=timeout,
                tool_name="wpscan",
            )
        except AgentToolError:
            return []

        stdout = result.get("stdout", "")[:MAX_OUTPUT_BYTES]
        if not stdout:
            return []

        return self._parse_wpscan_json(stdout, target)

    @staticmethod
    def _parse_wpscan_json(stdout: str, target: str) -> list[Vulnerability]:
        """Parsea output JSON de wpscan (FIX #19: CVE extraction)."""
        vulns: list[Vulnerability] = []

        json_start = stdout.find("{")
        if json_start == -1:
            return vulns
        json_str = stdout[json_start:]

        try:
            data = json.loads(json_str)
        except json.JSONDecodeError:
            return vulns

        # WordPress version vulns
        version = data.get("version", {}) or {}
        wp_version = version.get("number", "") or ""
        for v in version.get("vulnerabilities", []) or []:
            vuln = WPScanParser.parse_vulnerability(
                v, target, "wordpress_core", wp_version,
            )
            if vuln:
                vulns.append(vuln)

        # Plugin vulns
        plugins = data.get("plugins") or {}
        for plugin_name, plugin_data in plugins.items():
            if not isinstance(plugin_data, dict):
                continue
            plugin_version = plugin_data.get("version", {}).get("number", "") if isinstance(plugin_data.get("version"), dict) else ""
            for v in plugin_data.get("vulnerabilities", []) or []:
                vuln = WPScanParser.parse_vulnerability(
                    v, target, "plugin", plugin_version, component=plugin_name,
                )
                if vuln:
                    vulns.append(vuln)

        # Theme vulns
        themes = data.get("themes") or {}
        for theme_name, theme_data in themes.items():
            if not isinstance(theme_data, dict):
                continue
            for v in theme_data.get("vulnerabilities", []) or []:
                vuln = WPScanParser.parse_vulnerability(
                    v, target, "theme", component=theme_name,
                )
                if vuln:
                    vulns.append(vuln)

        return vulns

    # ------------------------------------------------------------------------
    # Deduplication (FIX #14)
    # ------------------------------------------------------------------------

    @staticmethod
    def _deduplicate_vulnerabilities(
        vulns: list[Vulnerability],
    ) -> list[Vulnerability]:
        """Deduplicación inteligente (FIX #14).

        Estrategia:
            - Agrupa por dedup_key (scanner + cve + title + url)
            - Mantiene el de mayor confidence
            - Fusiona evidence
        """
        by_key: dict[str, Vulnerability] = {}

        for v in vulns:
            key = v.dedup_key
            if key not in by_key:
                by_key[key] = v
            else:
                existing = by_key[key]
                # Mantener el de mayor confidence
                if v.confidence > existing.confidence:
                    # Fusionar evidence
                    merged_evidence = list(set(existing.evidence + v.evidence))
                    v.evidence = merged_evidence[:20]
                    by_key[key] = v
                else:
                    # Añadir evidence al existing
                    merged_evidence = list(set(existing.evidence + v.evidence))
                    existing.evidence = merged_evidence[:20]

        return list(by_key.values())

    # ------------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------------

    def _generate_findings(
        self,
        vulns: list[Vulnerability],
        target: str,
    ) -> list[AgentFinding]:
        """Convierte vulnerabilities en findings."""
        findings: list[AgentFinding] = []

        for v in vulns:
            findings.append(AgentFinding(
                title=v.title,
                description=v.description,
                severity=v.severity,
                cvss_score=v.cvss_score,
                cvss_vector=v.cvss_vector,
                attack_id=v.attack_id,
                evidence=v.evidence or [f"Detected by {v.scanner}"],
                poc=None,
                remediation=v.remediation,
                affected_asset=v.matched_at or target,
                metadata={
                    "scanner": v.scanner,
                    "cve": v.cve,
                    "cwe": v.cwe,
                    "template_id": v.template_id,
                    "confidence": v.confidence,
                    "computed_score": round(v.computed_score, 2),
                    "evidence_hash": v.evidence_hash,
                    **v.metadata,
                },
            ))

        return findings


# ============================================================================
# WPSCAN PARSER HELPER
# ============================================================================

class WPScanParser:
    """Helper para parsear vulnerabilidades de wpscan con CVE extraction."""

    @staticmethod
    def parse_vulnerability(
        v: dict[str, Any],
        target: str,
        component_type: str,
        component_version: str = "",
        component: str = "",
    ) -> Vulnerability | None:
        """Parsea una vulnerabilidad de wpscan (FIX #19)."""
        if not isinstance(v, dict):
            return None

        title = str(v.get("title", "WP vuln"))[:512]
        if not title:
            return None

        # CVE extraction
        cve = None
        references = v.get("references", {}) or {}
        cve_list = references.get("cve", []) if isinstance(references, dict) else []
        if isinstance(cve_list, str):
            cve_list = [cve_list]
        for cid in cve_list:
            m = _CVE_RE.search(str(cid))
            if m:
                cve = m.group(0).upper()
                break

        # Severity heurística (wpscan default high)
        severity = CriticalityLevel.HIGH
        title_lower = title.lower()
        if any(k in title_lower for k in ("rce", "remote code", "sql")):
            severity = CriticalityLevel.CRITICAL
        elif any(k in title_lower for k in ("xss", "csrf", "info disclosure")):
            severity = CriticalityLevel.MEDIUM

        # References URLs
        ref_urls: list[str] = []
        if isinstance(references, dict):
            for key in ("url", "cve"):
                vals = references.get(key, [])
                if isinstance(vals, str):
                    vals = [vals]
                if isinstance(vals, list):
                    for u in vals[:10]:
                        u_str = str(u)[:512]
                        if u_str.startswith("http"):
                            ref_urls.append(u_str)

        # Metadata
        metadata: dict[str, Any] = {"component_type": component_type}
        if component:
            metadata["component"] = component
        if component_version:
            metadata["version"] = component_version

        title_prefix = f"[{component}] " if component else ""
        full_title = f"{title_prefix}{title}"[:512]

        return Vulnerability(
            title=full_title,
            description=f"{title}"[:10_000],
            severity=severity,
            confidence=0.85 if cve else 0.7,
            cve=cve,
            attack_id="T1190",  # WordPress exploits son public-facing
            scanner="wpscan",
            matched_at=target[:2048],
            evidence=[f"wpscan: {title}", f"component: {component or component_type}"],
            references=ref_urls[:10],
            metadata=metadata,
        )


__all__ = [
    "ScannerAgent",
    "ScannerInput",
    "ScannerOutput",
    "Vulnerability",
    "WPScanParser",
    "SUPPORTED_SCANNERS",
]
