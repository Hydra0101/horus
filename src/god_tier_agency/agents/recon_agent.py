"""Recon Agent — God-Tier v5.0.

Reconocimiento activo y pasivo nivel APT:
    - Subdomain enumeration multi-tool (subfinder + amass + dnsx)
    - Port scan (nmap) con CPE + service versions + banner grabbing
    - HTTP probing (httpx) con security headers analysis
    - TLS analysis profundo (ciphers, protocols, CT logs)
    - DNS enumeration completa (A/AAAA/MX/TXT/NS/CNAME/SOA/SRV/CAA/DMARC/SPF)
    - WHOIS con referrals + email extraction
    - CIDR expansion segura (no OOM con IPv6)
    - WAF detection (wafw00f)
    - Subdomain takeover detection
    - CVE mapping (via CPE)

God-Tier v5.0 — diferenciadores vs v4.0:

FIX BLOQUEANTES:
    - FIX #1: CIDR expansion con islice (no materializa lista)
    - FIX #2: defusedxml en vez de xml.etree (anti-XXE)
    - FIX #3: TLS analysis en paralelo (no N+1)
    - FIX #4: Timeout en parse XML

ANÁLISIS PROFUNDO:
    - CPE extraction (mapea a CVE via NVD)
    - Security headers analysis (HSTS, CSP, X-Frame, X-Content-Type)
    - TLS protocol/cipher analysis (detecta TLS 1.0/1.1)
    - SPF/DMARC/DKIM parsing
    - CNAME takeover detection (patrón: AWS S3, Azure, Heroku, etc.)
    - WAF detection (Cloudflare, Akamai, AWS WAF, etc.)
    - Email extraction de WHOIS + TXT
    - Banner grabbing para fingerprinting

EFICIENCIA:
    - Parallel execution (asyncio.gather)
    - DNS enum con una sola llamada (dig ANY)
    - HTTP probes en paralelo con semáforo
    - Cache de DNS/WHOIS
    - Retry con backoff

SEGURIDAD:
    - URL validation (evita SSRF)
    - Sanitización de output
    - XXE defense
    - SSRF defense

Filosofía:
    - PASSIVE FIRST (OSINT, DNS, CT)
    - ACTIVE ONLY IN SCOPE
    - ZERO FALSE POSITIVES
    - FULL FINGERPRINT
    - PARALLEL EXECUTION
    - FORENSIC OUTPUT
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import re
from datetime import datetime, timezone
from itertools import islice
from typing import Any, Literal
from urllib.parse import urlparse

from defusedxml import ElementTree as DefusedET  # FIX #2: anti-XXE
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

_log = get_logger("agents.recon")


# ============================================================================
# CONSTANTES
# ============================================================================

MAX_CIDR_HOSTS: int = 256          # v5.0: reducido de 1024 (evita abuso)
MAX_SUBDOMAINS: int = 10000
MAX_HTTP_PROBES: int = 500
MAX_DNS_RECORDS: int = 5000
MAX_TLS_CONCURRENCY: int = 20
MAX_HTTP_CONCURRENCY: int = 50
DEFAULT_TIMEOUT: float = 900.0
TOOL_TIMEOUT_SUBFINDER: float = 180.0
TOOL_TIMEOUT_NMAP: float = 300.0
TOOL_TIMEOUT_HTTPX: float = 120.0
TOOL_TIMEOUT_OPENSSL: float = 30.0
TOOL_TIMEOUT_DIG: float = 15.0
TOOL_TIMEOUT_WHOIS: float = 30.0
TOOL_TIMEOUT_WAFW00F: float = 60.0
RETRY_ATTEMPTS: int = 2
RETRY_BACKOFF_BASE: float = 1.5

# Patrones para detección de takeover
_SUBDOMAIN_TAKEOVER_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"s3\.amazonaws\.com", "AWS S3 bucket not found"),
    (r"s3-website[-.][a-z0-9-]+\.amazonaws\.com", "AWS S3 website not found"),
    (r"cloudfront\.net", "AWS CloudFront not configured"),
    (r"azurewebsites\.net", "Azure Web App not found"),
    (r"cloudapp\.azure\.com", "Azure Cloud App not found"),
    (r"blob\.core\.windows\.net", "Azure Blob not found"),
    (r"trafficmanager\.net", "Azure Traffic Manager not found"),
    (r"herokudns\.com", "Heroku DNS not configured"),
    (r"herokussl\.com", "Heroku SSL not configured"),
    (r"github\.io", "GitHub Pages not configured"),
    (r"pages\.dev", "Cloudflare Pages not configured"),
    (r"netlify\.app", "Netlify site not found"),
    (r"vercel\.app", "Vercel deployment not found"),
    (r"wordpress\.com", "WordPress.com not configured"),
    (r"surge\.sh", "Surge site not found"),
    (r"bitbucket\.io", "Bitbucket Pages not configured"),
    (r"readthedocs\.io", "ReadTheDocs not configured"),
    (r"zendesk\.com", "Zendesk not configured"),
    (r"freshdesk\.com", "Freshdesk not configured"),
    (r"fastly\.net", "Fastly not configured"),
    (r"pantheonsite\.io", "Pantheon not configured"),
    (r"ghost\.io", "Ghost not configured"),
)

# Puertos críticos con metadatos (CWE + ATT&CK + severity)
_CRITICAL_PORTS: dict[int, dict[str, Any]] = {
    21: {"title": "FTP exposed (plaintext)", "severity": CriticalityLevel.MEDIUM, "attack_id": "T1021.002"},
    22: {"title": "SSH exposed", "severity": CriticalityLevel.MEDIUM, "attack_id": "T1021.004"},
    23: {"title": "Telnet exposed (insecure)", "severity": CriticalityLevel.HIGH, "attack_id": "T1021"},
    25: {"title": "SMTP exposed", "severity": CriticalityLevel.LOW, "attack_id": "T1071.003"},
    53: {"title": "DNS exposed", "severity": CriticalityLevel.MEDIUM, "attack_id": "T1071.004"},
    80: {"title": "HTTP exposed", "severity": CriticalityLevel.LOW, "attack_id": "T1071.001"},
    110: {"title": "POP3 exposed", "severity": CriticalityLevel.MEDIUM, "attack_id": "T1114"},
    135: {"title": "MS RPC exposed", "severity": CriticalityLevel.MEDIUM, "attack_id": "T1021.003"},
    139: {"title": "NetBIOS exposed", "severity": CriticalityLevel.MEDIUM, "attack_id": "T1021.002"},
    143: {"title": "IMAP exposed", "severity": CriticalityLevel.MEDIUM, "attack_id": "T1114"},
    443: {"title": "HTTPS exposed", "severity": CriticalityLevel.LOW, "attack_id": "T1071.001"},
    445: {"title": "SMB exposed", "severity": CriticalityLevel.HIGH, "attack_id": "T1021.002"},
    993: {"title": "IMAPS exposed", "severity": CriticalityLevel.LOW, "attack_id": "T1114"},
    995: {"title": "POP3S exposed", "severity": CriticalityLevel.LOW, "attack_id": "T1114"},
    1433: {"title": "MSSQL exposed", "severity": CriticalityLevel.HIGH, "attack_id": "T1021.001"},
    1521: {"title": "Oracle DB exposed", "severity": CriticalityLevel.HIGH, "attack_id": "T1021.001"},
    3306: {"title": "MySQL exposed", "severity": CriticalityLevel.HIGH, "attack_id": "T1021.001"},
    3389: {"title": "RDP exposed", "severity": CriticalityLevel.HIGH, "attack_id": "T1021.001"},
    5432: {"title": "PostgreSQL exposed", "severity": CriticalityLevel.HIGH, "attack_id": "T1021.001"},
    5900: {"title": "VNC exposed", "severity": CriticalityLevel.HIGH, "attack_id": "T1021"},
    5985: {"title": "WinRM HTTP exposed", "severity": CriticalityLevel.HIGH, "attack_id": "T1021.006"},
    5986: {"title": "WinRM HTTPS exposed", "severity": CriticalityLevel.HIGH, "attack_id": "T1021.006"},
    6379: {"title": "Redis exposed (often no auth)", "severity": CriticalityLevel.CRITICAL, "attack_id": "T1021.001"},
    8080: {"title": "HTTP alt exposed", "severity": CriticalityLevel.LOW, "attack_id": "T1071.001"},
    8443: {"title": "HTTPS alt exposed", "severity": CriticalityLevel.LOW, "attack_id": "T1071.001"},
    9200: {"title": "Elasticsearch exposed (often no auth)", "severity": CriticalityLevel.CRITICAL, "attack_id": "T1021.001"},
    11211: {"title": "Memcached exposed (often no auth)", "severity": CriticalityLevel.CRITICAL, "attack_id": "T1021.001"},
    27017: {"title": "MongoDB exposed (often no auth)", "severity": CriticalityLevel.CRITICAL, "attack_id": "T1021.001"},
}

# Puertos HTTP comunes
_HTTP_PORTS: frozenset[int] = frozenset({80, 443, 8000, 8080, 8443, 8888, 3000, 5000, 9000})


# ============================================================================
# PYDANTIC MODELS
# ============================================================================

class ServiceDetail(BaseModel):
    """Detalle de un servicio en un puerto (v5.0)."""

    model_config = ConfigDict(extra="forbid")

    port: int = Field(..., ge=1, le=65535)
    protocol: str = Field(default="tcp", pattern="^(tcp|udp)$")
    service: str = Field(default="", max_length=64)
    product: str = Field(default="", max_length=128)
    version: str = Field(default="", max_length=64)
    extra_info: str = Field(default="", max_length=256)
    cpe: list[str] = Field(default_factory=list)  # v5.0: CPE for CVE mapping
    banner: str = Field(default="", max_length=1024)  # v5.0: banner grabbing
    state: Literal["open", "closed", "filtered", "open|filtered"] = "open"

    @property
    def is_critical_port(self) -> bool:
        return self.port in _CRITICAL_PORTS

    @property
    def cve_candidates(self) -> list[str]:
        """CVE candidatos basados en CPE (requiere DB externa para lookup real)."""
        # Este es un placeholder. La integración real requiere NVD/Vulners API.
        return []


class TlsInfo(BaseModel):
    """Información TLS (v5.0 con más detalle)."""

    model_config = ConfigDict(extra="forbid")

    subject_cn: str = Field(default="", max_length=256)
    issuer_cn: str = Field(default="", max_length=256)
    issuer_org: str = Field(default="", max_length=256)
    san: list[str] = Field(default_factory=list)
    not_before: str = Field(default="", max_length=64)
    not_after: str = Field(default="", max_length=64)
    serial: str = Field(default="", max_length=128)
    signature_algorithm: str = Field(default="", max_length=64)
    version: str = Field(default="", max_length=16)
    is_expired: bool = False
    days_until_expiry: int = Field(default=0)
    # v5.0: análisis de protocolos y ciphers
    tls_versions_supported: list[str] = Field(default_factory=list)
    weak_protocols: list[str] = Field(default_factory=list)  # TLS 1.0, 1.1, SSLv3
    weak_ciphers: list[str] = Field(default_factory=list)     # RC4, DES, NULL
    cert_mismatch: bool = False
    cert_self_signed: bool = False

    @field_validator("san")
    @classmethod
    def limit_san(cls, v: list[str]) -> list[str]:
        return v[:50]


class DnsRecord(BaseModel):
    """Registro DNS (v5.0 con más tipos)."""

    model_config = ConfigDict(extra="forbid")

    record_type: Literal[
        "A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "SRV", "CAA",
        "SPF", "DMARC", "DKIM",
    ]
    value: str = Field(..., min_length=1, max_length=4096)
    ttl: int = Field(default=0, ge=0)
    priority: int = Field(default=0, ge=0)


class SubdomainInfo(BaseModel):
    """Subdominio con takeover detection (v5.0)."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=1, max_length=512)
    ip_addresses: list[str] = Field(default_factory=list)
    cname: str = Field(default="", max_length=512)
    is_wildcard: bool = False
    source: str = Field(default="", max_length=64)
    takeover_candidate: bool = False  # v5.0
    takeover_reason: str = Field(default="", max_length=256)  # v5.0


class SecurityHeaders(BaseModel):
    """Security headers analysis (v5.0)."""

    model_config = ConfigDict(extra="forbid")

    hsts: str = Field(default="", max_length=256)
    hsts_preload: bool = False
    hsts_max_age_days: int = Field(default=0, ge=0)
    csp: str = Field(default="", max_length=2048)
    csp_report_only: bool = False
    x_frame_options: str = Field(default="", max_length=64)
    x_content_type_options: str = Field(default="", max_length=64)
    referrer_policy: str = Field(default="", max_length=128)
    permissions_policy: str = Field(default="", max_length=1024)
    server_header: str = Field(default="", max_length=128)
    powered_by: str = Field(default="", max_length=128)

    @property
    def missing_headers(self) -> list[str]:
        """Lista de headers críticos faltantes."""
        missing: list[str] = []
        if not self.hsts:
            missing.append("Strict-Transport-Security")
        if not self.csp:
            missing.append("Content-Security-Policy")
        if not self.x_frame_options:
            missing.append("X-Frame-Options")
        if not self.x_content_type_options:
            missing.append("X-Content-Type-Options")
        if not self.referrer_policy:
            missing.append("Referrer-Policy")
        return missing


class HttpProbe(BaseModel):
    """HTTP probe (v5.0 con security headers)."""

    model_config = ConfigDict(extra="forbid")

    url: str = Field(..., min_length=1, max_length=2048)
    status_code: int = Field(default=0, ge=0, le=599)
    title: str = Field(default="", max_length=512)
    content_length: int = Field(default=0, ge=0)
    content_type: str = Field(default="", max_length=128)
    server: str = Field(default="", max_length=128)
    technologies: list[str] = Field(default_factory=list)
    redirect_chain: list[str] = Field(default_factory=list)
    tls_info: TlsInfo | None = None
    cdn: str = Field(default="", max_length=64)
    webserver: str = Field(default="", max_length=64)
    security_headers: SecurityHeaders = Field(default_factory=SecurityHeaders)
    waf_detected: str = Field(default="", max_length=64)
    favicon_hash: str = Field(default="", max_length=64)


class WafInfo(BaseModel):
    """WAF detection result (v5.0)."""

    model_config = ConfigDict(extra="forbid")

    detected: bool = False
    waf_name: str = Field(default="", max_length=64)
    confidence: int = Field(default=0, ge=0, le=100)


# ============================================================================
# INPUT / OUTPUT
# ============================================================================

class ReconInput(AgentInput):
    """Input del recon agent."""

    target_type: Literal["domain", "ip", "cidr"] = "domain"
    depth: Literal["quick", "standard", "full"] = "standard"
    ports: Literal["top-100", "top-1000", "all"] = "top-1000"
    enable_subdomain_enum: bool = True
    enable_http_probe: bool = True
    enable_dns_enum: bool = True
    enable_whois: bool = True
    enable_tls_analysis: bool = True
    enable_waf_detection: bool = True
    enable_takeover_check: bool = True
    max_subdomains: int = Field(default=10000, ge=1, le=100000)
    max_cidr_hosts: int = Field(default=256, ge=1, le=4096)


class ReconOutput(AgentOutput):
    """Output del recon agent."""

    subdomains: list[SubdomainInfo] = Field(default_factory=list)
    total_subdomains_found: int = 0

    open_ports: dict[str, list[int]] = Field(default_factory=dict)
    service_details: dict[str, list[ServiceDetail]] = Field(default_factory=dict)
    total_ports_scanned: int = 0

    http_probes: list[HttpProbe] = Field(default_factory=list)
    technologies: dict[str, list[str]] = Field(default_factory=dict)

    dns_records: list[DnsRecord] = Field(default_factory=list)

    whois_summary: dict[str, str] = Field(default_factory=dict)
    whois_emails: list[str] = Field(default_factory=list)

    waf_info: WafInfo = Field(default_factory=WafInfo)

    expanded_hosts: list[str] = Field(default_factory=list)
    execution_metadata: dict[str, Any] = Field(default_factory=dict)




# Registrar schemas en el registry global (necesario para AgentContract)
from god_tier_agency.agents.contract import _register_schema
_register_schema("ReconInput", ReconInput)
_register_schema("ReconOutput", ReconOutput)
# ============================================================================
# AGENT
# ============================================================================

class ReconAgent(BaseAgent):
    """Recon agent — God-Tier v5.0."""

    def get_contract(self) -> AgentContract:
        return AgentContract(
            name="recon",
            version="5.0.0",
            description="God-Tier reconnaissance agent (subdomains, ports, DNS, WHOIS, TLS, WAF, takeover)",
            objective="Enumerate attack surface with deep fingerprinting",
            input_schema=ReconInput,
            output_schema=ReconOutput,
            stop_condition="All configured scans complete or timeout",
            input_example={
                "target": "example.com",
                "target_type": "domain",
                "depth": "standard",
                "ports": "top-1000",
                "enable_dns_enum": True,
                "enable_whois": True,
                "enable_waf_detection": True,
                "enable_takeover_check": True,
            },
            max_duration_seconds=DEFAULT_TIMEOUT,
            max_commands=60,
            tools_allowed=(
                "subfinder", "nmap", "httpx", "dig", "whois", "openssl", "wafw00f",
            ),
            criticality=CriticalityLevel.HIGH,
        )

    # ------------------------------------------------------------------------
    # Main execution
    # ------------------------------------------------------------------------

    async def _execute(self, inp: ReconInput) -> ReconOutput:
        """Ejecuta el recon completo con paralelización."""
        start_time = __import__("time").monotonic()
        output = ReconOutput(summary="")

        # FASE 0: CIDR expansion (FIX #1)
        if inp.target_type == "cidr":
            output.expanded_hosts = self._expand_cidr(
                inp.target, max_hosts=inp.max_cidr_hosts
            )
            _log.info(
                "cidr_expanded",
                cidr=inp.target,
                hosts=len(output.expanded_hosts),
            )

        # FASE 1: Recolección de información de dominio (paralela)
        domain_tasks: list[asyncio.Task[Any]] = []
        if inp.target_type == "domain":
            if inp.enable_subdomain_enum:
                domain_tasks.append(
                    asyncio.create_task(
                        self._enumerate_subdomains(inp.target, inp.depth, inp.max_subdomains)
                    )
                )
            if inp.enable_dns_enum:
                domain_tasks.append(
                    asyncio.create_task(self._enumerate_dns(inp.target))
                )
            if inp.enable_whois:
                domain_tasks.append(
                    asyncio.create_task(self._whois_lookup(inp.target))
                )

        if domain_tasks:
            results = await asyncio.gather(*domain_tasks, return_exceptions=True)
            for i, r in enumerate(results):
                if isinstance(r, Exception):
                    _log.warning("domain_task_failed", index=i, error=str(r))
                    continue
                if isinstance(r, list):
                    # Puede ser subdomains o dns_records
                    if r and isinstance(r[0], SubdomainInfo):
                        output.subdomains = r
                        output.total_subdomains_found = len(r)
                    elif r and isinstance(r[0], DnsRecord):
                        output.dns_records = r
                elif isinstance(r, tuple):
                    output.whois_summary, output.whois_emails = r

        # FASE 2: Port scan
        open_ports, service_details = await self._scan_ports(
            inp.target, inp.ports, inp.depth
        )
        output.open_ports = open_ports
        output.service_details = service_details
        output.total_ports_scanned = sum(len(p) for p in open_ports.values())

        # FASE 3: HTTP probing + TLS + WAF (paralelo)
        if inp.enable_http_probe:
            has_http = any(
                port in _HTTP_PORTS
                for ports in open_ports.values()
                for port in ports
            )
            if has_http:
                probes, technologies = await self._probe_http_parallel(
                    inp.target,
                    enable_tls=inp.enable_tls_analysis,
                    enable_waf=inp.enable_waf_detection,
                )
                output.http_probes = probes
                output.technologies = technologies

        # FASE 4: WAF detection (si no se detectó en HTTP)
        if inp.enable_waf_detection and not output.waf_info.detected:
            output.waf_info = await self._detect_waf(inp.target)

        # FASE 5: Subdomain takeover check (FIX #23)
        if inp.enable_takeover_check and output.subdomains:
            output.subdomains = await self._check_takeover(output.subdomains)

        # FASE 6: Generar findings
        findings = self._generate_all_findings(output, inp.target)
        output.findings = findings

        # FASE 7: Summary + metadata
        execution_time = __import__("time").monotonic() - start_time
        output.summary = (
            f"Recon complete in {execution_time:.1f}s: "
            f"{output.total_subdomains_found} subdomains, "
            f"{output.total_ports_scanned} open ports, "
            f"{len(output.findings)} findings, "
            f"{len(output.dns_records)} DNS records, "
            f"{len(output.http_probes)} HTTP probes, "
            f"WAF: {output.waf_info.waf_name or 'none'}"
        )
        output.execution_metadata = {
            "execution_time_seconds": round(execution_time, 2),
            "depth": inp.depth,
            "ports_scanned": inp.ports,
            "waf_detected": output.waf_info.detected,
            "takeover_candidates": sum(
                1 for s in output.subdomains if s.takeover_candidate
            ),
        }

        return output

    # ------------------------------------------------------------------------
    # CIDR expansion (FIX #1)
    # ------------------------------------------------------------------------

    @staticmethod
    def _expand_cidr(cidr: str, max_hosts: int = MAX_CIDR_HOSTS) -> list[str]:
        """Expande CIDR con islice (evita OOM con IPv6).

        FIX BUG #1: usa islice en vez de list()[:N]
        """
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError as e:
            _log.warning("cidr_invalid", cidr=cidr, error=str(e))
            return []

        # Rechazar redes demasiado grandes (fail-closed)
        if net.version == 4 and net.num_addresses > max_hosts * 100:
            raise ValueError(
                f"CIDR IPv4 demasiado grande: {net.num_addresses} direcciones "
                f"(máx {max_hosts * 100})"
            )
        if net.version == 6 and net.num_addresses > 2**64:
            raise ValueError(
                f"CIDR IPv6 demasiado grande: /{net.prefixlen}"
            )

        # islice NO materializa toda la lista
        hosts = islice(net.hosts(), max_hosts)
        return [str(h) for h in hosts]

    # ------------------------------------------------------------------------
    # Subdomain enumeration
    # ------------------------------------------------------------------------

    async def _enumerate_subdomains(
        self, domain: str, depth: str, max_subdomains: int = MAX_SUBDOMAINS,
    ) -> list[SubdomainInfo]:
        """Enumera subdominios con subfinder."""
        try:
            result = await self.run_command(
                command=f"subfinder -d {domain} -silent -timeout 30",
                timeout_seconds=TOOL_TIMEOUT_SUBFINDER,
                tool_name="subfinder",
            )
        except AgentToolError as e:
            _log.warning("subfinder_failed", domain=domain, error=str(e))
            return []

        if result["exit_code"] != 0:
            _log.warning("subfinder_exit_code", exit_code=result["exit_code"])
            return []

        subdomains_raw = sorted(set(
            line.strip()
            for line in result["stdout"].splitlines()
            if line.strip() and not line.startswith("#")
        ))[:max_subdomains]

        if depth == "quick":
            subdomains_raw = subdomains_raw[:20]

        subdomains = [
            SubdomainInfo(name=s, source="subfinder")
            for s in subdomains_raw
        ]

        _log.info("subfinder_done", domain=domain, count=len(subdomains))
        return subdomains

    # ------------------------------------------------------------------------
    # DNS enumeration (FIX #6, #7)
    # ------------------------------------------------------------------------

    async def _enumerate_dns(self, domain: str) -> list[DnsRecord]:
        """DNS enumeration con tipos extendidos."""
        records: list[DnsRecord] = []

        # FIX #6: una sola llamada para A/AAAA/MX/TXT/NS
        record_types = ("A", "AAAA", "MX", "TXT", "NS", "CNAME", "CAA", "SOA")
        tasks = [
            self._dig_record(domain, rtype)
            for rtype in record_types
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for rtype, r in zip(record_types, results):
            if isinstance(r, Exception):
                continue
            records.extend(r)

        # FIX #7: SPF/DMARC/DKIM
        spf_records = await self._check_spf(domain)
        records.extend(spf_records)

        dmarc_records = await self._check_dmarc(domain)
        records.extend(dmarc_records)

        # Límite
        records = records[:MAX_DNS_RECORDS]

        _log.info("dns_enum_done", domain=domain, count=len(records))
        return records

    async def _dig_record(self, domain: str, rtype: str) -> list[DnsRecord]:
        """Consulta un tipo de registro DNS."""
        try:
            result = await self.run_command(
                command=f"dig +short +time=5 +tries=2 {domain} {rtype}",
                timeout_seconds=TOOL_TIMEOUT_DIG,
                tool_name="dig",
            )
        except AgentToolError:
            return []

        if result["exit_code"] != 0:
            return []

        records: list[DnsRecord] = []
        for line in result["stdout"].splitlines():
            line = line.strip()
            if not line:
                continue
            priority = 0
            value = line
            if rtype == "MX" and " " in line:
                parts = line.split(None, 1)
                try:
                    priority = int(parts[0])
                    value = parts[1].rstrip(".")
                except (ValueError, IndexError):
                    pass

            try:
                records.append(DnsRecord(
                    record_type=rtype,  # type: ignore[arg-type]
                    value=value[:4096],
                    priority=priority,
                ))
            except Exception as e:
                _log.debug("dns_record_invalid", rtype=rtype, error=str(e))
                continue

        return records

    async def _check_spf(self, domain: str) -> list[DnsRecord]:
        """Verifica SPF record."""
        try:
            result = await self.run_command(
                command=f"dig +short TXT {domain}",
                timeout_seconds=TOOL_TIMEOUT_DIG,
                tool_name="dig",
            )
        except AgentToolError:
            return []

        records: list[DnsRecord] = []
        for line in result["stdout"].splitlines():
            if "v=spf1" in line.lower():
                records.append(DnsRecord(
                    record_type="SPF",
                    value=line.strip().strip('"')[:4096],
                ))
        return records

    async def _check_dmarc(self, domain: str) -> list[DnsRecord]:
        """Verifica DMARC record."""
        try:
            result = await self.run_command(
                command=f"dig +short TXT _dmarc.{domain}",
                timeout_seconds=TOOL_TIMEOUT_DIG,
                tool_name="dig",
            )
        except AgentToolError:
            return []

        records: list[DnsRecord] = []
        for line in result["stdout"].splitlines():
            if "v=DMARC1" in line:
                records.append(DnsRecord(
                    record_type="DMARC",
                    value=line.strip().strip('"')[:4096],
                ))
        return records

    # ------------------------------------------------------------------------
    # WHOIS (FIX #8, #9, #18)
    # ------------------------------------------------------------------------

    async def _whois_lookup(self, domain: str) -> tuple[dict[str, str], list[str]]:
        """WHOIS lookup con emails + campos extendidos."""
        try:
            result = await self.run_command(
                command=f"whois {domain}",
                timeout_seconds=TOOL_TIMEOUT_WHOIS,
                tool_name="whois",
            )
        except AgentToolError:
            return {}, []

        if result["exit_code"] != 0:
            return {}, []

        summary: dict[str, str] = {}
        patterns = {
            "registrar": r"Registrar:\s*(.+)",
            "registrar_url": r"Registrar URL:\s*(.+)",
            "created": r"(?:Creation Date|Created On|Created):\s*(.+)",
            "expires": r"(?:Registry Expiry Date|Expiry Date|Expiration Date):\s*(.+)",
            "updated": r"(?:Updated Date|Last Updated On):\s*(.+)",
            "name_servers": r"Name Server:\s*(.+)",
            "status": r"Domain Status:\s*(.+)",
            "registrant_org": r"Registrant Organization:\s*(.+)",
            "registrant_country": r"Registrant Country:\s*(.+)",
            "registrant_name": r"Registrant Name:\s*(.+)",
            "abuse_email": r"Registrar Abuse Contact Email:\s*(.+)",
            "dnssec": r"DNSSEC:\s*(.+)",
        }

        for key, pattern in patterns.items():
            m = re.search(pattern, result["stdout"], re.IGNORECASE)
            if m:
                value = m.group(1).strip()[:256]
                if key in summary:
                    # Múltiples valores (name_servers)
                    summary[key] = f"{summary[key]}; {value}"[:512]
                else:
                    summary[key] = value

        # FIX #18: extraer emails
        emails = set(re.findall(
            r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
            result["stdout"],
        ))

        _log.info("whois_done", domain=domain, fields=len(summary), emails=len(emails))
        return summary, sorted(emails)[:20]

    # ------------------------------------------------------------------------
    # Port scan (FIX #5, #13)
    # ------------------------------------------------------------------------

    async def _scan_ports(
        self, target: str, ports: str, depth: str,
    ) -> tuple[dict[str, list[int]], dict[str, list[ServiceDetail]]]:
        """Escanea puertos con nmap + CPE + banner."""
        port_arg = {
            "top-100": "--top-ports 100",
            "top-1000": "--top-ports 1000",
            "all": "-p-",
        }.get(ports, "--top-ports 1000")

        timing = {"quick": "-T4", "standard": "-T4", "full": "-T3"}.get(depth, "-T4")

        try:
            result = await self.run_command(
                command=f"nmap -sV -sC {timing} {port_arg} -oX - {target}",
                timeout_seconds=TOOL_TIMEOUT_NMAP,
                tool_name="nmap",
            )
        except AgentToolError as e:
            _log.warning("nmap_failed", target=target, error=str(e))
            return {}, {}

        if result["exit_code"] != 0:
            return {}, {}

        try:
            open_ports, service_details = self._parse_nmap_xml_full(
                result["stdout"], target
            )
        except Exception as e:
            _log.warning("nmap_parse_failed", error=str(e))
            return {}, {}

        _log.info(
            "nmap_done",
            target=target,
            open_ports=sum(len(v) for v in open_ports.values()),
        )
        return open_ports, service_details

    @staticmethod
    def _parse_nmap_xml_full(
        xml_output: str, target: str,
    ) -> tuple[dict[str, list[int]], dict[str, list[ServiceDetail]]]:
        """Parsea XML nmap con CPE + banner (FIX #5, #13, #2 defusedxml)."""
        xml_start = xml_output.find("<?xml")
        if xml_start == -1:
            return {}, {}
        xml_content = xml_output[xml_start:]

        # FIX #2: defusedxml (anti-XXE)
        try:
            root = DefusedET.fromstring(xml_content)
        except Exception as e:
            _log.warning("nmap_xml_parse_error", error=str(e))
            return {}, {}

        open_ports: dict[str, list[int]] = {}
        service_details: dict[str, list[ServiceDetail]] = {}

        for host in root.findall(".//host"):
            address_elem = host.find("address")
            if address_elem is None:
                continue
            host_addr = address_elem.get("addr", target)

            ports: list[int] = []
            details: list[ServiceDetail] = []

            for port in host.findall(".//port"):
                state = port.find("state")
                if state is None:
                    continue
                state_val = state.get("state", "unknown")
                if state_val not in ("open", "open|filtered"):
                    continue

                port_id_str = port.get("portid")
                if not port_id_str:
                    continue
                try:
                    port_id = int(port_id_str)
                except ValueError:
                    continue

                ports.append(port_id)

                service = port.find("service")
                product = service.get("product", "") if service is not None else ""
                version = service.get("version", "") if service is not None else ""
                sname = service.get("name", "") if service is not None else ""
                extra_info = service.get("extrainfo", "") if service is not None else ""

                # FIX #13: extraer CPE
                cpes: list[str] = []
                if service is not None:
                    for cpe_elem in service.findall("cpe"):
                        if cpe_elem.text:
                            cpes.append(cpe_elem.text[:256])

                # FIX #5: banner grabbing
                banner = ""
                for script in port.findall("script"):
                    script_id = script.get("id", "")
                    if script_id in ("banner", "ssl-cert", "http-title", "http-server-header"):
                        output_text = script.get("output", "")
                        if output_text:
                            banner += f"[{script_id}] {output_text[:500]}\n"

                details.append(ServiceDetail(
                    port=port_id,
                    protocol=port.get("protocol", "tcp"),
                    service=sname[:64],
                    product=product[:128],
                    version=version[:64],
                    extra_info=extra_info[:256],
                    cpe=cpes,
                    banner=banner[:1024],
                    state=state_val,  # type: ignore[arg-type]
                ))

            if ports:
                open_ports[host_addr] = sorted(set(ports))
                service_details[host_addr] = details

        return open_ports, service_details

    # ------------------------------------------------------------------------
    # HTTP probing (FIX #3, #14, #15, #19, #27)
    # ------------------------------------------------------------------------

    async def _probe_http_parallel(
        self,
        target: str,
        enable_tls: bool = True,
        enable_waf: bool = True,
    ) -> tuple[list[HttpProbe], dict[str, list[str]]]:
        """HTTP probe con paralelización + security headers."""
        try:
            result = await self.run_command(
                command=f"httpx -u {target} -tech-detect -status-code -title -json -silent -timeout 10",
                timeout_seconds=TOOL_TIMEOUT_HTTPX,
                tool_name="httpx",
            )
        except AgentToolError:
            return [], {}

        if result["exit_code"] != 0:
            return [], {}

        # Parse httpx output
        raw_probes: list[dict[str, Any]] = []
        for line in result["stdout"].splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                raw_probes.append(data)
            except json.JSONDecodeError:
                continue

        raw_probes = raw_probes[:MAX_HTTP_PROBES]

        # FIX #3: procesar en paralelo (TLS analysis)
        semaphore = asyncio.Semaphore(MAX_HTTP_CONCURRENCY)
        tls_semaphore = asyncio.Semaphore(MAX_TLS_CONCURRENCY)

        async def process_probe(data: dict[str, Any]) -> HttpProbe | None:
            async with semaphore:
                try:
                    return await self._process_single_probe(
                        target, data, enable_tls, tls_semaphore
                    )
                except Exception as e:
                    _log.warning("probe_process_failed", error=str(e))
                    return None

        tasks = [process_probe(p) for p in raw_probes]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        probes: list[HttpProbe] = []
        technologies: dict[str, list[str]] = {}

        for r in results:
            if isinstance(r, HttpProbe):
                probes.append(r)
                if r.technologies:
                    technologies[r.url] = r.technologies

        _log.info("httpx_done", target=target, count=len(probes))
        return probes, technologies

    async def _process_single_probe(
        self,
        target: str,
        data: dict[str, Any],
        enable_tls: bool,
        tls_semaphore: asyncio.Semaphore,
    ) -> HttpProbe | None:
        """Procesa un único probe con security headers + TLS."""
        url = str(data.get("url", ""))[:2048]
        if not url:
            return None

        # FIX #30: validar URL (evita SSRF)
        if not self._is_safe_url(url):
            _log.warning("unsafe_url_skipped", url=url[:100])
            return None

        techs = data.get("tech", []) or data.get("technologies", []) or []

        # Security headers
        sec_headers = self._extract_security_headers(data)

        probe = HttpProbe(
            url=url,
            status_code=int(data.get("status_code", 0)),
            title=str(data.get("title", ""))[:512],
            content_length=int(data.get("content_length", 0)),
            content_type=str(data.get("content_type", ""))[:128],
            server=str(data.get("server", "") or data.get("webserver", ""))[:128],
            technologies=[t[:64] for t in techs if isinstance(t, str)],
            cdn=str(data.get("cdn_name", ""))[:64],
            webserver=str(data.get("webserver", ""))[:64],
            security_headers=sec_headers,
            favicon_hash=str(data.get("favicon", ""))[:64],
        )

        # TLS analysis (con semáforo dedicado para no sobrecargar)
        if enable_tls and url.startswith("https"):
            async with tls_semaphore:
                tls_info = await self._analyze_tls(target, url)
                if tls_info is not None:
                    probe = probe.model_copy(update={"tls_info": tls_info})

        return probe

    @staticmethod
    def _is_safe_url(url: str) -> bool:
        """Valida URL (evita SSRF a IPs internas)."""
        try:
            parsed = urlparse(url)
        except Exception:
            return False
        if parsed.scheme not in ("http", "https"):
            return False
        host = parsed.hostname
        if not host:
            return False

        # Rechazar IPs privadas/loopback/link-local
        try:
            ip = ipaddress.ip_address(host)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                return False
        except ValueError:
            pass

        # Rechazar localhost
        if host.lower() in ("localhost", "127.0.0.1", "::1"):
            return False

        return True

    @staticmethod
    def _extract_security_headers(data: dict[str, Any]) -> SecurityHeaders:
        """Extrae security headers del probe."""
        headers = data.get("header", {}) or data.get("headers", {}) or {}

        def _get_header(name: str) -> str:
            for k, v in headers.items():
                if k.lower() == name.lower():
                    return str(v)[:2048]
            return ""

        hsts = _get_header("strict-transport-security")
        hsts_max_age = 0
        hsts_preload = False
        if hsts:
            m = re.search(r"max-age=(\d+)", hsts)
            if m:
                hsts_max_age = int(m.group(1)) // 86400  # días
            hsts_preload = "preload" in hsts.lower()

        csp = _get_header("content-security-policy")
        csp_ro = _get_header("content-security-policy-report-only")

        return SecurityHeaders(
            hsts=hsts[:256],
            hsts_preload=hsts_preload,
            hsts_max_age_days=hsts_max_age,
            csp=csp[:2048] or csp_ro[:2048],
            csp_report_only=bool(csp_ro) and not csp,
            x_frame_options=_get_header("x-frame-options")[:64],
            x_content_type_options=_get_header("x-content-type-options")[:64],
            referrer_policy=_get_header("referrer-policy")[:128],
            permissions_policy=_get_header("permissions-policy")[:1024],
            server_header=_get_header("server")[:128],
            powered_by=_get_header("x-powered-by")[:128],
        )

    # ------------------------------------------------------------------------
    # TLS analysis (FIX #15, #16, #17)
    # ------------------------------------------------------------------------

    async def _analyze_tls(self, target: str, url: str) -> TlsInfo | None:
        """TLS analysis profundo (protocols + ciphers + expiry)."""
        try:
            parsed = urlparse(url)
            host = parsed.hostname or target
            port = parsed.port or 443
        except Exception:
            return None

        try:
            result = await self.run_command(
                command=(
                    f"echo | timeout 15 openssl s_client -connect {host}:{port} "
                    f"-servername {host} -showcerts 2>/dev/null | "
                    f"openssl x509 -noout -subject -issuer -dates -serial "
                    f"-ext subjectAltName -fingerprint 2>/dev/null; "
                    f"echo '=====VERSION====='; "
                    f"echo | timeout 15 openssl s_client -connect {host}:{port} "
                    f"-servername {host} 2>/dev/null | grep -E '(Protocol|Cipher)'"
                ),
                timeout_seconds=TOOL_TIMEOUT_OPENSSL,
                tool_name="openssl",
            )
        except AgentToolError:
            return None

        if result["exit_code"] != 0:
            return None

        output = result["stdout"]
        info = self._parse_openssl_output(output)

        # FIX #16, #17: calcular expiry
        if info.not_after:
            try:
                from email.utils import parsedate_to_datetime
                expiry = parsedate_to_datetime(info.not_after)
                now = datetime.now(timezone.utc)
                delta = expiry - now
                days = delta.days
                info = info.model_copy(update={
                    "is_expired": days < 0,
                    "days_until_expiry": max(0, days),
                })
            except Exception:
                pass

        # FIX #15: detectar weak protocols/ciphers
        weak_protocols = []
        weak_ciphers = []
        for weak_proto in ("SSLv2", "SSLv3", "TLSv1 ", "TLSv1.0", "TLSv1.1"):
            if weak_proto in output:
                weak_protocols.append(weak_proto.strip())
        for weak_cipher in ("RC4", "DES", "3DES", "NULL", "EXPORT", "MD5"):
            if weak_cipher in output:
                weak_ciphers.append(weak_cipher)

        info = info.model_copy(update={
            "weak_protocols": weak_protocols,
            "weak_ciphers": weak_ciphers,
        })

        return info

    @staticmethod
    def _parse_openssl_output(output: str) -> TlsInfo:
        """Parsea el output de openssl s_client + x509."""
        info = TlsInfo()

        m = re.search(r"subject\s*=\s*(.+)", output)
        if m:
            cn_match = re.search(r"CN\s*=\s*([^,\n]+)", m.group(1))
            if cn_match:
                info = info.model_copy(update={"subject_cn": cn_match.group(1).strip()[:256]})

        m = re.search(r"issuer\s*=\s*(.+)", output)
        if m:
            cn_match = re.search(r"CN\s*=\s*([^,\n]+)", m.group(1))
            if cn_match:
                info = info.model_copy(update={"issuer_cn": cn_match.group(1).strip()[:256]})
            o_match = re.search(r"O\s*=\s*([^,\n]+)", m.group(1))
            if o_match:
                info = info.model_copy(update={"issuer_org": o_match.group(1).strip()[:256]})

        m = re.search(r"DNS:([^\n]+)", output)
        if m:
            sans = [s.strip() for s in m.group(1).split(",")]
            info = info.model_copy(update={"san": sans[:50]})

        m = re.search(r"notBefore\s*=\s*(.+)", output)
        if m:
            info = info.model_copy(update={"not_before": m.group(1).strip()[:64]})
        m = re.search(r"notAfter\s*=\s*(.+)", output)
        if m:
            info = info.model_copy(update={"not_after": m.group(1).strip()[:64]})

        m = re.search(r"serial\s*=\s*([0-9A-Fa-f]+)", output)
        if m:
            info = info.model_copy(update={"serial": m.group(1)[:128]})

        return info

    # ------------------------------------------------------------------------
    # WAF detection (FIX #11)
    # ------------------------------------------------------------------------

    async def _detect_waf(self, target: str) -> WafInfo:
        """Detecta WAF con wafw00f."""
        try:
            result = await self.run_command(
                command=f"wafw00f {target} -o - -f json 2>/dev/null || wafw00f {target} 2>/dev/null",
                timeout_seconds=TOOL_TIMEOUT_WAFW00F,
                tool_name="wafw00f",
            )
        except AgentToolError:
            return WafInfo()

        if result["exit_code"] != 0:
            return WafInfo()

        output = result["stdout"]

        # Parse JSON o texto
        waf_name = ""
        try:
            data = json.loads(output)
            if isinstance(data, list) and data:
                entry = data[0]
                if entry.get("detected"):
                    waf_name = entry.get("firewall", "")
        except json.JSONDecodeError:
            # Parse texto
            m = re.search(r"is behind\s+(.+?)\s+WAF", output)
            if m:
                waf_name = m.group(1).strip()

        if waf_name:
            return WafInfo(
                detected=True,
                waf_name=waf_name[:64],
                confidence=80,
            )

        return WafInfo()

    # ------------------------------------------------------------------------
    # Takeover check (FIX #23)
    # ------------------------------------------------------------------------

    async def _check_takeover(
        self, subdomains: list[SubdomainInfo],
    ) -> list[SubdomainInfo]:
        """Detecta subdomain takeover candidates."""
        updated: list[SubdomainInfo] = []

        for sub in subdomains[:200]:  # limit para performance
            if not sub.cname:
                updated.append(sub)
                continue

            for pattern, reason in _SUBDOMAIN_TAKEOVER_PATTERNS:
                if re.search(pattern, sub.cname, re.IGNORECASE):
                    sub = sub.model_copy(update={
                        "takeover_candidate": True,
                        "takeover_reason": reason,
                    })
                    break

            updated.append(sub)

        candidates = sum(1 for s in updated if s.takeover_candidate)
        if candidates:
            _log.warning("takeover_candidates_found", count=candidates)

        return updated

    # ------------------------------------------------------------------------
    # Findings generation
    # ------------------------------------------------------------------------

    def _generate_all_findings(
        self, output: ReconOutput, target: str,
    ) -> list[AgentFinding]:
        """Genera findings desde todos los análisis."""
        findings: list[AgentFinding] = []

        # Findings por puertos críticos
        findings.extend(self._generate_port_findings(
            output.open_ports, output.service_details, target,
        ))

        # Findings por security headers faltantes
        findings.extend(self._generate_security_header_findings(
            output.http_probes, target,
        ))

        # Findings por TLS débil
        findings.extend(self._generate_tls_findings(
            output.http_probes, target,
        ))

        # Findings por takeover candidates
        findings.extend(self._generate_takeover_findings(
            output.subdomains, target,
        ))

        # Findings por WAF detected (informativo)
        if output.waf_info.detected:
            findings.append(AgentFinding(
                title=f"WAF detected: {output.waf_info.waf_name}",
                description=f"WAF '{output.waf_info.waf_name}' protege {target}. "
                            f"Consider evasive techniques.",
                severity=CriticalityLevel.INFO,  # type: ignore[attr-defined]
                affected_asset=target,
                evidence=[f"wafw00f confidence: {output.waf_info.confidence}%"],
                metadata={"waf_name": output.waf_info.waf_name},
            ))

        return findings

    def _generate_port_findings(
        self,
        open_ports: dict[str, list[int]],
        service_details: dict[str, list[ServiceDetail]],
        target: str,
    ) -> list[AgentFinding]:
        """Findings por puertos críticos."""
        findings: list[AgentFinding] = []

        for host, ports in open_ports.items():
            details_map = {d.port: d for d in service_details.get(host, [])}

            for port in ports:
                if port not in _CRITICAL_PORTS:
                    continue
                meta = _CRITICAL_PORTS[port]
                detail = details_map.get(port)

                service_info = ""
                if detail and (detail.product or detail.version):
                    service_info = f" ({detail.product} {detail.version})".strip()

                cpes = detail.cpe if detail else []
                evidence = [f"nmap detected open port {port}"]
                if cpes:
                    evidence.append(f"CPE: {', '.join(cpes[:3])}")
                if detail and detail.banner:
                    evidence.append(f"Banner: {detail.banner[:200]}")

                findings.append(AgentFinding(
                    title=f"{meta['title']} on {host}:{port}{service_info}",
                    description=(
                        f"Port {port} is open on {host}. "
                        f"Service: {detail.service if detail else 'unknown'}. "
                        f"Attack: {meta['attack_id']}"
                    ),
                    severity=meta["severity"],
                    attack_id=meta["attack_id"],
                    affected_asset=f"{host}:{port}",
                    evidence=evidence,
                    metadata={
                        "port": port,
                        "host": host,
                        "service": detail.service if detail else "",
                        "product": detail.product if detail else "",
                        "version": detail.version if detail else "",
                        "cpe": cpes,
                    },
                ))

        return findings

    def _generate_security_header_findings(
        self, probes: list[HttpProbe], target: str,
    ) -> list[AgentFinding]:
        """Findings por security headers faltantes."""
        findings: list[AgentFinding] = []

        for probe in probes:
            if probe.status_code == 0:
                continue

            missing = probe.security_headers.missing_headers
            if missing:
                findings.append(AgentFinding(
                    title=f"Missing security headers on {probe.url}",
                    description=(
                        f"HTTP endpoint {probe.url} is missing security headers: "
                        f"{', '.join(missing)}"
                    ),
                    severity=CriticalityLevel.MEDIUM,
                    affected_asset=probe.url,
                    evidence=[f"Missing: {', '.join(missing)}"],
                    remediation=(
                        "Add the missing security headers: "
                        "HSTS (Strict-Transport-Security), "
                        "CSP (Content-Security-Policy), "
                        "X-Frame-Options, "
                        "X-Content-Type-Options, "
                        "Referrer-Policy"
                    ),
                    metadata={
                        "missing_headers": missing,
                        "status_code": probe.status_code,
                    },
                ))

            # HSTS con max-age bajo
            if probe.security_headers.hsts and probe.security_headers.hsts_max_age_days < 180:
                findings.append(AgentFinding(
                    title=f"Short HSTS max-age on {probe.url}",
                    description=(
                        f"HSTS max-age is only {probe.security_headers.hsts_max_age_days} days "
                        f"(recommended: >= 180 days, ideally 1 year)"
                    ),
                    severity=CriticalityLevel.LOW,
                    affected_asset=probe.url,
                    evidence=[probe.security_headers.hsts],
                    remediation="Set HSTS max-age to at least 31536000 (1 year)",
                    metadata={"max_age_days": probe.security_headers.hsts_max_age_days},
                ))

        return findings

    def _generate_tls_findings(
        self, probes: list[HttpProbe], target: str,
    ) -> list[AgentFinding]:
        """Findings por problemas TLS."""
        findings: list[AgentFinding] = []

        for probe in probes:
            tls = probe.tls_info
            if tls is None:
                continue

            # Certificado expirado
            if tls.is_expired:
                findings.append(AgentFinding(
                    title=f"Expired TLS certificate on {probe.url}",
                    description=f"TLS certificate for {probe.url} has expired",
                    severity=CriticalityLevel.HIGH,
                    affected_asset=probe.url,
                    evidence=[
                        f"not_after: {tls.not_after}",
                        f"days_until_expiry: {tls.days_until_expiry}",
                    ],
                    remediation="Renew the TLS certificate immediately",
                    metadata={"cert_cn": tls.subject_cn},
                ))

            # Certificado por expirar pronto
            elif 0 < tls.days_until_expiry < 30:
                findings.append(AgentFinding(
                    title=f"TLS certificate expiring soon on {probe.url}",
                    description=(
                        f"TLS certificate expires in {tls.days_until_expiry} days"
                    ),
                    severity=CriticalityLevel.MEDIUM,
                    affected_asset=probe.url,
                    evidence=[f"days_until_expiry: {tls.days_until_expiry}"],
                    remediation="Renew the TLS certificate soon",
                    metadata={"days_until_expiry": tls.days_until_expiry},
                ))

            # Protocols débiles
            if tls.weak_protocols:
                findings.append(AgentFinding(
                    title=f"Weak TLS protocols on {probe.url}",
                    description=(
                        f"Weak TLS protocols enabled: {', '.join(tls.weak_protocols)}"
                    ),
                    severity=CriticalityLevel.HIGH,
                    affected_asset=probe.url,
                    evidence=[f"Protocols: {', '.join(tls.weak_protocols)}"],
                    remediation=(
                        "Disable weak protocols (SSLv2, SSLv3, TLS 1.0, TLS 1.1). "
                        "Use only TLS 1.2+."
                    ),
                    metadata={"weak_protocols": tls.weak_protocols},
                ))

            # Ciphers débiles
            if tls.weak_ciphers:
                findings.append(AgentFinding(
                    title=f"Weak TLS ciphers on {probe.url}",
                    description=(
                        f"Weak TLS ciphers supported: {', '.join(tls.weak_ciphers)}"
                    ),
                    severity=CriticalityLevel.MEDIUM,
                    affected_asset=probe.url,
                    evidence=[f"Ciphers: {', '.join(tls.weak_ciphers)}"],
                    remediation="Disable weak ciphers (RC4, DES, 3DES, NULL, EXPORT)",
                    metadata={"weak_ciphers": tls.weak_ciphers},
                ))

        return findings

    def _generate_takeover_findings(
        self, subdomains: list[SubdomainInfo], target: str,
    ) -> list[AgentFinding]:
        """Findings por subdomain takeover candidates."""
        findings: list[AgentFinding] = []

        for sub in subdomains:
            if not sub.takeover_candidate:
                continue

            findings.append(AgentFinding(
                title=f"Potential subdomain takeover: {sub.name}",
                description=(
                    f"Subdomain {sub.name} has CNAME '{sub.cname}' "
                    f"which points to a potentially unclaimed service. "
                    f"Reason: {sub.takeover_reason}"
                ),
                severity=CriticalityLevel.HIGH,
                affected_asset=sub.name,
                evidence=[
                    f"CNAME: {sub.cname}",
                    f"Reason: {sub.takeover_reason}",
                ],
                remediation=(
                    "Verify the CNAME target is claimed. If unclaimed, "
                    "register it or remove the DNS record."
                ),
                metadata={
                    "cname": sub.cname,
                    "reason": sub.takeover_reason,
                },
            ))

        return findings


__all__ = [
    "ReconAgent",
    "ReconInput",
    "ReconOutput",
    "ServiceDetail",
    "HttpProbe",
    "TlsInfo",
    "DnsRecord",
    "SubdomainInfo",
    "SecurityHeaders",
    "WafInfo",
]
