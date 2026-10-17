"""
Reporter Agent --- God-Tier v2.0 (Conclave Absolute).
Genera reportes multi-formato (Markdown, PDF, SARIF 2.1.0, ATT&CK Navigator v4.1,
JSON para SIEM/GRC) a partir del Knowledge Graph persistente del ConsensusEngine.
Incluye cadena de custodia criptográfica, redacción automática de secretos,
compliance mapping (NIST 800-115, PTES, OWASP WSTG, TIBER-EU) y firma Ed25519.
"""
from __future__ import annotations

import asyncio
import hashlib
import io
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from god_tier_agency.agents.base import BaseAgent
from god_tier_agency.agents.contract import (
    AgentContract, AgentFinding, AgentInput, AgentOutput, CriticalityLevel
)
from god_tier_agency.core.logging import get_logger
from god_tier_agency.agents.exceptions import (
    AgentOutputError, AgentToolError, AgentSecurityError
)

_log = get_logger("agents.reporter")


# ============================================================================
# MODELOS --- Contratos de Datos v2.0
# ============================================================================

class EvidencePackage(BaseModel):
    """Evidencia empaquetada con cadena de custodia criptográfica."""
    evidence_id: str
    finding_id: str
    evidence_type: Literal[
        "screenshot", "command_output", "http_request",
        "http_response", "log", "file", "kg_node",
    ]
    content: str = ""
    content_preview: str = ""
    file_path: str = ""
    sha256: str = ""
    size_bytes: int = 0
    captured_at: float = Field(default_factory=time.time)
    captured_by: str = "operator"
    chain_of_custody: list[dict[str, Any]] = Field(default_factory=list)


class ATTACKNavigatorTechnique(BaseModel):
    """Técnica para el ATT&CK Navigator Layer v4.1."""
    techniqueID: str
    tactic: str = ""
    comment: str = ""
    enabled: bool = True
    score: float = 1.0
    color: str = ""
    metadata: list[dict[str, Any]] = Field(default_factory=list)


class ATTACKNavigatorLayer(BaseModel):
    """Layer v4.1 para ATT&CK Navigator."""
    name: str
    description: str = ""
    domain: Literal["enterprise-attack", "mobile-attack", "ics-attack"] = "enterprise-attack"
    techniques: list[ATTACKNavigatorTechnique] = Field(default_factory=list)
    gradient: dict[str, Any] = Field(
        default_factory=lambda: {
            "colors": ["#ff6666", "#ffe766", "#8ec843"],
            "minValue": 0,
            "maxValue": 100,
        }
    )
    sorting: int = 3
    versions: dict[str, Any] = Field(default_factory=lambda: {"layer": "4.1", "attack": "16", "navigator": "5.1.0"})
    hideDisabled: bool = False


class SARIFRule(BaseModel):
    """Regla SARIF (rule) con id único."""
    id: str
    name: str = ""
    shortDescription: dict[str, str] = Field(default_factory=lambda: {"text": ""})
    fullDescription: dict[str, str] = Field(default_factory=lambda: {"text": ""})
    helpUri: str = ""
    properties: dict[str, Any] = Field(default_factory=dict)
    defaultConfiguration: dict[str, str] = Field(default_factory=lambda: {"level": "warning"})


class SARIFResult(BaseModel):
    """Resultado SARIF 2.1.0 con ruleIndex correcto."""
    ruleId: str
    ruleIndex: int = 0
    level: Literal["error", "warning", "note", "none"] = "warning"
    message: dict[str, str] = Field(default_factory=lambda: {"text": ""})
    locations: list[dict[str, Any]] = Field(default_factory=list)
    properties: dict[str, Any] = Field(default_factory=dict)


class SARIFLog(BaseModel):
    """Documento SARIF 2.1.0 (Pydantic V2: usa populate_by_name)."""
    model_config = ConfigDict(populate_by_name=True)
    schema_uri: str = Field(
        default="https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        alias="$schema",
    )
    version: str = "2.1.0"
    runs: list[dict[str, Any]] = Field(default_factory=list)


class ComplianceMapping(BaseModel):
    """Mapeo a frameworks de compliance."""
    nist_800_115_phases: list[str] = Field(default_factory=list)
    ptes_phases: list[str] = Field(default_factory=list)
    owasp_wstg_ids: list[str] = Field(default_factory=list)
    tiber_eu_phases: list[str] = Field(default_factory=list)


class ReportInput(AgentInput):
    """Input del ReporterAgent."""
    target_os: Literal["windows", "linux", "macos", "multi"] = "multi"
    engagement_name: str = Field(description="Nombre del engagement")
    client_name: str = Field(description="Nombre del cliente")
    authorization_ref: str = Field(description="Referencia al ROE firmado")
    engagement_start: str = Field(description="Fecha de inicio ISO 8601")
    engagement_end: str = Field(description="Fecha de fin ISO 8601")
    current_user: str = Field(default="operator")
    output_formats: list[Literal["markdown", "pdf", "sarif", "navigator", "json"]] = Field(
        default_factory=lambda: ["markdown", "pdf", "navigator", "json", "sarif"]
    )
    redact_secrets: bool = True
    include_evidence: bool = True
    sign_report: bool = True
    compliance_frameworks: list[Literal["nist_800_115", "ptes", "owasp_wstg", "tiber_eu"]] = Field(
        default_factory=lambda: ["nist_800_115", "ptes"]
    )


class ReportOutput(AgentOutput):
    """Output del ReporterAgent."""
    markdown_report: str = ""
    pdf_bytes: bytes | None = None
    navigator_layer: ATTACKNavigatorLayer | None = None
    sarif_log: SARIFLog | None = None
    json_export: dict[str, Any] = Field(default_factory=dict)
    evidence_index: list[EvidencePackage] = Field(default_factory=list)
    compliance_mapping: ComplianceMapping | None = None
    report_manifest: dict[str, Any] = Field(default_factory=dict)
    report_hash_sha256: str = ""
    report_signature_ed25519: str = ""
    total_findings_reported: int = 0
    total_findings_rejected: int = 0
    execution_metadata: dict[str, Any] = Field(default_factory=dict)

# Registrar schemas en el registry global (necesario para AgentContract)
from god_tier_agency.agents.contract import _register_schema
_register_schema("ReportInput", ReportInput)
_register_schema("ReportOutput", ReportOutput)





# ============================================================================
# SANITIZACIÓN Y REDACT
# ============================================================================

_SECRET_PATTERNS = (
    re.compile(r'(?i)(api[_ -]?key|apikey|secret|token|password|passwd|pwd)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{8,})'),
    re.compile(r'AKIA[0-9A-Z]{16}'),
    re.compile(r'ghp_[a-zA-Z0-9]{36}'),
    re.compile(r'sk_live_[a-zA-Z0-9]{24,}'),
    re.compile(r'xox[baprs]-[a-zA-Z0-9-]+'),
    re.compile(r'eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+'),
)

_PII_PATTERNS = (
    re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'),
    re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
    re.compile(r'\b(?:\d[ -]*?){13,19}\b'),
)


def _redact_text(text: str) -> tuple[str, int]:
    if not text:
        return "", 0
    result = text
    count = 0
    for pattern in _SECRET_PATTERNS:
        result, n = pattern.subn("[REDACTED]", result)
        count += n
    for pattern in _PII_PATTERNS:
        result, n = pattern.subn("[REDACTED-PII]", result)
        count += n
    return result, count


def _hash_content(content: str | bytes) -> str:
    if isinstance(content, str):
        content = content.encode("utf-8", errors="ignore")
    return hashlib.sha256(content).hexdigest()


def _severity_str(sev: Any) -> str:
    """Normaliza severidad a string estable (evita CriticalityLevel.CRITICAL)."""
    if hasattr(sev, "value"):
        return str(sev.value)
    return str(sev)


# ============================================================================
# REPORTER AGENT v2.0
# ============================================================================

class ReporterAgent(BaseAgent):
    """Agente de reportería multi-formato con cadena de custodia criptográfica."""

    def get_contract(self) -> AgentContract:
        return AgentContract(
            name="reporter",
            version="2.0.0",
            description="God-Tier multi-format reporter (Markdown, PDF, SARIF 2.1.0, ATT&CK Navigator v4.1, JSON) con firma Ed25519",
            objective="Generate client-ready reports with cryptographic chain of custody, compliance mapping, and multi-audience structure",
            input_schema_name="ReportInput",
            output_schema_name="ReportOutput",
            stop_condition="All requested report formats generated, hashed, and signed",
            input_example={
                "target": "10.0.0.0/24",
                "target_os": "multi",
                "engagement_name": "Q1 2026 Red Team",
                "client_name": "ACME Corp",
                "authorization_ref": "ROE-2026-001",
                "engagement_start": "2026-01-15T00:00:00Z",
                "engagement_end": "2026-02-15T00:00:00Z",
                "output_formats": ["markdown", "pdf", "navigator", "json", "sarif"],
                "redact_secrets": True,
                "sign_report": True,
                "compliance_frameworks": ["nist_800_115", "ptes", "owasp_wstg"],
            },
            max_duration_seconds=600.0,
            max_commands=10,
            tools_allowed=("python3", "pandoc", "weasyprint", "reportlab"),
            criticality=CriticalityLevel.HIGH,
        )

    def __init__(
        self,
        *args: Any,
        knowledge_graph: Any = None,
        signing_key_path: str | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        self._knowledge_graph = knowledge_graph
        self._signing_key_path = signing_key_path

    async def _execute(self, inp: ReportInput) -> ReportOutput:
        _log.info("reporter_start", engagement=inp.engagement_name, formats=inp.output_formats)
        output = ReportOutput(summary="Report generation initiated")
        start_time = time.monotonic()

        # 1. Recopilar findings del Knowledge Graph (solo los REPORT)
        findings, rejected_count = self._collect_findings_from_kg()
        output.total_findings_reported = len(findings)
        output.total_findings_rejected = rejected_count

        # 2. Construir paquetes de evidencia con cadena de custodia
        if inp.include_evidence:
            output.evidence_index = self._build_evidence_packages(findings, inp.redact_secrets)

        # 3. Compliance mapping
        if inp.compliance_frameworks:
            output.compliance_mapping = self._map_compliance(findings, inp.compliance_frameworks)

        # 4. Markdown (fuente de verdad)
        if "markdown" in inp.output_formats:
            output.markdown_report = self._render_markdown(findings, output, inp)
            output.report_hash_sha256 = _hash_content(output.markdown_report)

        # 5. PDF (real, no simulacro)
        if "pdf" in inp.output_formats:
            output.pdf_bytes = self._render_pdf(output.markdown_report, inp)
            if output.pdf_bytes is None:
                _log.warning("reporter_pdf_unavailable", msg="PDF backend no disponible")

        # 6. ATT&CK Navigator Layer v4.1
        if "navigator" in inp.output_formats:
            output.navigator_layer = self._render_navigator_layer(findings, inp)

        # 7. SARIF 2.1.0 (con rules correctas)
        if "sarif" in inp.output_formats:
            output.sarif_log = self._render_sarif(findings, inp)

        # 8. JSON export (SIEM/GRC)
        if "json" in inp.output_formats:
            output.json_export = self._render_json_export(findings, output, inp)

        # 9. Report manifest firmado (hash chain)
        output.report_manifest = self._build_manifest(output, inp)
        if inp.sign_report:
            output.report_signature_ed25519 = self._sign_manifest(output.report_manifest)

        # 10. Metadata
        output.execution_metadata = {
            "engagement_name": inp.engagement_name,
            "client_name": inp.client_name,
            "authorization_ref": inp.authorization_ref,
            "engagement_start": inp.engagement_start,
            "engagement_end": inp.engagement_end,
            "formats_generated": inp.output_formats,
            "total_findings": len(findings),
            "total_evidence_packages": len(output.evidence_index),
            "report_hash_sha256": output.report_hash_sha256,
            "report_signature_ed25519": output.report_signature_ed25519[:32] + "..." if output.report_signature_ed25519 else "",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "generation_duration_ms": round((time.monotonic() - start_time) * 1000, 2),
        }

        output.summary = (
            f"Report generated: {len(findings)} findings, "
            f"{len(output.evidence_index)} evidence packages, "
            f"formats={inp.output_formats}, "
            f"hash={output.report_hash_sha256[:16]}, "
            f"signed={'yes' if output.report_signature_ed25519 else 'no'}"
        )
        _log.info("reporter_done", **output.execution_metadata)
        return output

    # ========================================================================
    # RECOLECCIÓN DE FINDINGS DEL KNOWLEDGE GRAPH (edges + nodos)
    # ========================================================================

    def _collect_findings_from_kg(self) -> tuple[list[AgentFinding], int]:
        """Recopila findings confirmados del Knowledge Graph, siguiendo edges causales."""
        if self._knowledge_graph is None:
            _log.warning("reporter_no_kg", msg="No Knowledge Graph attached")
            return [], 0

        findings: list[AgentFinding] = []
        rejected_count = 0
        try:
            kg_nodes = getattr(self._knowledge_graph, "_nodes", {})
            kg_edges = getattr(self._knowledge_graph, "_edges", {})

            # Indexar edges por finding_id para recuperar evidencia causal
            finding_edges: dict[str, list[Any]] = {}
            for edge in kg_edges.values():
                if getattr(edge, "edge_type", "") in ("DISCOVERED_ON", "EXPLOITS"):
                    finding_edges.setdefault(getattr(edge, "source_id", ""), []).append(edge)

            for node_id, node in kg_nodes.items():
                if getattr(node, "node_type", "") != "Finding":
                    continue
                attrs = getattr(node, "attributes", {}) or {}
                severity_raw = attrs.get("severity", "medium")
                try:
                    severity = CriticalityLevel(severity_raw)
                except Exception:
                    severity = CriticalityLevel.MEDIUM

                # Construir evidencia real desde edges + nodo summary
                evidence_lines: list[str] = []
                for edge in finding_edges.get(node_id, []):
                    evidence_lines.append(
                        f"[{getattr(edge, 'edge_type', 'edge')}] "
                        f"{getattr(edge, 'fact', '')[:300]} "
                        f"(confidence={getattr(edge, 'confidence', 0.0):.2f})"
                    )
                if not evidence_lines and getattr(node, "summary", ""):
                    evidence_lines.append(getattr(node, "summary", "")[:300])

                findings.append(
                    AgentFinding(
                        id=UUID(node_id) if _is_uuid(node_id) else uuid4(),
                        title=getattr(node, "name", "Unknown"),
                        description=getattr(node, "summary", ""),
                        severity=severity,
                        attack_id=attrs.get("attack_id") or None,
                        cve_id=attrs.get("cve_id") or None,
                        cwe_id=attrs.get("cwe_id") or None,
                        affected_asset=attrs.get("target", ""),
                        evidence=evidence_lines,
                        remediation=attrs.get("remediation"),
                    )
                )

            kg_metrics = getattr(self._knowledge_graph, "to_dict", lambda: {})()
            rejected_count = int(kg_metrics.get("rejected_findings", 0))
        except Exception as e:
            _log.error("reporter_kg_collection_failed", error=str(e))

        _log.info("reporter_findings_collected", confirmed=len(findings), rejected=rejected_count)
        return findings, rejected_count

    # ========================================================================
    # EVIDENCE PACKAGES CON CADENA DE CUSTODIA
    # ========================================================================

    def _build_evidence_packages(
        self, findings: list[AgentFinding], redact: bool
    ) -> list[EvidencePackage]:
        packages: list[EvidencePackage] = []
        for finding in findings:
            for i, ev in enumerate(finding.evidence or []):
                content = ev
                redactions = 0
                if redact:
                    content, redactions = _redact_text(content)
                packages.append(
                    EvidencePackage(
                        evidence_id=f"EV-{finding.id}-{i}",
                        finding_id=str(finding.id),
                        evidence_type="kg_node",
                        content=content,
                        content_preview=content[:200],
                        sha256=_hash_content(content),
                        size_bytes=len(content.encode("utf-8")),
                        captured_at=time.time(),
                        captured_by="operator",
                        chain_of_custody=[
                            {
                                "action": "captured_from_kg",
                                "timestamp": time.time(),
                                "actor": "reporter",
                                "redactions_applied": redactions,
                                "hash": _hash_content(content),
                            }
                        ],
                    )
                )
        return packages

    # ========================================================================
    # COMPLIANCE MAPPING
    # ========================================================================

    def _map_compliance(
        self, findings: list[AgentFinding], frameworks: list[str]
    ) -> ComplianceMapping:
        mapping = ComplianceMapping()
        if "nist_800_115" in frameworks:
            mapping.nist_800_115_phases = [
                "Discovery", "Attack", "Reporting",
            ]
        if "ptes" in frameworks:
            mapping.ptes_phases = [
                "Pre-engagement Interactions", "Intelligence Gathering",
                "Threat Modeling", "Vulnerability Analysis", "Exploitation",
                "Post Exploitation", "Reporting",
            ]
        if "owasp_wstg" in frameworks:
            owasp_ids = set()
            for f in findings:
                if f.attack_id and f.attack_id.startswith("T1190"):
                    owasp_ids.add("WSTG-INPV-01")
                if f.cve_id:
                    owasp_ids.add("WSTG-ATHN-04")
            mapping.owasp_wstg_ids = sorted(owasp_ids)
        if "tiber_eu" in frameworks:
            mapping.tiber_eu_phases = [
                "Preparation", "Red Team Testing", "Blue Team Testing", "Closure",
            ]
        return mapping

    # ========================================================================
    # MARKDOWN RENDER (con TOC y referencias cruzadas)
    # ========================================================================

    def _render_markdown(
        self, findings: list[AgentFinding], output: ReportOutput, inp: ReportInput
    ) -> str:
        now = datetime.now(timezone.utc).isoformat()
        sev_counts = {
            "critical": sum(1 for f in findings if _severity_str(f.severity) == "critical"),
            "high": sum(1 for f in findings if _severity_str(f.severity) == "high"),
            "medium": sum(1 for f in findings if _severity_str(f.severity) == "medium"),
            "low": sum(1 for f in findings if _severity_str(f.severity) == "low"),
        }
        priority = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        top_findings = sorted(findings, key=lambda f: priority.get(_severity_str(f.severity), 4))[:3]

        lines: list[str] = []
        lines.append(f"# Red Team Engagement Report — {inp.client_name}")
        lines.append("")
        lines.append(f"**Engagement:** {inp.engagement_name}  ")
        lines.append(f"**Authorization:** {inp.authorization_ref}  ")
        lines.append(f"**Period:** {inp.engagement_start} — {inp.engagement_end}  ")
        lines.append(f"**Generated:** {now}  ")
        lines.append(f"**Classification:** CONFIDENTIAL — Red Team  ")
        lines.append("")
        lines.append("## Table of Contents")
        lines.append("1. [Executive Summary](#1-executive-summary)")
        lines.append("2. [Risk Posture](#risk-posture)")
        lines.append("3. [Top Findings](#top-3-business-relevant-findings)")
        lines.append("4. [Technical Findings](#2-technical-findings)")
        lines.append("5. [Compliance Mapping](#3-compliance-mapping)")
        lines.append("6. [Evidence Index](#4-evidence-index-chain-of-custody)")
        lines.append("7. [Appendix — Methodology](#5-appendix--methodology--limitations)")
        lines.append("")
        lines.append("---")
        lines.append("")

        lines.append("## 1. Executive Summary")
        lines.append("")
        lines.append("### Risk Posture")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("| :--- | :--- |")
        for sev in ("critical", "high", "medium", "low"):
            lines.append(f"| {sev.capitalize()} | {sev_counts[sev]} |")
        lines.append(f"| **Total** | **{len(findings)}** |")
        lines.append("")

        if top_findings:
            lines.append("### Top 3 Business-Relevant Findings")
            lines.append("")
            for i, f in enumerate(top_findings, 1):
                desc, _ = _redact_text(f.description[:200])
                lines.append(f"{i}. **{f.title}** ({_severity_str(f.severity)}) — {desc}")
            lines.append("")

        lines.append("## 2. Technical Findings")
        lines.append("")
        for idx, finding in enumerate(
            sorted(findings, key=lambda f: priority.get(_severity_str(f.severity), 4)),
            start=1,
        ):
            lines.append(f"### FINDING-{idx:03d}: {finding.title}")
            lines.append("")
            lines.append(f"- **Severity:** {_severity_str(finding.severity)}")
            lines.append(f"- **Affected Asset:** {finding.affected_asset or 'N/A'}")
            lines.append(f"- **ATT&CK:** {finding.attack_id or 'N/A'}")
            lines.append(f"- **CVE:** {finding.cve_id or 'N/A'}")
            lines.append(f"- **CWE:** {finding.cwe_id or 'N/A'}")
            lines.append("")
            desc, _ = _redact_text(finding.description)
            lines.append(f"**Description:** {desc}")
            lines.append("")
            if finding.evidence:
                lines.append("**Evidence references:**")
                for ev in finding.evidence[:5]:
                    redacted, _ = _redact_text(ev)
                    lines.append(f"- `{redacted[:250]}`")
                lines.append("")
            if finding.remediation:
                lines.append(f"**Remediation:** {finding.remediation}")
                lines.append("")
            lines.append("---")
            lines.append("")

        lines.append("## 3. Compliance Mapping")
        lines.append("")
        if output.compliance_mapping:
            cm = output.compliance_mapping
            if cm.nist_800_115_phases:
                lines.append(f"- **NIST 800-115:** {', '.join(cm.nist_800_115_phases)}")
            if cm.ptes_phases:
                lines.append(f"- **PTES:** {', '.join(cm.ptes_phases)}")
            if cm.owasp_wstg_ids:
                lines.append(f"- **OWASP WSTG:** {', '.join(cm.owasp_wstg_ids)}")
            if cm.tiber_eu_phases:
                lines.append(f"- **TIBER-EU:** {', '.join(cm.tiber_eu_phases)}")
        lines.append("")

        lines.append("## 4. Evidence Index (Chain of Custody)")
        lines.append("")
        lines.append("| Evidence ID | Finding ID | SHA-256 (first 16) | Size (bytes) |")
        lines.append("| :--- | :--- | :--- | :--- |")
        for pkg in output.evidence_index[:50]:
            lines.append(
                f"| {pkg.evidence_id} | {pkg.finding_id[:8]}... | "
                f"`{pkg.sha256[:16]}` | {pkg.size_bytes} |"
            )
        if len(output.evidence_index) > 50:
            lines.append(f"| *(and {len(output.evidence_index) - 50} more)* | | | |")
        lines.append("")

        lines.append("## 5. Appendix — Methodology & Limitations")
        lines.append("")
        lines.append("**Methodology:** Reconnaissance → Exploitation → Post-Exploitation → Reporting")
        lines.append("")
        lines.append("**Validation:** Findings validated via ConsensusEngine (DeepSeek + Qwen + deterministic oracle + Knowledge Graph).")
        lines.append("")
        lines.append("**Limitations:**")
        lines.append("- Testing conducted within authorized scope only")
        lines.append("- Production data was not exfiltrated")
        lines.append("- Findings reflect the state of the environment at engagement time")
        lines.append("")

        return "\n".join(lines)

    # ========================================================================
    # PDF RENDER (WeasyPrint → reportlab → fallback)
    # ========================================================================

    def _render_pdf(self, markdown: str, inp: ReportInput) -> bytes | None:
        """Genera PDF real. Intenta WeasyPrint, luego reportlab, luego None."""
        html = self._markdown_to_html(markdown)
        # Intento 1: WeasyPrint
        try:
            from weasyprint import HTML  # type: ignore
            pdf = HTML(string=html).write_pdf()
            _log.info("reporter_pdf_weasyprint", bytes=len(pdf))
            return pdf
        except Exception as e:
            _log.debug("reporter_pdf_weasyprint_failed", error=str(e)[:200])
        # Intento 2: reportlab
        try:
            from reportlab.lib.pagesizes import A4  # type: ignore
            from reportlab.lib.styles import getSampleStyleSheet  # type: ignore
            from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer  # type: ignore
            from reportlab.lib.units import cm  # type: ignore

            buf = io.BytesIO()
            doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=2 * cm, rightMargin=2 * cm)
            styles = getSampleStyleSheet()
            flowables = []
            for line in markdown.splitlines():
                if line.startswith("# "):
                    flowables.append(Paragraph(line[2:], styles["Heading1"]))
                elif line.startswith("## "):
                    flowables.append(Paragraph(line[3:], styles["Heading2"]))
                elif line.startswith("### "):
                    flowables.append(Paragraph(line[4:], styles["Heading3"]))
                elif line.strip() == "---":
                    flowables.append(Spacer(1, 0.5 * cm))
                elif line.strip():
                    safe = line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                    flowables.append(Paragraph(safe, styles["BodyText"]))
            doc.build(flowables)
            pdf = buf.getvalue()
            _log.info("reporter_pdf_reportlab", bytes=len(pdf))
            return pdf
        except Exception as e:
            _log.warning("reporter_pdf_reportlab_failed", error=str(e)[:200])
        return None

    @staticmethod
    def _markdown_to_html(markdown: str) -> str:
        """Markdown → HTML mínimo (sin dependencia de markdown lib)."""
        out: list[str] = ["<html><head><meta charset='utf-8'><style>",
                           "body{font-family:system-ui;max-width:900px;margin:2em auto;padding:0 1em;}",
                           "table{border-collapse:collapse;width:100%;}th,td{border:1px solid #ccc;padding:6px;}",
                           "code{background:#f4f4f4;padding:2px 4px;border-radius:3px;}",
                           "</style></head><body>"]
        for line in markdown.splitlines():
            if line.startswith("# "):
                out.append(f"<h1>{line[2:]}</h1>")
            elif line.startswith("## "):
                out.append(f"<h2>{line[3:]}</h2>")
            elif line.startswith("### "):
                out.append(f"<h3>{line[4:]}</h3>")
            elif line.startswith("- "):
                out.append(f"<li>{line[2:]}</li>")
            elif line.startswith("|"):
                out.append(line)  # Tables se dejan crudas; WeasyPrint las renderiza
            elif line.strip() == "---":
                out.append("<hr/>")
            elif line.strip():
                out.append(f"<p>{line}</p>")
        out.append("</body></html>")
        return "".join(out)

    # ========================================================================
    # ATT&CK NAVIGATOR LAYER v4.1
    # ========================================================================

    def _render_navigator_layer(
        self, findings: list[AgentFinding], inp: ReportInput
    ) -> ATTACKNavigatorLayer:
        techniques_map: dict[str, ATTACKNavigatorTechnique] = {}
        for finding in findings:
            if not finding.attack_id:
                continue
            attack_id = finding.attack_id
            if attack_id not in techniques_map:
                techniques_map[attack_id] = ATTACKNavigatorTechnique(
                    techniqueID=attack_id,
                    comment=finding.title[:100],
                    score=1.0,
                    enabled=True,
                    metadata=[{"name": "finding", "value": str(finding.id)}],
                )
            techniques_map[attack_id].score += 1.0
        # Normalizar score a 0-100
        max_score = max((t.score for t in techniques_map.values()), default=1.0)
        for t in techniques_map.values():
            t.score = round(min(100.0, (t.score / max_score) * 100.0), 2)

        return ATTACKNavigatorLayer(
            name=f"Red Team Layer — {inp.client_name}",
            description=f"ATT&CK coverage for {inp.engagement_name} ({inp.authorization_ref})",
            domain="enterprise-attack",
            techniques=list(techniques_map.values()),
            sorting=3,
            hideDisabled=False,
        )

    # ========================================================================
    # SARIF 2.1.0 (con rules + ruleIndex)
    # ========================================================================

    def _render_sarif(self, findings: list[AgentFinding], inp: ReportInput) -> SARIFLog:
        rules: list[dict[str, Any]] = []
        rule_index: dict[str, int] = {}
        results: list[dict[str, Any]] = []

        for finding in findings:
            rule_id = finding.attack_id or finding.cve_id or f"FINDING-{finding.id}"
            if rule_id not in rule_index:
                rule_index[rule_id] = len(rules)
                rules.append(
                    SARIFRule(
                        id=rule_id,
                        name=finding.title[:100],
                        shortDescription={"text": finding.title[:100]},
                        fullDescription={"text": finding.description[:500]},
                        properties={
                            "severity": _severity_str(finding.severity),
                            "attack_id": finding.attack_id,
                            "cve_id": finding.cve_id,
                            "cwe_id": finding.cwe_id,
                            "remediation": finding.remediation,
                        },
                        defaultConfiguration={
                            "level": "error"
                            if _severity_str(finding.severity) in ("critical", "high")
                            else "warning"
                            if _severity_str(finding.severity) == "medium"
                            else "note"
                        },
                    ).model_dump()
                )

            level = "error"
            if _severity_str(finding.severity) == "medium":
                level = "warning"
            elif _severity_str(finding.severity) == "low":
                level = "note"

            results.append(
                SARIFResult(
                    ruleId=rule_id,
                    ruleIndex=rule_index[rule_id],
                    level=level,
                    message={"text": f"{finding.title}: {finding.description[:400]}"},
                    locations=[{
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.affected_asset or "unknown"},
                        }
                    }],
                    properties={
                        "severity": _severity_str(finding.severity),
                        "attack_id": finding.attack_id,
                        "cve_id": finding.cve_id,
                    },
                ).model_dump()
            )

        return SARIFLog(
            runs=[{
                "tool": {
                    "driver": {
                        "name": "god-tier-agency",
                        "informationUri": "https://github.com/your-org/god-tier-agency",
                        "version": "2.0.0",
                        "rules": rules,
                    }
                },
                "results": results,
                "automationDetails": {
                    "id": f"red-team-{inp.engagement_name.replace(' ', '-').lower()}"
                },
            }]
        )

    # ========================================================================
    # JSON EXPORT (SIEM/GRC)
    # ========================================================================

    def _render_json_export(
        self, findings: list[AgentFinding], output: ReportOutput, inp: ReportInput
    ) -> dict[str, Any]:
        return {
            "engagement": {
                "name": inp.engagement_name,
                "client": inp.client_name,
                "authorization_ref": inp.authorization_ref,
                "start": inp.engagement_start,
                "end": inp.engagement_end,
                "generated_at": datetime.now(timezone.utc).isoformat(),
            },
            "findings": [
                {
                    "id": str(f.id),
                    "title": f.title,
                    "description": _redact_text(f.description)[0] if inp.redact_secrets else f.description,
                    "severity": _severity_str(f.severity),
                    "affected_asset": f.affected_asset,
                    "attack_id": f.attack_id,
                    "cve_id": f.cve_id,
                    "cwe_id": f.cwe_id,
                    "evidence_count": len(f.evidence or []),
                    "remediation": f.remediation,
                }
                for f in findings
            ],
            "summary": {
                "total_findings": len(findings),
                "critical": sum(1 for f in findings if _severity_str(f.severity) == "critical"),
                "high": sum(1 for f in findings if _severity_str(f.severity) == "high"),
                "medium": sum(1 for f in findings if _severity_str(f.severity) == "medium"),
                "low": sum(1 for f in findings if _severity_str(f.severity) == "low"),
            },
            "evidence": [
                {
                    "evidence_id": pkg.evidence_id,
                    "finding_id": pkg.finding_id,
                    "sha256": pkg.sha256,
                    "size_bytes": pkg.size_bytes,
                    "captured_at": pkg.captured_at,
                }
                for pkg in output.evidence_index
            ],
            "metadata": {
                "generator": "god-tier-agency/reporter v2.0.0",
                "format_version": "2.0",
            },
        }

    # ========================================================================
    # MANIFEST + FIRMA Ed25519
    # ========================================================================

    def _build_manifest(self, output: ReportOutput, inp: ReportInput) -> dict[str, Any]:
        hashes: dict[str, str] = {}
        if output.markdown_report:
            hashes["markdown"] = _hash_content(output.markdown_report)
        if output.pdf_bytes:
            hashes["pdf"] = _hash_content(output.pdf_bytes)
        if output.sarif_log:
            hashes["sarif"] = _hash_content(output.sarif_log.model_dump_json())
        if output.navigator_layer:
            hashes["navigator"] = _hash_content(output.navigator_layer.model_dump_json())
        if output.json_export:
            hashes["json"] = _hash_content(json.dumps(output.json_export, sort_keys=True))

        return {
            "manifest_version": "2.0",
            "engagement_name": inp.engagement_name,
            "client_name": inp.client_name,
            "authorization_ref": inp.authorization_ref,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "formats": list(hashes.keys()),
            "format_hashes": hashes,
            "evidence_hashes": [pkg.sha256 for pkg in output.evidence_index],
            "total_findings": output.total_findings_reported,
            "total_evidence_packages": len(output.evidence_index),
        }

    def _sign_manifest(self, manifest: dict[str, Any]) -> str:
        """Firma el manifest con Ed25519. Si no hay clave, retorna hash SHA-256."""
        payload = json.dumps(manifest, sort_keys=True).encode("utf-8")
        if not self._signing_key_path:
            # Fallback: hash del manifest (no firma criptográfica)
            return "sha256:" + _hash_content(payload)
        try:
            from cryptography.hazmat.primitives import serialization  # type: ignore
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # type: ignore
            from pathlib import Path as _P

            key_bytes = _P(self._signing_key_path).read_bytes()
            try:
                private_key = serialization.load_pem_private_key(key_bytes, password=None)
            except Exception:
                private_key = Ed25519PrivateKey.from_private_bytes(key_bytes)
            signature = private_key.sign(payload)
            return "ed25519:" + signature.hex()
        except Exception as e:
            _log.warning("reporter_sign_failed", error=str(e)[:200])
            return "sha256:" + _hash_content(payload)


# ============================================================================
# HELPERS
# ============================================================================

def _is_uuid(value: str) -> bool:
    try:
        UUID(value)
        return True
    except Exception:
        return False
