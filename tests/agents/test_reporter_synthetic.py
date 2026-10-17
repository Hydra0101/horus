"""
Test sintético del ReporterAgent v2.0.

Valida el pipeline completo de reporte con un Knowledge Graph falso:
- 3 findings de severidades distintas.
- Evidencia real con hashes SHA-256.
- Generación de Markdown, SARIF, Navigator, JSON.
- Manifest firmado (Ed25519 o fallback SHA-256).
- Redacción de secretos en la evidencia.

Uso:
    uv run pytest tests/agents/test_reporter_synthetic.py -v
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

# Import del agente bajo prueba
from god_tier_agency.agents.reporter_agent import (
    ReporterAgent,
    ReportInput,
    ReportOutput,
    EvidencePackage,
    ATTACKNavigatorLayer,
    SARIFLog,
)
from god_tier_agency.agents.contract import AgentFinding, CriticalityLevel


# ============================================================================
# FAKE KNOWLEDGE GRAPH (interfaz mínima compatible con ReporterAgent)
# ============================================================================

class FakeKGNode:
    """Nodo sintético compatible con el KG real."""
    def __init__(
        self,
        node_id: str,
        node_type: str,
        name: str,
        summary: str = "",
        attributes: dict[str, Any] | None = None,
    ) -> None:
        self.node_id = node_id
        self.node_type = node_type
        self.name = name
        self.summary = summary
        self.attributes = attributes or {}
        self.flow_id = "test-flow"
        self.created_at = time.time()
        self.valid_at = time.time()
        self.expired_at = None


class FakeKGEdge:
    """Edge sintético compatible con el KG real."""
    def __init__(
        self,
        edge_id: str,
        edge_type: str,
        source_id: str,
        target_id: str,
        fact: str = "",
        confidence: float = 0.9,
    ) -> None:
        self.edge_id = edge_id
        self.edge_type = edge_type
        self.source_id = source_id
        self.target_id = target_id
        self.fact = fact
        self.confidence = confidence


class FakeKnowledgeGraph:
    """Knowledge Graph sintético con la interfaz mínima que el ReporterAgent consume."""
    def __init__(self) -> None:
        self._nodes: dict[str, FakeKGNode] = {}
        self._edges: dict[str, FakeKGEdge] = {}

    def add_node(self, node: FakeKGNode) -> None:
        self._nodes[node.node_id] = node

    def add_edge(self, edge: FakeKGEdge) -> None:
        self._edges[edge.edge_id] = edge

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes_count": len(self._nodes),
            "edges_count": len(self._edges),
            "rejected_findings": 2,  # findings que el ConsensusEngine rechazó
        }


# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture
def fake_kg() -> FakeKnowledgeGraph:
    """Knowledge Graph con 3 findings representativos + edges causales."""
    kg = FakeKnowledgeGraph()

    # 1. Target node
    target_id = "target-acme-web-01"
    kg.add_node(FakeKGNode(
        node_id=target_id,
        node_type="Target",
        name="web-01.acme.local",
        summary="Production web server",
    ))

    # 2. Finding 1: SQL Injection (critical, con API key en evidencia)
    f1_id = str(uuid4())
    kg.add_node(FakeKGNode(
        node_id=f1_id,
        node_type="Finding",
        name="SQL Injection in login endpoint",
        summary="Union-based SQL injection confirmed at /api/login",
        attributes={
            "severity": "critical",
            "attack_id": "T1190",
            "cve_id": "CVE-2026-12345",
            "cwe_id": "CWE-89",
            "target": "web-01.acme.local",
            "remediation": "Use parameterized queries and input validation.",
        },
    ))
    kg.add_edge(FakeKGEdge(
        edge_id=str(uuid4()),
        edge_type="DISCOVERED_ON",
        source_id=f1_id,
        target_id=target_id,
        fact="sqlmap confirmed union-based injection at /api/login with api_key=FAKE-STRIPE-KEY-FOR-TESTING-ONLY",
        confidence=0.95,
    ))

    # 3. Finding 2: Outdated TLS (high, con email PII en evidencia)
    f2_id = str(uuid4())
    kg.add_node(FakeKGNode(
        node_id=f2_id,
        node_type="Finding",
        name="Outdated TLS configuration",
        summary="TLS 1.0 and 1.1 enabled; weak ciphers present",
        attributes={
            "severity": "high",
            "attack_id": "T1040",
            "target": "web-01.acme.local",
            "remediation": "Disable TLS 1.0/1.1; require TLS 1.2+ with strong ciphers.",
        },
    ))
    kg.add_edge(FakeKGEdge(
        edge_id=str(uuid4()),
        edge_type="DISCOVERED_ON",
        source_id=f2_id,
        target_id=target_id,
        fact="Certificate issued to admin@acme.local, expired in 30 days",
        confidence=0.88,
    ))

    # 4. Finding 3: SMB relay (medium)
    f3_id = str(uuid4())
    kg.add_node(FakeKGNode(
        node_id=f3_id,
        node_type="Finding",
        name="SMB signing not enforced",
        summary="SMB signing disabled, allowing relay attacks",
        attributes={
            "severity": "medium",
            "attack_id": "T1557",
            "target": "web-01.acme.local",
            "remediation": "Enforce SMB signing via Group Policy.",
        },
    ))
    kg.add_edge(FakeKGEdge(
        edge_id=str(uuid4()),
        edge_type="DISCOVERED_ON",
        source_id=f3_id,
        target_id=target_id,
        fact="nmap --script smb2-security-mode confirmed signing disabled",
        confidence=0.75,
    ))

    return kg


@pytest.fixture
def report_input() -> ReportInput:
    """Input estándar para el ReporterAgent."""
    return ReportInput(
        target="web-01.acme.local",
        target_os="linux",
        engagement_name="Q1 2026 Red Team Synthetic Test",
        client_name="ACME Corp",
        authorization_ref="ROE-2026-001",
        engagement_start="2026-01-15T00:00:00Z",
        engagement_end="2026-02-15T00:00:00Z",
        output_formats=["markdown", "pdf", "navigator", "json", "sarif"],
        redact_secrets=True,
        include_evidence=True,
        sign_report=True,
        compliance_frameworks=["nist_800_115", "ptes", "owasp_wstg"],
    )


@pytest.fixture
def reporter(fake_kg: FakeKnowledgeGraph) -> ReporterAgent:
    """Instancia del ReporterAgent con KG sintético inyectado."""
    # Construimos un objeto mock que tenga el atributo "sandbox" y "gateway"
    # que el BaseAgent.__init__ espera, pero que no se usan en el reporter.
    class _NullClient:
        pass

    agent = ReporterAgent(
        sandbox=_NullClient(),
        gateway=_NullClient(),
        knowledge_graph=fake_kg,
        signing_key_path=None,  # sin clave → fallback a SHA-256
    )
    return agent


# ============================================================================
# TESTS
# ============================================================================

@pytest.mark.asyncio
async def test_reporter_generates_all_formats(reporter: ReporterAgent, report_input: ReportInput):
    """El reporter debe generar todos los formatos solicitados."""
    result = await reporter.run(report_input.model_dump())

    assert result.success, f"Reporter falló: {result.error}"
    output: ReportOutput = result.output
    assert output is not None

    # Findings recolectados
    assert output.total_findings_reported == 3, f"Esperaba 3 findings, obtuve {output.total_findings_reported}"

    # Markdown generado
    assert output.markdown_report, "Markdown vacío"
    assert "ACME Corp" in output.markdown_report
    assert "FINDING-001" in output.markdown_report
    assert "SQL Injection" in output.markdown_report

    # SARIF generado
    assert output.sarif_log is not None
    assert len(output.sarif_log.runs) == 1
    runs = output.sarif_log.runs[0]
    assert "results" in runs
    assert len(runs["results"]) == 3
    assert len(runs["tool"]["driver"]["rules"]) == 3

    # Navigator generado
    assert output.navigator_layer is not None
    assert len(output.navigator_layer.techniques) >= 2  # al menos 2 técnicas distintas
    technique_ids = {t.techniqueID for t in output.navigator_layer.techniques}
    assert "T1190" in technique_ids
    assert "T1557" in technique_ids

    # JSON export generado
    assert output.json_export
    assert output.json_export["summary"]["total_findings"] == 3
    assert output.json_export["summary"]["critical"] == 1
    assert output.json_export["summary"]["high"] == 1
    assert output.json_export["summary"]["medium"] == 1

    # Evidence index generado
    assert len(output.evidence_index) == 3
    for ev in output.evidence_index:
        assert ev.sha256, f"Evidencia {ev.evidence_id} sin hash"
        assert len(ev.sha256) == 64, f"Hash inválido: {ev.sha256}"

    # Manifest firmado
    assert output.report_manifest
    assert output.report_hash_sha256
    assert len(output.report_hash_sha256) == 64
    assert output.report_signature_ed25519, "Sin firma"


@pytest.mark.asyncio
async def test_reporter_redacts_secrets(reporter: ReporterAgent, report_input: ReportInput):
    """El reporter debe redactar secretos (API keys, PII) en la evidencia."""
    result = await reporter.run(report_input.model_dump())

    assert result.success
    output: ReportOutput = result.output

    # Concatenar toda la evidencia
    all_evidence = " ".join(ev.content for ev in output.evidence_index)

    # Verificar que se redactó
    assert "FAKE-STRIPE-KEY-FOR-TESTING-ONLY" not in all_evidence, "API key NO redactada"
    assert "[REDACTED]" in all_evidence, "Falta marcador [REDACTED]"
    assert "admin@acme.local" not in all_evidence, "Email PII NO redactado"


@pytest.mark.asyncio
async def test_reporter_manifest_hash_chain(reporter: ReporterAgent, report_input: ReportInput):
    """El manifest debe incluir hashes de todos los formatos generados."""
    result = await reporter.run(report_input.model_dump())

    assert result.success
    output: ReportOutput = result.output
    manifest = output.report_manifest

    assert manifest["manifest_version"] == "2.0"
    assert manifest["engagement_name"] == report_input.engagement_name
    assert manifest["client_name"] == report_input.client_name
    assert manifest["authorization_ref"] == report_input.authorization_ref

    # Debe incluir hashes de todos los formatos generados
    assert "format_hashes" in manifest
    assert "markdown" in manifest["format_hashes"]
    assert "pdf" in manifest["format_hashes"] or output.pdf_bytes is None
    assert "sarif" in manifest["format_hashes"]
    assert "navigator" in manifest["format_hashes"]
    assert "json" in manifest["format_hashes"]

    # Todos los hashes deben ser SHA-256 válidos
    for fmt, h in manifest["format_hashes"].items():
        assert len(h) == 64, f"Hash inválido para {fmt}: {h}"


@pytest.mark.asyncio
async def test_reporter_signature_format(reporter: ReporterAgent, report_input: ReportInput):
    """La firma debe ser ed25519:xxx (si hay clave) o sha256:xxx (fallback)."""
    result = await reporter.run(report_input.model_dump())

    assert result.success
    output: ReportOutput = result.output

    sig = output.report_signature_ed25519
    assert sig, "Firma vacía"
    assert sig.startswith("ed25519:") or sig.startswith("sha256:"), f"Firma inválida: {sig[:20]}"


@pytest.mark.asyncio
async def test_reporter_compliance_mapping(reporter: ReporterAgent, report_input: ReportInput):
    """El compliance mapping debe incluir NIST 800-115, PTES y OWASP WSTG."""
    result = await reporter.run(report_input.model_dump())

    assert result.success
    output: ReportOutput = result.output
    cm = output.compliance_mapping

    assert cm is not None
    assert "Discovery" in cm.nist_800_115_phases
    assert "Reporting" in cm.nist_800_115_phases
    assert "Pre-engagement Interactions" in cm.ptes_phases
    assert cm.owasp_wstg_ids, "OWASP WSTG IDs vacío"


@pytest.mark.asyncio
async def test_reporter_empty_kg_handles_gracefully(report_input: ReportInput):
    """Si el KG está vacío, el reporter debe generar un reporte válido sin findings."""
    empty_kg = FakeKnowledgeGraph()

    class _NullClient:
        pass

    agent = ReporterAgent(
        sandbox=_NullClient(),
        gateway=_NullClient(),
        knowledge_graph=empty_kg,
        signing_key_path=None,
    )

    result = await agent.run(report_input.model_dump())

    assert result.success
    output: ReportOutput = result.output
    assert output.total_findings_reported == 0
    assert output.markdown_report
    assert "ACME Corp" in output.markdown_report
    assert output.report_hash_sha256  # manifest generado aunque no haya findings


@pytest.mark.asyncio
async def test_reporter_no_kg_handles_gracefully(report_input: ReportInput):
    """Si no se inyecta KG, el reporter debe generar un reporte vacío válido."""
    class _NullClient:
        pass

    agent = ReporterAgent(
        sandbox=_NullClient(),
        gateway=_NullClient(),
        knowledge_graph=None,
        signing_key_path=None,
    )

    result = await agent.run(report_input.model_dump())

    assert result.success
    output: ReportOutput = result.output
    assert output.total_findings_reported == 0
    assert output.markdown_report  # reporte vacío pero válido
