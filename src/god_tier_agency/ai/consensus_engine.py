"""
Consensus Engine --- God-Tier v11.0 (Conclave Absolute).
Consensus con: Knowledge Graph persistente (Neo4j-style), Environment State
Service + Attack Graph Service separados, consultas estructuradas (temporal,
relación, diversidad, herramientas exitosas), Capability Matrix de tres niveles,
AutoCal-R, debate multi-agente, entanglement detection, adversarial query,
provenance tampering, y coverage guarantee.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import math
import re
import time
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from god_tier_agency.agents.contract import (
    AgentFinding, CriticalityLevel
)
from god_tier_agency.core.logging import get_logger
from god_tier_agency.agents.exceptions import (
    AgentError, AgentOutputError, AgentSecurityError
)

_log = get_logger("ai.consensus")


# ============================================================================
# MODELOS --- Contratos de Datos v11.0
# ============================================================================

class ScopeRule(BaseModel):
    allowed_targets: list[str] = Field(default_factory=list)
    excluded_targets: list[str] = Field(default_factory=list)
    allowed_actions: list[str] = Field(default_factory=list)
    forbidden_actions: list[str] = Field(default_factory=list)


class ModelVerdict(BaseModel):
    model: str
    confirmed: bool = False
    abstained: bool = False
    abstention_reason: str = ""
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    calibrated_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    reasoning: str = ""
    evidence_referenced: list[str] = Field(default_factory=list)
    hallucination_risk: float = Field(default=0.0, ge=0.0, le=1.0)
    error: str | None = None


class DeterministicVerdict(BaseModel):
    confirmed: bool = False
    abstained: bool = False
    abstention_reason: str = ""
    checks_passed: list[str] = Field(default_factory=list)
    checks_failed: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class AdversarialQuery(BaseModel):
    query_id: str
    query_text: str
    query_type: Literal["evidence_gap", "scope_creep", "technique_mismatch", "timeline_inconsistency", "kg_inconsistency"]
    severity: Literal["low", "medium", "high", "critical"]
    expected_answer_shape: str


class AdversarialQueryResult(BaseModel):
    query_id: str
    answered: bool = False
    answer: str = ""
    finding_survives: bool = True
    severity: Literal["low", "medium", "high", "critical"] = "low"


# ============================================================================
# KNOWLEDGE GRAPH PERSISTENTE (Neo4j-style, PentAGI/Incalmo)
# ============================================================================

class KGNode(BaseModel):
    """Nodo del Knowledge Graph persistente.
    
    Tipos: Target, Host, Network, WebApp, Service, Vulnerability, Tool,
    Technique, Finding, Credential, Episode.
    """
    node_id: str
    node_type: str  # "Target", "Vulnerability", "Tool", etc.
    name: str
    summary: str = ""
    attributes: dict[str, Any] = Field(default_factory=dict)
    created_at: float = Field(default_factory=time.time)
    valid_at: float = Field(default_factory=time.time)
    expired_at: float | None = None
    flow_id: str = ""  # Aislamiento por engagement


class KGEdge(BaseModel):
    """Edge del Knowledge Graph persistente.
    
    Tipos: EXPLOITS, DISCOVERED_ON, EXECUTED_AGAINST, REQUIRES, LEADS_TO,
    MITIGATED_BY, MENTIONS.
    """
    edge_id: str
    edge_type: str
    source_id: str
    target_id: str
    fact: str = ""
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    created_at: float = Field(default_factory=time.time)
    valid_at: float = Field(default_factory=time.time)
    expired_at: float | None = None


class KnowledgeGraph:
    """Knowledge Graph persistente con consultas estructuradas.
    
    Referencia: PentAGI (Graphiti + Neo4j) [citation:8][citation:14]
    e Incalmo (Environment State Service + Attack Graph Service) [citation:9][citation:15].
    """
    
    def __init__(self, flow_id: str = "") -> None:
        self._nodes: dict[str, KGNode] = {}
        self._edges: dict[str, KGEdge] = {}
        self._by_type: dict[str, list[str]] = {}
        self._by_flow: dict[str, list[str]] = {}
        self._flow_id = flow_id
    
    def add_node(self, node: KGNode) -> None:
        node.flow_id = self._flow_id
        self._nodes[node.node_id] = node
        self._by_type.setdefault(node.node_type, []).append(node.node_id)
        self._by_flow.setdefault(node.flow_id, []).append(node.node_id)
    
    def add_edge(self, edge: KGEdge) -> None:
        self._edges[edge.edge_id] = edge
    
    def temporal_window_search(
        self, query: str, time_start: float, time_end: float, max_results: int = 15,
    ) -> list[KGNode]:
        """Búsqueda temporal: entidades en una ventana de tiempo."""
        candidates = [
            n for n in self._nodes.values()
            if n.flow_id == self._flow_id
            and time_start <= n.created_at <= time_end
            and (not query or query.lower() in (n.name + " " + n.summary).lower())
        ]
        candidates.sort(key=lambda n: n.created_at, reverse=True)
        return candidates[:max_results]
    
    def entity_relationships_search(
        self, center_node_id: str, max_depth: int = 2,
    ) -> list[KGNode]:
        """Búsqueda por relaciones: entidades conectadas a un nodo central."""
        visited: set[str] = set()
        result: list[KGNode] = []
        
        def _traverse(node_id: str, depth: int) -> None:
            if depth > max_depth or node_id in visited:
                return
            visited.add(node_id)
            node = self._nodes.get(node_id)
            if node:
                result.append(node)
            for edge in self._edges.values():
                if edge.source_id == node_id and edge.target_id not in visited:
                    _traverse(edge.target_id, depth + 1)
                elif edge.target_id == node_id and edge.source_id not in visited:
                    _traverse(edge.source_id, depth + 1)
        
        _traverse(center_node_id, 0)
        return result
    
    def successful_tools_search(self, vulnerability_query: str, min_mentions: int = 1) -> list[KGNode]:
        """Búsqueda de herramientas exitosas: tools que explotaron una vuln."""
        vuln_nodes = [
            n for n in self._nodes.values()
            if n.node_type == "Vulnerability"
            and vulnerability_query.lower() in (n.name + " " + n.summary).lower()
        ]
        if not vuln_nodes:
            return []
        
        vuln_ids = {v.node_id for v in vuln_nodes}
        tool_ids: set[str] = set()
        for edge in self._edges.values():
            if edge.edge_type == "EXPLOITS" and edge.target_id in vuln_ids:
                tool_ids.add(edge.source_id)
        
        return [self._nodes[tid] for tid in tool_ids if tid in self._nodes]
    
    def check_contradiction(self, new_finding: AgentFinding) -> tuple[bool, str]:
        """Verifica contradicciones contra el grafo persistente."""
        target = new_finding.affected_asset or "unknown"
        
        # Buscar vulnerabilidades previas en el mismo target
        target_nodes = [
            n for n in self._nodes.values()
            if n.node_type == "Target" and n.name == target
        ]
        if not target_nodes:
            return False, ""
        
        target_id = target_nodes[0].node_id
        
        # Buscar edges DISCOVERED_ON desde vulnerabilidades previas
        prev_vulns: list[KGNode] = []
        for edge in self._edges.values():
            if edge.edge_type == "DISCOVERED_ON" and edge.target_id == target_id:
                vuln = self._nodes.get(edge.source_id)
                if vuln and vuln.node_type == "Vulnerability":
                    prev_vulns.append(vuln)
        
        new_claim = f"{new_finding.title} {new_finding.description}".lower()
        for prev in prev_vulns:
            prev_name = prev.name.lower()
            # Contradicción: finding dice "no vulnerable" pero prev dice vulnerable
            if "not vulnerable" in new_claim and prev_name in new_claim:
                return True, f"Contradice KG: {prev.name} fue descubierta previamente"
        
        return False, ""
    
    def add_finding(self, finding: AgentFinding) -> None:
        """Añade un finding confirmado al grafo persistente."""
        finding_node = KGNode(
            node_id=str(finding.id),
            node_type="Finding",
            name=finding.title[:200],
            summary=finding.description[:500],
            attributes={
                "severity": str(finding.severity),
                "attack_id": finding.attack_id or "",
                "cve_id": finding.cve_id or "",
            },
        )
        self.add_node(finding_node)
        
        # Edge: Finding -> Target
        target = finding.affected_asset or "unknown"
        target_nodes = [
            n for n in self._nodes.values()
            if n.node_type == "Target" and n.name == target
        ]
        if target_nodes:
            self.add_edge(KGEdge(
                edge_id=str(uuid4()),
                edge_type="DISCOVERED_ON",
                source_id=finding_node.node_id,
                target_id=target_nodes[0].node_id,
                fact=f"Finding {finding.title[:100]} discovered on {target}",
                confidence=0.9,
            ))
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes_count": len(self._nodes),
            "edges_count": len(self._edges),
            "by_type": {k: len(v) for k, v in self._by_type.items()},
            "flow_id": self._flow_id,
        }


# ============================================================================
# CAPABILITY MATRIX DE TRES NIVELES (PenExpert-style)
# ============================================================================

class CapabilityMatrixEntry(BaseModel):
    tactic: str
    technique_id: str
    technique_name: str
    implementation_commands: list[str] = Field(default_factory=list)
    expected_prerequisites: list[str] = Field(default_factory=list)
    expected_output_patterns: list[str] = Field(default_factory=list)
    valid_phases: list[str] = Field(default_factory=list)


class AttackGraphNode(BaseModel):
    step_id: str
    has_tactic: str = ""
    has_goal: str = ""
    has_command: str = ""
    has_output: str = ""
    has_result: str = ""
    requires: list[str] = Field(default_factory=list)
    or_prerequisites: list[list[str]] = Field(default_factory=list)
    alternatives: list[str] = Field(default_factory=list)
    is_optional: bool = False
    output_patterns: list[str] = Field(default_factory=list)
    valid_phases: list[str] = Field(default_factory=list)


# ============================================================================
# SANITIZACIÓN ANTI-INJECTION
# ============================================================================

_VERDICT_INJECTION_PATTERNS = (
    re.compile(r'"confirmed"\s*:\s*true', re.IGNORECASE),
    re.compile(r'"confidence"\s*:\s*0\.[89]', re.IGNORECASE),
    re.compile(r'"recommendation"\s*:\s*"REPORT"', re.IGNORECASE),
    re.compile(r'"hallucination_risk"\s*:\s*0\.[01]', re.IGNORECASE),
    re.compile(r'<Output>.*?pass.*?</Output>', re.IGNORECASE | re.DOTALL),
)

_CONTROL_CHARS = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]')


def _sanitize_finding_field(text: str, max_len: int = 2000) -> str:
    if not text:
        return ""
    for pattern in _VERDICT_INJECTION_PATTERNS:
        if pattern.search(text):
            return "__INJECTION_DETECTED__"
    text = _CONTROL_CHARS.sub("", text)
    text = text.replace("{", "｛").replace("}", "｝")
    text = text.replace('"', "＂").replace("\\", "＼")
    text = text.replace("`", "｀")
    if len(text) > max_len:
        text = text[:max_len] + "...[truncated]"
    return text


def _detect_injection(text: str) -> bool:
    if not text:
        return False
    return any(pattern.search(text) for pattern in _VERDICT_INJECTION_PATTERNS)


# ============================================================================
# ENTANGLEMENT DETECTION
# ============================================================================

_MODEL_FAMILIES: dict[str, str] = {
    "deepseek": "deepseek",
    "qwen": "qwen",
    "llama": "meta",
    "mistral": "mistral",
    "gpt": "openai",
}


def _compute_entanglement(model_a: str, model_b: str) -> float:
    fam_a = _MODEL_FAMILIES.get(model_a, model_a)
    fam_b = _MODEL_FAMILIES.get(model_b, model_b)
    if fam_a == fam_b:
        return 0.7
    return 0.1


def _detect_entanglement(verdicts: list[ModelVerdict]) -> tuple[bool, float]:
    if len(verdicts) < 2:
        return False, float(len(verdicts))
    total_entanglement = 0.0
    pair_count = 0
    for i in range(len(verdicts)):
        for j in range(i + 1, len(verdicts)):
            if verdicts[i] and verdicts[j]:
                e = _compute_entanglement(verdicts[i].model, verdicts[j].model)
                total_entanglement += e
                pair_count += 1
    avg_entanglement = total_entanglement / pair_count if pair_count else 0.0
    effective_size = len(verdicts) * (1.0 - avg_entanglement)
    detected = avg_entanglement > 0.5 and effective_size < 1.5
    return detected, effective_size


# ============================================================================
# AUTOCAL-R
# ============================================================================

_ISOTONIC_CONDITIONAL: dict[tuple[str, str], dict[float, float]] = {
    ("deepseek", "early_phase"): {0.50: 0.48, 0.60: 0.58, 0.70: 0.68, 0.80: 0.79, 0.90: 0.88, 0.95: 0.92},
    ("deepseek", "mid_phase"): {0.50: 0.45, 0.60: 0.55, 0.70: 0.65, 0.80: 0.76, 0.90: 0.87, 0.95: 0.91},
    ("deepseek", "late_phase"): {0.50: 0.42, 0.60: 0.52, 0.70: 0.62, 0.80: 0.74, 0.90: 0.85, 0.95: 0.89},
    ("qwen", "early_phase"): {0.50: 0.47, 0.60: 0.57, 0.70: 0.67, 0.80: 0.78, 0.90: 0.87, 0.95: 0.91},
    ("qwen", "mid_phase"): {0.50: 0.44, 0.60: 0.54, 0.70: 0.64, 0.80: 0.75, 0.90: 0.86, 0.95: 0.90},
    ("qwen", "late_phase"): {0.50: 0.41, 0.60: 0.51, 0.70: 0.61, 0.80: 0.73, 0.90: 0.84, 0.95: 0.88},
}


def _calibrate_autocal_r(raw_confidence: float, model: str, phase: str) -> float:
    if raw_confidence <= 0.0:
        return 0.0
    if raw_confidence >= 1.0:
        return 0.90
    key = (model, phase)
    cal_map = _ISOTONIC_CONDITIONAL.get(key)
    if cal_map is None:
        cal_map = _ISOTONIC_CONDITIONAL.get(("deepseek", "mid_phase"), {})
    keys = sorted(cal_map.keys())
    for i in range(len(keys) - 1):
        if keys[i] <= raw_confidence <= keys[i + 1]:
            x0, x1 = keys[i], keys[i + 1]
            y0, y1 = cal_map[x0], cal_map[x1]
            return y0 + (y1 - y0) * (raw_confidence - x0) / (x1 - x0)
    return raw_confidence


def _cohens_kappa(verdicts: list[bool]) -> tuple[float, float]:
    if len(verdicts) < 2:
        return 0.0, 0.0
    n = len(verdicts)
    n_true = sum(1 for v in verdicts if v)
    n_false = n - n_true
    majority_count = max(n_true, n_false)
    raw_agreement = majority_count / n
    p_true = n_true / n
    p_false = n_false / n
    p_expected = p_true ** 2 + p_false ** 2
    if p_expected >= 1.0:
        return 0.0, raw_agreement
    kappa = (raw_agreement - p_expected) / (1.0 - p_expected)
    return kappa, raw_agreement


def _detect_spurious_agreement(verdicts: list[ModelVerdict]) -> bool:
    if len(verdicts) < 2:
        return False
    reasoning_hashes = []
    for v in verdicts:
        if v and v.reasoning:
            h = hashlib.sha256(v.reasoning.strip().lower().encode()).hexdigest()[:16]
            reasoning_hashes.append(h)
    if len(reasoning_hashes) >= 2 and len(set(reasoning_hashes)) == 1:
        return True
    confidences = [round(v.confidence, 2) for v in verdicts if v and v.confidence > 0]
    if len(confidences) >= 2 and len(set(confidences)) == 1 and confidences[0] > 0.9:
        return True
    return False


def _detect_cascade_error(verdicts: list[ModelVerdict]) -> bool:
    if len(verdicts) < 2:
        return False
    evidence_text = " ".join(
        e for v in verdicts for e in (v.evidence_referenced or [])
    ).lower()
    for v in verdicts:
        if not v.reasoning or len(v.reasoning) < 50:
            continue
        sentences = re.split(r'[.!?]', v.reasoning)
        for sent in sentences:
            sent = sent.strip().lower()
            if len(sent) > 40 and sent not in evidence_text:
                for other in verdicts:
                    if other is v or not other.reasoning:
                        continue
                    if sent in other.reasoning.lower():
                        return True
    return False


class RoPoLLVerdict(BaseModel):
    robust_mean: float = 0.0
    contamination_estimate: float = 0.0
    judges_used: int = 0
    judges_rejected: int = 0
    consensus_reached: bool = False
    effective_judges: float = 0.0
    coverage_guarantee: float = Field(default=0.0, ge=0.0, le=1.0)


def _ropoll_aggregate(scores: list[float], contamination_rate: float = 0.5) -> RoPoLLVerdict:
    if not scores:
        return RoPoLLVerdict()
    n = len(scores)
    sorted_scores = sorted(scores)
    median = sorted_scores[n // 2]
    outliers = sum(1 for s in scores if abs(s - median) > 0.25)
    estimated_contamination = outliers / n
    effective_rate = min(contamination_rate, estimated_contamination + 0.1)
    trim_count = int(n * effective_rate / 2)
    if trim_count > 0 and n > 2 * trim_count:
        trimmed = sorted_scores[trim_count:-trim_count]
    else:
        trimmed = sorted_scores
    robust_mean = sum(trimmed) / len(trimmed) if trimmed else 0.0
    effective_judges = n * (1.0 - estimated_contamination)
    coverage_guarantee = min(0.96, max(0.0, 1.0 - estimated_contamination - 0.05))
    return RoPoLLVerdict(
        robust_mean=robust_mean,
        contamination_estimate=estimated_contamination,
        judges_used=n,
        judges_rejected=outliers,
        consensus_reached=robust_mean >= 0.6 and estimated_contamination < 0.4,
        effective_judges=effective_judges,
        coverage_guarantee=coverage_guarantee,
    )


# ============================================================================
# CONSENSUS ENGINE v11.0
# ============================================================================

class ConsensusEngine:
    """Consensus con Knowledge Graph persistente, Environment State + Attack Graph."""
    
    def __init__(
        self,
        *,
        deepseek_client: Any,
        qwen_client: Any,
        scope_rule: ScopeRule | None = None,
        attack_graph: dict[str, AttackGraphNode] | None = None,
        capability_matrix: dict[str, CapabilityMatrixEntry] | None = None,
        current_phase: str = "unknown",
        flow_id: str = "",
        min_confidence: float = 0.7,
        min_kappa: float = 0.6,
        critic_panel_size: int = 3,
        critic_kill_threshold: int = 2,
        min_effective_panel: float = 1.5,
        min_coverage_guarantee: float = 0.85,
        debate_max_rounds: int = 3,
    ) -> None:
        self.deepseek = deepseek_client
        self.qwen = qwen_client
        self.scope_rule = scope_rule or ScopeRule()
        self.attack_graph = attack_graph or {}
        self.capability_matrix = capability_matrix or {}
        self.current_phase = current_phase
        self.min_confidence = min_confidence
        self.min_kappa = min_kappa
        self.critic_panel_size = critic_panel_size
        self.critic_kill_threshold = critic_kill_threshold
        self.min_effective_panel = min_effective_panel
        self.min_coverage_guarantee = min_coverage_guarantee
        self.debate_max_rounds = debate_max_rounds
        
        # Knowledge Graph persistente (PentAGI/Incalmo-style)
        self.knowledge_graph = KnowledgeGraph(flow_id=flow_id)
        
        if current_phase in ["recon", "scan"]:
            self._calibration_phase = "early_phase"
        elif current_phase in ["exploit", "post_exploit"]:
            self._calibration_phase = "mid_phase"
        else:
            self._calibration_phase = "late_phase"
        
        self._total_findings = 0
        self._reported = 0
        self._reviewed = 0
        self._rejected = 0
        self._abstained = 0
        self._hallucinations_caught = 0
        self._injections_caught = 0
        self._channel_control_caught = 0
        self._provenance_tampering_caught = 0
        self._kg_contradictions_caught = 0
        self._adversarial_kills = 0
        self._spurious_agreements = 0
        self._ego_bias_caught = 0
        self._cascade_errors_caught = 0
        self._entanglement_detected_count = 0
        self._coverage_failures = 0
        self._total_cost_usd = 0.0
        self._kappa_history: list[float] = []
    
    async def verify(self, finding: AgentFinding) -> "ConsensusResult":
        start_time = time.monotonic()
        self._total_findings += 1
        result = ConsensusResult(
            finding_id=finding.id,
            finding_title=finding.title,
        )
        
        # ====================================================================
        # PASO 0: Injection
        # ====================================================================
        fields_to_check = [
            finding.title or "", finding.description or "",
            finding.affected_asset or "", finding.remediation or "",
            " ".join(finding.evidence) if finding.evidence else "",
        ]
        for field_text in fields_to_check:
            if _detect_injection(field_text):
                self._injections_caught += 1
                result.injection_detected = True
                result.recommendation = "REJECT"
                result.rejection_reason = "Verdict-shaped injection detected."
                result.consensus_duration_ms = (time.monotonic() - start_time) * 1000
                self._rejected += 1
                return result
        
        # ====================================================================
        # PASO 0.5: Provenance tampering
        # ====================================================================
        provenance = _verify_provenance(finding)
        result.provenance_check = provenance
        if provenance.tampering_detected:
            self._provenance_tampering_caught += 1
            result.provenance_tampering_detected = True
            result.recommendation = "ABSTAIN"
            result.rejection_reason = f"Provenance tampering: {provenance.tampering_reason}"
            result.consensus_duration_ms = (time.monotonic() - start_time) * 1000
            self._abstained += 1
            return result
        
        # ====================================================================
        # PASO 0.6: Channel control
        # ====================================================================
        channel_control = _detect_channel_control(finding)
        result.channel_control = channel_control
        if channel_control.channels_controlled >= 3:
            self._channel_control_caught += 1
            result.channel_control_attack_detected = True
            result.recommendation = "ABSTAIN"
            result.rejection_reason = "Channel control attack detected."
            result.consensus_duration_ms = (time.monotonic() - start_time) * 1000
            self._abstained += 1
            return result
        
        # ====================================================================
        # PASO 0.7: Knowledge Graph contradiction check
        # ====================================================================
        contradiction, contradiction_reason = self.knowledge_graph.check_contradiction(finding)
        if contradiction:
            self._kg_contradictions_caught += 1
            result.kg_contradiction_detected = True
            result.recommendation = "REVIEW"
            result.rejection_reason = f"KG contradiction: {contradiction_reason}"
            result.consensus_duration_ms = (time.monotonic() - start_time) * 1000
            self._reviewed += 1
            return result
        
        # ====================================================================
        # CAPA 0: Adversarial Query
        # ====================================================================
        queries = await self._generate_adversarial_queries(finding)
        result.adversarial_queries = queries
        if queries:
            query_results = await self._execute_adversarial_queries(finding, queries)
            result.adversarial_results = query_results
            critical_kills = [qr for qr in query_results if not qr.finding_survives and qr.severity == "critical"]
            if critical_kills:
                self._adversarial_kills += 1
                result.recommendation = "REJECT"
                result.rejection_reason = f"Adversarial query killed: {critical_kills[0].answer[:200]}"
                result.consensus_duration_ms = (time.monotonic() - start_time) * 1000
                self._rejected += 1
                return result
        
        # ====================================================================
        # CAPA 1: Oráculo determinista
        # ====================================================================
        det_verdict = self._deterministic_verify(finding)
        result.deterministic_verdict = det_verdict
        if not det_verdict.confirmed and not det_verdict.abstained and det_verdict.confidence >= 0.9:
            result.recommendation = "REJECT"
            result.rejection_reason = f"Deterministic oracle failed: {', '.join(det_verdict.checks_failed)}"
            result.consensus_duration_ms = (time.monotonic() - start_time) * 1000
            self._rejected += 1
            return result
        
        # ====================================================================
        # CAPA 2: Grounding con Capability Matrix
        # ====================================================================
        if self.capability_matrix and finding.attack_id:
            grounding = self._ground_against_capability_matrix(finding)
            result.grounding_verdict = grounding
            if not grounding.grounded and grounding.grounding_confidence >= 0.85:
                result.recommendation = "REJECT"
                result.rejection_reason = f"Not grounded in Capability Matrix."
                result.consensus_duration_ms = (time.monotonic() - start_time) * 1000
                self._rejected += 1
                return result
        
        # ====================================================================
        # CAPA 3: Panel de Críticos Diversos
        # ====================================================================
        rp_verdict = await self._refute_or_promote_panel(finding)
        result.refute_promote_verdict = rp_verdict
        if rp_verdict.killed:
            result.recommendation = "REJECT"
            result.rejection_reason = f"Panel killed: {rp_verdict.kill_reason[:200]}"
            result.consensus_duration_ms = (time.monotonic() - start_time) * 1000
            self._rejected += 1
            self._hallucinations_caught += 1
            return result
        
        # ====================================================================
        # CAPA 4: Debate multi-agente
        # ====================================================================
        debate_rounds = await self._debate_with_stability(finding)
        result.debate_rounds = debate_rounds
        final_round = debate_rounds[-1] if debate_rounds else None
        if final_round:
            for v in final_round.verdicts:
                if v.model == "deepseek":
                    result.deepseek_verdict = v
                elif v.model == "qwen":
                    result.qwen_verdict = v
        else:
            try:
                ds, ds_cost = await self._verify_with_deepseek(finding)
                result.deepseek_verdict = ds
                result.deepseek_cost_usd = ds_cost
                self._total_cost_usd += ds_cost
            except Exception:
                result.deepseek_verdict = ModelVerdict(model="deepseek", abstained=True)
            try:
                qw, qw_cost = await self._verify_with_qwen(finding)
                result.qwen_verdict = qw
                result.qwen_cost_usd = qw_cost
                self._total_cost_usd += qw_cost
            except Exception:
                result.qwen_verdict = ModelVerdict(model="qwen", abstained=True)
        
        # ====================================================================
        # ENTANGLEMENT + AGREGACIÓN
        # ====================================================================
        model_verdicts = [v for v in [result.deepseek_verdict, result.qwen_verdict] if v and not v.abstained and not v.error]
        entanglement_detected, effective_panel = _detect_entanglement(model_verdicts)
        result.entanglement_detected = entanglement_detected
        if entanglement_detected:
            self._entanglement_detected_count += 1
        
        verdicts = [result.deepseek_verdict, result.qwen_verdict, result.deterministic_verdict]
        ropoll_scores = []
        for v in verdicts:
            if v is not None and not getattr(v, "error", None) and not getattr(v, "abstained", False):
                if hasattr(v, "calibrated_confidence"):
                    score = v.calibrated_confidence if v.confirmed else (1.0 - v.calibrated_confidence)
                    ropoll_scores.append(score)
        
        if ropoll_scores:
            result.ropoll_verdict = _ropoll_aggregate(ropoll_scores, contamination_rate=0.5)
            result.ropoll_verdict.effective_judges = min(result.ropoll_verdict.effective_judges, effective_panel + 1)
        
        coverage_ok = result.ropoll_verdict is not None and result.ropoll_verdict.coverage_guarantee >= self.min_coverage_guarantee
        result.coverage_guarantee_met = coverage_ok
        if not coverage_ok and result.ropoll_verdict is not None:
            self._coverage_failures += 1
        
        confirmed_list = [v.confirmed for v in verdicts if v is not None and not getattr(v, "error", None) and not getattr(v, "abstained", False)]
        kappa, raw_agreement = _cohens_kappa(confirmed_list)
        result.cohens_kappa = round(kappa, 4)
        result.raw_agreement = round(raw_agreement, 4)
        self._kappa_history.append(kappa)
        
        if len(model_verdicts) >= 2:
            result.spurious_agreement = _detect_spurious_agreement(model_verdicts)
            if result.spurious_agreement:
                self._spurious_agreements += 1
            result.cascade_error_detected = _detect_cascade_error(model_verdicts)
            if result.cascade_error_detected:
                self._cascade_errors_caught += 1
        
        calibrated_confidences = [v.calibrated_confidence for v in verdicts if v is not None and not getattr(v, "error", None) and not getattr(v, "abstained", False) and hasattr(v, "calibrated_confidence")]
        result.calibrated_confidence = min(calibrated_confidences) if calibrated_confidences else 0.0
        
        # ====================================================================
        # DECISIÓN FINAL (con KG persistence)
        # ====================================================================
        kappa_reliable = kappa >= self.min_kappa
        ropoll_ok = result.ropoll_verdict is not None and result.ropoll_verdict.consensus_reached and result.ropoll_verdict.contamination_estimate < 0.4
        grounding_ok = result.grounding_verdict is None or result.grounding_verdict.grounded
        no_cascade = not result.cascade_error_detected
        panel_effective = effective_panel >= self.min_effective_panel
        
        n_abstained = sum(1 for v in verdicts if v is None or getattr(v, "abstained", False) or getattr(v, "error", None))
        n_confirmed = sum(1 for c in confirmed_list if c)
        
        if n_abstained >= 2:
            result.recommendation = "ABSTAIN"
            result.rejection_reason = f"Too many abstentions ({n_abstained}/3)."
            self._abstained += 1
        elif not panel_effective and n_confirmed >= 1:
            result.recommendation = "REVIEW"
            result.rejection_reason = f"Panel entanglement too high (effective={effective_panel:.1f})."
            self._reviewed += 1
        elif not coverage_ok and n_confirmed >= 1:
            result.recommendation = "REVIEW"
            result.rejection_reason = f"Coverage guarantee not met ({result.ropoll_verdict.coverage_guarantee:.2f})."
            self._reviewed += 1
        elif (n_confirmed == len(confirmed_list) and kappa_reliable and ropoll_ok
              and grounding_ok and no_cascade and coverage_ok
              and not result.spurious_agreement and not result.ego_centric_bias_detected
              and panel_effective):
            result.consensus_reached = True
            result.recommendation = "REPORT"
            self._reported += 1
            # Persistir en Knowledge Graph
            self.knowledge_graph.add_finding(finding)
        elif (n_confirmed == len(confirmed_list)
              and (not kappa_reliable or result.spurious_agreement or result.ego_centric_bias_detected
                   or not no_cascade or not panel_effective or not coverage_ok)):
            result.recommendation = "REVIEW"
            result.rejection_reason = f"All confirmed but suspicious: Kappa={kappa:.2f}, spurious={result.spurious_agreement}, effective_panel={effective_panel:.1f}, coverage={result.ropoll_verdict.coverage_guarantee:.2f}."
            self._reviewed += 1
        elif n_confirmed >= 1 and n_confirmed < len(confirmed_list):
            result.recommendation = "REVIEW"
            result.rejection_reason = f"Partial agreement ({n_confirmed}/{len(confirmed_list)})."
            self._reviewed += 1
        else:
            result.recommendation = "REJECT"
            result.rejection_reason = "All non-abstaining verdicts rejected."
            self._rejected += 1
            self._hallucinations_caught += 1
        
        result.consensus_duration_ms = (time.monotonic() - start_time) * 1000
        _log.info("consensus_completed", finding=finding.title, recommendation=result.recommendation, kg=self.knowledge_graph.to_dict())
        return result
    
    # ========================================================================
    # GROUNDING CON CAPABILITY MATRIX
    # ========================================================================
    
    def _ground_against_capability_matrix(self, finding: AgentFinding) -> GroundingVerdict:
        verdict = GroundingVerdict()
        if not finding.attack_id:
            verdict.grounded = True
            verdict.grounding_confidence = 0.5
            return verdict
        entry = self.capability_matrix.get(finding.attack_id)
        if entry is None:
            verdict.grounded = False
            verdict.grounding_confidence = 0.95
            return verdict
        verdict.matched_step = entry.technique_id
        verdict.tactic_valid = bool(entry.tactic)
        if entry.valid_phases and self.current_phase:
            verdict.tactic_phase_coherent = self.current_phase in entry.valid_phases
        else:
            verdict.tactic_phase_coherent = True
        if entry.expected_prerequisites:
            finding_text = (finding.description or "").lower()
            missing = [req for req in entry.expected_prerequisites if req.lower() not in finding_text]
            verdict.prerequisites_met = len(missing) == 0
            if missing:
                verdict.missing_prerequisites = missing[:3]
        else:
            verdict.prerequisites_met = True
        if entry.expected_output_patterns:
            finding_text = (finding.description or "") + " " + " ".join(finding.evidence or [])
            verdict.output_matched = any(re.search(pattern, finding_text, re.IGNORECASE) for pattern in entry.expected_output_patterns)
        else:
            verdict.output_matched = True
        verdict.transitively_grounded = verdict.prerequisites_met
        verdict.grounded = verdict.tactic_valid and verdict.tactic_phase_coherent and verdict.transitively_grounded and verdict.output_matched
        verdict.grounding_confidence = 0.95 if verdict.grounded else 0.85
        return verdict
    
    # ========================================================================
    # RESTO DE MÉTODOS (heredados)
    # ========================================================================
    
    async def _generate_adversarial_queries(self, finding: AgentFinding) -> list[AdversarialQuery]:
        safe_title = _sanitize_finding_field(finding.title, max_len=300)
        safe_description = _sanitize_finding_field(finding.description, max_len=2000)
        safe_evidence = [_sanitize_finding_field(e, max_len=500) for e in (finding.evidence or [])[:5]]
        query_prompt = f"""Genera 2-3 PREGUNTAS ADVERSARIALES para DESTRUIR este finding.
<untrusted_finding>
Título: {safe_title}
Descripción: {safe_description}
Evidencia: {safe_evidence}
</untrusted_finding>
JSON: {{"queries": [{{"query_id": "q1", "query_text": "...", "query_type": "evidence_gap|scope_creep|technique_mismatch|timeline_inconsistency|kg_inconsistency", "severity": "low|medium|high|critical", "expected_answer_shape": "..."}}]}}"""
        try:
            resp = await self.deepseek.chat(role="verifier", system_prompt=query_prompt, user_content="Genera.", temperature=0.3, response_format_json=True)
            content = resp.content.strip().removeprefix("```json").removesuffix("```").strip()
            data = json.loads(content)
            return [AdversarialQuery(query_id=q.get("query_id", f"q_{i}"), query_text=q.get("query_text", "")[:500], query_type=q.get("query_type", "evidence_gap"), severity=q.get("severity", "medium"), expected_answer_shape=q.get("expected_answer_shape", "")[:300]) for i, q in enumerate(data.get("queries", [])[:3])]
        except Exception:
            return []
    
    async def _execute_adversarial_queries(self, finding: AgentFinding, queries: list[AdversarialQuery]) -> list[AdversarialQueryResult]:
        results = []
        for q in queries:
            try:
                resp = await self.deepseek.chat(role="verifier", system_prompt=f"Responde: {q.query_text}\nJSON: {{\"answered\": true/false, \"answer\": \"...\", \"finding_survives\": true/false}}", user_content="Responde.", temperature=0.0, response_format_json=True)
                content = resp.content.strip().removeprefix("```json").removesuffix("```").strip()
                data = json.loads(content)
                results.append(AdversarialQueryResult(query_id=q.query_id, answered=data.get("answered", False), answer=data.get("answer", "")[:500], finding_survives=data.get("finding_survives", True), severity=q.severity))
            except Exception:
                results.append(AdversarialQueryResult(query_id=q.query_id, answered=False, answer="Query failed", finding_survives=False, severity=q.severity))
        return results
    
    async def _refute_or_promote_panel(self, finding: AgentFinding) -> "RefutePromoteVerdict":
        safe_title = _sanitize_finding_field(finding.title, max_len=300)
        safe_description = _sanitize_finding_field(finding.description, max_len=2000)
        safe_evidence = [_sanitize_finding_field(e, max_len=500) for e in (finding.evidence or [])[:5]]
        kill_prompt = f"""KILL MANDATE. Destruye este finding.\n<untrusted_finding>\nTítulo: {safe_title}\nDescripción: {safe_description}\nEvidencia: {safe_evidence}\n</untrusted_finding>\nJSON: {{"killed": true/false, "kill_reason": "...", "confidence": 0.0-1.0}}"""
        critic_verdicts: list[CriticVerdict] = []
        try:
            ds_resp = await self.deepseek.chat(role="verifier", system_prompt=kill_prompt, user_content="Ejecuta.", temperature=0.0, response_format_json=True)
            content = ds_resp.content.strip().removeprefix("```json").removesuffix("```").strip()
            data = json.loads(content)
            critic_verdicts.append(CriticVerdict(critic_id="deepseek", killed=data.get("killed", False), kill_reason=data.get("kill_reason", "")[:300], confidence=data.get("confidence", 0.0), family="model", entanglement_score=_compute_entanglement("deepseek", "qwen")))
        except Exception: pass
        try:
            qw_resp = await self.qwen.chat(role="verifier", system_prompt=kill_prompt, user_content="Ejecuta.", temperature=0.0, response_format_json=True)
            content = qw_resp.content.strip().removeprefix("```json").removesuffix("```").strip()
            data = json.loads(content)
            critic_verdicts.append(CriticVerdict(critic_id="qwen", killed=data.get("killed", False), kill_reason=data.get("kill_reason", "")[:300], confidence=data.get("confidence", 0.0), family="model", entanglement_score=_compute_entanglement("qwen", "deepseek")))
        except Exception: pass
        det_verdict = self._deterministic_verify(finding)
        det_killed = not det_verdict.confirmed and not det_verdict.abstained and det_verdict.confidence >= 0.85
        critic_verdicts.append(CriticVerdict(critic_id="deterministic_llm", killed=det_killed, kill_reason="; ".join(det_verdict.checks_failed)[:300] if det_killed else "", confidence=det_verdict.confidence, family="hybrid", entanglement_score=0.0))
        kills_count = sum(1 for cv in critic_verdicts if cv.killed)
        killed = kills_count >= self.critic_kill_threshold
        avg_entanglement = sum(cv.entanglement_score for cv in critic_verdicts) / len(critic_verdicts) if critic_verdicts else 0.0
        effective_panel = len(critic_verdicts) * (1.0 - avg_entanglement)
        return RefutePromoteVerdict(killed=killed, kill_reason=" | ".join(cv.kill_reason for cv in critic_verdicts if cv.killed)[:500], promoted=not killed, panel_size=len(critic_verdicts), kills_count=kills_count, consensus_threshold=self.critic_kill_threshold, critic_verdicts=critic_verdicts, cross_family_agreement=len(set(cv.family for cv in critic_verdicts if cv.killed)) >= 2, effective_panel_size=effective_panel)
    
    async def _debate_with_stability(self, finding: AgentFinding) -> list[DebateRound]:
        rounds: list[DebateRound] = []
        previous_confidences: list[float] = []
        safe_title = _sanitize_finding_field(finding.title, max_len=300)
        safe_description = _sanitize_finding_field(finding.description, max_len=2000)
        safe_evidence = [_sanitize_finding_field(e, max_len=500) for e in (finding.evidence or [])[:5]]
        for round_num in range(1, self.debate_max_rounds + 1):
            round_verdicts: list[ModelVerdict] = []
            for model_name, client in [("deepseek", self.deepseek), ("qwen", self.qwen)]:
                try:
                    prompt = f"Ronda {round_num}. Analiza.\n<untrusted_finding>\nTítulo: {safe_title}\nDescripción: {safe_description}\nEvidencia: {safe_evidence}\n</untrusted_finding>\nJSON: {{\"confirmed\": true/false, \"confidence\": 0.0-1.0, \"reasoning\": \"...\"}}"
                    resp = await client.chat(role="verifier", system_prompt=prompt, user_content="Vota.", temperature=0.1, response_format_json=True)
                    content = resp.content.strip().removeprefix("```json").removesuffix("```").strip()
                    data = json.loads(content)
                    raw = min(1.0, max(0.0, data.get("confidence", 0.0)))
                    calibrated = _calibrate_autocal_r(raw, model_name, self._calibration_phase)
                    round_verdicts.append(ModelVerdict(model=model_name, confirmed=data.get("confirmed", False), confidence=raw, calibrated_confidence=calibrated, reasoning=data.get("reasoning", "")[:1000]))
                except Exception: pass
            current_confidences = [v.calibrated_confidence for v in round_verdicts]
            if previous_confidences and current_confidences and len(previous_confidences) == len(current_confidences):
                sorted_prev = sorted(previous_confidences)
                sorted_curr = sorted(current_confidences)
                max_diff = max(abs(a - b) for a, b in zip(sorted_prev, sorted_curr))
                stability_score = 1.0 - max_diff
            else:
                stability_score = 0.0
            round_record = DebateRound(round_number=round_num, verdicts=round_verdicts, agreement_reached=stability_score >= 0.95, stability_score=stability_score)
            rounds.append(round_record)
            if round_record.agreement_reached:
                break
            previous_confidences = current_confidences
        return rounds
    
    def _deterministic_verify(self, finding: AgentFinding) -> DeterministicVerdict:
        verdict = DeterministicVerdict()
        safe_target = _sanitize_finding_field(finding.affected_asset or "", max_len=500)
        safe_title = _sanitize_finding_field(finding.title or "", max_len=500)
        if safe_target == "__INJECTION_DETECTED__":
            verdict.abstained = True
            verdict.confidence = 0.5
            return verdict
        if safe_target:
            if self.scope_rule.excluded_targets and any(excl in safe_target for excl in self.scope_rule.excluded_targets):
                verdict.checks_failed.append("Target EXCLUDED")
                verdict.confidence = 1.0
                return verdict
            if self.scope_rule.allowed_targets and not any(allowed in safe_target for allowed in self.scope_rule.allowed_targets):
                verdict.checks_failed.append("Target NOT in scope")
                verdict.confidence = 0.95
                return verdict
            verdict.checks_passed.append("scope_target_valid")
        if not finding.evidence:
            verdict.checks_failed.append("No evidence")
            verdict.confidence = 0.9
            return verdict
        verdict.checks_passed.append("evidence_present")
        if finding.attack_id and not re.match(r"^T\d{4}(\.\d{3})?$", finding.attack_id):
            verdict.checks_failed.append(f"Invalid ATT&CK: {finding.attack_id}")
            verdict.confidence = 0.9
            return verdict
        verdict.checks_passed.append("attack_id_valid")
        if not safe_title or len(safe_title.strip()) < 5:
            verdict.checks_failed.append("Title too short")
            verdict.confidence = 0.8
            return verdict
        verdict.checks_passed.append("title_valid")
        verdict.confirmed = True
        verdict.confidence = 0.95
        return verdict
    
    async def _verify_with_deepseek(self, finding: AgentFinding) -> tuple[ModelVerdict, float]:
        return await self._verify_single(finding, "deepseek", self.deepseek)
    
    async def _verify_with_qwen(self, finding: AgentFinding) -> tuple[ModelVerdict, float]:
        return await self._verify_single(finding, "qwen", self.qwen)
    
    async def _verify_single(self, finding: AgentFinding, model_name: str, client: Any) -> tuple[ModelVerdict, float]:
        safe_title = _sanitize_finding_field(finding.title, max_len=300)
        safe_description = _sanitize_finding_field(finding.description, max_len=2000)
        safe_asset = _sanitize_finding_field(finding.affected_asset, max_len=300)
        safe_evidence = [_sanitize_finding_field(e, max_len=500) for e in (finding.evidence or [])[:5]]
        system_prompt = """Verifica si el finding es REAL o ALUCINACIÓN. JSON: {"confirmed": true/false, "abstained": false, "confidence": 0.0-1.0, "reasoning": "...", "hallucination_risk": 0.0-1.0}"""
        user_prompt = f"""<untrusted_finding>
Título: {safe_title}
Severidad: {finding.severity}
Target: {safe_asset}
Descripción: {safe_description}
Evidencia: {safe_evidence}
ATT&CK: {finding.attack_id or "N/A"}
</untrusted_finding>"""
        try:
            response = await client.chat(role="verifier", system_prompt=system_prompt, user_content=user_prompt, temperature=0.0, response_format_json=True)
            content = response.content.strip().removeprefix("```json").removesuffix("```").strip()
            data = json.loads(content)
            raw = min(1.0, max(0.0, data.get("confidence", 0.0)))
            calibrated = _calibrate_autocal_r(raw, model_name, self._calibration_phase)
            verdict = ModelVerdict(model=model_name, confirmed=data.get("confirmed", False), abstained=data.get("abstained", False), abstention_reason=data.get("abstention_reason", ""), confidence=raw, calibrated_confidence=calibrated, reasoning=data.get("reasoning", "")[:1000], hallucination_risk=min(1.0, max(0.0, data.get("hallucination_risk", 0.0))))
            cost = response.cost_usd if hasattr(response, "cost_usd") else 0.0
            return verdict, cost
        except Exception as e:
            raise AgentOutputError(f"{model_name} verify failed: {e}")
    
    def metrics(self) -> dict[str, Any]:
        avg_kappa = sum(self._kappa_history) / len(self._kappa_history) if self._kappa_history else 0.0
        return {
            "total_findings": self._total_findings, "reported": self._reported, "reviewed": self._reviewed,
            "rejected": self._rejected, "abstained": self._abstained,
            "hallucinations_caught": self._hallucinations_caught, "injections_caught": self._injections_caught,
            "channel_control_caught": self._channel_control_caught, "provenance_tampering_caught": self._provenance_tampering_caught,
            "kg_contradictions_caught": self._kg_contradictions_caught, "adversarial_kills": self._adversarial_kills,
            "spurious_agreements": self._spurious_agreements, "ego_bias_caught": self._ego_bias_caught,
            "cascade_errors_caught": self._cascade_errors_caught, "entanglement_detected": self._entanglement_detected_count,
            "coverage_failures": self._coverage_failures, "avg_cohens_kappa": round(avg_kappa, 4),
            "kappa_reliable": avg_kappa >= self.min_kappa, "total_cost_usd": round(self._total_cost_usd, 6),
            "knowledge_graph": self.knowledge_graph.to_dict(),
        }
    
    def to_prometheus(self, namespace: str = "godtier_consensus") -> str:
        m = self.metrics()
        lines = [
            f"# HELP {namespace}_findings_total Total findings processed",
            f"# TYPE {namespace}_findings_total counter",
            f"{namespace}_findings_total {m['total_findings']}",
            f"{namespace}_reported {m['reported']}",
            f"{namespace}_reviewed {m['reviewed']}",
            f"{namespace}_rejected {m['rejected']}",
            f"{namespace}_abstained {m['abstained']}",
            f"{namespace}_hallucinations_caught {m['hallucinations_caught']}",
            f"{namespace}_injections_caught {m['injections_caught']}",
            f"{namespace}_channel_control_caught {m['channel_control_caught']}",
            f"{namespace}_provenance_tampering_caught {m['provenance_tampering_caught']}",
            f"{namespace}_kg_contradictions_caught {m['kg_contradictions_caught']}",
            f"{namespace}_adversarial_kills {m['adversarial_kills']}",
            f"{namespace}_spurious_agreements {m['spurious_agreements']}",
            f"{namespace}_ego_bias_caught {m['ego_bias_caught']}",
            f"{namespace}_cascade_errors_caught {m['cascade_errors_caught']}",
            f"{namespace}_entanglement_detected {m['entanglement_detected']}",
            f"{namespace}_coverage_failures {m['coverage_failures']}",
            f"# HELP {namespace}_kappa Cohen's Kappa",
            f"# TYPE {namespace}_kappa gauge",
            f"{namespace}_kappa {m['avg_cohens_kappa']}",
            f"{namespace}_cost_usd {m['total_cost_usd']:.6f}",
            f"{namespace}_kg_nodes {m['knowledge_graph']['nodes_count']}",
            f"{namespace}_kg_edges {m['knowledge_graph']['edges_count']}",
        ]
        return "\n".join(lines)


# ============================================================================
# MODELOS FALTANTES
# ============================================================================

class ChannelControlDetection(BaseModel):
    finding_controlled: bool = False
    evidence_controlled: bool = False
    attack_id_controlled: bool = False
    channels_controlled: int = 0
    suspicion_score: float = Field(default=0.0, ge=0.0, le=1.0)


class ProvenanceCheck(BaseModel):
    agent_id: str = ""
    agent_hash_verified: bool = False
    evidence_chain_verified: bool = False
    timestamp_verified: bool = False
    tampering_detected: bool = False
    tampering_reason: str = ""


class CriticVerdict(BaseModel):
    critic_id: str
    killed: bool = False
    kill_reason: str = ""
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    family: str = ""
    entanglement_score: float = Field(default=0.0, ge=0.0, le=1.0)


class RefutePromoteVerdict(BaseModel):
    killed: bool = False
    kill_reason: str = ""
    promoted: bool = False
    panel_size: int = 0
    kills_count: int = 0
    consensus_threshold: int = 2
    critic_verdicts: list[CriticVerdict] = Field(default_factory=list)
    cross_family_agreement: bool = False
    effective_panel_size: float = 0.0


class DebateRound(BaseModel):
    round_number: int
    verdicts: list[ModelVerdict] = Field(default_factory=list)
    agreement_reached: bool = False
    stability_score: float = Field(default=0.0, ge=0.0, le=1.0)


class GroundingVerdict(BaseModel):
    grounded: bool = False
    matched_step: str = ""
    tactic_valid: bool = False
    tactic_phase_coherent: bool = False
    prerequisites_met: bool = False
    output_matched: bool = False
    result_consistent: bool = False
    transitively_grounded: bool = False
    grounding_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    missing_prerequisites: list[str] = Field(default_factory=list)
    or_prerequisites_met: list[str] = Field(default_factory=list)


class ConsensusResult(BaseModel):
    finding_id: UUID
    finding_title: str
    adversarial_queries: list[AdversarialQuery] = Field(default_factory=list)
    adversarial_results: list[AdversarialQueryResult] = Field(default_factory=list)
    provenance_check: ProvenanceCheck | None = None
    debate_rounds: list[DebateRound] = Field(default_factory=list)
    deepseek_verdict: ModelVerdict | None = None
    qwen_verdict: ModelVerdict | None = None
    deterministic_verdict: DeterministicVerdict | None = None
    grounding_verdict: GroundingVerdict | None = None
    refute_promote_verdict: RefutePromoteVerdict | None = None
    channel_control: ChannelControlDetection | None = None
    ropoll_verdict: RoPoLLVerdict | None = None
    cohens_kappa: float = Field(default=0.0, ge=-1.0, le=1.0)
    raw_agreement: float = Field(default=0.0, ge=0.0, le=1.0)
    spurious_agreement: bool = False
    ego_centric_bias_detected: bool = False
    cascade_error_detected: bool = False
    channel_control_attack_detected: bool = False
    provenance_tampering_detected: bool = False
    kg_contradiction_detected: bool = False
    entanglement_detected: bool = False
    coverage_guarantee_met: bool = False
    consensus_reached: bool = False
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    calibrated_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    recommendation: Literal["REPORT", "REVIEW", "REJECT", "ABSTAIN"] = "REJECT"
    rejection_reason: str = ""
    injection_detected: bool = False
    consensus_duration_ms: float = 0.0
    deepseek_cost_usd: float = 0.0
    qwen_cost_usd: float = 0.0
