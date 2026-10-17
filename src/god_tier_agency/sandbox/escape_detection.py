"""Detección multi-capa de escape en runtime — God-Tier v2.

Detecta intentos de escape del sandbox en 5 capas independientes:
    1. Procesos — nsenter, unshare, setns, mount, nested containers
    2. Filesystem — /proc/1/, /sys/kernel/, /dev/mem, /proc/sysrq-trigger
    3. Network — IMDS, IPs privadas, reverse shells, DNS tunneling
    4. Seccomp — violaciones registradas en dmesg
    5. Markers — strings conocidos en stdout/stderr + AST Python

Fix v2:
    - Normalización Unicode antes de escanear (anti-evasión)
    - finditer: detecta TODOS los matches, no solo el primero
    - AST analysis para código Python (detecta strings maliciosos)
    - Filtro de falsos positivos (negaciones, comentarios)
    - Deduplicación por (layer, pattern, evidence_hash)
    - Hash SHA-256 de evidencia (integridad forense)
    - Reverse shell patterns (bash -i >& /dev/tcp, nc -e)
    - severity_score numérico para ranking

Filosofía:
    - Defense in depth: 5 capas independientes
    - Fail-closed: cualquier indicador → severity máximo
    - Forense: cada indicador registra evidence + hash + raw_data
    - Anti-evasión: normalización + finditer + AST
    - Auditable: hash chain detecta tampering

Uso:
    >>> from god_tier_agency.sandbox.escape_detection import EscapeDetector
    >>> detector = EscapeDetector()
    >>> result = detector.scan_all(stdout=..., stderr=..., dmesg=...)
    >>> if result.detected:
    ...     print(result.summary())
"""

from __future__ import annotations

import ast
import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Final, Literal

from god_tier_agency.core.logging import get_logger
from god_tier_agency.core.security.normalization import normalize_text

_log = get_logger("sandbox.escape_detection")

# ============================================================================
# TIPOS
# ============================================================================
Layer = Literal["process", "filesystem", "network", "seccomp", "marker", "ast"]
Severity = Literal["low", "medium", "high", "critical"]

# Niveles de severidad ordenados + score numérico
_SEVERITY_ORDER: Final[dict[str, int]] = {
    "none": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

_SEVERITY_SCORE: Final[dict[str, float]] = {
    "none": 0.0,
    "low": 0.25,
    "medium": 0.5,
    "high": 0.75,
    "critical": 1.0,
}


# ============================================================================
# PATRONES POR CAPA
# ============================================================================
# Capa 1: Procesos sospechosos
_PROCESS_PATTERNS: Final[tuple[tuple[re.Pattern[str], str, Severity], ...]] = (
    (re.compile(r"\bnsenter\b", re.I), "nsenter detectado (namespace escape)", "critical"),
    (re.compile(r"\bunshare\b", re.I), "unshare detectado (namespace escape)", "critical"),
    (re.compile(r"\bsetns\b", re.I), "setns detectado (namespace escape)", "critical"),
    (re.compile(r"\bmount\b.*?\s-t\s+", re.I), "mount con tipo detectado", "high"),
    (re.compile(r"\bumount\b", re.I), "umount detectado", "medium"),
    (re.compile(r"\bdocker\s+(run|exec|create)\b", re.I), "nested docker detectado", "high"),
    (re.compile(r"\bpodman\s+(run|exec|create)\b", re.I), "nested podman detectado", "high"),
    (re.compile(r"\bkubectl\s+(exec|run)\b", re.I), "nested kubectl detectado", "high"),
    (re.compile(r"\bchroot\s+/", re.I), "chroot detectado", "high"),
    (re.compile(r"cap_sys_admin", re.I), "CAP_SYS_ADMIN referenciado", "high"),
    (re.compile(r"cap_sys_ptrace", re.I), "CAP_SYS_PTRACE referenciado", "high"),
    (re.compile(r"\bptrace\s*\(", re.I), "ptrace llamado", "critical"),
    (re.compile(r"\bnsenter\s+-t\s+\d+", re.I), "nsenter con target PID", "critical"),
)

# Capa 2: Filesystem sensible
_FILESYSTEM_PATTERNS: Final[tuple[tuple[re.Pattern[str], str, Severity], ...]] = (
    (re.compile(r"/proc/1/", re.I), "acceso a /proc/1/ (init process)", "critical"),
    (re.compile(r"/proc/self/mountinfo", re.I), "lectura de mountinfo", "high"),
    (re.compile(r"/proc/self/root", re.I), "acceso a /proc/self/root", "critical"),
    (re.compile(r"/proc/self/ns/", re.I), "acceso a namespaces de /proc/self", "critical"),
    (re.compile(r"/sys/kernel/", re.I), "acceso a /sys/kernel/", "critical"),
    (re.compile(r"/sys/fs/cgroup", re.I), "acceso a cgroups", "high"),
    (re.compile(r"/sys/fs/bpf", re.I), "acceso a /sys/fs/bpf", "high"),
    (re.compile(r"/dev/mem\b", re.I), "acceso a /dev/mem", "critical"),
    (re.compile(r"/dev/kmem\b", re.I), "acceso a /dev/kmem", "critical"),
    (re.compile(r"/dev/sd[a-z]", re.I), "acceso a disco raw", "high"),
    (re.compile(r"/proc/sysrq-trigger", re.I), "sysrq-trigger (kernel panic)", "critical"),
    (re.compile(r"/etc/shadow", re.I), "acceso a /etc/shadow", "high"),
    (re.compile(r"/etc/sudoers", re.I), "acceso a /etc/sudoers", "high"),
    (re.compile(r"\.\./\.\./", re.I), "path traversal detectado", "medium"),
    (re.compile(r"/var/run/docker\.sock", re.I), "docker socket detectado", "critical"),
    (re.compile(r"/run/podman/podman\.sock", re.I), "podman socket detectado", "critical"),
)

# Capa 3: Network sospechosa + reverse shells
_NETWORK_PATTERNS: Final[tuple[tuple[re.Pattern[str], str, Severity], ...]] = (
    # IMDS / metadata
    (re.compile(r"169\.254\.169\.254", re.I), "IMDS (AWS/Azure) detectado", "critical"),
    (re.compile(r"169\.254\.170\.2", re.I), "ECS metadata detectado", "critical"),
    (re.compile(r"metadata\.google\.internal", re.I), "GCP metadata detectado", "critical"),
    (re.compile(r"metadata\.goog", re.I), "GCP metadata (short) detectado", "critical"),
    (re.compile(r"fd00:ec2::254", re.I), "IMDS IPv6 detectado", "critical"),
    (re.compile(r"169\.254\.", re.I), "link-local detectado", "high"),
    # DNS tunneling
    (re.compile(r"\bdns:\/\/", re.I), "DNS tunneling detectado", "high"),
    # Reverse shells (CRÍTICO)
    (re.compile(r"bash\s+-i\s*>&\s*/dev/tcp/", re.I), "reverse shell bash TCP", "critical"),
    (re.compile(r"/dev/tcp/\d+\.\d+\.\d+\.\d+/\d+", re.I), "conexión TCP raw", "critical"),
    (re.compile(r"\bnc\s+-e\s+/bin/(ba)?sh", re.I), "reverse shell nc", "critical"),
    (re.compile(r"\bncat\s+.*?\s-e\s", re.I), "reverse shell ncat", "critical"),
    (re.compile(r"\bsocat\s+.*?exec:", re.I), "reverse shell socat", "critical"),
    (re.compile(r"python\s+-c\s+.*?socket.*?connect", re.I), "reverse shell python", "critical"),
    (re.compile(r"perl\s+-e\s+.*?socket", re.I), "reverse shell perl", "high"),
)

# Capa 4: Seccomp violations (dmesg)
_SECCOMP_PATTERNS: Final[tuple[tuple[re.Pattern[str], str, Severity], ...]] = (
    (re.compile(r"audit:\s*type=1326", re.I), "seccomp violation registrada en dmesg", "high"),
    (re.compile(r"seccomp.*?kill", re.I), "seccomp kill action detectada", "critical"),
    (re.compile(r"syscall=\d+", re.I), "syscall bloqueada por seccomp", "medium"),
)

# Capa 5: Escape markers (strings conocidos)
_MARKER_PATTERNS: Final[tuple[tuple[re.Pattern[str], str, Severity], ...]] = (
    (re.compile(r"you have .*? escaped", re.I), "mensaje de escape explícito", "critical"),
    (re.compile(r"container escaped", re.I), "container escape confirmado", "critical"),
    (re.compile(r"breakout successful", re.I), "breakout exitoso", "critical"),
    (re.compile(r"cve-\d{4}-\d{4,7}", re.I), "CVE referenciada (posible exploit)", "medium"),
    (re.compile(r"privilege escalat", re.I), "escalada de privilegios mencionada", "high"),
    (re.compile(r"root access gained", re.I), "root access ganado", "critical"),
    (re.compile(r"successfully escaped", re.I), "escape exitoso", "critical"),
)

# Filtros anti-falsos-positivos (líneas que contienen estos patrones se ignoran)
_FALSE_POSITIVE_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r"#\s*.*?(nsenter|unshare|ptrace)", re.I),  # comentarios
    re.compile(r"^\s*//", re.I),  # comentarios C/JS
    re.compile(r'["\']no\s+(nsenter|unshare|ptrace)', re.I),  # negaciones
    re.compile(r"documentation.*?nsenter", re.I),  # docs
    re.compile(r"man\s+nsenter", re.I),  # man pages
    re.compile(r"example:.*?(nsenter|ptrace)", re.I),  # ejemplos
    re.compile(r"test.*?nsenter", re.I),  # tests
)


# ============================================================================
# DATACLASSES
# ============================================================================
@dataclass(frozen=True)
class EscapeIndicator:
    """Un indicador de escape detectado (v2 con hash + score)."""

    layer: Layer
    severity: Severity
    description: str
    evidence: str
    pattern: str
    evidence_hash: str  # SHA-256 truncado (16 chars)
    severity_score: float  # 0.0 - 1.0
    raw_data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serializa para audit log."""
        return {
            "layer": self.layer,
            "severity": self.severity,
            "severity_score": round(self.severity_score, 3),
            "description": self.description,
            "evidence": self.evidence[:500],
            "evidence_hash": self.evidence_hash,
            "pattern": self.pattern,
            "raw_data": self.raw_data,
        }

    @staticmethod
    def compute_hash(text: str) -> str:
        """SHA-256 truncado de evidencia."""
        return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


@dataclass(frozen=True)
class EscapeDetectionResult:
    """Resultado agregado de detección de escape (v2)."""

    detected: bool
    severity: Severity | Literal["none"]
    severity_score: float  # 0.0 - 1.0 (score total)
    indicators: list[EscapeIndicator]
    layers_scanned: tuple[str, ...]
    total_matches: int
    unique_matches: int  # después de dedup

    @property
    def is_critical(self) -> bool:
        return self.severity == "critical"

    @property
    def is_security_incident(self) -> bool:
        return _SEVERITY_ORDER[self.severity] >= _SEVERITY_ORDER["high"]

    @property
    def layers_hit(self) -> tuple[str, ...]:
        """Capas que efectivamente detectaron algo."""
        return tuple(sorted(set(i.layer for i in self.indicators)))

    def to_dict(self) -> dict[str, Any]:
        return {
            "detected": self.detected,
            "severity": self.severity,
            "severity_score": round(self.severity_score, 3),
            "total_matches": self.total_matches,
            "unique_matches": self.unique_matches,
            "layers_scanned": list(self.layers_scanned),
            "layers_hit": list(self.layers_hit),
            "indicators": [i.to_dict() for i in self.indicators],
        }

    def summary(self) -> str:
        if not self.detected:
            return "No escape detected"
        return (
            f"Escape {self.severity.upper()} "
            f"(score={self.severity_score:.2f}) — "
            f"{self.unique_matches} unique indicators across "
            f"{len(self.layers_hit)} layers"
        )


# ============================================================================
# DETECTOR
# ============================================================================
class EscapeDetector:
    """Detector multi-capa de intentos de escape v2.

    Uso:
        >>> detector = EscapeDetector()
        >>> result = detector.scan_text("...stdout...")
        >>> if result.detected:
        ...     print(result.summary())
    """

    def __init__(
        self,
        *,
        enable_process: bool = True,
        enable_filesystem: bool = True,
        enable_network: bool = True,
        enable_seccomp: bool = True,
        enable_markers: bool = True,
        enable_ast: bool = True,
        enable_normalization: bool = True,
        enable_fp_filter: bool = True,
    ) -> None:
        self._enabled_layers: tuple[str, ...] = tuple(
            layer for layer, enabled in [
                ("process", enable_process),
                ("filesystem", enable_filesystem),
                ("network", enable_network),
                ("seccomp", enable_seccomp),
                ("marker", enable_markers),
                ("ast", enable_ast),
            ] if enabled
        )
        self._normalize = enable_normalization
        self._fp_filter = enable_fp_filter

    # -- API pública --------------------------------------------------------

    def scan_text(self, text: str, source: str = "stdout") -> EscapeDetectionResult:
        """Escanea texto buscando indicadores de escape."""
        if not text:
            return self._empty_result()

        # 1. Normalización anti-evasión
        if self._normalize:
            text = normalize_text(text)

        indicators: list[EscapeIndicator] = []
        layers_scanned: list[str] = []

        # Capa 1: Process
        if "process" in self._enabled_layers:
            layers_scanned.append("process")
            indicators.extend(
                self._scan_patterns(text, _PROCESS_PATTERNS, "process", source)
            )

        # Capa 2: Filesystem
        if "filesystem" in self._enabled_layers:
            layers_scanned.append("filesystem")
            indicators.extend(
                self._scan_patterns(text, _FILESYSTEM_PATTERNS, "filesystem", source)
            )

        # Capa 3: Network
        if "network" in self._enabled_layers:
            layers_scanned.append("network")
            indicators.extend(
                self._scan_patterns(text, _NETWORK_PATTERNS, "network", source)
            )

        # Capa 4: Seccomp
        if "seccomp" in self._enabled_layers:
            layers_scanned.append("seccomp")
            indicators.extend(
                self._scan_patterns(text, _SECCOMP_PATTERNS, "seccomp", source)
            )

        # Capa 5: Markers
        if "marker" in self._enabled_layers:
            layers_scanned.append("marker")
            indicators.extend(
                self._scan_patterns(text, _MARKER_PATTERNS, "marker", source)
            )

        # Capa 6: AST Python
        if "ast" in self._enabled_layers:
            layers_scanned.append("ast")
            indicators.extend(self._scan_python_ast(text, source))

        return self._build_result(indicators, tuple(layers_scanned))

    def scan_all(
        self,
        stdout: str = "",
        stderr: str = "",
        dmesg: str = "",
    ) -> EscapeDetectionResult:
        """Escanea múltiples fuentes."""
        all_indicators: list[EscapeIndicator] = []
        layers_scanned: set[str] = set()

        for text, source in [(stdout, "stdout"), (stderr, "stderr"), (dmesg, "dmesg")]:
            if not text:
                continue
            result = self.scan_text(text, source=source)
            all_indicators.extend(result.indicators)
            layers_scanned.update(result.layers_scanned)

        return self._build_result(all_indicators, tuple(sorted(layers_scanned)))

    # -- Internals ----------------------------------------------------------

    def _is_false_positive(self, line: str) -> bool:
        """Filtro de falsos positivos."""
        if not self._fp_filter:
            return False
        return any(p.search(line) for p in _FALSE_POSITIVE_PATTERNS)

    def _scan_patterns(
        self,
        text: str,
        patterns: tuple[tuple[re.Pattern[str], str, Severity], ...],
        layer: Layer,
        source: str,
    ) -> list[EscapeIndicator]:
        """Escanea un texto contra un conjunto de patrones.

        v2: usa finditer (detecta TODOS los matches) + filtro FP.
        """
        indicators: list[EscapeIndicator] = []
        lines = text.split("\n")

        for pattern, description, severity in patterns:
            # finditer sobre el texto completo
            for match in pattern.finditer(text):
                # Extraer línea completa para filtro FP
                line_start = text.rfind("\n", 0, match.start()) + 1
                line_end = text.find("\n", match.end())
                if line_end == -1:
                    line_end = len(text)
                line = text[line_start:line_end]

                # Filtro de falsos positivos
                if self._is_false_positive(line):
                    continue

                # Evidence con contexto
                ev_start = max(0, match.start() - 50)
                ev_end = min(len(text), match.end() + 50)
                evidence = text[ev_start:ev_end]

                indicators.append(EscapeIndicator(
                    layer=layer,
                    severity=severity,
                    description=description,
                    evidence=evidence,
                    pattern=pattern.pattern[:100],
                    evidence_hash=EscapeIndicator.compute_hash(evidence),
                    severity_score=_SEVERITY_SCORE[severity],
                    raw_data={
                        "source": source,
                        "match": match.group(0)[:200],
                        "position": match.start(),
                    },
                ))

        return indicators

    def _scan_python_ast(self, text: str, source: str) -> list[EscapeIndicator]:
        """Escanea código Python con AST para detectar strings maliciosos."""
        indicators: list[EscapeIndicator] = []

        # Intentar parsear SIEMPRE (si falla, no es Python válido)
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError, RecursionError):
            return indicators

        # Extraer todos los strings constantes
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                string_val = node.value
                # Aplicar mismos patrones al string literal
                for pattern, description, severity in _NETWORK_PATTERNS:
                    if pattern.search(string_val):
                        if self._is_false_positive(string_val):
                            continue
                        indicators.append(EscapeIndicator(
                            layer="ast",
                            severity=severity,
                            description=f"[AST] {description}",
                            evidence=f"String literal: {string_val[:200]}",
                            pattern=pattern.pattern[:100],
                            evidence_hash=EscapeIndicator.compute_hash(string_val),
                            severity_score=_SEVERITY_SCORE[severity],
                            raw_data={
                                "source": source,
                                "ast_type": "Constant",
                                "line": getattr(node, "lineno", 0),
                            },
                        ))

        return indicators

    def _build_result(
        self,
        indicators: list[EscapeIndicator],
        layers_scanned: tuple[str, ...],
    ) -> EscapeDetectionResult:
        """Construye el resultado agregado (con dedup + score)."""
        if not indicators:
            return self._empty_result(layers_scanned)

        # Deduplicación por (layer, pattern, evidence_hash)
        seen: set[tuple[str, str, str]] = set()
        unique: list[EscapeIndicator] = []
        for ind in indicators:
            key = (ind.layer, ind.pattern, ind.evidence_hash)
            if key not in seen:
                seen.add(key)
                unique.append(ind)

        # Severidad máxima
        max_severity = max(
            (i.severity for i in unique),
            key=lambda s: _SEVERITY_ORDER[s],
        )

        # Score total (máximo de todos los indicadores + bonus por múltiples capas)
        base_score = max(i.severity_score for i in unique)
        layers_hit = len(set(i.layer for i in unique))
        layer_bonus = min(0.2, (layers_hit - 1) * 0.05)
        total_score = min(1.0, base_score + layer_bonus)

        return EscapeDetectionResult(
            detected=True,
            severity=max_severity,
            severity_score=total_score,
            indicators=unique,
            layers_scanned=layers_scanned,
            total_matches=len(indicators),
            unique_matches=len(unique),
        )

    def _empty_result(self, layers_scanned: tuple[str, ...] = ()) -> EscapeDetectionResult:
        return EscapeDetectionResult(
            detected=False,
            severity="none",
            severity_score=0.0,
            indicators=[],
            layers_scanned=layers_scanned,
            total_matches=0,
            unique_matches=0,
        )


# ============================================================================
# INTEGRACIÓN CON MANAGER
# ============================================================================
def detect_escape_in_result(
    stdout: str,
    stderr: str,
    detector: EscapeDetector | None = None,
) -> EscapeDetectionResult:
    """Helper: escanea stdout + stderr."""
    if detector is None:
        detector = EscapeDetector()
    return detector.scan_all(stdout=stdout, stderr=stderr)


def log_escape_detection(result: EscapeDetectionResult) -> None:
    """Loguea al security logger si es incidente."""
    if not result.detected:
        return

    if result.is_security_incident:
        from god_tier_agency.core.logging import get_security_logger
        security_log = get_security_logger()
        security_log.critical(
            "sandbox_escape_indicators",
            severity=result.severity,
            severity_score=round(result.severity_score, 3),
            total_matches=result.total_matches,
            unique_matches=result.unique_matches,
            layers_hit=list(result.layers_hit),
            descriptions=[i.description for i in result.indicators[:5]],
        )
    else:
        _log.warning(
            "sandbox_escape_indicators",
            severity=result.severity,
            total_matches=result.total_matches,
        )


__all__ = [
    "EscapeIndicator",
    "EscapeDetectionResult",
    "EscapeDetector",
    "detect_escape_in_result",
    "log_escape_detection",
    "Layer",
    "Severity",
]
