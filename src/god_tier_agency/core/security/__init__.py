"""Seguridad multi-capa God-Tier — API pública.

9 capas de defensa:
    1. Validación de tipo y longitud
    2. Circuit breaker por engagement
    3. Rate limiting por source
    4. Scoring multi-señal (0.0 a 1.0)
    5. Canary tokens dinámicos
    6. Normalización Unicode + multi-decoding recursivo
    7. Detección multi-capa (regex sobre normalized + decoded)
    8. AST analysis de código Python
    9. Envoltura en delimitadores + instrucción de seguridad

Uso típico:
    >>> from god_tier_agency.core.security import sanitize_for_llm, validate_command
    >>> sanitized = sanitize_for_llm(untrusted_text, source="nmap")
    >>> is_valid, reason = validate_command(poc_code)

Módulos:
    - patterns: regex multi-idioma + canary tokens
    - normalization: NFKC + NFC + zero-width + homoglifos + multi-decoding
    - ast_analysis: análisis de código Python
    - telemetry: scoring + rate limiting + eventos forenses
    - sanitizer: API pública de alto nivel
"""

# --- AST analysis ---
from god_tier_agency.core.security.ast_analysis import ast_analyze_python

# --- Normalización + decoding ---
from god_tier_agency.core.security.normalization import (
    decode_variants,
    normalize_text,
    try_decode_layers,
)

# --- Patterns + canary ---
from god_tier_agency.core.security.patterns import (
    CANARY_TOKENS,
    HOMOGLYPH_MAP,
    INJECTION_PATTERNS,
    ZERO_WIDTH_CHARS,
    generate_canary,
)

# --- Sanitizer (API principal) ---
from god_tier_agency.core.security.sanitizer import (
    MAX_COMMAND_LENGTH,
    MAX_INPUT_LENGTH,
    detect_canary_leak,
    detect_prompt_injection,
    get_circuit_breaker_status,
    is_safe_for_llm,
    reset_circuit_breaker,
    sanitize_for_llm,
    validate_command,
)

# --- Telemetría ---
from god_tier_agency.core.security.telemetry import (
    TELEMETRY,
    InjectionScore,
    SecurityEvent,
    SecurityTelemetry,
    score_injection_risk,
)

__all__ = [
    # Patterns
    "INJECTION_PATTERNS",
    "CANARY_TOKENS",
    "ZERO_WIDTH_CHARS",
    "HOMOGLYPH_MAP",
    "generate_canary",
    # Normalization
    "normalize_text",
    "try_decode_layers",
    "decode_variants",
    # AST
    "ast_analyze_python",
    # Telemetry
    "InjectionScore",
    "SecurityEvent",
    "SecurityTelemetry",
    "TELEMETRY",
    "score_injection_risk",
    # Sanitizer (API principal)
    "sanitize_for_llm",
    "validate_command",
    "detect_prompt_injection",
    "detect_canary_leak",
    "is_safe_for_llm",
    "reset_circuit_breaker",
    "get_circuit_breaker_status",
    "MAX_INPUT_LENGTH",
    "MAX_COMMAND_LENGTH",
]
