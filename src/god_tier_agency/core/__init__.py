"""Core del sistema: config, logging, excepciones, seguridad, contexto.

API pública:
    from god_tier_agency.core import (
        settings,
        get_logger, setup_logging,
        CorrelationContext, bind_context,
        GodTierError, SecurityError, ...
    )
"""

from god_tier_agency.config import settings
from god_tier_agency.core.context import (
    CorrelationContext,
    RequestContext,
    bind_context,
    get_context,
)
from god_tier_agency.core.exceptions import (
    AIError,
    BudgetExceededError,
    CanaryLeakDetected,
    ConfigurationError,
    ConsensusError,
    EvidenceError,
    GodTierError,
    PromptInjectionDetected,
    SandboxError,
    SandboxEscapeDetected,
    ScopeViolation,
    SecurityError,
)
from god_tier_agency.core.logging import (
    get_audit_logger,
    get_logger,
    get_security_logger,
    setup_logging,
)

__all__ = [
    "settings",
    "setup_logging",
    "get_logger",
    "get_audit_logger",
    "get_security_logger",
    "CorrelationContext",
    "RequestContext",
    "bind_context",
    "get_context",
    "GodTierError",
    "SecurityError",
    "PromptInjectionDetected",
    "CanaryLeakDetected",
    "ScopeViolation",
    "SandboxError",
    "SandboxEscapeDetected",
    "BudgetExceededError",
    "AIError",
    "ConsensusError",
    "EvidenceError",
    "ConfigurationError",
]
