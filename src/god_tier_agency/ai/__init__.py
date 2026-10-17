"""Capa de IA — Clientes LLM con fallback, cost tracking y resilience.

Arquitectura:
    - base: AIClient abstracto + ChatRequest/Response + capabilities
    - _resilience: ResponseCache + CircuitBreaker (DRY, thread-safe)
    - deepseek: Cliente DeepSeek (OpenAI-compatible)
    - qwen: Cliente Qwen (DashScope)
    - gateway: AIGateway único con fallback + cost tracking

Uso:
    >>> from god_tier_agency.ai import AIGateway, ChatRequest, ChatMessage, MessageRole
    >>> gateway = AIGateway(max_cost=10.0)
    >>> response = await gateway.call(
    ...     role="planner",
    ...     request=ChatRequest(
    ...         system="Eres un planificador...",
    ...         messages=[ChatMessage(role=MessageRole.USER, content="...")],
    ...     ),
    ... )

Excepciones:
    >>> from god_tier_agency.ai import (
    ...     AIError,                    # base
    ...     AIRateLimitError,           # retryable
    ...     AITimeoutError,             # retryable
    ...     AIProviderDownError,        # retryable
    ...     AIContextLengthError,       # NO retryable (bug del caller)
    ...     AIInvalidResponseError,     # NO retryable (bug del provider)
    ... )
"""

__version__ = "0.1.0"

# ============================================================================
# Base — contrato, request/response, enums
# ============================================================================
from god_tier_agency.ai.base import (
    AIClient,
    AIContextLengthError,
    AIInvalidResponseError,
    AIProviderDownError,
    AIRateLimitError,
    AITimeoutError,
    ChatMessage,
    ChatRequest,
    FinishReason,
    LLMResponse,
    MessageRole,
    ModelCapabilities,
)

# ============================================================================
# Resilience — cache + circuit breaker (DRY)
# ============================================================================
from god_tier_agency.ai._resilience import (
    CacheEntry,
    CacheStats,
    CircuitBreaker,
    CircuitStatus,
    ResponseCache,
)

# ============================================================================
# Clientes — implementaciones concretas de AIClient
# ============================================================================
from god_tier_agency.ai.deepseek import DeepSeekClient
from god_tier_agency.ai.qwen import QwenClient

# ============================================================================
# Gateway — punto único de integración
# ============================================================================
from god_tier_agency.ai.gateway import (
    AIGateway,
    CostRecord,
    CostTracker,
    Provider,
    Role,
)

# ============================================================================
# Excepciones base (re-exportadas desde core)
# ============================================================================
from god_tier_agency.core.exceptions import AIError, BudgetExceededError

# ============================================================================
# API pública
# ============================================================================
__all__ = [
    # Versión
    "__version__",
    # --- Base ---
    "AIClient",
    "ChatMessage",
    "ChatRequest",
    "LLMResponse",
    "MessageRole",
    "FinishReason",
    "ModelCapabilities",
    # --- Excepciones específicas ---
    "AIError",
    "AIRateLimitError",
    "AITimeoutError",
    "AIContextLengthError",
    "AIProviderDownError",
    "AIInvalidResponseError",
    "BudgetExceededError",
    # --- Resilience ---
    "ResponseCache",
    "CacheEntry",
    "CacheStats",
    "CircuitBreaker",
    "CircuitStatus",
    # --- Clientes ---
    "DeepSeekClient",
    "QwenClient",
    # --- Gateway ---
    "AIGateway",
    "CostTracker",
    "CostRecord",
    "Role",
    "Provider",
]
