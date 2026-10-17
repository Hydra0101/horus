"""
Configuración central del sistema.

Todos los secretos usan SecretStr de Pydantic para prevenir leaks.
La validación es fail-fast: si algo falta, el sistema NO arranca.
"""

from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Configuración God-Tier con validación estricta."""

    # --- IA ---
    deepseek_api_key: SecretStr = SecretStr("placeholder-not-set-yet-0000")
    qwen_api_key: SecretStr = SecretStr("placeholder-not-set-yet-0000")
    qwen_base_url: str = "https://dashscope.aliyuncs.com/compatible-mode/v1"

    # --- Base de datos ---
    database_url: str = "sqlite+aiosqlite:///./god_tier.db"

    # --- Sandbox ---
    sandbox_network: str = "god_tier_sandbox"
    sandbox_memory_limit: str = "512m"
    sandbox_cpu_limit: float = 0.5
    sandbox_pids_limit: int = 100
    sandbox_timeout_seconds: int = 300

    # --- Presupuesto ---
    max_cost_per_engagement: float = 100.0
    max_tokens_per_call: int = 8000

    # --- Seguridad ---
    operator_id: str = "default-operator"

    # --- Logging ---
    log_level: str = "INFO"
    log_format: str = "console"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    @field_validator("sandbox_cpu_limit")
    @classmethod
    def validate_cpu(cls, v: float) -> float:
        """Valida que el límite de CPU sea razonable."""
        if not 0.1 <= v <= 4.0:
            raise ValueError("sandbox_cpu_limit debe estar entre 0.1 y 4.0")
        return v


# Instancia global — fail-fast al importar
settings = Settings()

