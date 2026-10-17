"""Operator con RBAC y MFA obligatorio para roles admin."""

from datetime import datetime, timezone
from uuid import UUID, uuid4

from pydantic import Field, field_validator

from god_tier_agency.models.base import GodTierBaseModel
from god_tier_agency.models.enums import Role


class Operator(GodTierBaseModel):
    """Un operador del sistema con rol RBAC."""

    schema_version: str = Field(default="1.0", frozen=True)

    id: UUID = Field(default_factory=uuid4)
    username: str = Field(..., min_length=3, max_length=64)
    email: str = Field(..., min_length=5, max_length=254)
    full_name: str = Field(default="", max_length=128)
    role: Role = Field(default=Role.OPERATOR)

    mfa_enabled: bool = False
    pgp_fingerprint: str | None = None

    active: bool = True
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    last_login_at: datetime | None = None

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        import re
        if not re.match(r"^[a-z0-9_.-]+$", v):
            raise ValueError(
                "Username solo permite [a-z0-9_.-]"
            )
        return v.lower()

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        import re
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", v):
            raise ValueError(f"Email inválido: {v!r}")
        return v.lower()
