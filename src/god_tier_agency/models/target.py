"""Target con validación específica por tipo."""

from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

from pydantic import Field, field_validator, model_validator

from god_tier_agency.models.base import GodTierBaseModel
from god_tier_agency.models.enums import TargetType
from god_tier_agency.models.validators import (
    validate_cidr,
    validate_domain,
    validate_ip,
    validate_no_shell_injection,
    validate_url,
)


class Target(GodTierBaseModel):
    """Un objetivo dentro del scope autorizado."""

    schema_version: str = Field(default="1.0", frozen=True)

    id: UUID = Field(default_factory=uuid4)
    type: TargetType
    value: str = Field(..., min_length=1, max_length=512)
    scope: str = Field(
        default="in_scope",
        pattern="^(in_scope|out_of_scope)$",
    )
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    @model_validator(mode="after")
    def validate_value_matches_type(self) -> "Target":
        """Valida value contra el formato esperado según type.

        Usa mode='after' para tener acceso al type.
        NO asigna self.value (evita recursión). Solo valida y retorna.
        """
        v = self.value
        t = self.type

        # Bloqueo universal de shell injection
        validate_no_shell_injection(v)

        # Validación específica por tipo (lanza ValueError si falla)
        if t == TargetType.DOMAIN:
            validate_domain(v)
        elif t == TargetType.IP:
            validate_ip(v)
        elif t == TargetType.CIDR:
            validate_cidr(v)
        elif t in (TargetType.URL, TargetType.API_ENDPOINT):
            validate_url(v)
        # cloud_account, repository, mobile_app: validación delegada

        return self
