"""AttackStep y AttackChain — modelan cadenas de ataque end-to-end."""

from datetime import datetime, timezone
from uuid import UUID, uuid4

from pydantic import Field, field_validator

from god_tier_agency.models.base import GodTierBaseModel
from god_tier_agency.models.validators import validate_attack_id


class AttackStep(GodTierBaseModel):
    """Un paso individual dentro de una cadena de ataque."""

    schema_version: str = Field(default="1.0", frozen=True)

    id: UUID = Field(default_factory=uuid4)
    technique_id: str | None = None
    description: str = Field(..., min_length=1, max_length=2000)
    command: str | None = Field(None, max_length=10_000)
    output: str | None = Field(None, max_length=50_000)
    success: bool = False
    detected_by_blue: bool | None = None
    detection_latency_seconds: int | None = Field(None, ge=0)
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    @field_validator("technique_id")
    @classmethod
    def validate_technique(cls, v: str | None) -> str | None:
        if v is None:
            return None
        return validate_attack_id(v)


class AttackChain(GodTierBaseModel):
    """Cadena completa de ataque desde entry point hasta crown jewel."""

    schema_version: str = Field(default="1.0", frozen=True)

    id: UUID = Field(default_factory=uuid4)
    engagement_id: UUID
    name: str = Field(..., min_length=1, max_length=256)
    steps: list[AttackStep] = Field(default_factory=list)
    entry_point: str = Field(..., min_length=1)
    crown_jewel: str = Field(..., min_length=1)
    success: bool = False
    detected_by_blue: bool | None = None
    total_detection_latency_seconds: int | None = Field(None, ge=0)
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
