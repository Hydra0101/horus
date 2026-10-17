"""Engagement — contenedor raíz del sistema con validación cross-field."""

from datetime import datetime, timezone
from uuid import UUID, uuid4

from pydantic import Field, model_validator

from god_tier_agency.models.base import GodTierBaseModel
from god_tier_agency.models.enums import (
    EngagementMode,
    EngagementStatus,
)
from god_tier_agency.models.finding import Finding
from god_tier_agency.models.target import Target


class Engagement(GodTierBaseModel):
    """Un engagement completo de red teaming."""

    schema_version: str = Field(default="1.0", frozen=True)

    id: UUID = Field(default_factory=uuid4)
    client_name: str = Field(..., min_length=1, max_length=128)
    authorization_ref: str = Field(..., min_length=1, max_length=256)

    start_date: datetime
    end_date: datetime | None = None

    targets: list[Target] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)

    status: EngagementStatus = Field(default=EngagementStatus.PLANNING)
    mode: EngagementMode = Field(default=EngagementMode.SEMI_BLIND)

    operator_ids: list[str] = Field(default_factory=list)
    crown_jewels: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)

    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    @model_validator(mode="after")
    def validate_dates(self) -> "Engagement":
        if self.end_date is not None and self.end_date < self.start_date:
            raise ValueError(
                "end_date debe ser posterior a start_date"
            )
        return self
