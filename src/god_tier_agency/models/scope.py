"""Entidad Scope — define el perímetro autorizado de un engagement."""

from datetime import datetime, timezone
from uuid import UUID, uuid4

from pydantic import Field

from god_tier_agency.models.base import GodTierBaseModel


class Scope(GodTierBaseModel):
    """Perímetro autorizado de un engagement."""

    schema_version: str = Field(default="1.0", frozen=True)

    id: UUID = Field(default_factory=uuid4)
    engagement_id: UUID

    legal_contact: str = Field(..., min_length=3)
    emergency_contact: str = Field(..., min_length=3)

    start_date: datetime
    end_date: datetime | None = None
    timezone: str = Field(default="UTC")

    allowed_actions: list[str] = Field(default_factory=list)
    forbidden_actions: list[str] = Field(default_factory=list)

    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
