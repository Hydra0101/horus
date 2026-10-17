"""Finding con validación CVSS + MITRE ATT&CK + consensus result."""

from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

from pydantic import Field, computed_field, field_validator

from god_tier_agency.models.base import GodTierBaseModel
from god_tier_agency.models.enums import FindingStatus, Severity
from god_tier_agency.models.evidence import Evidence
from god_tier_agency.models.validators import (
    validate_attack_id,
    validate_cvss_vector,
)


class Finding(GodTierBaseModel):
    """Un hallazgo de seguridad verificado."""

    schema_version: str = Field(default="1.0", frozen=True)

    id: UUID = Field(default_factory=uuid4)
    target_id: UUID
    title: str = Field(..., min_length=1, max_length=256)
    severity: Severity
    status: FindingStatus = Field(default=FindingStatus.DRAFT)

    cvss_vector: str | None = None
    cvss_score: float | None = Field(None, ge=0.0, le=10.0)
    attack_id: str | None = None

    description: str = Field(default="", max_length=10_000)
    remediation: str | None = Field(None, max_length=5_000)
    references: list[str] = Field(default_factory=list)

    evidence: list[Evidence] = Field(default_factory=list)
    poc: str | None = Field(None, max_length=50_000)

    verified: bool = False
    consensus_result: dict[str, Any] | None = None

    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    @field_validator("cvss_vector")
    @classmethod
    def validate_cvss(cls, v: str | None) -> str | None:
        if v is None:
            return None
        return validate_cvss_vector(v)

    @field_validator("attack_id")
    @classmethod
    def validate_attack(cls, v: str | None) -> str | None:
        if v is None:
            return None
        return validate_attack_id(v)

    @computed_field
    @property
    def is_critical(self) -> bool:
        return self.severity == Severity.CRITICAL or (
            self.cvss_score is not None and self.cvss_score >= 9.0
        )

    @computed_field
    @property
    def is_open(self) -> bool:
        return self.status not in (
            FindingStatus.REMEDIATED,
            FindingStatus.FALSE_POSITIVE,
            FindingStatus.ACCEPTED_RISK,
        )
