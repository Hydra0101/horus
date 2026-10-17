"""Evidence con integridad criptográfica y soporte binario."""

import base64
import hashlib
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

from pydantic import Field, field_serializer, model_validator

from god_tier_agency.models.base import GodTierBaseModel
from god_tier_agency.models.enums import EvidenceType


class Evidence(GodTierBaseModel):
    """Evidencia con integridad criptográfica."""

    schema_version: str = Field(default="1.0", frozen=True)

    id: UUID = Field(default_factory=uuid4)
    type: EvidenceType
    content: str = Field(...)
    content_encoding: str = Field(
        default="utf-8",
        pattern="^(utf-8|base64|hex)$",
    )
    content_mime: str | None = None

    sha256: str = Field(
        default="",
        pattern="^[a-f0-9]{64}$|^$",
    )
    signature: str | None = None
    rfc3161_token: str | None = None

    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    operator_id: str = Field(..., min_length=1)
    chain_of_custody: list[dict[str, Any]] = Field(default_factory=list)

    @model_validator(mode="after")
    def compute_sha256_if_missing(self) -> "Evidence":
        if not self.sha256:
            if self.content_encoding == "base64":
                raw = base64.b64decode(self.content)
            elif self.content_encoding == "hex":
                raw = bytes.fromhex(self.content)
            else:
                raw = self.content.encode("utf-8")
            self.sha256 = hashlib.sha256(raw).hexdigest()
        return self

    @field_serializer("timestamp")
    def serialize_timestamp(self, dt: datetime) -> str:
        return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
