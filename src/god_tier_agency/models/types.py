"""NewTypes para IDs fuertemente tipados."""

from typing import NewType
from uuid import UUID

TargetId = NewType("TargetId", UUID)
FindingId = NewType("FindingId", UUID)
EvidenceId = NewType("EvidenceId", UUID)
OperatorId = NewType("OperatorId", str)
ScopeId = NewType("ScopeId", UUID)
AttackStepId = NewType("AttackStepId", UUID)
AttackChainId = NewType("AttackChainId", UUID)
EngagementId = NewType("EngagementId", UUID)
