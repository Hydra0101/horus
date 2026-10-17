"""Enumeraciones tipadas del sistema."""

from enum import Enum


class Severity(str, Enum):
    """Severidad cualitativa, alineada con CVSS qualitative rating."""

    CRITICAL = "critical"  # CVSS 9.0-10.0
    HIGH = "high"          # CVSS 7.0-8.9
    MEDIUM = "medium"      # CVSS 4.0-6.9
    LOW = "low"            # CVSS 0.1-3.9
    INFO = "info"          # CVSS 0.0


class TargetType(str, Enum):
    """Tipo de objetivo dentro del scope."""

    DOMAIN = "domain"
    IP = "ip"
    CIDR = "cidr"
    URL = "url"
    CLOUD_ACCOUNT = "cloud_account"
    REPOSITORY = "repository"
    MOBILE_APP = "mobile_app"
    API_ENDPOINT = "api_endpoint"


class EvidenceType(str, Enum):
    """Tipo de evidencia recolectada."""

    SCREENSHOT = "screenshot"
    HTTP_REQUEST = "http_request"
    HTTP_RESPONSE = "http_response"
    COMMAND_OUTPUT = "command_output"
    FILE = "file"
    MEMORY_DUMP = "memory_dump"
    NETWORK_CAPTURE = "network_capture"
    LOG_EXCERPT = "log_excerpt"


class FindingStatus(str, Enum):
    """Estado de un hallazgo en el ciclo de vida."""

    DRAFT = "draft"
    PENDING_VERIFICATION = "pending_verification"
    VERIFIED = "verified"
    FALSE_POSITIVE = "false_positive"
    REMEDIATED = "remediated"
    ACCEPTED_RISK = "accepted_risk"


class EngagementStatus(str, Enum):
    """Estado de un engagement."""

    PLANNING = "planning"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    ABORTED = "aborted"


class EngagementMode(str, Enum):
    """Modo de ejercicio respecto a visibilidad del blue team."""

    COLLABORATIVE = "collaborative"
    SEMI_BLIND = "semi_blind"
    BLIND = "blind"


class Role(str, Enum):
    """Rol de un operador en el sistema (RBAC)."""

    ADMIN = "admin"
    LEAD = "lead"
    OPERATOR = "operator"
    VIEWER = "viewer"
    AUDITOR = "auditor"
