"""Validadores reutilizables de formato."""

import ipaddress
import re
from urllib.parse import urlparse

_DOMAIN_REGEX = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}\.?$"
)

_CVSS31_REGEX = re.compile(
    r"^CVSS:3\.[01]/"
    r"AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/"
    r"C:[HLN]/I:[HLN]/A:[HLN]$"
)
_CVSS40_REGEX = re.compile(
    r"^CVSS:4\.0/"
    r"AV:[NALP]/AC:[LH]/AT:[NP]/PR:[NLH]/UI:[NPA]/"
    r"VC:[HLN]/VI:[HLN]/VA:[HLN]/"
    r"SC:[HLN]/SI:[HLN]/SA:[HLN]"
    r"(/.*)?$"
)

_ATTACK_ID_REGEX = re.compile(r"^T\d{4}(\.\d{3})?$")


def validate_domain(value: str) -> str:
    if not _DOMAIN_REGEX.match(value):
        raise ValueError(
            f"Dominio inválido: {value!r}. "
            "Debe cumplir RFC 1035 (ej: 'example.com')"
        )
    return value.lower().rstrip(".")


def validate_ip(value: str) -> str:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError as e:
        raise ValueError(f"IP inválida: {value!r}. {e}") from e
    return str(ip)


def validate_cidr(value: str) -> str:
    try:
        net = ipaddress.ip_network(value, strict=False)
    except ValueError as e:
        raise ValueError(f"CIDR inválido: {value!r}. {e}") from e
    return str(net)


def validate_url(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(
            f"URL debe usar http o https, no {parsed.scheme!r}: {value!r}"
        )
    if not parsed.netloc:
        raise ValueError(f"URL sin host: {value!r}")
    return value


def validate_cvss_vector(value: str) -> str:
    if _CVSS31_REGEX.match(value) or _CVSS40_REGEX.match(value):
        return value
    raise ValueError(
        f"CVSS vector inválido: {value!r}. "
        "Debe ser CVSS:3.1/... o CVSS:4.0/..."
    )


def validate_attack_id(value: str) -> str:
    if not _ATTACK_ID_REGEX.match(value):
        raise ValueError(
            f"MITRE ATT&CK ID inválido: {value!r}. Formato: T1234 o T1234.567"
        )
    return value


def validate_no_shell_injection(value: str) -> str:
    forbidden = [";", "|", "&", "$", "`", "\n", "\r", ">", "<"]
    for char in forbidden:
        if char in value:
            raise ValueError(
                f"Carácter prohibido {char!r} detectado (posible shell injection)"
            )
    return value.strip()
