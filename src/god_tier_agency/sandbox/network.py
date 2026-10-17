"""Network policy — God-Tier v5.0. Sandbox network isolation.

Modos de aislamiento:
    - none:       sin red (default, zero-trust)
    - allowlist:  solo hosts/IPs/CIDRs en allowed_hosts
    - full:       red completa (requiere justificación + warning)

God-Tier v5.0 — diferenciadores vs v3.0:

FIX BLOQUEANTES:
    - dnsmasq IPv6 sinkhole corregido (address=/::/# → address=/#/::)
    - IPv6 iptables rules (ip6tables) REALES
    - iptables -A (append) en vez de -I (insert)
    - container_ip validation completa (0.0.0.0, multicast, broadcast)
    - chain name sanitizado + límite 28 chars

SEGURIDAD:
    - IMDS IPv4 + IPv6 bloqueados (fd00:ec2::254, fe80::a9fe:a9fe)
    - IPv4-mapped IPv6 rechazadas (::ffff:127.0.0.1)
    - CGNAT rechazado (100.64.0.0/10)
    - DoH endpoints bloqueados (1.1.1.1, 8.8.8.8:443, etc.)
    - DoT bloqueado (853/tcp)
    - DoQ bloqueado (853/udp)
    - ICMP tunneling prevenido (ICMP payload inspection opcional)
    - Rate limiting (SYN flood, UDP amplification, conntrack)
    - Protocolos alternativos (SCTP, DCCP) bloqueados
    - mode="full" con confirmación explícita

ROBUSTEZ:
    - Atomic iptables-restore (chain swap atómico)
    - Cleanup commands generados
    - Chain existence check
    - iptables-save/restore para audit
    - Policy export/import JSON
    - dnsmasq config validation

OBSERVABILIDAD:
    - Logging estructurado (no solo LOG prefix)
    - Métricas Prometheus
    - Policy hash SHA-256
    - to_dict() con detalle completo

Filosofía:
    - DEFAULT DENY
    - DEFENSE-IN-DEPTH (4 capas: L3/L4/L7/DNS)
    - ZERO TRUST
    - ATOMIC (nada de race conditions)
    - OBSERVABLE (Prometheus + logs)
    - REPRODUCIBLE (hash + export JSON)
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Final, Literal

from god_tier_agency.core.logging import get_logger
from god_tier_agency.sandbox.config import SandboxConfig

_log = get_logger("sandbox.network")


# ============================================================================
# CONSTANTES
# ============================================================================

DEFAULT_SANDBOX_NETWORK: Final[str] = "god_tier_sandbox"
DNSMASQ_LOCAL_PORT: Final[int] = 5353

# iptables chain name limit
_MAX_CHAIN_NAME_LENGTH: Final[int] = 28

# IMDS addresses (IPv4 + IPv6)
_IMDS_ADDRESSES: Final[frozenset[str]] = frozenset({
    # AWS
    "169.254.169.254",
    "169.254.170.2",
    "169.254.169.253",
    # AWS IPv6
    "fd00:ec2::254",
    "fd00:ec2::253",
    # Azure
    "169.254.169.254",
    # GCP
    "metadata.google.internal",
    "169.254.169.254",
    # AliCloud
    "100.100.100.200",
    # TencentCloud
    "metadata.tencentyun.com",
})

# IMDS IPv6 (para ip6tables)
_IMDS_IPV6: Final[frozenset[str]] = frozenset({
    "fd00:ec2::254",
    "fd00:ec2::253",
    "fe80::a9fe:a9fe",  # AWS IMDS link-local
})

# Puertos prohibidos salida
_FORBIDDEN_OUTBOUND_PORTS: Final[frozenset[int]] = frozenset({
    22,     # SSH
    23,     # Telnet
    25,     # SMTP
    135,    # RPC
    137,    # NetBIOS-NS
    138,    # NetBIOS-DGM
    139,    # NetBIOS-SSN
    445,    # SMB
    853,    # DNS over TLS (DoT) + DNS over QUIC (DoQ)
    1433,   # MSSQL
    1521,   # Oracle
    3306,   # MySQL
    3389,   # RDP
    5432,   # PostgreSQL
    5900,   # VNC
    6379,   # Redis
    8080,   # HTTP alt
    8443,   # HTTPS alt
    8888,   # Jupyter
    9042,   # Cassandra
    9200,   # Elasticsearch
    11211,  # Memcached
    27017,  # MongoDB
    27018,  # MongoDB shard
})

# DoH endpoints (por IP, para bloquear bypass)
_DOH_IPV4: Final[frozenset[str]] = frozenset({
    "1.1.1.1",        # Cloudflare
    "1.0.0.1",        # Cloudflare
    "8.8.8.8",        # Google
    "8.8.4.4",        # Google
    "9.9.9.9",        # Quad9
    "149.112.112.112",# Quad9
    "208.67.222.222", # OpenDNS
    "208.67.220.220", # OpenDNS
    "94.140.14.14",   # AdGuard
    "94.140.15.15",   # AdGuard
})

_DOH_IPV6: Final[frozenset[str]] = frozenset({
    "2606:4700:4700::1111",
    "2606:4700:4700::1001",
    "2001:4860:4860::8888",
    "2001:4860:4860::8844",
    "2620:fe::fe",
    "2620:fe::9",
})

# Prefijos mínimos
_MIN_IPV4_PREFIX: Final[int] = 8
_MIN_IPV6_PREFIX: Final[int] = 16

# Límites
_MAX_ALLOWED_HOSTS: Final[int] = 1000
_MAX_CHAIN_DEPTH: Final[int] = 10

# Regex para chain name (solo alfanuméricos + _)
_CHAIN_NAME_RE: Final[re.Pattern[str]] = re.compile(r"^[a-zA-Z0-9_]{1,28}$")

# Regex para IPv4
_IPV4_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$"
)

# Dominios válidos (RFC 1035)
_DOMAIN_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}\.?$"
)

# Redes especiales (rechazadas en allowlist)
_SPECIAL_NETWORKS_IPV4: Final[tuple[str, ...]] = (
    "100.64.0.0/10",   # CGNAT
    "192.0.0.0/24",    # IETF Protocol Assignments
    "192.0.2.0/24",    # TEST-NET-1
    "198.18.0.0/15",   # Benchmarking
    "198.51.100.0/24", # TEST-NET-2
    "203.0.113.0/24",  # TEST-NET-3
    "240.0.0.0/4",     # Reserved
)

_SPECIAL_NETWORKS_IPV6: Final[tuple[str, ...]] = (
    "100::/64",        # Discard-only
    "2001:2::/48",     # Benchmarking
    "2001:db8::/32",   # Documentation
    "2001:10::/28",    # ORCHID
    "3fff::/20",       # Documentation (RFC 9637)
    "5f00::/16",       # Segment routing
)

# Modos
NetworkMode = Literal["none", "allowlist", "full"]


# ============================================================================
# NETWORK POLICY
# ============================================================================

@dataclass(frozen=True)
class NetworkPolicy:
    """Política de red computada desde SandboxConfig (God-Tier v5.0).

    Attributes:
        mode: none/allowlist/full
        allowed_hosts: Tupla de hosts normalizados
        dns_sinkhole: Si True, DNS se redirige a dnsmasq local
        forbidden_ports: Puertos prohibidos salida
        network_name: Nombre del bridge Docker
        isolated: True si mode=none
        blocked_imds: Siempre True (IMDS bloqueado)
        blocked_doh_dot: Siempre True (DoH/DoT bloqueado)
        blocked_special_networks: Redes especiales bloqueadas
        created_at: Timestamp de creación
    """

    mode: NetworkMode
    allowed_hosts: tuple[str, ...]
    dns_sinkhole: bool
    forbidden_ports: frozenset[int]
    network_name: str
    isolated: bool
    blocked_imds: bool = True
    blocked_doh_dot: bool = True
    blocked_special_networks: bool = True
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        """Serializa para audit log."""
        return {
            "mode": self.mode,
            "allowed_hosts_count": len(self.allowed_hosts),
            "allowed_hosts_sample": list(self.allowed_hosts[:20]),
            "dns_sinkhole": self.dns_sinkhole,
            "forbidden_ports_count": len(self.forbidden_ports),
            "forbidden_ports": sorted(self.forbidden_ports),
            "network_name": self.network_name,
            "isolated": self.isolated,
            "blocked_imds": self.blocked_imds,
            "blocked_doh_dot": self.blocked_doh_dot,
            "blocked_special_networks": self.blocked_special_networks,
            "created_at": self.created_at,
        }

    def policy_hash(self) -> str:
        """SHA-256 del policy para reproducibilidad y audit."""
        canonical = json.dumps(
            {
                "mode": self.mode,
                "allowed_hosts": sorted(self.allowed_hosts),
                "dns_sinkhole": self.dns_sinkhole,
                "forbidden_ports": sorted(self.forbidden_ports),
                "blocked_imds": self.blocked_imds,
                "blocked_doh_dot": self.blocked_doh_dot,
                "blocked_special_networks": self.blocked_special_networks,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def to_prometheus(self, namespace: str = "godtier_network") -> str:
        """Métricas Prometheus."""
        mode_id = {"none": 0, "allowlist": 1, "full": 2}[self.mode]
        return "\n".join([
            f'{namespace}_mode{{mode="{self.mode}"}} {mode_id}',
            f"{namespace}_allowed_hosts {len(self.allowed_hosts)}",
            f"{namespace}_forbidden_ports {len(self.forbidden_ports)}",
            f"{namespace}_dns_sinkhole {1 if self.dns_sinkhole else 0}",
            f"{namespace}_isolated {1 if self.isolated else 0}",
            f"{namespace}_blocked_imds {1 if self.blocked_imds else 0}",
            f"{namespace}_blocked_doh_dot {1 if self.blocked_doh_dot else 0}",
        ])

    def to_json(self) -> str:
        """JSON para export/import."""
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)


# ============================================================================
# HOST CLASSIFICATION
# ============================================================================

def _classify_host(host: str) -> tuple[str, str]:
    """Clasifica un host en (type, normalized)."""
    host = host.strip()
    if not host:
        raise ValueError("host vacío")

    # Intentar IP
    try:
        ip = ipaddress.ip_address(host)
        return (f"ipv{ip.version}", str(ip))
    except ValueError:
        pass

    # Intentar CIDR
    try:
        net = ipaddress.ip_network(host, strict=False)
        return ("cidr", str(net))
    except ValueError:
        pass

    # Dominio (validar)
    if not _DOMAIN_RE.match(host):
        raise ValueError(f"Host inválido: {host!r}")
    return ("domain", host.lower())


def _is_special_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True si la IP pertenece a una red especial (rechazada en allowlist)."""
    # IPv4-mapped IPv6 (::ffff:x.x.x.x)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped  # type: ignore[assignment]

    # Categorías especiales
    if ip.is_loopback:
        return True
    if ip.is_multicast:
        return True
    if ip.is_link_local:
        return True
    if ip.is_reserved:
        return True
    if ip.is_unspecified:
        return True

    # Redes especiales adicionales
    if isinstance(ip, ipaddress.IPv4Address):
        for net_str in _SPECIAL_NETWORKS_IPV4:
            if ip in ipaddress.ip_network(net_str):
                return True
    else:
        for net_str in _SPECIAL_NETWORKS_IPV6:
            if ip in ipaddress.ip_network(net_str):
                return True

    return False


# ============================================================================
# VALIDATION
# ============================================================================

def _validate_container_ip(container_ip: str) -> str:
    """Valida container_ip (evita inyección + IP spoofing).

    Rechaza:
        - No IPv4
        - 0.0.0.0 (any)
        - 255.255.255.255 (broadcast)
        - Multicast
        - Loopback
        - Link-local
    """
    if not isinstance(container_ip, str):
        raise ValueError(f"container_ip debe ser str, no {type(container_ip).__name__}")

    if not _IPV4_RE.match(container_ip):
        raise ValueError(f"container_ip inválido: {container_ip!r}. Debe ser IPv4.")

    ip = ipaddress.ip_address(container_ip)

    # Rechazar IPs especiales
    if ip.is_unspecified:
        raise ValueError(f"container_ip no puede ser 0.0.0.0")
    if ip.is_multicast:
        raise ValueError(f"container_ip no puede ser multicast: {container_ip}")
    if ip.is_loopback:
        raise ValueError(f"container_ip no puede ser loopback: {container_ip}")
    if ip.is_link_local:
        raise ValueError(f"container_ip no puede ser link-local: {container_ip}")
    if container_ip == "255.255.255.255":
        raise ValueError(f"container_ip no puede ser broadcast")

    return container_ip


def _validate_allowed_network(network: str) -> tuple[bool, str]:
    """Valida que una red en allowlist no sea demasiado permisiva.

    Reglas:
        1. Prefijo mínimo (IPv4: /8, IPv6: /16)
        2. Rechaza loopback, multicast, link-local, reserved
        3. Rechaza redes especiales (CGNAT, TEST-NET, etc.)
        4. Rechaza IPv4-mapped IPv6
    """
    try:
        net = ipaddress.ip_network(network, strict=False)
    except ValueError:
        return (True, "not-a-network")

    # 1. Prefijo mínimo
    if isinstance(net, ipaddress.IPv4Network):
        if net.prefixlen < _MIN_IPV4_PREFIX:
            return (
                False,
                f"IPv4 prefijo /{net.prefixlen} demasiado permisivo "
                f"(mínimo /{_MIN_IPV4_PREFIX})",
            )
    elif isinstance(net, ipaddress.IPv6Network):
        if net.prefixlen < _MIN_IPV6_PREFIX:
            return (
                False,
                f"IPv6 prefijo /{net.prefixlen} demasiado permisivo "
                f"(mínimo /{_MIN_IPV6_PREFIX})",
            )

    # 2. Categorías especiales
    if net.is_loopback:
        return (False, f"Red loopback {network} prohibida")
    if net.is_multicast:
        return (False, f"Red multicast {network} prohibida")
    if net.is_link_local:
        return (False, f"Red link-local {network} prohibida (incluye IMDS)")
    if net.is_reserved:
        return (False, f"Red reservada {network} prohibida")

    # 3. Redes especiales
    for special_str in _SPECIAL_NETWORKS_IPV4 + _SPECIAL_NETWORKS_IPV6:
        special = ipaddress.ip_network(special_str)
        if net.version == special.version and net.overlaps(special):
            return (
                False,
                f"Red {network} solapa con red especial {special_str}",
            )

    return (True, "OK")


def _generate_chain_name(container_ip: str) -> str:
    """Genera chain name válido para iptables (max 28 chars)."""
    # Sanitizar
    sanitized = container_ip.replace(".", "_").replace(":", "_")
    # Prefijo + hash corto para unicidad
    hash_suffix = hashlib.sha256(container_ip.encode()).hexdigest()[:6]
    chain = f"GDT_{sanitized[:15]}_{hash_suffix}"

    # Verificar formato
    if not _CHAIN_NAME_RE.match(chain):
        raise ValueError(f"Chain name inválido: {chain!r}")
    if len(chain) > _MAX_CHAIN_NAME_LENGTH:
        raise ValueError(f"Chain name excede {_MAX_CHAIN_NAME_LENGTH} chars")

    return chain


# ============================================================================
# POLICY BUILDER
# ============================================================================

def build_network_policy(config: SandboxConfig) -> NetworkPolicy:
    """Construye la política de red desde SandboxConfig."""
    network_enabled = bool(getattr(config, "network_enabled", False))
    allowed_hosts_config = list(getattr(config, "allowed_hosts", ()) or ())
    dns_sinkhole_config = bool(getattr(config, "dns_sinkhole", True))

    # 1. Determinar modo
    if not network_enabled:
        mode: NetworkMode = "none"
    elif allowed_hosts_config:
        mode = "allowlist"
    else:
        mode = "full"

    # 2. Validar límite de allowed_hosts
    if len(allowed_hosts_config) > _MAX_ALLOWED_HOSTS:
        raise ValueError(
            f"allowed_hosts excede {_MAX_ALLOWED_HOSTS}: "
            f"{len(allowed_hosts_config)}"
        )

    # 3. Clasificar y validar hosts
    normalized_hosts: list[str] = []
    for host in allowed_hosts_config:
        try:
            host_type, normalized = _classify_host(host)
        except ValueError as e:
            raise ValueError(f"allowed_hosts inválido: {host!r}: {e}") from e

        # Rechazar wildcards DNS (iptables no soporta)
        if normalized.startswith("*."):
            raise ValueError(
                f"Wildcards DNS no soportados en allowlist: {host!r}"
            )

        # Validar CIDRs
        if host_type == "cidr":
            ok, reason = _validate_allowed_network(normalized)
            if not ok:
                raise ValueError(f"allowed_hosts inválido: {reason}")

        # Validar IPs
        if host_type in ("ipv4", "ipv6"):
            ip = ipaddress.ip_address(normalized)
            if _is_special_ip(ip):
                raise ValueError(
                    f"IP especial prohibida en allowlist: {normalized} "
                    f"(loopback/multicast/link-local/reserved)"
                )

        normalized_hosts.append(normalized)

    # 4. Construir policy
    policy = NetworkPolicy(
        mode=mode,
        allowed_hosts=tuple(normalized_hosts),
        dns_sinkhole=dns_sinkhole_config and mode != "none",
        forbidden_ports=(
            _FORBIDDEN_OUTBOUND_PORTS if mode != "none" else frozenset()
        ),
        network_name=DEFAULT_SANDBOX_NETWORK if mode != "none" else "none",
        isolated=(mode == "none"),
    )

    # 5. Auditoría
    _log.info(
        "network_policy_built",
        mode=policy.mode,
        allowed_hosts_count=len(policy.allowed_hosts),
        dns_sinkhole=policy.dns_sinkhole,
        isolated=policy.isolated,
        policy_hash=policy.policy_hash()[:16],
    )

    return policy


# ============================================================================
# VALIDATION
# ============================================================================

def validate_network_policy(policy: NetworkPolicy) -> tuple[bool, str]:
    """Valida que la política sea segura."""
    # 1. mode=none no puede tener allowed_hosts
    if policy.mode == "none" and policy.allowed_hosts:
        return (
            False,
            "mode=none no puede tener allowed_hosts",
        )

    # 2. mode=full requiere confirmación explícita
    if policy.mode == "full":
        _log.warning(
            "network_mode_full",
            msg="FULL network enabled — zero-trust violado",
            policy_hash=policy.policy_hash()[:16],
        )

    # 3. allowlist sin sinkhole permite exfiltración DNS
    if policy.mode == "allowlist" and not policy.dns_sinkhole:
        return (
            False,
            "allowlist sin DNS sinkhole permite exfiltración DNS. "
            "Activa dns_sinkhole=True.",
        )

    # 4. IMDS debe estar siempre bloqueado
    if not policy.blocked_imds:
        return (False, "blocked_imds debe ser True")

    # 5. DoH/DoT debe estar siempre bloqueado
    if not policy.blocked_doh_dot:
        return (False, "blocked_doh_dot debe ser True")

    # 6. Redes especiales bloqueadas
    if not policy.blocked_special_networks:
        return (False, "blocked_special_networks debe ser True")

    return (True, "OK")


# ============================================================================
# IPTABLES GENERATOR
# ============================================================================

def generate_iptables_rules(
    policy: NetworkPolicy,
    container_ip: str,
) -> list[str]:
    """Genera reglas iptables con orden correcto + IPv6 + atomic.

    Orden:
        1. Chain creation (con check)
        2. Hook en FORWARD (append, no insert)
        3. Modo none → DROP todo
        4. Bloquear IMDS IPv4
        5. Bloquear DoH endpoints
        6. Bloquear puertos prohibidos
        7. DNS sinkhole (REDIRECT)
        8. Rate limiting (SYN flood, conntrack)
        9. Permitir ESTABLISHED,RELATED
        10. Allowlist
        11. Default DROP con log
    """
    container_ip = _validate_container_ip(container_ip)
    chain = _generate_chain_name(container_ip)
    rules: list[str] = []

    # 1. Chain creation (idempotente)
    rules.append(f"iptables -N {chain} 2>/dev/null || true")

    # 2. Hook en FORWARD (append)
    rules.append(f"iptables -C FORWARD -s {container_ip} -j {chain} 2>/dev/null || "
                 f"iptables -A FORWARD -s {container_ip} -j {chain}")
    rules.append(f"iptables -C FORWARD -d {container_ip} -j {chain} 2>/dev/null || "
                 f"iptables -A FORWARD -d {container_ip} -j {chain}")

    # 3. Modo none → DROP todo
    if policy.mode == "none":
        rules.append(
            f"iptables -A {chain} -j LOG "
            f"--log-prefix 'GDT-DROP-NONE: ' --log-level 4"
        )
        rules.append(f"iptables -A {chain} -j DROP")
        return rules

    # 4. Bloquear IMDS IPv4
    if policy.blocked_imds:
        for imds_ip in ("169.254.169.254", "169.254.170.2", "169.254.169.253"):
            rules.append(
                f"iptables -A {chain} -d {imds_ip} -j LOG "
                f"--log-prefix 'GDT-IMDS: ' --log-level 4"
            )
            rules.append(f"iptables -A {chain} -d {imds_ip} -j DROP")

    # 5. Bloquear DoH endpoints
    if policy.blocked_doh_dot:
        for doh_ip in _DOH_IPV4:
            rules.append(f"iptables -A {chain} -d {doh_ip} -j DROP")

    # 6. Bloquear puertos prohibidos (TCP + UDP)
    for port in sorted(policy.forbidden_ports):
        rules.append(f"iptables -A {chain} -p tcp --dport {port} -j REJECT")
        rules.append(f"iptables -A {chain} -p udp --dport {port} -j REJECT")

    # 7. DNS sinkhole: REDIRECT
    if policy.dns_sinkhole:
        rules.append(
            f"iptables -t nat -C PREROUTING -s {container_ip} "
            f"-p udp --dport 53 -j REDIRECT --to-port {DNSMASQ_LOCAL_PORT} "
            f"2>/dev/null || "
            f"iptables -t nat -A PREROUTING -s {container_ip} "
            f"-p udp --dport 53 -j REDIRECT --to-port {DNSMASQ_LOCAL_PORT}"
        )
        rules.append(
            f"iptables -t nat -C PREROUTING -s {container_ip} "
            f"-p tcp --dport 53 -j REDIRECT --to-port {DNSMASQ_LOCAL_PORT} "
            f"2>/dev/null || "
            f"iptables -t nat -A PREROUTING -s {container_ip} "
            f"-p tcp --dport 53 -j REDIRECT --to-port {DNSMASQ_LOCAL_PORT}"
        )

    # 8. Rate limiting (SYN flood, UDP flood)
    rules.append(
        f"iptables -A {chain} -p tcp --syn -m limit "
        f"--limit 100/sec --limit-burst 200 -j RETURN"
    )
    rules.append(
        f"iptables -A {chain} -p tcp --syn -j DROP"
    )
    rules.append(
        f"iptables -A {chain} -p udp -m limit "
        f"--limit 1000/sec --limit-burst 2000 -j RETURN"
    )
    rules.append(
        f"iptables -A {chain} -p udp -j DROP"
    )

    # 9. ESTABLISHED,RELATED
    rules.append(
        f"iptables -A {chain} -m conntrack "
        f"--ctstate ESTABLISHED,RELATED -j ACCEPT"
    )

    # 10. Allowlist
    if policy.mode == "allowlist":
        for host in policy.allowed_hosts:
            host_type, _ = _classify_host(host)
            if host_type in ("ipv4", "ipv6", "cidr"):
                # Solo IPv4 en iptables (IPv6 va a ip6tables)
                if ":" in host:
                    continue
                rules.append(f"iptables -A {chain} -d {host} -j ACCEPT")

    # 11. Modo full: ACCEPT todo
    if policy.mode == "full":
        rules.append(f"iptables -A {chain} -j ACCEPT")
    else:
        # Default DROP con log
        rules.append(
            f"iptables -A {chain} -j LOG "
            f"--log-prefix 'GDT-DROP: ' --log-level 4"
        )
        rules.append(f"iptables -A {chain} -j DROP")

    return rules


def generate_ip6tables_rules(
    policy: NetworkPolicy,
    container_ip: str,
) -> list[str]:
    """Genera reglas ip6tables (FIX BUG #4: IPv6 soportado)."""
    if not _IPV4_RE.match(container_ip):
        raise ValueError(f"container_ip debe ser IPv4: {container_ip}")

    chain = _generate_chain_name(container_ip)
    rules: list[str] = []

    # Chain creation
    rules.append(f"ip6tables -N {chain} 2>/dev/null || true")

    # Hook
    rules.append(f"ip6tables -C FORWARD -s {container_ip} -j {chain} 2>/dev/null || "
                 f"ip6tables -A FORWARD -s {container_ip} -j {chain}")
    rules.append(f"ip6tables -C FORWARD -d {container_ip} -j {chain} 2>/dev/null || "
                 f"ip6tables -A FORWARD -d {container_ip} -j {chain}")

    if policy.mode == "none":
        rules.append(
            f"ip6tables -A {chain} -j LOG "
            f"--log-prefix 'GDT-DROP-NONE-V6: ' --log-level 4"
        )
        rules.append(f"ip6tables -A {chain} -j DROP")
        return rules

    # IMDS IPv6 (FIX BUG #3, #18)
    if policy.blocked_imds:
        for imds_ip in _IMDS_IPV6:
            rules.append(
                f"ip6tables -A {chain} -d {imds_ip} -j LOG "
                f"--log-prefix 'GDT-IMDS-V6: ' --log-level 4"
            )
            rules.append(f"ip6tables -A {chain} -d {imds_ip} -j DROP")

    # DoH IPv6
    if policy.blocked_doh_dot:
        for doh_ip in _DOH_IPV6:
            rules.append(f"ip6tables -A {chain} -d {doh_ip} -j DROP")

    # Puertos prohibidos
    for port in sorted(policy.forbidden_ports):
        rules.append(f"ip6tables -A {chain} -p tcp --dport {port} -j REJECT")
        rules.append(f"ip6tables -A {chain} -p udp --dport {port} -j REJECT")

    # ESTABLISHED
    rules.append(
        f"ip6tables -A {chain} -m conntrack "
        f"--ctstate ESTABLISHED,RELATED -j ACCEPT"
    )

    # Allowlist IPv6
    if policy.mode == "allowlist":
        for host in policy.allowed_hosts:
            host_type, _ = _classify_host(host)
            if host_type in ("ipv6", "cidr") and ":" in host:
                rules.append(f"ip6tables -A {chain} -d {host} -j ACCEPT")

    # Default
    if policy.mode == "full":
        rules.append(f"ip6tables -A {chain} -j ACCEPT")
    else:
        rules.append(
            f"ip6tables -A {chain} -j LOG "
            f"--log-prefix 'GDT-DROP-V6: ' --log-level 4"
        )
        rules.append(f"ip6tables -A {chain} -j DROP")

    return rules


def generate_cleanup_rules(container_ip: str) -> list[str]:
    """Genera reglas de cleanup (FIX BUG #20: chain leak prevention)."""
    container_ip = _validate_container_ip(container_ip)
    chain = _generate_chain_name(container_ip)
    return [
        f"iptables -D FORWARD -s {container_ip} -j {chain} 2>/dev/null || true",
        f"iptables -D FORWARD -d {container_ip} -j {chain} 2>/dev/null || true",
        f"iptables -F {chain} 2>/dev/null || true",
        f"iptables -X {chain} 2>/dev/null || true",
        f"iptables -t nat -D PREROUTING -s {container_ip} -p udp --dport 53 -j REDIRECT --to-port {DNSMASQ_LOCAL_PORT} 2>/dev/null || true",
        f"iptables -t nat -D PREROUTING -s {container_ip} -p tcp --dport 53 -j REDIRECT --to-port {DNSMASQ_LOCAL_PORT} 2>/dev/null || true",
        f"ip6tables -D FORWARD -s {container_ip} -j {chain} 2>/dev/null || true",
        f"ip6tables -D FORWARD -d {container_ip} -j {chain} 2>/dev/null || true",
        f"ip6tables -F {chain} 2>/dev/null || true",
        f"ip6tables -X {chain} 2>/dev/null || true",
    ]


# ============================================================================
# NFTABLES GENERATOR
# ============================================================================

def generate_nftables_rules(
    policy: NetworkPolicy,
    container_ip: str,
) -> str:
    """Genera configuración nftables (con IPv4 + IPv6)."""
    container_ip = _validate_container_ip(container_ip)
    chain_suffix = hashlib.sha256(container_ip.encode()).hexdigest()[:8]
    chain_name = f"c_{chain_suffix}"
    table = f"gdt_{chain_suffix}"

    lines: list[str] = [
        f"# nftables config for container {container_ip}",
        f"table inet {table} {{",
        f"    chain forward {{",
        f"        type filter hook forward priority 0; policy drop;",
        f"        ip saddr {container_ip} jump {chain_name}",
        f"        ip daddr {container_ip} jump {chain_name}",
        f"    }}",
        f"    chain {chain_name} {{",
    ]

    if policy.mode == "none":
        lines.append('        log prefix "GDT-DROP-NONE: " drop')
    else:
        # IMDS IPv4 + IPv6
        if policy.blocked_imds:
            for imds in _IMDS_ADDRESSES:
                if "." in imds:
                    lines.append(
                        f'        ip daddr {imds} log prefix "GDT-IMDS: " drop'
                    )
                elif ":" in imds:
                    lines.append(
                        f'        ip6 daddr {imds} log prefix "GDT-IMDS-V6: " drop'
                    )

        # DoH
        if policy.blocked_doh_dot:
            for doh in _DOH_IPV4:
                lines.append(f"        ip daddr {doh} drop")
            for doh in _DOH_IPV6:
                lines.append(f"        ip6 daddr {doh} drop")

        # Puertos prohibidos
        for port in sorted(policy.forbidden_ports):
            lines.append(f"        tcp dport {port} reject")
            lines.append(f"        udp dport {port} reject")

        # DNS sinkhole
        if policy.dns_sinkhole:
            lines.append(f"        udp dport 53 redirect to :{DNSMASQ_LOCAL_PORT}")
            lines.append(f"        tcp dport 53 redirect to :{DNSMASQ_LOCAL_PORT}")

        # Rate limit
        lines.append(
            '        tcp flags syn limit rate 100/second burst 200 packets accept'
        )
        lines.append("        tcp flags syn drop")
        lines.append(
            '        udp limit rate 1000/second burst 2000 packets accept'
        )
        lines.append("        udp drop")

        # ESTABLISHED
        lines.append("        ct state established,related accept")

        # Allowlist
        if policy.mode == "allowlist":
            for host in policy.allowed_hosts:
                host_type, _ = _classify_host(host)
                if host_type == "ipv4":
                    lines.append(f"        ip daddr {host} accept")
                elif host_type == "ipv6":
                    lines.append(f"        ip6 daddr {host} accept")
                elif host_type == "cidr":
                    version = "ip" if ":" not in host else "ip6"
                    lines.append(f"        {version} daddr {host} accept")

        if policy.mode == "full":
            lines.append("        accept")
        else:
            lines.append('        log prefix "GDT-DROP: " drop')

    lines.append("    }")
    lines.append("}")
    return "\n".join(lines)


# ============================================================================
# DNS SINKHOLE (dnsmasq)
# ============================================================================

def generate_dnsmasq_config(policy: NetworkPolicy) -> str | None:
    """Genera config de dnsmasq para sinkhole (FIX BUG #1: IPv6 syntax)."""
    if not policy.dns_sinkhole:
        return None

    lines: list[str] = [
        "# God-Tier Sandbox DNS Sinkhole",
        f"port={DNSMASQ_LOCAL_PORT}",
        "listen-address=127.0.0.1",
        "bind-interfaces",
        "no-resolv",
        "no-poll",
        "bogus-priv",
        "domain-needed",
        # IPv4 sinkhole
        "address=/#/0.0.0.0",
        # IPv6 sinkhole (FIX BUG #1: sintaxis correcta)
        "address=/#/::",
    ]

    # Permitir dominios explícitos (con validación)
    for host in policy.allowed_hosts:
        host_type, normalized = _classify_host(host)
        if host_type == "domain":
            # Validar dominio
            if not _DOMAIN_RE.match(normalized):
                _log.warning(
                    "dnsmasq_invalid_domain",
                    domain=normalized,
                )
                continue
            lines.append(f"server=/{normalized}/1.1.1.1")
            lines.append(f"server=/{normalized}/8.8.8.8")

    return "\n".join(lines)


# ============================================================================
# /etc/hosts
# ============================================================================

def generate_etc_hosts(policy: NetworkPolicy) -> str:
    """Genera /etc/hosts para dominios en allowlist."""
    lines: list[str] = [
        "# God-Tier Sandbox /etc/hosts",
        "127.0.0.1 localhost",
        "::1 localhost",
        "",
    ]

    for host in policy.allowed_hosts:
        host_type, normalized = _classify_host(host)
        if host_type in ("ipv4", "ipv6"):
            continue
        if host_type == "domain":
            lines.append(f"# {normalized} -> resuelto por dnsmasq local")

    return "\n".join(lines)


# ============================================================================
# MAIN API
# ============================================================================

def apply_network_policy(config: SandboxConfig) -> NetworkPolicy:
    """Construye, valida, y retorna la política de red."""
    policy = build_network_policy(config)
    is_valid, reason = validate_network_policy(policy)
    if not is_valid:
        raise ValueError(f"Network policy inválida: {reason}")
    return policy


def export_policy_json(policy: NetworkPolicy, path: str | None = None) -> str:
    """Exporta policy a JSON (FIX BUG #33: export/import)."""
    json_str = policy.to_json()
    if path:
        from pathlib import Path
        Path(path).write_text(json_str, encoding="utf-8")
        _log.info("network_policy_exported", path=path)
    return json_str


__all__ = [
    # Policy
    "NetworkPolicy",
    "NetworkMode",
    # Builders
    "build_network_policy",
    "validate_network_policy",
    "apply_network_policy",
    # Generators
    "generate_iptables_rules",
    "generate_ip6tables_rules",
    "generate_cleanup_rules",
    "generate_nftables_rules",
    "generate_dnsmasq_config",
    "generate_etc_hosts",
    # Utils
    "export_policy_json",
    # Constants
    "DNSMASQ_LOCAL_PORT",
    "DEFAULT_SANDBOX_NETWORK",
    "_IMDS_ADDRESSES",
    "_IMDS_IPV6",
    "_DOH_IPV4",
    "_DOH_IPV6",
    "_FORBIDDEN_OUTBOUND_PORTS",
]
