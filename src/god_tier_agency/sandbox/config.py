"""Configuración del sandbox con validación estricta God-Tier.

SandboxConfig es:
    - Inmutable (frozen=True) → defensa TOCTOU
    - Con validación cross-field (model_validator)
    - Con allowlist de imágenes y lenguajes coherentes
    - Con rechazo de root obligatorio (nunca user=0:0)
    - Con cache_key determinístico (SHA-256)

Filosofía:
    - Fail-closed: si algo no se valida, se rechaza
    - Zero-trust: root no es válido, :latest no es válido
    - Coherencia: language ↔ image deben coincidir
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from typing import Any, Final, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    computed_field,
    field_validator,
    model_validator,
)


# ============================================================================
# CONSTANTES
# ============================================================================
# Prefijo obligatorio para nombres (evita colisiones con contenedores del sistema)
_NAME_PREFIX: Final[str] = "gdt"

# Imágenes base permitidas por lenguaje (allowlist estricta)
_ALLOWED_IMAGES: Final[dict[str, tuple[str, ...]]] = {
    "python": (
        "python:3.11-slim",
        "python:3.11-alpine",
        "python:3.12-slim",
        "python:3.12-alpine",
        "python:3.12-slim-bookworm",
        "god-tier-sandbox-python:latest",  # custom del proyecto
    ),
    "bash": (
        "alpine:3.19",
        "alpine:3.20",
        "debian:12-slim",
        "ubuntu:24.04",
        "god-tier-sandbox-bash:latest",  # custom del proyecto
    ),
    "node": (
        "node:20-alpine",
        "node:20-slim",
        "node:22-alpine",
        "node:22-slim",
    ),
}

# Prefijos de usuario que indican ROOT (prohibidos)
_ROOT_USER_PATTERNS: Final[tuple[str, ...]] = (
    "root", "0:0", "0:", ":0", "0", "root:root", "root:", ":root",
)

# Dominio regex RFC 1035
_DOMAIN_RE: Final[re.Pattern[str]] = re.compile(
    r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
    r"(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$"
)

# Hostname regex (RFC 1123)
_HOSTNAME_RE: Final[re.Pattern[str]] = re.compile(
    r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$"
)


# ============================================================================
# SANDBOX CONFIG
# ============================================================================
class SandboxConfig(BaseModel):
    """Configuración completa del sandbox (inmutable).

    Uso:
        >>> config = SandboxConfig(
        ...     name="gdt-test-scan",
        ...     image="python:3.12-slim",
        ...     language="python",
        ...     cpu_limit=0.5,
        ...     memory_limit_mb=512,
        ... )
        >>> kwargs = config.to_docker_kwargs()
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        str_strip_whitespace=True,
        validate_default=True,
    )

    # --- Identidad ---
    name: str = Field(
        ...,
        min_length=5,
        max_length=64,
        pattern=r"^gdt-[a-z0-9]([a-z0-9_-]*[a-z0-9])?$",
        description="Nombre del sandbox (debe empezar con 'gdt-')",
        examples=["gdt-a", "gdt-recon-001", "gdt-exploit-xyz"],
    )

    # --- Imagen ---
    image: str = Field(
        ...,
        min_length=3,
        max_length=256,
        description="Imagen Docker (tag específico o digest)",
        examples=["python:3.12-slim", "alpine:3.20"],
    )
    image_digest: str | None = Field(
        None,
        pattern=r"^sha256:[a-f0-9]{64}$",
        description="SHA-256 digest (para reproducibilidad bit-exacta)",
    )

    # --- Lenguaje ---
    language: Literal["python", "bash", "node"] = Field(
        default="python",
        description="Lenguaje de ejecución (debe coincidir con la imagen)",
    )

    # --- Recursos ---
    memory_limit_mb: int = Field(default=512, ge=64, le=16384)
    cpu_limit: float = Field(default=0.5, ge=0.1, le=8.0)
    pids_limit: int = Field(default=100, ge=10, le=1024)
    disk_limit_mb: int = Field(default=1024, ge=64, le=10240)

    # --- Timeouts ---
    timeout_seconds: float = Field(default=300.0, ge=1.0, le=3600.0)
    startup_grace_seconds: float = Field(default=2.0, ge=0.5, le=30.0)

    # --- Red ---
    network_enabled: bool = Field(default=False)
    allowed_hosts: tuple[str, ...] = Field(
        default_factory=tuple,
        description="Hosts/IPs/CIDRs permitidos si network_enabled=True",
    )
    dns_sinkhole: bool = Field(
        default=True,
        description="Redirigir DNS desconocido a 0.0.0.0",
    )

    # --- Filesystem ---
    read_only_root: bool = Field(default=True)
    tmpfs_size_mb: int = Field(default=64, ge=1, le=1024)

    # --- Seguridad ---
    drop_all_caps: bool = Field(default=True)
    no_new_privileges: bool = Field(default=True)
    seccomp_profile: Literal["default", "strict", "permissive"] = Field(default="strict")
    apparmor_profile: str | None = Field(default=None)
    user: str = Field(
        default="1000:1000",
        description="UID:GID (obligatorio NO-root)",
    )
    hostname: str = Field(default="sandbox", min_length=1, max_length=63)

    # ========================================================================
    # VALIDADORES DE CAMPO
    # ========================================================================
    @field_validator("image")
    @classmethod
    def validate_image(cls, v: str) -> str:
        """Valida imagen: rechaza :latest, shell chars."""
        # 1. Rechazar shell metacharacters
        forbidden = [";", "|", "&", "$", "`", "\n", "\r", " ", "\t"]
        for char in forbidden:
            if char in v:
                raise ValueError(
                    f"Carácter prohibido {char!r} en imagen Docker"
                )

        # 2. Rechazar :latest (no reproducible)
        if v.endswith(":latest"):
            raise ValueError(
                "Imagen ':latest' no permitida (no reproducible). "
                "Usa tag específico o digest."
            )

        # 3. Rechazar imágenes con prefijos sospechosos
        if v.startswith(("/", "..")):
            raise ValueError(f"Imagen con prefijo sospechoso: {v!r}")

        return v

    @field_validator("allowed_hosts")
    @classmethod
    def validate_allowed_hosts(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        """Valida IPs, dominios, y CIDRs en allowed_hosts."""
        for host in v:
            # 1. Intentar IP
            try:
                ipaddress.ip_address(host)
                continue
            except ValueError:
                pass

            # 2. Intentar CIDR
            try:
                ipaddress.ip_network(host, strict=False)
                continue
            except ValueError:
                pass

            # 3. Intentar dominio
            if not _DOMAIN_RE.match(host.lower()):
                raise ValueError(
                    f"Host inválido en allowed_hosts: {host!r}. "
                    "Debe ser IP, CIDR (10.0.0.0/8), o dominio RFC 1035."
                )
        return v

    @field_validator("tmpfs_size_mb")
    @classmethod
    def validate_tmpfs(cls, v: int) -> int:
        if v > 1024:
            raise ValueError("tmpfs_size_mb no puede exceder 1024 (riesgo de OOM)")
        return v

    @field_validator("user")
    @classmethod
    def validate_user(cls, v: str) -> str:
        """Rechaza root. El sandbox NUNCA debe ejecutar como root."""
        v_lower = v.strip().lower()
        for pattern in _ROOT_USER_PATTERNS:
            if v_lower == pattern or v_lower.startswith(pattern + ":"):
                raise ValueError(
                    f"Usuario root prohibido: {v!r}. "
                    "Usa UID:GID no-root (ej: '1000:1000')."
                )
        # Validar formato UID:GID numérico
        if ":" not in v:
            raise ValueError(
                f"user debe ser 'UID:GID' (ej: '1000:1000'), recibido: {v!r}"
            )
        uid, _, gid = v.partition(":")
        if not uid.isdigit() or not gid.isdigit():
            raise ValueError(
                f"user debe ser numérico 'UID:GID', recibido: {v!r}"
            )
        return v

    @field_validator("hostname")
    @classmethod
    def validate_hostname(cls, v: str) -> str:
        """Valida hostname RFC 1123."""
        if not _HOSTNAME_RE.match(v.lower()):
            raise ValueError(
                f"Hostname inválido: {v!r}. Debe cumplir RFC 1123."
            )
        return v.lower()

    @field_validator("apparmor_profile")
    @classmethod
    def validate_apparmor(cls, v: str | None) -> str | None:
        """Valida perfil AppArmor (sin inyección)."""
        if v is None:
            return None
        forbidden = [";", "|", "&", "$", "`", "\n", "\r", " "]
        for char in forbidden:
            if char in v:
                raise ValueError(
                    f"Carácter prohibido {char!r} en apparmor_profile"
                )
        return v

    # ========================================================================
    # VALIDADOR CROSS-FIELD (model_validator)
    # ========================================================================
    @model_validator(mode="after")
    def validate_cross_field(self) -> "SandboxConfig":
        """Validación de reglas entre múltiples campos."""
        # 1. Timeout > startup_grace
        if self.startup_grace_seconds >= self.timeout_seconds:
            raise ValueError(
                f"startup_grace_seconds ({self.startup_grace_seconds}s) debe ser "
                f"menor que timeout_seconds ({self.timeout_seconds}s)"
            )

        # 2. Si network_enabled, allowed_hosts no puede estar vacío
        if self.network_enabled and not self.allowed_hosts:
            raise ValueError(
                "network_enabled=True requiere allowed_hosts no vacío. "
                "Si quieres red total, esto viola zero-trust."
            )

        # 3. Si network_enabled=False, allowed_hosts debe estar vacío
        if not self.network_enabled and self.allowed_hosts:
            raise ValueError(
                "allowed_hosts especificado pero network_enabled=False. "
                "Activa network o elimina allowed_hosts."
            )

        # 4. Imagen debe estar en allowlist para el lenguaje
        allowed_for_lang = _ALLOWED_IMAGES.get(self.language, ())
        if self.image not in allowed_for_lang:
            raise ValueError(
                f"Imagen {self.image!r} no permitida para language={self.language!r}. "
                f"Permitidas: {list(allowed_for_lang)}"
            )

        # 5. Si drop_all_caps=False → debe tener no_new_privileges=True
        #    (defensa en profundidad: si no dropeas caps, al menos
        #    no permitas escalada)
        if not self.drop_all_caps and not self.no_new_privileges:
            raise ValueError(
                "drop_all_caps=False requiere no_new_privileges=True. "
                "Nunca desactives ambas protecciones."
            )

        # 6. Si read_only_root=False → debe tener user no-root
        if not self.read_only_root and self.user.startswith("0:"):
            raise ValueError(
                "read_only_root=False con user root es crítico. "
                "Usa user no-root o activa read_only_root."
            )

        return self

    # ========================================================================
    # COMPUTED FIELDS
    # ========================================================================
    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_network_isolated(self) -> bool:
        """True si no hay red habilitada."""
        return not self.network_enabled

    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_privileged_safe(self) -> bool:
        """True si cumple las protecciones de privilegios."""
        return (
            self.drop_all_caps
            and self.no_new_privileges
            and not self.user.startswith("0:")
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def image_digest_short(self) -> str:
        """Digest corto para logs."""
        if self.image_digest:
            return self.image_digest[:19]  # sha256:XXXX...
        return "no-digest"

    # ========================================================================
    # MÉTODOS
    # ========================================================================
    def cache_key(self) -> str:
        """Hash SHA-256 determinístico de la config (16 chars hex).

        Útil para cachear sandboxes por configuración idéntica.
        """
        payload = self.model_dump_json(exclude={"image_digest"})
        return hashlib.sha256(payload.encode()).hexdigest()[:16]

    def to_docker_kwargs(self) -> dict[str, Any]:
        """Traduce la config a kwargs del Docker SDK.

        Uso:
            >>> config = SandboxConfig(name="gdt-1", image="python:3.12-slim")
            >>> client.containers.run(image=config.image, **config.to_docker_kwargs())
        """
        kwargs: dict[str, Any] = {
            "name": self.name,
            "hostname": self.hostname,
            "user": self.user,
            # Filesystem
            "read_only": self.read_only_root,
            # Seguridad de privilegios
            "cap_drop": ["ALL"] if self.drop_all_caps else None,
            "security_opt": [],
        }

        # Security opts
        if self.no_new_privileges:
            kwargs["security_opt"].append("no-new-privileges:true")
        if self.apparmor_profile:
            kwargs["security_opt"].append(f"apparmor={self.apparmor_profile}")
        if self.seccomp_profile == "strict":
            kwargs["security_opt"].append(
                "seccomp=./docker/sandbox/seccomp-strict.json"
            )

        # Limpiar None
        if kwargs["cap_drop"] is None:
            del kwargs["cap_drop"]
        if not kwargs["security_opt"]:
            del kwargs["security_opt"]

        return kwargs

    def __str__(self) -> str:
        """Representación compacta para logs."""
        net = "net:on" if self.network_enabled else "net:off"
        return (
            f"SandboxConfig(name={self.name}, image={self.image}, "
            f"lang={self.language}, cpu={self.cpu_limit}, "
            f"mem={self.memory_limit_mb}MB, {net})"
        )


__all__ = ["SandboxConfig"]
