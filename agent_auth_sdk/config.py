"""SDK 配置模型。"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


@dataclass(slots=True, frozen=True)
class RuntimeProfile:
    """profile 决定运行时的安全策略。"""

    name: str
    allow_http: bool
    allow_ip_host: bool
    clock_skew_seconds: int
    metadata_cache_ttl_seconds: int
    nonce_ttl_seconds: int


class DiscoveryMode(StrEnum):
    """Metadata 信任源策略。"""

    REGISTRY_ONLY = "registry_only"
    DIRECT_ONLY = "direct_only"
    REGISTRY_THEN_DIRECT = "registry_then_direct"


STRICT_PROFILE = RuntimeProfile(
    name="strict",
    allow_http=False,
    allow_ip_host=False,
    clock_skew_seconds=120,
    metadata_cache_ttl_seconds=300,
    nonce_ttl_seconds=600,
)

TEST_PROFILE = RuntimeProfile(
    name="test",
    allow_http=True,
    allow_ip_host=True,
    clock_skew_seconds=300,
    metadata_cache_ttl_seconds=300,
    nonce_ttl_seconds=600,
)


def get_runtime_profile(name: str) -> RuntimeProfile:
    if name == "strict":
        return STRICT_PROFILE
    if name == "test":
        return TEST_PROFILE
    raise ValueError(f"Unknown runtime profile: {name}")


@dataclass(slots=True)
class SigningConfig:
    profile: RuntimeProfile = field(default_factory=lambda: STRICT_PROFILE)
    include_signature_input_header: bool = True


@dataclass(slots=True)
class VerificationConfig:
    profile: RuntimeProfile = field(default_factory=lambda: STRICT_PROFILE)
    require_signature_input_header: bool = True


@dataclass(slots=True)
class MetadataResolverConfig:
    profile: RuntimeProfile = field(default_factory=lambda: STRICT_PROFILE)
    cache_ttl_seconds: int | None = None
    request_timeout_seconds: float = 10.0
    registry_url: str | None = None
    discovery_mode: DiscoveryMode | None = None

    def __post_init__(self) -> None:
        if self.cache_ttl_seconds is not None and self.cache_ttl_seconds <= 0:
            raise ValueError("cache_ttl_seconds must be positive")
        if self.request_timeout_seconds <= 0:
            raise ValueError("request_timeout_seconds must be positive")
        if self.discovery_mode == DiscoveryMode.REGISTRY_ONLY and not self.registry_url:
            raise ValueError("registry_url is required for registry_only discovery")

    @property
    def effective_discovery_mode(self) -> DiscoveryMode:
        if self.discovery_mode is not None:
            return self.discovery_mode
        return DiscoveryMode.REGISTRY_ONLY if self.registry_url else DiscoveryMode.DIRECT_ONLY
