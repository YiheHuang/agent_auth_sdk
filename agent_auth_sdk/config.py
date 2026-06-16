"""SDK 配置模型。"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True, frozen=True)
class RuntimeProfile:
    """profile 决定运行时的安全策略。"""

    name: str
    allow_http: bool
    allow_ip_host: bool
    clock_skew_seconds: int
    metadata_cache_ttl_seconds: int
    nonce_ttl_seconds: int


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
