"""SDK 配置模型集中放在这里，方便库与示例服务共享。"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


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
    profile: RuntimeProfile = field(default_factory=lambda: TEST_PROFILE)
    include_signature_input_header: bool = True


@dataclass(slots=True)
class VerificationConfig:
    profile: RuntimeProfile = field(default_factory=lambda: TEST_PROFILE)
    require_signature_input_header: bool = True


@dataclass(slots=True)
class MetadataResolverConfig:
    profile: RuntimeProfile = field(default_factory=lambda: TEST_PROFILE)
    cache_ttl_seconds: int | None = None
    request_timeout_seconds: float = 10.0


@dataclass(slots=True)
class GatewaySettings:
    host: str = "0.0.0.0"
    port: int = 8010
    agent_host: str = "192.144.228.237:8010"
    agent_name: str = "llm-gateway"
    organization: str = "Demo Org"
    profile: RuntimeProfile = field(default_factory=lambda: TEST_PROFILE)
    audit_path: Path = field(default_factory=lambda: Path("runtime/audit.sqlite3"))
    metadata_dir: Path = field(default_factory=lambda: Path("runtime/well-known"))
    private_key_path: Path = field(default_factory=lambda: Path("runtime/keys/private_key.pem"))
    public_key_path: Path = field(default_factory=lambda: Path("runtime/keys/public_key.pem"))
    public_key_base64url_path: Path = field(default_factory=lambda: Path("runtime/keys/public_key.base64url"))
    kid: str = "main"
    llm_base_url: str = "https://yunwu.ai/"
    llm_api_key: str | None = None
    llm_model: str = "gpt-4o-mini"
    llm_timeout_seconds: float = 30.0
