"""Agent identity、签名验签、Registry client、Vault 与框架适配 SDK。"""

from importlib.metadata import PackageNotFoundError, version

from .agent import AgentInstance
from .config import (
    DiscoveryMode,
    MetadataResolverConfig,
    VerificationConfig,
)
from .messaging import verify_agent_message
from .metadata import resolve_agent
from .registry_client import RegistryClient
from .remote import AgentAuthASGIMiddleware, RemoteAgentClient
from .stores import (
    FileMetadataCache,
    InMemoryNonceStore,
)
from .verification import verify_http_request
from .verifier import AgentVerifier, AuthorizationPolicy

__all__ = [
    # 核心接口
    "AgentInstance",
    "verify_http_request",
    "verify_agent_message",
    "resolve_agent",
    "AgentVerifier",
    "AuthorizationPolicy",
    "RegistryClient",
    "RemoteAgentClient",
    "AgentAuthASGIMiddleware",
    # 必需配置
    "VerificationConfig",
    "MetadataResolverConfig",
    "DiscoveryMode",
    # 必需存储实现
    "InMemoryNonceStore",
    "FileMetadataCache",
    "__version__",
]

try:
    __version__ = version("verifiable-agent-auth-sdk")
except PackageNotFoundError:  # 源码树运行
    __version__ = "0.1.0b1"
