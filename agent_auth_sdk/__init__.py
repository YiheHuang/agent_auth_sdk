"""Agent identity、签名验签、Registry client、Vault 与框架适配 SDK。"""

from importlib.metadata import PackageNotFoundError, version

from .agent import AgentInstance
from .auth_context import AuthenticatedAgentContext, authenticated_context_from
from .config import (
    STRICT_PROFILE,
    TEST_PROFILE,
    DiscoveryMode,
    MetadataResolverConfig,
    RuntimeProfile,
    SigningConfig,
    VerificationConfig,
)
from .crypto import CallableSigner, Signer
from .errors import (
    AgentAuthenticationError,
    AgentAuthError,
    AgentAuthorizationError,
    AgentConfigurationError,
    AgentDiscoveryError,
    AgentIdentityError,
    AgentReplayError,
    AgentTransportError,
    MetadataValidationError,
    VerificationErrorCode,
)
from .identity import build_agent_id, parse_agent_id
from .integrations import (
    AgentAuthRouter,
    AuthenticatedTool,
    OpenAIAgentAuth,
    RemoteAgentToolSpec,
    authenticated_agent,
)
from .messaging import verify_agent_message
from .metadata import resolve_agent
from .models import (
    AgentAuditConfig,
    AgentKey,
    AgentMetadata,
    AgentRegistryDocument,
    AgentRegistryEntry,
    ParsedAgentId,
    ResolveResult,
    SignatureHeaders,
    SignedAgentMessage,
    VerificationFailure,
    VerificationSuccess,
)
from .observability import AgentAuthEvent, EventSink
from .registry_client import RegistryClient
from .remote import AgentAuthASGIMiddleware, RemoteAgentClient
from .stores import (
    FileMetadataCache,
    InMemoryMetadataCache,
    InMemoryNonceStore,
    MetadataCache,
    NonceStore,
    RedisNonceStore,
)
from .vault_kms import VaultKmsConfig, VaultTransitPublicKeyResolver, VaultTransitSigner
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
    "OpenAIAgentAuth",
    "AuthenticatedTool",
    "RemoteAgentToolSpec",
    "AgentAuthRouter",
    "authenticated_agent",
    "AuthenticatedAgentContext",
    "authenticated_context_from",
    "AgentAuthEvent",
    "EventSink",
    # 签名与身份扩展点
    "Signer",
    "CallableSigner",
    "build_agent_id",
    "parse_agent_id",
    # 必需配置
    "VerificationConfig",
    "SigningConfig",
    "MetadataResolverConfig",
    "DiscoveryMode",
    "RuntimeProfile",
    "STRICT_PROFILE",
    "TEST_PROFILE",
    # 必需存储实现
    "NonceStore",
    "MetadataCache",
    "InMemoryNonceStore",
    "RedisNonceStore",
    "InMemoryMetadataCache",
    "FileMetadataCache",
    # Vault
    "VaultKmsConfig",
    "VaultTransitSigner",
    "VaultTransitPublicKeyResolver",
    # 协议模型与结果
    "AgentAuditConfig",
    "AgentKey",
    "AgentMetadata",
    "SignedAgentMessage",
    "AgentRegistryEntry",
    "AgentRegistryDocument",
    "ResolveResult",
    "SignatureHeaders",
    "VerificationSuccess",
    "VerificationFailure",
    "ParsedAgentId",
    # 错误
    "VerificationErrorCode",
    "AgentIdentityError",
    "MetadataValidationError",
    "AgentAuthError",
    "AgentAuthenticationError",
    "AgentAuthorizationError",
    "AgentReplayError",
    "AgentDiscoveryError",
    "AgentTransportError",
    "AgentConfigurationError",
    "__version__",
]

try:
    __version__ = version("verifiable-agent-auth-sdk")
except PackageNotFoundError:  # 源码树运行
    __version__ = "1.0.0rc1"
