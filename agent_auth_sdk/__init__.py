"""Python Agent Identity SDK 的统一导出入口。"""

from .config import (
    MetadataResolverConfig,
    RuntimeProfile,
    SigningConfig,
    VerificationConfig,
)
from .agent import AgentInstance
from .crypto import CallableSigner, GeneratedKeyPair, LocalPemSigner, generate_ed25519_keypair
from .identity import ParsedAgentId, assert_subject_match, build_agent_id, parse_agent_id
from .messaging import (
    build_canonical_message,
    sign_agent_message,
    sign_agent_message_sync,
    verify_agent_message,
    verify_agent_message_sync,
)
from .metadata import resolve_agent, select_verification_key
from .models import (
    AgentAuditConfig,
    AgentKey,
    AgentMetadata,
    AgentRegistryDocument,
    AgentRegistryEntry,
    ResolveResult,
    SignedAgentMessage,
    SignatureHeaders,
    VerificationFailure,
    VerificationSuccess,
)
from .publish import export_well_known, publish_to_registry, render_agent_metadata
from .registry_security import RegistrySignatureHeaders, sign_registry_publish_request
from .signing import sign_http_request, sign_http_request_sync
from .stores import (
    FileMetadataCache,
    InMemoryMetadataCache,
    InMemoryNonceStore,
    MetadataCache,
    NonceStore,
    RedisNonceStore,
)
from .verification import verify_http_request, verify_http_request_sync
from .vault_kms import (
    VaultKmsConfig,
    VaultKmsKeyDescription,
    VaultTransitPublicKeyResolver,
    VaultTransitSigner,
    create_vault_key_if_missing,
    parse_vault_signature,
    resolve_vault_public_key,
    validate_vault_key,
)

__all__ = [
    "AgentAuditConfig",
    "AgentInstance",
    "AgentKey",
    "AgentMetadata",
    "AgentRegistryDocument",
    "AgentRegistryEntry",
    "CallableSigner",
    "FileMetadataCache",
    "GeneratedKeyPair",
    "InMemoryMetadataCache",
    "InMemoryNonceStore",
    "LocalPemSigner",
    "MetadataCache",
    "MetadataResolverConfig",
    "NonceStore",
    "ParsedAgentId",
    "RedisNonceStore",
    "RegistrySignatureHeaders",
    "ResolveResult",
    "RuntimeProfile",
    "SignedAgentMessage",
    "SignatureHeaders",
    "SigningConfig",
    "VerificationConfig",
    "VerificationFailure",
    "VerificationSuccess",
    "VaultKmsConfig",
    "VaultKmsKeyDescription",
    "VaultTransitPublicKeyResolver",
    "VaultTransitSigner",
    "assert_subject_match",
    "build_agent_id",
    "build_canonical_message",
    "create_vault_key_if_missing",
    "export_well_known",
    "generate_ed25519_keypair",
    "parse_agent_id",
    "parse_vault_signature",
    "publish_to_registry",
    "render_agent_metadata",
    "resolve_agent",
    "resolve_vault_public_key",
    "select_verification_key",
    "sign_agent_message",
    "sign_agent_message_sync",
    "sign_http_request",
    "sign_http_request_sync",
    "sign_registry_publish_request",
    "verify_agent_message",
    "verify_agent_message_sync",
    "verify_http_request",
    "verify_http_request_sync",
    "validate_vault_key",
]

