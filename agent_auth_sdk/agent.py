"""面向开发者的一站式 Agent 实例封装。"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import httpx

from .crypto import LocalPemSigner, public_key_to_base64url
from .identity import build_agent_id
from .messaging import sign_agent_message
from .models import AgentAuditConfig, AgentKey, AgentMetadata, SignedAgentMessage
from .publish import export_well_known, publish_to_registry, render_agent_metadata
from .signing import sign_http_request
from .vault_kms import VaultKmsConfig, VaultTransitSigner, resolve_vault_public_key


@dataclass(slots=True)
class AgentInstance:
    """把身份、metadata 和签名能力聚合到一个对象里。"""

    agent_id: str
    domain: str
    name: str
    organization: str
    endpoint: str
    kid: str
    public_key_pem: str
    public_key_base64url: str
    capabilities: list[str]
    environment: str | None = None
    metadata: AgentMetadata | None = None
    signer_override: object | None = None
    kms_key_id: str | None = None

    @classmethod
    def create(
        cls,
        *,
        domain: str,
        name: str,
        organization: str,
        endpoint: str,
        capabilities: list[str] | None = None,
        kid: str = "main",
        environment: str | None = None,
        private_key_pem: str | None = None,
        public_key_pem: str | None = None,
    ) -> "AgentInstance":
        if not private_key_pem or not public_key_pem:
            raise ValueError("Local key generation is removed. Use from_vault() or from_signer().")
        return cls.from_signer(
            domain=domain,
            name=name,
            organization=organization,
            endpoint=endpoint,
            signer=LocalPemSigner(private_key_pem=private_key_pem, kid_value=kid),
            public_key_pem=public_key_pem,
            kid=kid,
            capabilities=capabilities,
            environment=environment,
        )

    @classmethod
    def from_vault(
        cls,
        *,
        domain: str,
        name: str,
        organization: str,
        endpoint: str,
        vault_addr: str,
        vault_token: str,
        transit_mount: str,
        key_name: str,
        namespace: str | None = None,
        verify: bool | str = True,
        capabilities: list[str] | None = None,
        environment: str | None = None,
        kid: str | None = None,
    ) -> "AgentInstance":
        config = VaultKmsConfig(
            vault_addr=vault_addr,
            vault_token=vault_token,
            transit_mount=transit_mount,
            key_name=key_name,
            namespace=namespace,
            verify=verify,
            kid=kid,
        )
        signer = VaultTransitSigner(config)
        signer.validate_access()
        description = resolve_vault_public_key(config)
        return cls.from_signer(
            domain=domain,
            name=name,
            organization=organization,
            endpoint=endpoint,
            signer=signer,
            public_key_pem=description.public_key_pem,
            kid=kid or f"vault:{transit_mount}/{key_name}",
            capabilities=capabilities,
            environment=environment,
            alg="ES256",
            kms_key_id=key_name,
        )

    @classmethod
    def from_kms(
        cls,
        *,
        domain: str,
        name: str,
        organization: str,
        endpoint: str,
        vault_addr: str,
        vault_token: str,
        transit_mount: str,
        key_name: str,
        namespace: str | None = None,
        verify: bool | str = True,
        capabilities: list[str] | None = None,
        environment: str | None = None,
        kid: str | None = None,
    ) -> "AgentInstance":
        """Deprecated compatibility alias; use from_vault()."""

        return cls.from_vault(
            domain=domain,
            name=name,
            organization=organization,
            endpoint=endpoint,
            vault_addr=vault_addr,
            vault_token=vault_token,
            transit_mount=transit_mount,
            key_name=key_name,
            namespace=namespace,
            verify=verify,
            capabilities=capabilities,
            environment=environment,
            kid=kid,
        )

    @classmethod
    def from_signer(
        cls,
        *,
        domain: str,
        name: str,
        organization: str,
        endpoint: str,
        signer: object,
        public_key_pem: str,
        kid: str,
        capabilities: list[str] | None = None,
        environment: str | None = None,
        alg: str = "Ed25519",
        kms_key_id: str | None = None,
    ) -> "AgentInstance":
        agent_id = build_agent_id(domain, name)
        metadata = render_agent_metadata(
            agent_id=agent_id,
            domain=domain,
            name=name,
            organization=organization,
            endpoint=endpoint,
            capabilities=capabilities or [],
            keys=[
                AgentKey(
                    kid=kid,
                    alg=alg,
                    public_key_pem=public_key_pem,
                    public_key_base64url=public_key_to_base64url(public_key_pem),
                    status="active",
                )
            ],
            environment=environment,
            signing_policy={"canonical_request": "v1", "signed_message": "v1"},
            verification_policy={"resolve_via": "/.well-known/agent.json"},
            audit=AgentAuditConfig(mode="jsonl"),
        )
        return cls(
            agent_id=agent_id,
            domain=domain,
            name=name,
            organization=organization,
            endpoint=endpoint,
            kid=kid,
            public_key_pem=public_key_pem,
            public_key_base64url=public_key_to_base64url(public_key_pem),
            capabilities=capabilities or [],
            environment=environment,
            metadata=metadata,
            signer_override=signer,
            kms_key_id=kms_key_id,
        )

    @property
    def signer(self):
        if self.signer_override is None:
            raise ValueError("signer is not available; use from_vault() or from_signer()")
        return self.signer_override

    def export_metadata(self, output_dir: str | Path) -> Path:
        if self.metadata is None:
            raise ValueError("metadata has not been initialized")
        return export_well_known(self.metadata, output_dir)

    async def publish(
        self,
        *,
        registry_url: str,
        client_id: str,
        api_key: str,
        http_client: httpx.AsyncClient | None = None,
        timeout_seconds: float = 10.0,
    ) -> dict:
        if self.metadata is None:
            raise ValueError("metadata has not been initialized")
        return await publish_to_registry(
            self.metadata,
            registry_url=registry_url,
            client_id=client_id,
            api_key=api_key,
            signer=self.signer,
            http_client=http_client,
            timeout_seconds=timeout_seconds,
        )

    async def sign_http(self, **kwargs: object):
        return await sign_http_request(agent_id=self.agent_id, signer=self.signer, **kwargs)

    async def sign_message(
        self,
        *,
        payload: bytes | str | dict | list | None,
        payload_type: str = "application/json",
        recipient: str | None = None,
        message_type: str | None = None,
    ) -> SignedAgentMessage:
        return await sign_agent_message(
            agent_id=self.agent_id,
            signer=self.signer,
            payload=payload,
            payload_type=payload_type,
            recipient=recipient,
            message_type=message_type,
        )
