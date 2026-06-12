"""面向开发者的一站式 Agent 实例封装。"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import httpx

from .crypto import LocalPemSigner, generate_ed25519_keypair, public_key_to_base64url
from .identity import build_agent_id
from .messaging import sign_agent_message
from .models import AgentAuditConfig, AgentKey, AgentMetadata, SignedAgentMessage
from .publish import export_well_known, publish_to_registry, render_agent_metadata
from .signing import sign_http_request


@dataclass(slots=True)
class AgentInstance:
    """把身份、密钥、metadata 和签名能力聚合到一个对象里。"""

    agent_id: str
    domain: str
    name: str
    organization: str
    endpoint: str
    kid: str
    private_key_pem: str
    public_key_pem: str
    public_key_base64url: str
    capabilities: list[str]
    environment: str | None = None
    metadata: AgentMetadata | None = None

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
        if private_key_pem and not public_key_pem:
            raise ValueError("public_key_pem is required when private_key_pem is provided")

        if private_key_pem and public_key_pem:
            pair_private = private_key_pem
            pair_public = public_key_pem
            pair_public_b64 = public_key_to_base64url(public_key_pem)
        else:
            pair = generate_ed25519_keypair(kid=kid)
            pair_private = pair.private_key_pem
            pair_public = pair.public_key_pem
            pair_public_b64 = pair.public_key_base64url

        agent_id = build_agent_id(domain, name)
        keys = [
            AgentKey(
                kid=kid,
                public_key_pem=pair_public,
                public_key_base64url=pair_public_b64,
                status="active",
            )
        ]
        metadata = render_agent_metadata(
            agent_id=agent_id,
            domain=domain,
            name=name,
            organization=organization,
            endpoint=endpoint,
            capabilities=capabilities or [],
            keys=keys,
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
            private_key_pem=pair_private,
            public_key_pem=pair_public,
            public_key_base64url=pair_public_b64,
            capabilities=capabilities or [],
            environment=environment,
            metadata=metadata,
        )

    @property
    def signer(self) -> LocalPemSigner:
        return LocalPemSigner(private_key_pem=self.private_key_pem, kid_value=self.kid)

    def export_metadata(self, output_dir: str | Path) -> Path:
        if self.metadata is None:
            raise ValueError("metadata has not been initialized")
        return export_well_known(self.metadata, output_dir)

    def save_keys(self, output_dir: str | Path) -> dict[str, Path]:
        target_dir = Path(output_dir)
        target_dir.mkdir(parents=True, exist_ok=True)
        private_key_path = target_dir / "private_key.pem"
        public_key_path = target_dir / "public_key.pem"
        public_key_base64url_path = target_dir / "public_key.base64url"
        private_key_path.write_text(self.private_key_pem, encoding="utf-8")
        public_key_path.write_text(self.public_key_pem, encoding="utf-8")
        public_key_base64url_path.write_text(self.public_key_base64url, encoding="utf-8")
        return {
            "private_key.pem": private_key_path,
            "public_key.pem": public_key_path,
            "public_key.base64url": public_key_base64url_path,
        }

    async def publish(
        self,
        *,
        registry_url: str,
        publisher: str | None = None,
        token: str | None = None,
        http_client: httpx.AsyncClient | None = None,
        timeout_seconds: float = 10.0,
    ) -> dict:
        if self.metadata is None:
            raise ValueError("metadata has not been initialized")
        return await publish_to_registry(
            self.metadata,
            registry_url=registry_url,
            publisher=publisher,
            token=token,
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
