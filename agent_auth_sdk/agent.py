"""面向开发者的一站式 Agent 实例封装。"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import httpx

from .crypto import public_key_to_base64url
from .identity import build_agent_id
from .messaging import sign_agent_message
from .models import AgentAuditConfig, AgentKey, AgentMetadata, SignedAgentMessage
from .publish import (
    add_key_in_registry,
    export_well_known,
    publish_to_registry,
    render_agent_metadata,
    revoke_agent_in_registry,
    revoke_key_in_registry,
    rotate_key_in_registry,
)
from .signing import sign_http_request
from .vault_kms import VaultKmsConfig, VaultTransitSigner, _ensure_transit_key, resolve_vault_public_key


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
    key_name: str | None = None

    @classmethod
    def from_vault(
        cls,
        *,
        domain: str,
        name: str,
        organization: str,
        endpoint: str,
        vault_addr: str,
        transit_mount: str,
        key_name: str,
        vault_token_file: str | Path | None = None,
        vault_token: str | None = None,
        allow_insecure_raw_token: bool = False,
        namespace: str | None = None,
        verify: bool | str = True,
        capabilities: list[str] | None = None,
        environment: str | None = None,
        kid: str | None = None,
        auto_create_key: bool = False,
    ) -> "AgentInstance":
        config = VaultKmsConfig(
            vault_addr=vault_addr,
            transit_mount=transit_mount,
            key_name=key_name,
            vault_token_file=vault_token_file,
            vault_token=vault_token,
            allow_insecure_raw_token=allow_insecure_raw_token,
            namespace=namespace,
            verify=verify,
            kid=kid,
        )
        if auto_create_key:
            _ensure_transit_key(config)
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
            key_name=key_name,
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
        alg: str = "ES256",
        key_name: str | None = None,
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
            key_name=key_name,
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

    def _resolve_new_key_signer(
        self,
        *,
        new_key_name: str | None = None,
        new_signer: object | None = None,
        new_public_key_pem: str | None = None,
        new_kid: str | None = None,
    ) -> tuple[object, str, str]:
        """解析新 key 的 signer、公钥 PEM 和 kid。

        支持两种模式：
        - Vault 托管：提供 new_key_name，SDK 复用当前 Vault 配置自动创建并解析
        - 外部 signer：同时提供 new_signer、new_public_key_pem、new_kid

        Returns:
            (new_signer_obj, new_public_key_pem, new_kid) 三元组。
        """
        if new_key_name is not None:
            current_config = self.signer._config  # type: ignore[attr-defined]
            new_config = VaultKmsConfig(
                vault_addr=current_config.vault_addr,
                transit_mount=current_config.transit_mount,
                key_name=new_key_name,
                vault_token_file=current_config.vault_token_file,
                vault_token=current_config.vault_token,
                namespace=current_config.namespace,
                verify=current_config.verify,
                allow_insecure_raw_token=current_config.allow_insecure_raw_token,
            )
            _ensure_transit_key(new_config)
            new_signer_obj: object = VaultTransitSigner(new_config)
            new_signer_obj.validate_access()  # type: ignore[union-attr]
            description = resolve_vault_public_key(new_config)
            return (
                new_signer_obj,
                description.public_key_pem,
                f"vault:{current_config.transit_mount}/{new_key_name}",
            )

        if new_signer is None or new_public_key_pem is None or new_kid is None:
            raise ValueError(
                "Either new_key_name (for Vault-managed key creation) "
                "or all of new_signer, new_public_key_pem, new_kid must be provided."
            )
        return (new_signer, new_public_key_pem, new_kid)

    async def rotate_key(
        self,
        *,
        registry_url: str,
        client_id: str,
        api_key: str,
        # 方式 A（兼容）: 预创建的 signer（new_signer + new_public_key_pem + new_kid）
        new_signer: object | None = None,
        new_public_key_pem: str | None = None,
        new_kid: str | None = None,
        # 方式 B（Vault 托管）: SDK 自动在 Vault 中创建新 key
        new_key_name: str | None = None,
        http_client: httpx.AsyncClient | None = None,
        timeout_seconds: float = 10.0,
    ) -> dict:
        new_signer_obj, new_public_key_pem, new_kid = self._resolve_new_key_signer(
            new_key_name=new_key_name,
            new_signer=new_signer,
            new_public_key_pem=new_public_key_pem,
            new_kid=new_kid,
        )
        new_key = AgentKey(
            kid=new_kid,
            alg="ES256",
            public_key_pem=new_public_key_pem,
            public_key_base64url=public_key_to_base64url(new_public_key_pem),
            status="active",
        )
        result = await rotate_key_in_registry(
            agent_id=self.agent_id,
            new_key=new_key,
            registry_url=registry_url,
            client_id=client_id,
            api_key=api_key,
            current_signer=self.signer,
            new_signer=new_signer_obj,
            http_client=http_client,
            timeout_seconds=timeout_seconds,
        )
        self.kid = new_kid
        self.public_key_pem = new_public_key_pem
        self.public_key_base64url = new_key.public_key_base64url or ""
        self.signer_override = new_signer_obj
        if self.metadata is not None:
            self.metadata = self.metadata.model_copy(
                update={
                    "keys": [
                        *(key.model_copy(update={"status": "inactive"}) if key.status == "active" else key for key in self.metadata.keys),
                        new_key,
                    ],
                },
            )
        return result

    async def add_key(
        self,
        *,
        registry_url: str,
        client_id: str,
        api_key: str,
        # 方式 A（兼容）: 预创建的 signer
        new_signer: object | None = None,
        new_public_key_pem: str | None = None,
        new_kid: str | None = None,
        # 方式 B（Vault 托管）: SDK 自动在 Vault 中创建新 key
        new_key_name: str | None = None,
        http_client: httpx.AsyncClient | None = None,
        timeout_seconds: float = 10.0,
    ) -> dict:
        """为 Agent 添加额外活跃密钥，保留已有 active key 不变。

        与 rotate_key() 的关键区别：已有 active key 不会被标记为 inactive，
        允许多个活跃 key 并存（多地域部署、平滑算法迁移等场景）。
        """
        new_signer_obj, new_public_key_pem, new_kid = self._resolve_new_key_signer(
            new_key_name=new_key_name,
            new_signer=new_signer,
            new_public_key_pem=new_public_key_pem,
            new_kid=new_kid,
        )
        new_key = AgentKey(
            kid=new_kid,
            alg="ES256",
            public_key_pem=new_public_key_pem,
            public_key_base64url=public_key_to_base64url(new_public_key_pem),
            status="active",
        )
        result = await add_key_in_registry(
            agent_id=self.agent_id,
            new_key=new_key,
            registry_url=registry_url,
            client_id=client_id,
            api_key=api_key,
            current_signer=self.signer,
            new_signer=new_signer_obj,
            http_client=http_client,
            timeout_seconds=timeout_seconds,
        )
        if self.metadata is not None:
            self.metadata = self.metadata.model_copy(
                update={"keys": [*self.metadata.keys, new_key]},
            )
        return result

    async def revoke_key(
        self,
        *,
        registry_url: str,
        client_id: str,
        api_key: str,
        kid_to_revoke: str,
        http_client: httpx.AsyncClient | None = None,
        timeout_seconds: float = 10.0,
    ) -> dict:
        """显式撤销一个密钥，将其加入 revoked_kids 黑名单。

        Raises:
            ValueError: 若 kid_to_revoke 是唯一的 active key（防止锁死）。
        """
        if self.metadata is None:
            raise ValueError("metadata has not been initialized")

        # 校验 kid 存在
        target_key = None
        active_count = 0
        for key in self.metadata.keys:
            if key.kid == kid_to_revoke:
                target_key = key
            if key.status == "active":
                active_count += 1

        if target_key is None:
            raise ValueError(f"Key not found in metadata: {kid_to_revoke}")

        # 防锁死：不能撤销唯一的 active key
        if target_key.status == "active" and active_count <= 1:
            raise ValueError(
                f"Cannot revoke the last active key '{kid_to_revoke}'. "
                "Use add_key() or rotate_key() to establish a new active key first."
            )

        result = await revoke_key_in_registry(
            agent_id=self.agent_id,
            kid_to_revoke=kid_to_revoke,
            registry_url=registry_url,
            client_id=client_id,
            api_key=api_key,
            current_signer=self.signer,
            http_client=http_client,
            timeout_seconds=timeout_seconds,
        )
        # 本地更新：加入 revoked_kids + 标记 status="revoked"
        updated_revoked = [*self.metadata.revoked_kids, kid_to_revoke]
        updated_keys = [
            key.model_copy(update={"status": "revoked"}) if key.kid == kid_to_revoke else key
            for key in self.metadata.keys
        ]
        self.metadata = self.metadata.model_copy(
            update={"revoked_kids": updated_revoked, "keys": updated_keys},
        )
        return result

    async def revoke_agent(
        self,
        *,
        registry_url: str,
        client_id: str,
        api_key: str,
        http_client: httpx.AsyncClient | None = None,
        timeout_seconds: float = 10.0,
    ) -> dict:
        """撤销整个 Agent。撤销后 agent 从 Registry 公开文档消失，所有操作被拒绝。

        注意：此操作不可逆。撤销后需重新 publish 一个全新的 agent。
        """
        result = await revoke_agent_in_registry(
            agent_id=self.agent_id,
            registry_url=registry_url,
            client_id=client_id,
            api_key=api_key,
            current_signer=self.signer,
            http_client=http_client,
            timeout_seconds=timeout_seconds,
        )
        return result

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
