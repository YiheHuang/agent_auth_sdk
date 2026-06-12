"""Pydantic 模型负责把协议结构稳定下来，并给 CLI / FastAPI 复用。"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class AgentAuditConfig(BaseModel):
    """审计配置属于可选扩展字段，供网关或厂商自定义落盘策略。"""

    model_config = ConfigDict(extra="allow")

    mode: Literal["jsonl", "sqlite", "custom"] = "jsonl"
    destination: str | None = None


class AgentKey(BaseModel):
    """一把可供验签使用的公钥。"""

    kid: str
    alg: Literal["Ed25519"] = "Ed25519"
    status: Literal["active", "inactive"] = "active"
    public_key_base64url: str | None = None
    public_key_pem: str | None = None
    not_before: datetime | None = None
    not_after: datetime | None = None

    @field_validator("public_key_pem", mode="after")
    @classmethod
    def validate_public_key_presence(cls, value: str | None, info: Any) -> str | None:
        base64url = info.data.get("public_key_base64url")
        if not value and not base64url:
            raise ValueError("Either public_key_pem or public_key_base64url is required")
        return value


class AgentMetadata(BaseModel):
    """`/.well-known/agent.json` 对外暴露的完整结构。"""

    model_config = ConfigDict(extra="allow")

    version: str = "1.0"
    agent_id: str
    domain: str
    name: str
    organization: str
    endpoint: str
    capabilities: list[str] = Field(default_factory=list)
    keys: list[AgentKey]
    revoked_kids: list[str] = Field(default_factory=list)
    updated_at: datetime
    environment: str | None = None
    signing_policy: dict[str, Any] | None = None
    verification_policy: dict[str, Any] | None = None
    audit: AgentAuditConfig | None = None


class SignedAgentMessage(BaseModel):
    """Agent 之间传递的规范签名消息。"""

    model_config = ConfigDict(extra="allow")

    version: str = "1.0"
    agent_id: str
    kid: str
    alg: Literal["Ed25519"] = "Ed25519"
    timestamp: datetime
    nonce: str
    payload_type: str = "application/json"
    payload: Any
    signature: str
    recipient: str | None = None
    message_type: str | None = None


class AgentRegistryEntry(BaseModel):
    """中心注册表中的单个 Agent 条目。"""

    model_config = ConfigDict(extra="allow")

    agent_id: str
    metadata: AgentMetadata
    published_at: datetime
    publisher: str | None = None


class AgentRegistryDocument(BaseModel):
    """中心服务器的 `/.well-known/agent.json` 结构。"""

    model_config = ConfigDict(extra="allow")

    version: str = "1.0"
    registry_type: Literal["agent_registry"] = "agent_registry"
    updated_at: datetime
    agents: list[AgentRegistryEntry] = Field(default_factory=list)


@dataclass(slots=True)
class ResolveResult:
    """解析 metadata 后返回给调用方的结构化结果。"""

    metadata: AgentMetadata
    resolved_at: datetime
    etag: str | None = None
    source_url: str | None = None


@dataclass(slots=True)
class SignatureHeaders:
    """签名过程产出的 headers 与 canonical string。"""

    headers: dict[str, str]
    canonical: str
    body_digest: str


@dataclass(slots=True)
class VerificationSuccess:
    """验签成功时返回的业务上下文。"""

    ok: Literal[True] = True
    agent_id: str = ""
    kid: str = ""
    metadata: AgentMetadata | None = None
    canonical: str = ""
    request_id: str | None = None
    message: SignedAgentMessage | None = None


@dataclass(slots=True)
class VerificationFailure:
    """验签失败时返回的稳定结构。"""

    ok: Literal[False] = False
    code: str = ""
    reason: str = ""


@dataclass(slots=True)
class GeneratedKeyPair:
    """CLI、测试和示例服务都依赖这份统一的密钥返回结构。"""

    private_key_pem: str
    public_key_pem: str
    public_key_base64url: str
    kid: str


@dataclass(slots=True)
class ParsedAgentId:
    """解析 agent_id 后的最小语义结构。"""

    raw: str
    host: str
    agent_name: str
    path_segments: tuple[str, ...] = field(default_factory=tuple)

