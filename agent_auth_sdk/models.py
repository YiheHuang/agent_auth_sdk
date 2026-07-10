"""Pydantic 模型负责把协议结构稳定下来，并给 SDK / Registry 复用。"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Literal

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .http_utils import from_base64url


class AgentAuditConfig(BaseModel):
    """审计配置属于可选扩展字段，供网关或厂商自定义落盘策略。"""

    model_config = ConfigDict(extra="forbid")

    mode: Literal["jsonl", "sqlite", "custom"] = "jsonl"
    destination: str | None = None
    extensions: dict[str, Any] = Field(default_factory=dict)


class AgentKey(BaseModel):
    """一把可供验签使用的公钥。"""

    kid: str
    alg: Literal["ES256"] = "ES256"
    status: Literal["active", "inactive", "revoked"] = "active"
    public_key_base64url: str | None = None
    public_key_pem: str | None = None
    not_before: datetime | None = None
    not_after: datetime | None = None
    extensions: dict[str, Any] = Field(default_factory=dict)

    @field_validator("public_key_pem", mode="after")
    @classmethod
    def validate_public_key_presence(cls, value: str | None, info: Any) -> str | None:
        base64url = info.data.get("public_key_base64url")
        if not value and not base64url:
            raise ValueError("Either public_key_pem or public_key_base64url is required")
        return value

    @field_validator("not_before", "not_after")
    @classmethod
    def key_time_must_be_aware(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("key validity timestamps must include a timezone")
        return value

    @model_validator(mode="after")
    def validate_key_material(self) -> AgentKey:
        if not self.kid.strip():
            raise ValueError("kid must not be empty")
        pem_key = None
        der_key = None
        if self.public_key_pem:
            pem_key = serialization.load_pem_public_key(self.public_key_pem.encode("utf-8"))
        if self.public_key_base64url:
            der_key = serialization.load_der_public_key(from_base64url(self.public_key_base64url))
        for key in (pem_key, der_key):
            if key is None:
                continue
            if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
                raise ValueError("AgentKey must contain an ES256/P-256 public key")
        if pem_key is not None and der_key is not None:
            pem_der = pem_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            encoded_der = der_key.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            if pem_der != encoded_der:
                raise ValueError("public_key_pem and public_key_base64url describe different keys")
        if self.not_before and self.not_after and self.not_before > self.not_after:
            raise ValueError("not_before must not be after not_after")
        return self


class AgentMetadata(BaseModel):
    """单个 Agent 的身份、能力声明和验签公钥。"""

    model_config = ConfigDict(extra="forbid")

    version: Literal["1.0"] = "1.0"
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
    extensions: dict[str, Any] = Field(default_factory=dict)

    @field_validator("updated_at")
    @classmethod
    def updated_at_must_be_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("updated_at must include a timezone")
        return value

    @model_validator(mode="after")
    def validate_keys(self) -> AgentMetadata:
        if not self.keys:
            raise ValueError("metadata must contain at least one key")
        kids = [key.kid for key in self.keys]
        if len(kids) != len(set(kids)):
            raise ValueError("metadata contains duplicate kid values")
        if len(self.revoked_kids) != len(set(self.revoked_kids)):
            raise ValueError("metadata contains duplicate revoked_kids")
        return self


class SignedAgentMessage(BaseModel):
    """Agent 之间传递的规范签名消息。"""

    model_config = ConfigDict(extra="forbid")

    version: Literal["1.0"] = "1.0"
    agent_id: str
    kid: str
    alg: Literal["ES256"] = "ES256"
    timestamp: datetime
    nonce: str
    payload_type: str = "application/json"
    payload: Any
    signature: str
    recipient: str | None = None
    message_type: str | None = None
    extensions: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def timestamp_must_be_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must include a timezone")
        if value.utcoffset() != timedelta(0) or value.microsecond != 0:
            raise ValueError("timestamp must use UTC second precision")
        return value


class AgentRegistryEntry(BaseModel):
    """中心注册表中的单个 Agent 条目。"""

    model_config = ConfigDict(extra="forbid")

    agent_id: str
    metadata: AgentMetadata
    published_at: datetime
    publisher: str | None = None
    extensions: dict[str, Any] = Field(default_factory=dict)


class AgentRegistryDocument(BaseModel):
    """中心服务器的 `/.well-known/agent.json` 结构。"""

    model_config = ConfigDict(extra="forbid")

    version: Literal["1.0"] = "1.0"
    registry_type: Literal["agent_registry"] = "agent_registry"
    updated_at: datetime
    agents: list[AgentRegistryEntry] = Field(default_factory=list)
    extensions: dict[str, Any] = Field(default_factory=dict)


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
class ParsedAgentId:
    """解析 agent_id 后的最小语义结构。"""

    raw: str
    host: str
    agent_name: str
    path_segments: tuple[str, ...] = field(default_factory=tuple)
