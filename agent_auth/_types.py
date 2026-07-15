"""公开上下文和内部最小数据类型。"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True, frozen=True)
class AuthContext:
    """一次已认证调用的身份上下文。"""

    sender: str
    kid: str
    capabilities: tuple[str, ...]
    request_id: str
    call_type: str


@dataclass(slots=True, frozen=True)
class AgentRecord:
    agent_id: str
    endpoint: str
    capabilities: tuple[str, ...]
    kid: str
    public_key: str
    updated_at: str

    @classmethod
    def from_dict(cls, value: dict[str, object]) -> AgentRecord:
        try:
            capabilities = value.get("capabilities", [])
            if not isinstance(capabilities, list) or not all(isinstance(item, str) for item in capabilities):
                raise TypeError
            fields = ("agent_id", "endpoint", "kid", "public_key", "updated_at")
            if any(not isinstance(value.get(field), str) or not value[field] for field in fields):
                raise TypeError
            return cls(
                agent_id=value["agent_id"],  # type: ignore[arg-type]
                endpoint=value["endpoint"],  # type: ignore[arg-type]
                capabilities=tuple(capabilities),
                kid=value["kid"],  # type: ignore[arg-type]
                public_key=value["public_key"],  # type: ignore[arg-type]
                updated_at=value["updated_at"],  # type: ignore[arg-type]
            )
        except (KeyError, TypeError, ValueError) as exc:
            from ._errors import AgentAuthError

            raise AgentAuthError("INVALID_METADATA", "Registry returned invalid Agent metadata") from exc

    def as_dict(self) -> dict[str, object]:
        return {
            "agent_id": self.agent_id,
            "endpoint": self.endpoint,
            "capabilities": list(self.capabilities),
            "kid": self.kid,
            "public_key": self.public_key,
            "updated_at": self.updated_at,
        }
