"""跨 HTTP、OpenAI run context 和日志共享的认证上下文。"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass(slots=True, frozen=True)
class AuthenticatedAgentContext:
    """一次已认证 Agent 调用的最小安全上下文。"""

    agent_id: str
    kid: str
    capabilities: tuple[str, ...] = ()
    request_id: str | None = None
    authenticated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    extensions: dict[str, Any] = field(default_factory=dict)

    def has_capability(self, capability: str) -> bool:
        return capability in self.capabilities


def authenticated_context_from(value: Any) -> AuthenticatedAgentContext | None:
    """从 FastAPI state、RunContextWrapper 或应用 context 中读取认证上下文。"""

    if isinstance(value, AuthenticatedAgentContext):
        return value
    wrapped = getattr(value, "context", None)
    if isinstance(wrapped, AuthenticatedAgentContext):
        return wrapped
    candidate = getattr(value, "agent_auth", None)
    if isinstance(candidate, AuthenticatedAgentContext):
        return candidate
    state = getattr(value, "state", None)
    candidate = getattr(state, "agent_auth", None) if state is not None else None
    return candidate if isinstance(candidate, AuthenticatedAgentContext) else None
