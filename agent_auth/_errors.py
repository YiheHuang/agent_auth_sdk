"""单一、可安全记录的错误类型。"""

from __future__ import annotations

from typing import Any


class AgentAuthError(Exception):
    """所有公开失败都通过此异常返回。"""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        request_id: str | None = None,
        agent_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.request_id = request_id
        self.agent_id = agent_id
        self.details = dict(details or {})

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"

    def as_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.request_id:
            value["request_id"] = self.request_id
        if self.agent_id:
            value["agent_id"] = self.agent_id
        if self.details:
            value["details"] = dict(self.details)
        return value
