"""SDK 内部统一使用的错误码和异常定义。"""

from __future__ import annotations

from enum import StrEnum
from typing import Any


class VerificationErrorCode(StrEnum):
    INVALID_AGENT_ID = "INVALID_AGENT_ID"
    INVALID_METADATA = "INVALID_METADATA"
    MESSAGE_INVALID = "MESSAGE_INVALID"
    METADATA_FETCH_FAILED = "METADATA_FETCH_FAILED"
    METADATA_HOST_MISMATCH = "METADATA_HOST_MISMATCH"
    KEY_NOT_FOUND = "KEY_NOT_FOUND"
    KEY_REVOKED = "KEY_REVOKED"
    KEY_EXPIRED = "KEY_EXPIRED"
    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    TIMESTAMP_EXPIRED = "TIMESTAMP_EXPIRED"
    NONCE_REPLAYED = "NONCE_REPLAYED"
    POLICY_REJECTED = "POLICY_REJECTED"
    RECIPIENT_MISMATCH = "RECIPIENT_MISMATCH"


class AgentIdentityError(ValueError):
    """输入格式或协议层面的错误。"""


class MetadataValidationError(ValueError):
    """metadata 内容不合法时抛出。"""


class AgentAuthError(Exception):
    """可以安全交给应用处理的 Agent Auth 基础异常。

    ``details`` 只能保存非敏感诊断信息。调用方不应在其中放入 token、私钥、
    完整签名或未经清理的远端响应。
    """

    default_code = "AGENT_AUTH_ERROR"

    def __init__(
        self,
        message: str,
        *,
        code: str | None = None,
        agent_id: str | None = None,
        request_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code or self.default_code
        self.agent_id = agent_id
        self.request_id = request_id
        self.details = dict(details or {})

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"

    def as_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.agent_id is not None:
            payload["agent_id"] = self.agent_id
        if self.request_id is not None:
            payload["request_id"] = self.request_id
        if self.details:
            payload["details"] = dict(self.details)
        return payload


class AgentAuthenticationError(AgentAuthError, PermissionError):
    default_code = "AUTHENTICATION_FAILED"


class AgentAuthorizationError(AgentAuthError, PermissionError):
    default_code = "AUTHORIZATION_FAILED"


class AgentReplayError(AgentAuthenticationError):
    default_code = VerificationErrorCode.NONCE_REPLAYED.value


class AgentDiscoveryError(AgentAuthenticationError):
    default_code = VerificationErrorCode.METADATA_FETCH_FAILED.value


class AgentTransportError(AgentAuthError):
    default_code = "TRANSPORT_FAILED"


class AgentConfigurationError(AgentAuthError, ValueError):
    default_code = "CONFIGURATION_INVALID"
